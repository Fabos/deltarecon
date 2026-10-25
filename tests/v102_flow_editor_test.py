#!/usr/bin/env python3
"""Regression for v0.102 Flow Editor sequence reshaping."""
from pathlib import Path
import base64
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from jinja2 import Environment, FileSystemLoader
import negro_core as core
import negro_flows as flows
import negro_flow_runtime as runtime


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def capture(paths, domain, path, method="GET", body="", status=200):
    req = f"{method} {path} HTTP/1.1\r\nHost: api.flowedit.local\r\nContent-Type: application/json\r\n\r\n{body}".encode()
    resp = f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{{\"ok\":true}}".encode()
    return core.upsert_http_observation(
        paths, domain, url=f"https://api.flowedit.local{path}", method=method,
        source="burp_proxy", status_code=status, authenticated=True, tool="PROXY",
        request_content_type="application/json", response_content_type="application/json",
        request_b64=b64(req), response_b64=b64(resp), query={},
    )


def ordered(conn, flow_id):
    return [int(r["exchange_id"]) for r in conn.execute(
        "SELECT exchange_id FROM flow_steps WHERE flow_id=? ORDER BY position,id", (flow_id,)
    ).fetchall()]


def main():
    with tempfile.TemporaryDirectory(prefix="negro-v102-") as td:
        domain = "api.flowedit.local"
        paths = core.ensure_workspace(Path(td) / "project", domain)
        a = capture(paths, domain, "/search")
        b = capture(paths, domain, "/checkout", "POST", '{"cartId":1}')
        c = capture(paths, domain, "/payment", "POST", '{"cartId":1}')
        x = capture(paths, domain, "/fare/validate", "POST", '{"fareId":7}')
        noise = capture(paths, domain, "/analytics/tracking")

        with core.db_connect(paths) as conn:
            fid = flows.create_flow(conn, "Compra vuelo")
            sa = flows.add_step(conn, fid, int(a["exchange_id"]))
            sb = flows.add_step(conn, fid, int(b["exchange_id"]))
            sc = flows.add_step(conn, fid, int(c["exchange_id"]))

            # Runtime references stable step IDs. Reordering must not recreate them.
            runtime.init_schema(conn)
            var = runtime.create_variable(
                conn, fid, name="checkout_token", source_type="PREVIOUS_RESPONSE",
                producer_step_id=sb, extraction_type="json", extraction_expr="$.token",
            )

            sx = flows.add_step(conn, fid, int(x["exchange_id"]), position=2)
            assert ordered(conn, fid) == [int(a["exchange_id"]), int(x["exchange_id"]), int(b["exchange_id"]), int(c["exchange_id"])]

            flows.move_step(conn, fid, sc, 2)
            assert ordered(conn, fid) == [int(a["exchange_id"]), int(c["exchange_id"]), int(x["exchange_id"]), int(b["exchange_id"])]
            producer = conn.execute("SELECT producer_step_id FROM flow_variables WHERE id=?", (var,)).fetchone()
            assert int(producer["producer_step_id"]) == sb

            flows.remove_step(conn, fid, sx)
            assert ordered(conn, fid) == [int(a["exchange_id"]), int(c["exchange_id"]), int(b["exchange_id"])]
            assert [int(r["position"]) for r in conn.execute("SELECT position FROM flow_steps WHERE flow_id=? ORDER BY position", (fid,)).fetchall()] == [1,2,3]

            sn = flows.add_step(conn, fid, int(noise["exchange_id"]), candidate=True)
            flows.refresh_noise_suggestions(conn, fid)
            data = flows.get_flow(conn, fid)
            assert data and data["noise_suggested_count"] >= 1
            omitted = flows.exclude_suggested_noise(conn, fid)
            assert omitted >= 1
            row = conn.execute("SELECT included,noise_suggested FROM flow_steps WHERE id=?", (sn,)).fetchone()
            assert int(row["included"]) == 0 and int(row["noise_suggested"]) == 1

        env = Environment(loader=FileSystemLoader(str(ROOT / "web" / "templates")))
        env.get_template("flow_detail.html")
        template_text = (ROOT / "web" / "templates" / "flow_detail.html").read_text()
        assert "Agregar Request" in template_text
        assert "Quitar del Flow" in template_text
        assert "Mover por número" in template_text
        assert "Limpiar ruido sugerido" in template_text
        assert "Detener captura" in template_text

    print("[OK] insert Request at an exact narrative position")
    print("[OK] move Step without breaking runtime producer references")
    print("[OK] remove Step and renumber the remaining sequence")
    print("[OK] surface and explicitly omit suggested background traffic")
    print("[OK] Flow UI exposes add/move/remove/noise/stop-capture controls")


if __name__ == "__main__":
    main()
