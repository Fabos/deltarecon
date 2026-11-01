#!/usr/bin/env python3
"""Regression for v0.103 intuitive Flow ordering and safe Flow deletion."""
from pathlib import Path
import base64
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from jinja2 import Environment, FileSystemLoader
import negro_core as core
import negro_flows as flows
import negro_runners as runners


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def capture(paths, domain, path, method="GET", status=200):
    req = f"{method} {path} HTTP/1.1\r\nHost: api.flow103.local\r\n\r\n".encode()
    resp = f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{{\"ok\":true}}".encode()
    return core.upsert_http_observation(
        paths, domain, url=f"https://api.flow103.local{path}", method=method,
        source="burp_proxy", status_code=status, authenticated=True, tool="PROXY",
        request_b64=b64(req), response_b64=b64(resp), query={},
    )


def main():
    with tempfile.TemporaryDirectory(prefix="negro-v103-") as td:
        domain = "api.flow103.local"
        paths = core.ensure_workspace(Path(td) / "project", domain)
        a = capture(paths, domain, "/search")
        b = capture(paths, domain, "/reserve", "POST")
        c = capture(paths, domain, "/pay", "POST")

        with core.db_connect(paths) as conn:
            fid = flows.create_flow(conn, "Compra simple")
            s1 = flows.add_step(conn, fid, int(a["exchange_id"]))
            s2 = flows.add_step(conn, fid, int(b["exchange_id"]))
            s3 = flows.add_step(conn, fid, int(c["exchange_id"]))

            # Drag & drop uses the existing move primitive: IDs stay stable.
            flows.move_step(conn, fid, s3, 1)
            rows = conn.execute("SELECT id,position FROM flow_steps WHERE flow_id=? ORDER BY position", (fid,)).fetchall()
            assert [int(r["id"]) for r in rows] == [s3, s1, s2]
            assert [int(r["position"]) for r in rows] == [1, 2, 3]

            # A linked scenario is Flow-owned and should follow existing FK semantics.
            rid = runners.create_runner_from_flow(conn, fid, alias="Scenario temporal")
            assert conn.execute("SELECT id FROM runners WHERE id=?", (rid,)).fetchone()

            original_exchange_ids = {int(a["exchange_id"]), int(b["exchange_id"]), int(c["exchange_id"])}
            summary = flows.delete_flow(conn, fid)
            assert summary["steps"] == 3
            assert summary["runners"] == 1
            assert not conn.execute("SELECT id FROM flows WHERE id=?", (fid,)).fetchone()
            assert not conn.execute("SELECT id FROM flow_steps WHERE flow_id=?", (fid,)).fetchone()
            assert not conn.execute("SELECT id FROM runners WHERE id=?", (rid,)).fetchone()
            survivors = {int(r["id"]) for r in conn.execute(
                "SELECT id FROM http_exchanges WHERE id IN (?,?,?)",
                tuple(sorted(original_exchange_ids)),
            ).fetchall()}
            assert survivors == original_exchange_ids

        env = Environment(loader=FileSystemLoader(str(ROOT / "web" / "templates")))
        env.get_template("flow_detail.html")
        template_text = (ROOT / "web" / "templates" / "flow_detail.html").read_text()
        css_text = (ROOT / "web" / "static" / "style.css").read_text()
        web_text = (ROOT / "negro_web.py").read_text()

        assert "data-flow-sortable" in template_text
        assert "data-drag-handle" in template_text
        assert "Se agrega al final. Luego arrástrala" in template_text
        assert "Mover por número" in template_text
        assert "Eliminar Flow" in template_text
        assert "/flows/{flow_id}/delete" in web_text
        assert ".flow-drag-handle" in css_text

    print("[OK] drag ordering keeps stable Step IDs")
    print("[OK] Flow deletion preserves original HTTP Requests")
    print("[OK] linked Flow-owned scenario follows existing cascade semantics")
    print("[OK] Flow UI exposes native drag handle and hidden numeric fallback")
    print("[OK] Flow delete action is explicit and administrative")


if __name__ == "__main__":
    main()
