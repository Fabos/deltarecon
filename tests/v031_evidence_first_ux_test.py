#!/usr/bin/env python3
"""Regression for v0.31 evidence-first Identity/Object/Flow UX."""
from pathlib import Path
import base64
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_hunter as hunter
import negro_identity as identities
import negro_flows as flows
import negro_objects as objects
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def capture(paths, domain, path, *, cookie, order_id, status=200):
    req = f"GET {path} HTTP/1.1\r\nHost: api.uxlab.local\r\nCookie: session={cookie}\r\n\r\n".encode()
    resp = f'HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{{"orderId":{order_id},"ownerId":101}}'.encode()
    return core.upsert_http_observation(
        paths, domain, url=f"https://api.uxlab.local{path}", method="GET",
        source="burp_proxy", status_code=status, authenticated=True, tool="PROXY",
        response_content_type="application/json", request_b64=b64(req), response_b64=b64(resp), query={},
    )


def obs_id(conn, exchange_id, normalized_name):
    row = conn.execute(
        "SELECT id FROM parameter_observations WHERE exchange_id=? AND normalized_name=? ORDER BY id LIMIT 1",
        (int(exchange_id), normalized_name),
    ).fetchone()
    assert row
    return int(row["id"])


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="negro-v031-") as td:
        root = Path(td)
        old_targets = core.TARGETS_PATH
        core.TARGETS_PATH = root / "targets.json"
        try:
            domain = "uxlab.local"
            workspace = root / "workspace"
            paths = core.ensure_workspace(workspace, domain)
            r1 = capture(paths, domain, "/orders/123", cookie="diego", order_id=123)
            r2 = capture(paths, domain, "/orders/124", cookie="diego", order_id=124)
            with core.db_connect(paths) as conn:
                for ex in (r1, r2):
                    hunter.analyze_http_exchange(conn, int(ex["exchange_id"]), domain, emit_notifications=False)
                diego = identities.create_identity(conn, "Diego")
                identities.assign_exchange(conn, int(r1["exchange_id"]), diego, learn_auth=True)
                identities.assign_exchange(conn, int(r2["exchange_id"]), diego, learn_auth=False)
                oid = obs_id(conn, r1["exchange_id"], "orderid")
                # Deliberately bad label retained only as evidence.
                objects.ensure_identifier(conn, "111", "orderid", source_observation_id=oid)
                objects.rebuild(conn)
                f1 = flows.create_flow(conn, "Flow A")
                flows.add_step(conn, f1, int(r1["exchange_id"]))
                flows.add_step(conn, f1, int(r2["exchange_id"]))
                f2 = flows.create_flow(conn, "Flow B")
                flows.add_step(conn, f2, int(r1["exchange_id"]))
                obj = conn.execute(
                    """SELECT bo.id FROM business_objects bo JOIN business_object_types bt ON bt.id=bo.object_type_id
                       WHERE bt.name='111' AND bo.identifier_raw='123' LIMIT 1"""
                ).fetchone()
                assert obj
                object_id = int(obj["id"])

            key = core.register_target(domain, workspace, make_current=True, name="UX Lab", scopes=[domain, "api.uxlab.local"])
            app = create_app(domain, workspace)
            client = TestClient(app)

            identity_graph = client.get(f"/api/t/{key}/graph?scope=identity&identity_id={diego}").json()
            req_labels = [n["label"] for n in identity_graph["nodes"] if n["type"] == "request"]
            assert any("GET /orders/123" in x for x in req_labels), req_labels
            object_nodes = [n for n in identity_graph["nodes"] if n["type"] == "object"]
            assert object_nodes
            assert all("identifier_field" in n["meta"] for n in object_nodes), object_nodes
            assert any(n["label"] == "orderid=123" for n in object_nodes), object_nodes

            detail = client.get(f"/t/{key}/objects/{object_id}")
            assert detail.status_code == 200, detail.text
            assert "orderid" in detail.text and "123" in detail.text
            assert "todavía no sabe qué entidad" in detail.text
            assert "DÓNDE APARECIÓ" in detail.text and "/orders/123" in detail.text

            compare = client.get(f"/t/{key}/flows/compare?a={f1}&b={f2}")
            assert compare.status_code == 200, compare.text
            assert "Qué pasó distinto, paso por paso" in compare.text
            assert "BUSINESS OBJECT CHANGES" not in compare.text
            assert "Contexto de objetos · avanzado" in compare.text
            assert "tipos ambiguos" in compare.text

            js = (ROOT / "web" / "static" / "graph.js").read_text()
            for phrase in ("renderIdentityNarrative", "renderObjectNarrative", "Campos / contexto observado", "Ver relaciones gráficas · avanzado"):
                assert phrase in js, phrase
            css = (ROOT / "web" / "static" / "style.css").read_text()
            assert ".direct-nav" in css
            assert ".nav-divider" in css
        finally:
            core.TARGETS_PATH = old_targets

    print("[OK] Identity view makes method + endpoint + HTTP status primary")
    print("[OK] ambiguous objects render as key=value instead of meaningless type/value pairs")
    print("[OK] Object view starts from Requests where the value appeared")
    print("[OK] Flow Compare demotes ambiguous object-count deltas to advanced context")
    print("[OK] navigation stays explicit and direct without opaque dropdown groups")


if __name__ == "__main__":
    main()
