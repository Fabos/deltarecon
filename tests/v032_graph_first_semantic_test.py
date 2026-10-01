#!/usr/bin/env python3
"""Regression for v0.32 graph-first semantic investigation views."""
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


def capture(paths, domain, path, *, cookie, method="GET", body='{"orderId":4101,"ownerId":101}', status=200):
    req = f"{method} {path} HTTP/1.1\r\nHost: api.graphlab.local\r\nCookie: session={cookie}\r\n\r\n".encode()
    resp = f'HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{body}'.encode()
    return core.upsert_http_observation(
        paths, domain, url=f"https://api.graphlab.local{path}", method=method,
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


def main():
    with tempfile.TemporaryDirectory(prefix="negro-v032-") as td:
        root = Path(td)
        old_targets = core.TARGETS_PATH
        core.TARGETS_PATH = root / "targets.json"
        try:
            domain = "graphlab.local"
            workspace = root / "workspace"
            paths = core.ensure_workspace(workspace, domain)
            diego_me = capture(paths, domain, "/me", cookie="diego", body='{"id":101,"roleId":7}')
            diego_order = capture(paths, domain, "/orders/4101", cookie="diego", body='{"orderId":4101,"ownerId":101}')
            ana_me = capture(paths, domain, "/me", cookie="ana", body='{"id":102,"roleId":7}')
            ana_order = capture(paths, domain, "/orders/4103", cookie="ana", body='{"orderId":4103,"ownerId":102}')
            # Same endpoint with another method so endpoint detail can expose supported methods.
            capture(paths, domain, "/orders/4101", cookie="diego", method="OPTIONS", body='{}', status=204)

            with core.db_connect(paths) as conn:
                for ex in (diego_me, diego_order, ana_me, ana_order):
                    hunter.analyze_http_exchange(conn, int(ex["exchange_id"]), domain, emit_notifications=False)
                diego = identities.create_identity(conn, "Diego")
                ana = identities.create_identity(conn, "Ana")
                identities.assign_exchange(conn, int(diego_me["exchange_id"]), diego, learn_auth=True)
                identities.assign_exchange(conn, int(diego_order["exchange_id"]), diego, learn_auth=False)
                identities.assign_exchange(conn, int(ana_me["exchange_id"]), ana, learn_auth=True)
                identities.assign_exchange(conn, int(ana_order["exchange_id"]), ana, learn_auth=False)

                oid = obs_id(conn, diego_order["exchange_id"], "orderid")
                objects.ensure_identifier(conn, "Order", "orderid", source_observation_id=oid)
                objects.rebuild(conn)
                obj = conn.execute(
                    """SELECT bo.id FROM business_objects bo JOIN business_object_types bt ON bt.id=bo.object_type_id
                       WHERE bt.name='Order' AND bo.identifier_raw='4101' LIMIT 1"""
                ).fetchone()
                assert obj
                object_id = int(obj["id"])

                flow_id = flows.create_flow(conn, "Compra Diego", identity_id=diego)
                flows.add_step(conn, flow_id, int(diego_me["exchange_id"]))
                flows.add_step(conn, flow_id, int(diego_order["exchange_id"]))

            key = core.register_target(domain, workspace, make_current=True, name="Graph Lab", scopes=[domain, "api.graphlab.local"])
            client = TestClient(create_app(domain, workspace))

            ident = client.get(f"/api/t/{key}/graph?scope=identity&identity_id={diego}&compare_identity_id={ana}").json()
            resources = {n["label"]: n for n in ident["nodes"] if n["type"] == "resource"}
            assert "/me" in resources and "/orders/4101" in resources and "/orders/4103" in resources, resources.keys()
            assert any(e["relation"] == "called_endpoint" and e["source"] == f"identity:{diego}" and e["target"] == resources["/me"]["id"] for e in ident["edges"])
            assert any(e["relation"] == "called_endpoint" and e["source"] == f"identity:{ana}" and e["target"] == resources["/me"]["id"] for e in ident["edges"])
            assert "GET" in resources["/orders/4101"]["meta"].get("methods", "")
            assert "OPTIONS" in resources["/orders/4101"]["meta"].get("methods", "")

            og = client.get(f"/api/t/{key}/graph?scope=object&object_id={object_id}").json()
            order_node = next(n for n in og["nodes"] if n["id"] == f"object:{object_id}")
            endpoint = next(n for n in og["nodes"] if n["type"] == "resource" and n["label"] == "/orders/4101")
            assert any(e["relation"] == "appeared_in_endpoint" and {e["source"], e["target"]} == {order_node["id"], endpoint["id"]} for e in og["edges"])
            assert any(n["type"] == "identity" and n["label"] == "Diego" for n in og["nodes"])
            assert any(n["type"] == "flow" and n["label"] == "Compra Diego" for n in og["nodes"])

            page = client.get(f"/t/{key}/graph")
            assert page.status_code == 200
            for phrase in ("Métodos HTTP", "Requests individuales", "Línea de tiempo", "Endpoint = ruta"):
                assert phrase in page.text, phrase

            js = (ROOT / "web" / "static" / "graph.js").read_text()
            for phrase in ("autoLayoutIdentity", "autoLayoutObject", "autoLayoutFlow", "called_endpoint", "keepLabelScreenSize", "flowViewMode"):
                assert phrase in js, phrase
            css = (ROOT / "web" / "static" / "style.css").read_text()
            for phrase in (".graph-node-label.label-identity", ".graph-node-label.label-resource", ".legend-endpoint", ".flow-view-switch"):
                assert phrase in css, phrase
        finally:
            core.TARGETS_PATH = old_targets

    print("[OK] Identity graph centers shared endpoints between dynamic identities")
    print("[OK] Object graph connects the focused object directly to endpoints, identities and flows")
    print("[OK] endpoint labels remain graph-first and method nodes are optional context")
    print("[OK] Flow supports both graph and timeline presentations")


if __name__ == "__main__":
    main()
