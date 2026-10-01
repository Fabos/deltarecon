#!/usr/bin/env python3
"""Regression for v0.29 Investigation Map 2.0 and Request-first UX."""
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


def capture(paths, domain, path, *, cookie, order_id, status="CREATED", http_status=200):
    req = f"GET {path} HTTP/1.1\r\nHost: api.maplab.local\r\nCookie: session={cookie}\r\n\r\n".encode()
    resp = f'HTTP/1.1 {http_status} OK\r\nContent-Type: application/json\r\n\r\n{{"orderId":{order_id},"status":"{status}"}}'.encode()
    return core.upsert_http_observation(
        paths, domain, url=f"https://api.maplab.local{path}", method="GET",
        source="burp_proxy", status_code=http_status, authenticated=True, tool="PROXY",
        response_content_type="application/json", request_b64=b64(req), response_b64=b64(resp), query={},
    )


def obs_id(conn, exchange_id, normalized_name):
    row = conn.execute(
        "SELECT id FROM parameter_observations WHERE exchange_id=? AND normalized_name=? ORDER BY id LIMIT 1",
        (int(exchange_id), normalized_name),
    ).fetchone()
    assert row, (exchange_id, normalized_name)
    return int(row["id"])


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="negro-v029-") as td:
        root = Path(td)
        old_targets = core.TARGETS_PATH
        core.TARGETS_PATH = root / "targets.json"
        try:
            domain = "maplab.local"
            workspace = root / "workspace"
            paths = core.ensure_workspace(workspace, domain)
            a = capture(paths, domain, "/orders/4101", cookie="azul", order_id=4101, status="CREATED")
            b = capture(paths, domain, "/orders/4101/invoice", cookie="verde", order_id=4101, status="CREATED")
            c = capture(paths, domain, "/orders/4101/ship", cookie="azul", order_id=4101, status="SHIPPED")

            with core.db_connect(paths) as conn:
                for ex in (a, b, c):
                    hunter.analyze_http_exchange(conn, int(ex["exchange_id"]), domain, emit_notifications=False)

                azul = identities.create_identity(conn, "Cuenta Azul")
                verde = identities.create_identity(conn, "Operador Verde")
                identities.assign_exchange(conn, int(a["exchange_id"]), azul, learn_auth=True)
                identities.assign_exchange(conn, int(b["exchange_id"]), verde, learn_auth=True)
                identities.assign_exchange(conn, int(c["exchange_id"]), azul, learn_auth=False)

                flows.create_state_track(
                    conn,
                    obs_id(conn, a["exchange_id"], "status"),
                    obs_id(conn, a["exchange_id"], "orderid"),
                    object_type="Order",
                )
                objects.rebuild(conn)
                flow_id = flows.create_flow(conn, "Despacho controlado")
                for ex in (a, c):
                    flows.add_step(conn, flow_id, int(ex["exchange_id"]))
                objects.rebuild(conn)
                order = conn.execute(
                    """SELECT bo.id FROM business_objects bo JOIN business_object_types bt ON bt.id=bo.object_type_id
                       WHERE bt.name_key='order' AND bo.identifier_raw='4101' LIMIT 1"""
                ).fetchone()
                assert order
                object_id = int(order["id"])

            # Register after data exists so the web app resolves the exact workspace.
            key = core.register_target(domain, workspace, make_current=True, name="Map Lab", scopes=[domain, "api.maplab.local"])
            app = create_app(domain, workspace)
            client = TestClient(app)

            page = client.get(f"/t/{key}/graph")
            assert page.status_code == 200, page.text
            for phrase in ("INVESTIGATION MAP", "Superficie", "Identidades", "Flows", "Objetos", "Inteligencia", "Negro no asume buyer, seller, admin"):
                assert phrase in page.text, phrase

            identity_graph = client.get(f"/api/t/{key}/graph?scope=identity&identity_id={azul}&compare_identity_id={verde}")
            assert identity_graph.status_code == 200, identity_graph.text
            payload = identity_graph.json()
            labels = {n["label"] for n in payload["nodes"]}
            types = {n["type"] for n in payload["nodes"]}
            assert {"Cuenta Azul", "Operador Verde"} <= labels, labels
            assert {"identity", "request", "object"} <= types, types
            assert payload["meta"]["focus_node"] == f"identity:{azul}"

            flow_graph = client.get(f"/api/t/{key}/graph?scope=flow&flow_id={flow_id}")
            assert flow_graph.status_code == 200, flow_graph.text
            fp = flow_graph.json()
            assert any(n["type"] == "flow" and n["label"] == "Despacho controlado" for n in fp["nodes"])
            assert sum(1 for n in fp["nodes"] if n["type"] == "request") >= 2
            assert any(n["type"] == "state" for n in fp["nodes"]), fp["nodes"]

            object_graph = client.get(f"/api/t/{key}/graph?scope=object&object_id={object_id}")
            assert object_graph.status_code == 200, object_graph.text
            op = object_graph.json()
            assert op["meta"]["focus_node"] == f"object:{object_id}"
            assert any(n["type"] == "object" and "Order 4101" in n["label"] for n in op["nodes"])
            assert {"Cuenta Azul", "Operador Verde"} <= {n["label"] for n in op["nodes"]}

            request_graph = client.get(f"/api/t/{key}/graph?focus=request:{int(a['exchange_id'])}")
            assert request_graph.status_code == 200, request_graph.text
            rp = request_graph.json()
            assert rp["meta"]["scope"] == "request"
            assert rp["meta"]["focus_node"] == f"exchange:{int(a['exchange_id'])}"

            # Context entry points exist on the entities a hunter actually works from.
            identity_page = client.get(f"/t/{key}/identities/view/{azul}")
            assert f"graph?focus=identity:{azul}" in identity_page.text
            flow_page = client.get(f"/t/{key}/flows/{flow_id}")
            assert f"graph?focus=flow:{flow_id}" in flow_page.text
            flow_add_page = client.get(f"/t/{key}/flows/add?exchange_id={int(a['exchange_id'])}")
            assert flow_add_page.status_code == 200, flow_add_page.text
            assert f"Request #{int(a['exchange_id'])}" in flow_add_page.text
            assert 'name="exchange_id"' in flow_add_page.text
            object_page = client.get(f"/t/{key}/objects/{object_id}")
            assert f"graph?focus=object:{object_id}" in object_page.text

            # Visible terminology is now Request-first; internals may still be exchange_id.
            guide = client.get(f"/t/{key}/guide")
            assert "Resource / Operation / Request" in guide.text
            assert "Investigation Map" in guide.text
            assert "<b>Exchange</b>" not in guide.text
        finally:
            core.TARGETS_PATH = old_targets

    print("[OK] Map 2.0 uses dynamic Identity Context names and semantic lenses")
    print("[OK] Identity/Flow/Object/Request focus projections reuse existing Negro data")
    print("[OK] entity detail pages can pivot directly into the investigation map")
    print("[OK] visible UX uses Request while internal exchange_id compatibility remains intact")


if __name__ == "__main__":
    main()
