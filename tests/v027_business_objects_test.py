#!/usr/bin/env python3
"""Regression for v0.27 Business Objects, cross-host correlation and Pattern Anomalies."""
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


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def capture(paths, domain, host, path, method="GET", request_body="", response_body="{}", *, status=200, cookie=""):
    headers = f"Cookie: session={cookie}\r\n" if cookie else ""
    req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n{headers}\r\n{request_body}".encode()
    resp = f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\r\n{response_body}".encode()
    result = core.upsert_http_observation(
        paths, domain, url=f"https://{host}{path}", method=method, source="burp_proxy", status_code=status,
        authenticated=bool(cookie), tool="PROXY", request_content_type="application/json", response_content_type="application/json",
        request_b64=b64(req), response_b64=b64(resp), query={},
    )
    return result


def obs_id(conn, exchange_id, normalized_name):
    row = conn.execute(
        "SELECT id FROM parameter_observations WHERE exchange_id=? AND normalized_name=? ORDER BY id LIMIT 1",
        (int(exchange_id), normalized_name),
    ).fetchone()
    assert row, (exchange_id, normalized_name)
    return int(row["id"])


def main():
    with tempfile.TemporaryDirectory(prefix="negro-v027-") as td:
        domain = "example.test"
        paths = core.ensure_workspace(Path(td) / "project", domain)
        captured = []

        # Four peer orders establish the repeated relationship pattern Payment + Shipment.
        for oid in (9001, 9002, 9003, 9004):
            captured.append(capture(paths, domain, "api.example.test", f"/orders/{oid}", "POST", "{}", f'{{"orderId":{oid},"status":"CREATED"}}'))
            captured.append(capture(paths, domain, "payments.example.test", f"/payments/PAY-{oid}", "POST", f'{{"orderId":{oid}}}', f'{{"orderId":{oid},"paymentId":"PAY-{oid}","status":"PAID"}}'))
            captured.append(capture(paths, domain, "shipping.example.test", f"/shipments/SHIP-{oid}", "POST", f'{{"orderId":{oid}}}', f'{{"orderId":{oid},"shipmentId":"SHIP-{oid}","status":"SHIPPED"}}'))

        # Variant order intentionally has Shipment but no observed Payment relation.
        variant_create = capture(paths, domain, "api.example.test", "/orders/9005", "POST", "{}", '{"orderId":9005,"status":"CREATED"}')
        variant_ship = capture(paths, domain, "shipping.example.test", "/shipments/SHIP-9005", "POST", '{"orderId":9005}', '{"orderId":9005,"shipmentId":"SHIP-9005","status":"SHIPPED"}')
        captured.extend([variant_create, variant_ship])

        # Same identity + same normalized operation: peers return 403, one object returns 200.
        invoice_results = []
        for oid, status in ((9002, 403), (9003, 403), (9004, 403), (9005, 200)):
            ex = capture(paths, domain, "api.example.test", f"/orders/{oid}/invoice", "GET", "", f'{{"orderId":{oid}}}', status=status, cookie="buyer-b")
            invoice_results.append((oid, ex, status))
            captured.append(ex)

        with core.db_connect(paths) as conn:
            for ex in captured:
                hunter.analyze_http_exchange(conn, int(ex["exchange_id"]), domain, emit_notifications=False)

            buyer_b = identities.create_identity(conn, "Buyer B")
            for _oid, ex, _status in invoice_results:
                identities.assign_exchange(conn, int(ex["exchange_id"]), buyer_b, learn_auth=False)

            # State tracking teaches Order(orderId) automatically in v0.27.
            first_create = captured[0]
            flows.create_state_track(
                conn,
                obs_id(conn, first_create["exchange_id"], "status"),
                obs_id(conn, first_create["exchange_id"], "orderid"),
                object_type="Order",
            )
            # Teach related object types from observed response fields.
            first_payment = captured[1]
            first_shipment = captured[2]
            objects.track_observation(conn, obs_id(conn, first_payment["exchange_id"], "paymentid"), "Payment")
            objects.track_observation(conn, obs_id(conn, first_shipment["exchange_id"], "shipmentid"), "Shipment")
            # Teach the request-path alias order_id as the same Order type.
            objects.track_observation(conn, obs_id(conn, invoice_results[0][1]["exchange_id"], "order_id"), "Order")
            objects.rebuild(conn)

            order9001 = conn.execute(
                """SELECT bo.id FROM business_objects bo JOIN business_object_types bt ON bt.id=bo.object_type_id
                   WHERE bt.name_key='order' AND bo.identifier_raw='9001'"""
            ).fetchone()
            order9005 = conn.execute(
                """SELECT bo.id FROM business_objects bo JOIN business_object_types bt ON bt.id=bo.object_type_id
                   WHERE bt.name_key='order' AND bo.identifier_raw='9005'"""
            ).fetchone()
            assert order9001 and order9005

            d1 = objects.object_detail(conn, int(order9001["id"]))
            assert d1 and d1["object"]["cross_host"], d1
            assert {x["hostname"] for x in d1["hosts"]} >= {"api.example.test", "payments.example.test", "shipping.example.test"}
            assert {x["object_type"] for x in d1["related"]} >= {"Payment", "Shipment"}, d1["related"]
            assert d1["states"], "Business State observations should bind to the same Order instance"

            d5 = objects.object_detail(conn, int(order9005["id"]))
            assert d5
            kinds = {x["kind"] for x in d5["anomalies"]}
            assert "status_pattern" in kinds, d5["anomalies"]
            assert "relationship_pattern" in kinds, d5["anomalies"]
            status_anomaly = next(x for x in d5["anomalies"] if x["kind"] == "status_pattern")
            assert status_anomaly["baseline"] == "403" and status_anomaly["current"] == "200", status_anomaly
            relation_anomaly = next(x for x in d5["anomalies"] if x["kind"] == "relationship_pattern")
            assert "Payment" in relation_anomaly.get("missing", []), relation_anomaly

            # Flow integration: compare object-type presence without comparing the actual IDs.
            normal_flow = flows.create_flow(conn, "Normal object flow")
            for ex in captured[:3]:
                flows.add_step(conn, normal_flow, int(ex["exchange_id"]))
            variant_flow = flows.create_flow(conn, "Variant object flow")
            for ex in (variant_create, variant_ship):
                flows.add_step(conn, variant_flow, int(ex["exchange_id"]))
            flow_detail = flows.get_flow(conn, normal_flow)
            assert {x["object_type"] for x in flow_detail["business_objects"]} >= {"Order", "Payment", "Shipment"}, flow_detail["business_objects"]
            flow_compare = flows.compare_flows(conn, normal_flow, variant_flow)
            changes = {x["object_type"]: x for x in flow_compare["object_type_changes"]}
            assert "Payment" in changes and changes["Payment"]["a_count"] == 1 and changes["Payment"]["b_count"] == 0, changes

            overview = objects.overview(conn)
            assert int(overview["stats"]["cross_host_objects"]) >= 4
            assert any(card["object"]["id"] == int(order9005["id"]) for card in overview["anomaly_cards"]), overview["anomaly_cards"]

    print("[OK] Business Object aliases unify the same instance by type + exact value")
    print("[OK] One object correlates across API, payment and shipping hosts")
    print("[OK] Co-observed Payment/Shipment relationships are retained")
    print("[OK] Flow Detail/Compare reuse Business Objects and expose type-presence differences")
    print("[OK] Pattern Anomalies flag repeated-status and relationship differences without verdicts")


if __name__ == "__main__":
    main()
