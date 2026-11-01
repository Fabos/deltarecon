#!/usr/bin/env python3
"""Regression for v0.26 Burp Identity/Flow foundations + Business State Observations."""
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


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def capture(paths, domain, path, method, request_body, response_body, *, cookie="", auth="", status=200):
    headers = ""
    if cookie:
        headers += f"Cookie: session={cookie}\r\n"
    if auth:
        headers += f"Authorization: Bearer {auth}\r\n"
    req = f"{method} {path} HTTP/1.1\r\nHost: api.example.test\r\nContent-Type: application/json\r\n{headers}\r\n{request_body}".encode()
    resp = f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{response_body}".encode()
    return core.upsert_http_observation(
        paths, domain, url=f"https://api.example.test{path}", method=method, source="burp_proxy", status_code=status,
        authenticated=bool(cookie or auth), tool="PROXY", request_content_type="application/json", response_content_type="application/json",
        request_b64=b64(req), response_b64=b64(resp), query={},
    )


def main():
    with tempfile.TemporaryDirectory(prefix="negro-v026-") as td:
        domain = "api.example.test"
        paths = core.ensure_workspace(Path(td) / "project", domain)

        a1 = capture(paths, domain, "/me", "GET", "", '{"userId":101,"status":"active"}', cookie="sess-a")
        b1 = capture(paths, domain, "/me", "GET", "", '{"userId":202,"status":"active"}', cookie="sess-b-old")
        b2 = capture(paths, domain, "/refresh", "POST", "{}", '{"userId":202,"status":"active"}', cookie="sess-b-new")

        created = capture(paths, domain, "/orders/8001", "POST", '{"productId":501}', '{"orderId":8001,"status":"CREATED"}', cookie="sess-a")
        paid = capture(paths, domain, "/orders/8001/pay", "POST", '{"orderId":8001}', '{"orderId":8001,"status":"PAID"}', cookie="sess-a")
        shipped = capture(paths, domain, "/orders/8001/ship", "POST", '{"orderId":8001}', '{"orderId":8001,"status":"SHIPPED"}', cookie="sess-a")
        created2 = capture(paths, domain, "/orders/8002", "POST", '{"productId":501}', '{"orderId":8002,"status":"CREATED"}', cookie="sess-b-new")
        shipped2 = capture(paths, domain, "/orders/8002/ship", "POST", '{"orderId":8002}', '{"orderId":8002,"status":"SHIPPED"}', cookie="sess-b-new")

        with core.db_connect(paths) as conn:
            all_ex = (a1,b1,b2,created,paid,shipped,created2,shipped2)
            for ex in all_ex:
                hunter.analyze_http_exchange(conn, int(ex["exchange_id"]), domain, emit_notifications=False)

            buyer_a = identities.create_identity(conn, "Buyer A")
            buyer_b = identities.create_identity(conn, "Buyer B")
            identities.assign_exchange(conn, int(a1["exchange_id"]), buyer_a, learn_auth=True)
            identities.assign_exchange(conn, int(b1["exchange_id"]), buyer_b, learn_auth=True)
            # Explicit rotation: old B material becomes historical, new one is current.
            identities.update_identity_auth_from_exchange(conn, int(b2["exchange_id"]), buyer_b)
            identities.assign_exchange(conn, int(b2["exchange_id"]), buyer_b, learn_auth=False)

            rewritten = identities.rewrite_exchange_as_identity(conn, int(a1["exchange_id"]), buyer_b)
            raw = base64.b64decode(rewritten["request_b64"]).decode("iso-8859-1")
            assert "session=sess-b-new" in raw, raw
            assert "session=sess-a" not in raw, raw
            anonymous = identities.rewrite_exchange_as_identity(conn, int(a1["exchange_id"]), None)
            anon_raw = base64.b64decode(anonymous["request_b64"]).decode("iso-8859-1")
            assert "session=sess-a" not in anon_raw, anon_raw

            # Burp-style capture window: real observations are appended as ordered
            # occurrences. Capture is not reconstructed later from exchange-id ranges.
            flow_capture = flows.start_capture(conn, "Captured checkout", start_exchange_id=int(created["exchange_id"]), source="burp")
            flows.capture_observed_exchange(conn, int(paid["exchange_id"]))
            flows.capture_observed_exchange(conn, int(shipped["exchange_id"]))
            cap_result = flows.stop_capture(conn, flow_capture, end_exchange_id=int(shipped["exchange_id"]))
            assert cap_result["steps"] == 3, cap_result
            cap = flows.get_flow(conn, flow_capture)
            assert cap and len(cap["steps"]) == 3 and all(int(s["candidate"]) == 1 for s in cap["steps"]), cap
            flows.set_step_included(conn, flow_capture, int(cap["steps"][1]["id"]), False)
            cap2 = flows.get_flow(conn, flow_capture)
            assert len(cap2["included_steps"]) == 2

            # Repeated identical traffic must remain two Flow occurrences even when
            # http_exchanges points both observations to the same deduplicated row.
            repeated = flows.start_capture(conn, "Repeated request", start_exchange_id=int(created["exchange_id"]), source="burp")
            flows.capture_observed_exchange(conn, int(paid["exchange_id"]))
            flows.capture_observed_exchange(conn, int(paid["exchange_id"]))
            flows.stop_capture(conn, repeated)
            repeat_data = flows.get_flow(conn, repeated)
            paid_occurrences = [s for s in repeat_data["steps"] if int(s["exchange_id"]) == int(paid["exchange_id"])]
            assert len(paid_occurrences) == 2, repeat_data["steps"]

            # Teach one semantic state schema: Order = orderId + status.
            state_obs = conn.execute("SELECT id FROM parameter_observations WHERE exchange_id=? AND normalized_name='status' ORDER BY id LIMIT 1", (int(created["exchange_id"]),)).fetchone()
            object_obs = conn.execute("SELECT id FROM parameter_observations WHERE exchange_id=? AND normalized_name='orderid' ORDER BY id LIMIT 1", (int(created["exchange_id"]),)).fetchone()
            assert state_obs and object_obs
            track_id = flows.create_state_track(conn, int(state_obs["id"]), int(object_obs["id"]), object_type="Order")
            assert track_id > 0

            f1 = flows.create_flow(conn, "Normal order")
            for ex in (created, paid, shipped): flows.add_step(conn, f1, int(ex["exchange_id"]))
            f2 = flows.create_flow(conn, "Variant order")
            for ex in (created2, shipped2): flows.add_step(conn, f2, int(ex["exchange_id"]))
            d1 = flows.get_flow(conn, f1)
            d2 = flows.get_flow(conn, f2)
            assert d1 and d1["state_timelines"], d1
            assert d1["state_timelines"][0]["sequence"] == ["CREATED","PAID","SHIPPED"], d1["state_timelines"]
            assert d2 and d2["state_timelines"][0]["sequence"] == ["CREATED","SHIPPED"], d2["state_timelines"]
            comp = flows.compare_flows(conn, f1, f2)
            assert comp and comp["state_changes"], comp
            assert comp["state_changes"][0]["a_sequence"] == ["CREATED","PAID","SHIPPED"]
            assert comp["state_changes"][0]["b_sequence"] == ["CREATED","SHIPPED"]

    print("[OK] Identity auth can rotate and Send-as rewrites only known auth slots")
    print("[OK] Anonymous variant removes known authentication material")
    print("[OK] Burp-style Flow Capture stores ordered occurrences and supports Include/Ignore")
    print("[OK] Business State track follows object instances and Flow Compare exposes sequence changes")


if __name__ == "__main__":
    main()
