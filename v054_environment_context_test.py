#!/usr/bin/env python3
"""Regression for v0.34 graph readability + Custom Signals."""
from pathlib import Path
import base64
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_hunter as hunter
import negro_identity as identities
import negro_objects as objects
import negro_flows as flows
import negro_custom_signals as custom_signals
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def capture(paths, domain, path, *, cookie, body, status=200, method="GET"):
    req = f"{method} {path} HTTP/1.1\r\nHost: api.signal.local\r\nCookie: session={cookie}\r\n\r\n".encode()
    resp = f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{body}".encode()
    return core.upsert_http_observation(
        paths, domain, url=f"https://api.signal.local{path}", method=method,
        source="burp_proxy", status_code=status, authenticated=True, tool="PROXY",
        response_content_type="application/json", request_b64=b64(req), response_b64=b64(resp), query={},
    )


def obs_id(conn, exchange_id, name):
    row = conn.execute(
        "SELECT id FROM parameter_observations WHERE exchange_id=? AND normalized_name=? ORDER BY id LIMIT 1",
        (int(exchange_id), name),
    ).fetchone()
    assert row, (exchange_id, name)
    return int(row["id"])


def main():
    with tempfile.TemporaryDirectory(prefix="negro-v034-") as td:
        root = Path(td)
        old_targets = core.TARGETS_PATH
        core.TARGETS_PATH = root / "targets.json"
        try:
            domain = "signal.local"
            workspace = root / "workspace"
            paths = core.ensure_workspace(workspace, domain)
            d1 = capture(paths, domain, "/orders/4101", cookie="diego", body='{"orderId":4101,"ownerId":101,"status":"OPEN"}', status=200)
            d2 = capture(paths, domain, "/orders/4101/invoice", cookie="diego", body='{"orderId":4101,"ownerId":101,"invoiceId":9001}', status=200)
            a1 = capture(paths, domain, "/orders/4101", cookie="ana", body='{"orderId":4101,"ownerId":101,"status":"OPEN"}', status=403)

            with core.db_connect(paths) as conn:
                for ex in (d1, d2, a1):
                    hunter.analyze_http_exchange(conn, int(ex["exchange_id"]), domain, emit_notifications=False)
                diego = identities.create_identity(conn, "Diego")
                ana = identities.create_identity(conn, "Ana")
                identities.assign_exchange(conn, int(d1["exchange_id"]), diego, learn_auth=True)
                identities.assign_exchange(conn, int(d2["exchange_id"]), diego, learn_auth=False)
                identities.assign_exchange(conn, int(a1["exchange_id"]), ana, learn_auth=True)

                # Clear object + deliberately noisy object in one Flow.
                order_obs = obs_id(conn, d1["exchange_id"], "orderid")
                owner_obs = obs_id(conn, d1["exchange_id"], "ownerid")
                objects.ensure_identifier(conn, "Order", "orderid", source_observation_id=order_obs)
                objects.ensure_identifier(conn, "111", "ownerid", source_observation_id=owner_obs)
                objects.rebuild(conn)
                flow_id = flows.create_flow(conn, "Order read")
                flows.add_step(conn, flow_id, int(d1["exchange_id"]))
                flows.add_step(conn, flow_id, int(d2["exchange_id"]))
                fd = flows.get_flow(conn, flow_id)
                assert any(x["object_type"] == "Order" for x in fd["meaningful_business_objects"]), fd
                assert any(x["object_type"] == "111" for x in fd["ambiguous_business_objects"]), fd

                rule_id = custom_signals.save_rule(
                    conn, name="Object ID bajo una identidad", description="Recordar comparar ownership",
                    category="access_control", severity="low", parameter_names=["ownerId"],
                    identity_mode="present", suggested_action="Comparar identidades y usar Follow Value sobre ownerId.",
                )
                r = custom_signals.evaluate_exchange(conn, int(d1["exchange_id"]), rule_id=rule_id)
                assert r["matched"] == 1, r
                non = custom_signals.evaluate_exchange(conn, int(d2["exchange_id"]), rule_id=rule_id)
                assert non["matched"] == 1, non  # same ownerId appears here too
                signal = conn.execute("SELECT * FROM signal_occurrences WHERE kind=? ORDER BY id LIMIT 1", (f"custom_signal:{rule_id}",)).fetchone()
                assert signal and signal["source"] == "custom_signal", signal
                backfill = custom_signals.apply_rule_to_history(conn, rule_id)
                assert backfill["matched"] >= 2, backfill

                detail = identities.identity_detail(conn, diego)
                assert detail and int(detail["exchanges"][0]["exchange_id"]) == int(d2["exchange_id"]), detail["exchanges"]

            key = core.register_target(domain, workspace, make_current=True, name="Signal Lab", scopes=[domain, "api.signal.local"])
            client = TestClient(create_app(domain, workspace))

            graph = client.get(f"/api/t/{key}/graph?scope=identity&identity_id={diego}&compare_identity_id={ana}").json()
            order_node = next(n for n in graph["nodes"] if n["type"] == "resource" and n["label"] == "/orders/4101")
            edges = [e for e in graph["edges"] if e["target"] == order_node["id"] and e["relation"] == "called_endpoint"]
            status_by_source = {e["source"]: set(e["meta"]["evidence"]["statuses"]) for e in edges}
            assert status_by_source[f"identity:{diego}"] == {"200"}, status_by_source
            assert status_by_source[f"identity:{ana}"] == {"403"}, status_by_source

            flow_page = client.get(f"/t/{key}/flows/{flow_id}")
            assert flow_page.status_code == 200
            assert "Cosas de negocio con significado" in flow_page.text
            assert "Order" in flow_page.text
            assert "Identificadores sin clasificar" in flow_page.text

            custom_page = client.get(f"/t/{key}/signals/custom?edit={rule_id}")
            assert custom_page.status_code == 200
            assert "Enséñale a Negro qué merece atención" in custom_page.text
            assert "Object ID bajo una identidad" in custom_page.text
            assert "ownerId" in custom_page.text

            hunt_page = client.get(f"/t/{key}/hypotheses")
            assert hunt_page.status_code == 200
            assert "Custom Signals" in hunt_page.text
            assert "Tu regla" in hunt_page.text

            js = (ROOT / "web" / "static" / "graph.js").read_text()
            for phrase in ("endpointIdentityResults", "node-endpoint-status", "endpoint-mini", "host-server", "target-project"):
                assert phrase in js, phrase
        finally:
            core.TARGETS_PATH = old_targets

    print("[OK] Identity timeline is newest-first")
    print("[OK] Flow detail keeps ambiguous objects secondary")
    print("[OK] Identity graph carries per-identity HTTP outcomes for endpoints")
    print("[OK] Surface uses semantic endpoint/host/project icons")
    print("[OK] Custom Signals reuse signal_occurrences and can reinterpret history")


if __name__ == "__main__":
    main()
