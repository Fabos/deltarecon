#!/usr/bin/env python3
"""Regression for v0.25 Smart Compare correlations + Flow Workbench."""
from pathlib import Path
from types import SimpleNamespace
import base64
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from jinja2 import Environment, FileSystemLoader, select_autoescape
import negro_core as core
import negro_hunter as hunter
import negro_parameters as params
import negro_flows as flows


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def capture(paths, domain, path, method, request_body, response_body, *, cookie="", status=200):
    cookie_line = f"Cookie: accesslab_session={cookie}\r\n" if cookie else ""
    req = f"{method} {path} HTTP/1.1\r\nHost: api.example.test\r\nContent-Type: application/json\r\n{cookie_line}\r\n{request_body}".encode()
    resp = f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{response_body}".encode()
    return core.upsert_http_observation(
        paths, domain, url=f"https://api.example.test{path}", method=method, source="burp_proxy", status_code=status,
        authenticated=bool(cookie), tool="PROXY", request_content_type="application/json", response_content_type="application/json",
        request_b64=b64(req), response_b64=b64(resp), query={},
    )


def main():
    with tempfile.TemporaryDirectory(prefix="negro-v025-") as td:
        domain = "api.example.test"
        paths = core.ensure_workspace(Path(td) / "project", domain)
        login = capture(paths, domain, "/auth/login", "POST", '{"email":"diego@example.test","password":"x"}', '{"ok":true,"user":{"id":102,"email":"diego@example.test","displayName":"Diego Rojas"}}')
        me = capture(paths, domain, "/me", "GET", "", '{"memberId":102,"email":"diego@example.test","displayName":"Diego Rojas","status":"active"}', cookie="sess-diego")
        cart_a = capture(paths, domain, "/cart", "POST", '{"productId":501,"quantity":1}', '{"cartId":7001,"status":"CREATED","total":10000}', cookie="sess-diego")
        pay_a = capture(paths, domain, "/payment", "POST", '{"cartId":7001}', '{"paymentId":9001,"status":"PAID","total":10000}', cookie="sess-diego")
        order_a = capture(paths, domain, "/orders/8001", "GET", "", '{"orderId":8001,"status":"PAID","total":10000}', cookie="sess-diego")

        cart_b = capture(paths, domain, "/cart", "POST", '{"productId":501,"quantity":1}', '{"cartId":7002,"status":"CREATED","total":10000}', cookie="sess-other")
        order_b = capture(paths, domain, "/orders/8002", "GET", "", '{"orderId":8002,"status":"CREATED","total":10000}', cookie="sess-other")

        with core.db_connect(paths) as conn:
            for ex in (login, me, cart_a, pay_a, order_a, cart_b, order_b):
                hunter.analyze_http_exchange(conn, int(ex["exchange_id"]), domain, emit_notifications=False)

            diff = params.smart_diff(conn, int(login["exchange_id"]), int(me["exchange_id"]))
            assert diff and diff["correlations"], diff
            alias = [x for x in diff["correlations"] if x["value"] == "102" and x["alias_candidate"]]
            assert alias, diff["correlations"]
            assert any(x["a_name"] == "id" and x["b_name"] == "memberid" for x in alias), alias
            assert any(x["value"] == "diego@example.test" for x in diff["correlations"]), diff["correlations"]
            # Generic ok=true should not become a useful correlation.
            assert not any(str(x["value"]).lower() == "true" for x in diff["strong_correlations"] + diff["medium_correlations"])

            f1 = flows.create_flow(conn, "Compra con pago")
            for ex in (cart_a, pay_a, order_a):
                flows.add_step(conn, f1, int(ex["exchange_id"]))
            f2 = flows.create_flow(conn, "Compra sin pago")
            for ex in (cart_b, order_b):
                flows.add_step(conn, f2, int(ex["exchange_id"]))

            d1 = flows.get_flow(conn, f1)
            assert d1 and len(d1["steps"]) == 3
            # Flow captures business state values from observed traffic.
            assert any(v["normalized_name"] == "status" for s in d1["steps"] for v in s["state_values"])

            comp = flows.compare_flows(conn, f1, f2)
            assert comp and comp["aligned"], comp
            assert any(row["kind"] in {"only_a", "changed"} for row in comp["aligned"]), comp["aligned"]
            # The payment step should be visible as absent/changed relative to flow B.
            rendered_sigs = [(r.get("a") or {}).get("signature", "") for r in comp["aligned"]]
            assert any("POST /payment" in x for x in rendered_sigs), rendered_sigs

        env = Environment(loader=FileSystemLoader(str(ROOT / "web" / "templates")), autoescape=select_autoescape())
        request = SimpleNamespace(url=SimpleNamespace(path="/t/lab/parameters/diff"))
        base = dict(request=request, target_base="/t/lab", target_key="lab", domain=domain, workspace=str(paths["root"]), project={"name":"Lab"}, targets=[], version=core.VERSION, csrf_token="x", ui_label=lambda x:x, review_states=[], classifications=[], priorities=[])
        html = env.get_template("smart_diff.html").render(**base, a=login["exchange_id"], b=me["exchange_id"], diff=diff, diff_error=None)
        assert "COINCIDENCIAS" in html and "posible alias" in html and "memberid" in html
        html_flow = env.get_template("flow_compare.html").render(**base, flows=flows.list_flows(core.db_connect(paths)), a=f1, b=f2, comparison=comp, flow_error=None)
        assert "FLOW COMPARE" in html_flow and "POST" in html_flow

    print("[OK] Smart Compare surfaces exact-value aliases across different field names/paths")
    print("[OK] Smart Compare suppresses trivial generic matches")
    print("[OK] Flow Workbench captures ordered exchanges and observed business-state fields")
    print("[OK] Flow Compare aligns sequences and exposes missing/changed steps")


if __name__ == "__main__":
    main()
