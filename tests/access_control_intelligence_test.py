#!/usr/bin/env python3
"""Offline test for Negro v0.17.0 Access Control Intelligence."""
from pathlib import Path
import base64
import json
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_hunter as hunter
import negro_web as web


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def ingest(paths, domain, *, method, path, status=200, req_body=b"", resp_body=b"{}", req_headers=None, resp_headers=None, authenticated=True, query=None, request_ct=None, response_ct="application/json"):
    req_headers = req_headers or []
    resp_headers = resp_headers or []
    header_lines = [f"{method} {path}{(('?' + query) if isinstance(query, str) and query else '')} HTTP/1.1", f"Host: {domain}"]
    for h in req_headers:
        header_lines.append(f"{h['name']}: {h['value']}")
    if request_ct:
        header_lines.append(f"Content-Type: {request_ct}")
    if authenticated and not any(str(h.get('name','')).lower() == 'cookie' for h in req_headers):
        header_lines.append("Cookie: sid=test")
    req = ("\r\n".join(header_lines) + "\r\n\r\n").encode() + req_body

    status_text = {200:"OK",302:"Found",403:"Forbidden",404:"Not Found"}.get(status, "OK")
    response_header_lines = [f"HTTP/1.1 {status} {status_text}"]
    for h in resp_headers:
        response_header_lines.append(f"{h['name']}: {h['value']}")
    if response_ct:
        response_header_lines.append(f"Content-Type: {response_ct}")
    resp = ("\r\n".join(response_header_lines) + "\r\n\r\n").encode() + resp_body

    url = f"https://{domain}{path}" + (("?" + query) if isinstance(query, str) and query else "")
    return core.upsert_http_observation(
        paths, domain, url=url, method=method, source="burp_repeater", status_code=status,
        authenticated=authenticated, request_content_type=request_ct, response_content_type=response_ct,
        tool="REPEATER", request_b64=b64(req), response_b64=b64(resp),
        request_headers=req_headers, response_headers=resp_headers, query=query,
    )


def lead_types(conn):
    return {str(r["lead_type"]) for r in conn.execute("SELECT lead_type FROM leads_v2").fetchall()}


def main():
    with tempfile.TemporaryDirectory(prefix="negro-ac-017-") as td:
        domain = "access.test"
        paths = core.ensure_workspace(Path(td), domain)

        # 1) PATCH response exposes roleId/role that UI request did not send -> mass assignment clue.
        patch = ingest(
            paths, domain, method="PATCH", path="/api/me", request_ct="application/json",
            req_body=json.dumps({"email":"ana@access.test"}).encode(),
            resp_body=json.dumps({"id":101,"email":"ana@access.test","roleId":1,"role":"customer"}).encode(),
        )
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn, int(patch["exchange_id"]), domain, emit_notifications=False)
            assert "mass_assignment" in lead_types(conn), lead_types(conn)

        # 2) Authenticated object reference -> horizontal authorization hypothesis.
        order = ingest(paths, domain, method="GET", path="/api/orders/201", resp_body=json.dumps({"id":201,"ownerId":101}).encode())
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn, int(order["exchange_id"]), domain, emit_notifications=False)
            assert "access_object_reference" in lead_types(conn), lead_types(conn)

        # 3) Same resource seen with GET and POST -> method access-control hypothesis.
        post = ingest(
            paths, domain, method="POST", path="/catalog/sellers/feature", request_ct="application/json",
            req_body=json.dumps({"sellerId":201,"feature":True}).encode(), resp_body=json.dumps({"ok":True}).encode(),
        )
        get = ingest(
            paths, domain, method="GET", path="/catalog/sellers/feature", query="sellerId=201&feature=true",
            resp_body=json.dumps({"ok":True}).encode(),
        )
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn, int(post["exchange_id"]), domain, emit_notifications=False)
            hunter.analyze_http_exchange(conn, int(get["exchange_id"]), domain, emit_notifications=False)
            assert "method_access_control" in lead_types(conn), lead_types(conn)

        # 4) Redirect still returns meaningful account data -> inspect body before following Location.
        redir = ingest(
            paths, domain, method="GET", path="/accounts/view", query="id=202", status=302,
            resp_headers=[{"name":"Location","value":"https://access.test/"}],
            resp_body=json.dumps({"email":"other@access.test","api_key":"masked-demo-value","integrationKey":"masked-demo-value","padding":"x"*180}).encode(),
        )
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn, int(redir["exchange_id"]), domain, emit_notifications=False)
            assert "redirect_body_access_control" in lead_types(conn), lead_types(conn)

        # 5) A normal backend 404 looks unlike a front-layer 403 -> proxy/path hypothesis.
        not_found = ingest(
            paths, domain, method="GET", path="/definitely-not-here", status=404, authenticated=False,
            resp_headers=[{"name":"Server","value":"app-backend"}], response_ct="application/json",
            resp_body=json.dumps({"error":"route not found","detail":"backend response"}).encode(),
        )
        blocked = ingest(
            paths, domain, method="GET", path="/ops/audit/export", status=403,
            resp_headers=[{"name":"Server","value":"nginx"}], response_ct="text/html",
            resp_body=(b"<html><body>Forbidden</body></html>" * 12),
        )
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn, int(not_found["exchange_id"]), domain, emit_notifications=False)
            hunter.analyze_http_exchange(conn, int(blocked["exchange_id"]), domain, emit_notifications=False)
            assert "proxy_path_access_control" in lead_types(conn), lead_types(conn)

        # 6) Sensitive state-changing request carrying Referer -> low-priority quick check.
        ref = ingest(
            paths, domain, method="POST", path="/admin/communications/publish", request_ct="application/json",
            req_headers=[{"name":"Referer","value":"https://access.test/admin"}],
            req_body=json.dumps({"id":1}).encode(), resp_body=json.dumps({"published":True}).encode(),
        )
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn, int(ref["exchange_id"]), domain, emit_notifications=False)
            lt = lead_types(conn)
            expected = {
                "mass_assignment", "access_object_reference", "method_access_control",
                "redirect_body_access_control", "proxy_path_access_control", "referer_access_control",
            }
            missing = expected - lt
            assert not missing, (missing, lt)

            routes = web._investigation_routes(conn, limit=20)
            assert routes, "Expected investigation routes"
            route_types = {r["lead_type"] for r in routes}
            assert expected & route_types, route_types
            assert all(r["next_test"] for r in routes), routes
            assert all(str(r["id"]).startswith("route:") for r in routes), routes

        # Resource detail should expose hypotheses and review aids without inventing findings.
        detail = web._resource_detail(paths, int(patch["resource_id"]))
        assert detail and detail.get("resource_hypotheses"), detail
        assert any(h.get("lead_type") == "mass_assignment" for h in detail["resource_hypotheses"]), detail["resource_hypotheses"]

        with core.db_connect(paths) as conn:
            assert conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"] == 0

        print("[OK] Access Control Intelligence signals")
        print("[OK] Resource review aids")
        print("[OK] Investigation routes")
        print("[OK] No automatic findings/exploitation")


if __name__ == "__main__":
    main()
