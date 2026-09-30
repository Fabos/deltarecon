#!/usr/bin/env python3
"""Offline test for Negro v0.17.1 Access Control Intelligence."""
from pathlib import Path
import base64
import json
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_hunter as hunter
import negro_intel as intel
import negro_web as web


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def ingest(paths, domain, *, method, path, status=200, req_body=b"", resp_body=b"{}", req_headers=None, resp_headers=None, authenticated=True, query=None, request_ct=None, response_ct="application/json", host=None):
    req_headers = req_headers or []
    resp_headers = resp_headers or []
    request_host = host or domain
    header_lines = [f"{method} {path}{(('?' + query) if isinstance(query, str) and query else '')} HTTP/1.1", f"Host: {request_host}"]
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

    url = f"https://{request_host}{path}" + (("?" + query) if isinstance(query, str) and query else "")
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

        # The "Qué probar ahora" projection must materialize the nodes that
        # its route cards reference.  v0.19.0 exposed cards from overview but
        # left the canvas empty until the user clicked one.
        route_graph = web._graph_data(paths, domain, scope="routes")
        assert route_graph.get("routes"), route_graph
        route_node_ids = {nid for r in route_graph["routes"] for nid in (r.get("node_ids") or [])}
        graph_node_ids = {n["id"] for n in route_graph["nodes"]}
        assert any(nid.startswith("lead:") for nid in route_node_ids), route_node_ids
        assert any(nid.startswith("resource:") for nid in route_node_ids), route_node_ids
        assert route_node_ids & graph_node_ids, (route_node_ids, graph_node_ids)
        for route in route_graph["routes"]:
            essential = [nid for nid in (route.get("node_ids") or []) if nid.startswith(("host:","resource:","operation:","lead:"))]
            assert all(nid in graph_node_ids for nid in essential), (route, graph_node_ids)

        # Resource detail should expose hypotheses and review aids without inventing findings.
        detail = web._resource_detail(paths, int(patch["resource_id"]))
        assert detail and detail.get("resource_hypotheses"), detail
        assert any(h.get("lead_type") == "mass_assignment" for h in detail["resource_hypotheses"]), detail["resource_hypotheses"]

        with core.db_connect(paths) as conn:
            assert conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"] == 0

        # 7) First-party sibling CORS must not flood hypotheses; an external
        # reflected Origin remains a candidate.
        first_party = ingest(
            paths, domain, host="api.access.test", method="GET", path="/api/me",
            req_headers=[{"name":"Origin","value":"https://app.access.test"}],
            resp_headers=[{"name":"Access-Control-Allow-Origin","value":"https://app.access.test"},{"name":"Access-Control-Allow-Credentials","value":"true"}],
            resp_body=json.dumps({"id":101,"email":"ana@access.test"}).encode(),
        )
        external = ingest(
            paths, domain, host="api.access.test", method="GET", path="/api/external-cors-test",
            req_headers=[{"name":"Origin","value":"https://evil.example"}],
            resp_headers=[{"name":"Access-Control-Allow-Origin","value":"https://evil.example"},{"name":"Access-Control-Allow-Credentials","value":"true"}],
            resp_body=json.dumps({"ok":True}).encode(),
        )
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn, int(first_party["exchange_id"]), domain, emit_notifications=True)
            assert conn.execute("SELECT COUNT(*) c FROM leads_v2 WHERE lead_type='cors' AND resource_id=?", (first_party["resource_id"],)).fetchone()["c"] == 0
            hunter.analyze_http_exchange(conn, int(external["exchange_id"]), domain, emit_notifications=True)
            assert conn.execute("SELECT COUNT(*) c FROM leads_v2 WHERE lead_type='cors' AND resource_id=?", (external["resource_id"],)).fetchone()["c"] == 1

        # 8) A newly-created access-control hypothesis appears in Notifications,
        # deduplicated by lead rather than per repeated request.
        notify_patch = ingest(
            paths, domain, host="api.access.test", method="PATCH", path="/api/profile-notify", request_ct="application/json",
            req_body=json.dumps({"email":"new@access.test"}).encode(),
            resp_body=json.dumps({"email":"new@access.test","roleId":1,"role":"customer"}).encode(),
        )
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn, int(notify_patch["exchange_id"]), domain, emit_notifications=True)
            row=conn.execute("SELECT * FROM notifications WHERE kind='hypothesis' ORDER BY id DESC LIMIT 1").fetchone()
            assert row is not None, "Expected hypothesis notification"
            data=json.loads(row["data_json"] or "{}")
            assert data.get("lead_id"), data

        # 9) Local JS analysis turns discovered API routes into Resources,
        # creates one aggregate notification, and links JS -> cross-host Resource
        # in the scoped graph.
        with core.db_connect(paths) as conn:
            app_host_id,_=core.upsert_host(conn,"app.access.test","test")
            cur=conn.execute("INSERT INTO js_assets(host_id,url,source,discovered_at) VALUES(?,?,?,?)",(app_host_id,"https://app.access.test/assets/admin-tools.js","test",core.now_iso()))
            js_id=int(cur.lastrowid)
        original_http_bytes=intel.http_bytes
        try:
            js_code=b"fetch('https://api.access.test/admin/users'); fetch('https://api.access.test/ops/audit/export');"
            intel.http_bytes=lambda *args,**kwargs:(js_code,"application/javascript","https://app.access.test/assets/admin-tools.js")
            result=core.local_analyze_js_asset(domain,paths,js_id)
        finally:
            intel.http_bytes=original_http_bytes
        assert result["routes"]["in_scope"] >= 2, result
        assert result["routes"]["interesting"] >= 2, result
        with core.db_connect(paths) as conn:
            assert conn.execute("SELECT COUNT(*) c FROM leads_v2 WHERE lead_type='javascript_surface'").fetchone()["c"] >= 1
            assert conn.execute("SELECT COUNT(*) c FROM notifications WHERE kind='javascript_surface'").fetchone()["c"] >= 1
        graph=web._graph_data(paths,domain,scope="host",host_id=app_host_id)
        assert any(n["id"]==f"js:{js_id}" for n in graph["nodes"]), graph["nodes"]
        api_resources={n["id"] for n in graph["nodes"] if n["type"]=="resource" and str(n.get("meta",{}).get("host"))=="api.access.test"}
        assert api_resources, graph["nodes"]
        assert any(e["source"]==f"js:{js_id}" and e["target"] in api_resources and e["relation"]=="discovered" for e in graph["edges"]), graph["edges"]

        print("[OK] Access Control Intelligence signals")
        print("[OK] Resource review aids")
        print("[OK] Investigation routes")
        print("[OK] First-party CORS noise reduction")
        print("[OK] Hypothesis notifications")
        print("[OK] JavaScript surface -> resources -> graph")
        print("[OK] No automatic findings/exploitation")


if __name__ == "__main__":
    main()
