#!/usr/bin/env python3
"""Smoke test offline de Negro v0.13. No toca Internet ni ejecuta IA."""
from pathlib import Path
import json
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import negro_core as core
import negro_hunter as hunter


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="negro-smoke-") as td:
        domain = "example.test"
        paths = core.ensure_workspace(Path(td), domain)
        core.policy_set(paths, "conservative")
        with core.db_connect(paths) as conn:
            hid, _ = core.upsert_host(conn, domain, "selftest")
            rid, _ = core.upsert_resource(conn, "https://example.test/login?next=%2Fhome", "crawler", domain)
            core.record_observation(conn, "host", hid, "web_recon", "web_recon", "https://example.test/", {
                "fingerprints":[{"technology":"WordPress","category":"cms","confidence":"high","evidence":"selftest"}],
                "well_known":{"/.well-known/openid-configuration":{"json":{
                    "issuer":"https://example.test",
                    "authorization_endpoint":"https://example.test/oauth/authorize",
                    "token_endpoint":"https://example.test/oauth/token",
                    "jwks_uri":"https://example.test/.well-known/jwks.json",
                    "response_types_supported":["code"],
                    "scopes_supported":["openid","email"]
                }}},
                "directory_listing":False,
            })
            core.record_observation(conn, "host", hid, "cors_probe", "cors_probe", "https://example.test/api/me", {
                "url":"https://example.test/api/me",
                "origin_sent":"https://negro-validation.invalid",
                "allow_origin":"https://negro-validation.invalid",
                "allow_credentials":"true",
                "status":200,
            })
            conn.execute("INSERT INTO js_assets(host_id,url,source,local_analysis_json,discovered_at) VALUES(?,?,?,?,?)", (
                hid, "https://example.test/app.js", "selftest",
                json.dumps({
                    "contexts":[{"signal":"location.assign","context":"const next=new URLSearchParams(location.search).get('next'); location.assign(next);"}],
                    "detections":[], "source_maps":[], "in_scope_urls":[], "relative_paths":[], "external_urls":[], "websockets":[]
                }), core.now_iso()
            ))
            hunter.generate_leads(conn, domain)
            leads = hunter.list_leads(conn)
            assert any(x["lead_type"] == "open_redirect" and x["confidence"] == "high" for x in leads), leads
            assert any(x["lead_type"] == "oauth_oidc_surface" for x in leads), leads
            assert any(x["lead_type"] == "cors" for x in leads), leads
            payload, digest = hunter.build_target_ai_payload(conn, domain)
            assert "NEGRO_TARGET_EVIDENCE" in payload and len(digest) == 64
        q = hunter.search_queries(domain, ["WordPress"], ["api"])
        assert any("wp-" in x["query"] for x in q)
        policy = core.policy_get(paths)
        assert policy["profile"] == "conservative"

        # v0.10: Burp/HTTP ingestion models one resource with multiple methods.
        import base64
        raw_req = b"GET /api/users/42 HTTP/1.1\r\nHost: example.test\r\nCookie: sid=test\r\n\r\n"
        raw_resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
        one = core.upsert_http_observation(
            paths, domain, url="https://example.test/api/users/42?expand=profile", method="GET", source="burp_proxy",
            status_code=200, authenticated=True, request_content_type=None, response_content_type="application/json", tool="PROXY",
            request_b64=base64.b64encode(raw_req).decode(), response_b64=base64.b64encode(raw_resp).decode(), query="expand=profile",
        )
        two = core.upsert_http_observation(
            paths, domain, url="https://example.test/api/users/42", method="PUT", source="burp_repeater",
            status_code=200, authenticated=True, request_content_type="application/json", response_content_type="application/json", tool="REPEATER",
            request_b64=base64.b64encode(b"PUT /api/users/42 HTTP/1.1\r\nHost: example.test\r\n\r\n{}").decode(), response_b64=base64.b64encode(raw_resp).decode(),
        )
        again = core.upsert_http_observation(
            paths, domain, url="https://example.test/api/users/42?expand=profile", method="GET", source="burp_proxy",
            status_code=200, authenticated=True, response_content_type="application/json", tool="PROXY",
            request_b64=base64.b64encode(raw_req).decode(), response_b64=base64.b64encode(raw_resp).decode(), query="expand=profile",
        )
        with core.db_connect(paths) as conn:
            rr = conn.execute("SELECT id FROM resources WHERE url='https://example.test/api/users/42'").fetchone()
            assert rr, "Burp resource should be query-normalized"
            ops = conn.execute("SELECT method, seen_count FROM resource_operations WHERE resource_id=? ORDER BY method", (rr["id"],)).fetchall()
            assert [(x["method"], x["seen_count"]) for x in ops] == [("GET", 2), ("PUT", 1)], ops
            get_id = conn.execute("SELECT id FROM resource_operations WHERE resource_id=? AND method='GET'", (rr["id"],)).fetchone()["id"]
            ex = conn.execute("SELECT seen_count FROM http_exchanges WHERE operation_id=?", (get_id,)).fetchall()
            assert len(ex) == 1 and ex[0]["seen_count"] == 2, ex
            # v0.13: Findings are real entities, can record source and retest evidence.
            now = core.now_iso()
            cur = conn.execute("INSERT INTO findings(title,severity,status,source,created_at,updated_at) VALUES('Smoke finding','high','confirmed','selftest',?,?)", (now, now))
            fid = int(cur.lastrowid)
            conn.execute("INSERT INTO finding_entities(finding_id,entity_type,entity_id,relation,created_at) VALUES(?,?,?,?,?)", (fid, 'resource', rr['id'], 'affected', now))
            cur = conn.execute("INSERT INTO finding_retests(finding_id,result,notes,tested_at,created_at) VALUES(?,?,?,?,?)", (fid, 'still_vulnerable', 'reproduced', now, now))
            retest_id = int(cur.lastrowid)
            exchange_id = conn.execute("SELECT id FROM http_exchanges WHERE operation_id=? LIMIT 1", (get_id,)).fetchone()["id"]
            conn.execute("INSERT INTO finding_retest_entities(retest_id,entity_type,entity_id,relation,created_at) VALUES(?,?,?,?,?)", (retest_id, 'exchange', exchange_id, 'evidence', now))
            assert conn.execute("SELECT source FROM findings WHERE id=?", (fid,)).fetchone()["source"] == 'selftest'
            assert conn.execute("SELECT COUNT(*) c FROM finding_retest_entities WHERE retest_id=?", (retest_id,)).fetchone()["c"] == 1
            # v0.14: hypothesis workbench migrations + AI HTTP preview context.
            cols={x["name"] for x in conn.execute("PRAGMA table_info(leads_v2)").fetchall()}
            assert {"test_plan_json","result_notes","last_tested_at"}.issubset(cols), cols
            hunter.upsert_lead(conn, lead_key="ai_graph:smoke", host_id=hid, resource_id=rr["id"], lead_type="feature_flag", title="Toggle feature flag", confidence="medium", review_priority="medium", evidence=[{"source":"ai_graph","plain_language":"Cambia active y observa nuevas rutas"}], why="response has active", next_test="intercept response", confirm_if="new route appears", discard_if="no behavior change", source="AI")
            conn.execute("UPDATE leads_v2 SET test_plan_json=? WHERE lead_key='ai_graph:smoke'", (json.dumps([{"step":1,"action":"toggle active","what_to_watch":"new requests"}]),))
            listed=hunter.list_leads(conn)
            smoke=next(x for x in listed if x["lead_key"]=="ai_graph:smoke")
            assert smoke["test_plan"][0]["action"]=="toggle active"
            graph={"counts":{"resource":1},"nodes":[{"id":f"resource:{rr['id']}","type":"resource","label":"/api/users/42","state":"untested","meta":{"id":rr['id'],"url":"https://example.test/api/users/42"}}],"edges":[]}
            gp,gh=hunter.build_graph_ai_payload(conn,domain,graph,selected_node_id=f"resource:{rr['id']}")
            assert 'http_evidence' in gp and 'request_line' in gp and len(gh)==64
        print("[OK] schema + migration path")
        print("[OK] HTTP model: resource -> operations -> deduplicated exchanges")
        print("[OK] policy profile")
        print("[OK] correlation engine: Open Redirect / OIDC / CORS")
        print("[OK] target AI payload + evidence hash")
        print("[OK] search intelligence")
        print("[OK] findings + retest evidence model")
        print("[OK] hypothesis workbench + sanitized HTTP AI context")


if __name__ == "__main__":
    main()
