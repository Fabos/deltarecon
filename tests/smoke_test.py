#!/usr/bin/env python3
"""Smoke test offline de Negro v0.16.2. No toca Internet ni ejecuta IA."""
from pathlib import Path
import json
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import negro_core as core
import negro_hunter as hunter
import negro_intel as intel


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
            # v0.14.5: endpoint/method test coverage is persistent and feeds AI memory.
            tests=hunter.ensure_operation_test_coverage(conn, int(get_id))
            keys={x['test_key'] for x in tests}
            assert {'authorization','cors','parameter_tampering','method_variation','session_access','cache'}.issubset(keys), keys
            hunter.update_operation_test_coverage(conn, int(get_id), 'authorization', 'negative', 'cross-account check OK', source='manual')
            ts=hunter.operation_test_summary(conn, int(get_id))
            assert ts['negative'] >= 1
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
            # v0.15: untouched recommended checks are UI guidance only; AI receives actual testing memory.
            env=json.loads(gp.split('\n',1)[1])
            tc=env.get('test_coverage') or []
            assert any(x.get('test_key')=='authorization' and x.get('status')=='negative' for x in tc), tc
            assert not any(x.get('status')=='pending' and x.get('source')=='recommended' and not (x.get('notes') or '').strip() for x in tc), tc
            schema=hunter._graph_ideas_json_schema()
            assert schema['additionalProperties'] is False and schema['properties']['hypotheses']['type']=='array'
            hprops=schema['properties']['hypotheses']['items']['properties']
            assert set(hprops['investigation_priority']['enum'])=={'high','medium','quick'}
            assert 'priority_reasons' in hprops and hunter.GRAPH_AI_PROMPT_VERSION.startswith('0.16.0')
            assert 'prompt_version' in gp and '0.16.0-burp-signals-v1' in gp
            parsed=hunter._safe_json_object('{\"summary\":\"ok\",\"hypotheses\":[],\"unexplored_areas\":[]}', {})
            assert parsed['summary']=='ok'
            malformed=hunter._safe_json_object('{\"summary\": \"oops\" \"hypotheses\": []}', {"summary":"fallback","hypotheses":[],"unexplored_areas":[]})
            assert malformed['summary']=='fallback' and 'parse_warning' in malformed
            # v0.14.5: Graph AI distinguishes incomplete/invalid results and has dedicated budgets.
            failure=hunter._graph_ai_failure("incomplete", error_type="incomplete", retryable=True)
            assert failure["structured_ok"] is False and not hunter.graph_ai_result_is_cacheable(failure)
            assert intel.load_settings()["graph_ai_output_tokens"] >= 6000
            assert intel.load_settings()["graph_ai_retry_output_tokens"] >= intel.load_settings()["graph_ai_output_tokens"]
            # v0.14.3: priority metadata and actionable evidence references.
            conn.execute("UPDATE leads_v2 SET evidence_json=? WHERE lead_key='ai_graph:smoke'", (json.dumps([{"source":"ai_graph","plain_language":"Cambia active y observa nuevas rutas","investigation_priority":"high","priority_reasons":["client-controlled behavior","backend enforcement unknown"],"node_ids":[f"resource:{rr['id']}",f"operation:{get_id}"]}]),))
            enriched=next(x for x in hunter.list_leads(conn) if x['lead_key']=='ai_graph:smoke')
            assert enriched['investigation_priority']=='high' and enriched['primary_method']=='GET'
            assert enriched['evidence_refs'] and enriched['evidence_refs'][0]['resource_id']==rr['id']

        # v0.16: Burp passive intelligence consumes query/form/JSON and response bodies.
        redirect_req = (
            b"GET /login?next=https%3A%2F%2Fattacker.example HTTP/1.1\r\n"
            b"Host: example.test\r\nCookie: sid=smoke\r\n\r\n"
        )
        redirect_resp = (
            b"HTTP/1.1 302 Found\r\nLocation: https://attacker.example\r\nContent-Length: 0\r\n\r\n"
        )
        red = core.upsert_http_observation(
            paths, domain, url="https://example.test/login?next=https%3A%2F%2Fattacker.example", method="GET",
            source="burp_proxy", status_code=302, authenticated=True, tool="PROXY",
            request_b64=base64.b64encode(redirect_req).decode(), response_b64=base64.b64encode(redirect_resp).decode(),
            request_headers=[{"name":"Cookie","value":"sid=smoke"}],
            response_headers=[{"name":"Location","value":"https://attacker.example"}],
            query="next=https%3A%2F%2Fattacker.example",
        )
        with core.db_connect(paths) as conn:
            passive = hunter.analyze_http_exchange(conn, int(red['exchange_id']), domain, emit_notifications=True)
            assert len(passive['signals']) >= 1
            lead = conn.execute("SELECT evidence_json FROM leads_v2 WHERE lead_type='open_redirect' AND resource_id=? ORDER BY id DESC LIMIT 1", (red['resource_id'],)).fetchone()
            assert lead and 'next' in (lead['evidence_json'] or '') and 'query' in (lead['evidence_json'] or ''), lead
            note = conn.execute("SELECT * FROM notifications WHERE kind='open_redirect' ORDER BY id DESC LIMIT 1").fetchone()
            assert note and int(note['exchange_id']) == int(red['exchange_id']), note
            ndata=json.loads(note['data_json'] or '{}')
            assert ndata.get('href') == f"resource/{red['resource_id']}#exchange-{red['exchange_id']}"

        # Ambiguous `url` on a fetch route should surface as URL-fetch/SSRF, not be mislabeled redirect.
        fetch_req=b"GET /fetch?url=https%3A%2F%2Fprobe.example HTTP/1.1\r\nHost: example.test\r\n\r\n"
        fetch_resp=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
        fet=core.upsert_http_observation(paths,domain,url="https://example.test/fetch?url=https%3A%2F%2Fprobe.example",method="GET",source="burp_proxy",status_code=200,tool="PROXY",request_b64=base64.b64encode(fetch_req).decode(),response_b64=base64.b64encode(fetch_resp).decode(),query="url=https%3A%2F%2Fprobe.example")
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn,int(fet['exchange_id']),domain,emit_notifications=True)
            assert conn.execute("SELECT COUNT(*) c FROM leads_v2 WHERE lead_type='ssrf_surface' AND resource_id=?",(fet['resource_id'],)).fetchone()['c'] >= 1
            assert conn.execute("SELECT COUNT(*) c FROM leads_v2 WHERE lead_type='open_redirect' AND resource_id=?",(fet['resource_id'],)).fetchone()['c'] == 0

        api_key = "AIza" + "A" * 35
        config_req = b"GET /api/config HTTP/1.1\r\nHost: example.test\r\n\r\n"
        config_body = json.dumps({"username":"demo","password":"SuperSecret123!","googleApiKey":api_key}).encode()
        config_resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + config_body
        cfg = core.upsert_http_observation(
            paths, domain, url="https://example.test/api/config", method="GET", source="burp_proxy",
            status_code=200, authenticated=True, response_content_type="application/json", tool="PROXY",
            request_b64=base64.b64encode(config_req).decode(), response_b64=base64.b64encode(config_resp).decode(),
        )
        with core.db_connect(paths) as conn:
            passive2 = hunter.analyze_http_exchange(conn, int(cfg['exchange_id']), domain, emit_notifications=True)
            assert len(passive2['signals']) >= 1
            kinds={x['kind'] for x in conn.execute("SELECT kind FROM notifications WHERE exchange_id=?", (cfg['exchange_id'],)).fetchall()}
            assert 'secret_candidate' in kinds and 'sensitive_response' in kinds, kinds
            blobs='\n'.join((x['data_json'] or '') for x in conn.execute("SELECT data_json FROM notifications WHERE exchange_id=?", (cfg['exchange_id'],)).fetchall())
            assert 'SuperSecret123!' not in blobs and api_key not in blobs, blobs
            cols={x['name'] for x in conn.execute("PRAGMA table_info(notifications)").fetchall()}
            assert {'kind','severity','resource_id','operation_id','exchange_id','read_at'}.issubset(cols), cols
        print("[OK] schema + migration path")
        print("[OK] HTTP model: resource -> operations -> deduplicated exchanges")
        print("[OK] policy profile")
        print("[OK] correlation engine: Open Redirect / OIDC / CORS")
        print("[OK] target AI payload + evidence hash")
        print("[OK] search intelligence")
        print("[OK] findings + retest evidence model")
        print("[OK] hypothesis workbench + sanitized HTTP AI context")
        print("[OK] endpoint test coverage memory")
        print("[OK] Burp passive intelligence + notifications")


if __name__ == "__main__":
    main()
