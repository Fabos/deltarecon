#!/usr/bin/env python3
"""Smoke test offline de Negro v0.9. No toca Internet ni ejecuta IA."""
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
        print("[OK] schema + migration path")
        print("[OK] policy profile")
        print("[OK] correlation engine: Open Redirect / OIDC / CORS")
        print("[OK] target AI payload + evidence hash")
        print("[OK] search intelligence")


if __name__ == "__main__":
    main()
