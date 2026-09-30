#!/usr/bin/env python3
"""Offline regression for v0.23.1 parameter/identity UX fixes."""
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
import negro_identity as identity
import negro_parameters as params


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="negro-v0231-") as td:
        domain = "api.example.test"
        paths = core.ensure_workspace(Path(td) / "project", domain)
        req = (
            b"GET /me HTTP/1.1\r\nHost: api.example.test\r\n"
            b"Cookie: accesslab_session=session-buyer-a-secret\r\n"
            b"Authorization: Bearer aaa.eyJzdWIiOiIxMDEiLCJyb2xlIjoiYnV5ZXIifQ.sig\r\n\r\n"
        )
        resp = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"id":101,"ownerId":101,"name":"Ana"}'
        ex = core.upsert_http_observation(
            paths, domain, url="https://api.example.test/me", method="GET", source="burp_proxy", status_code=200,
            authenticated=True, tool="PROXY", request_content_type="application/json", response_content_type="application/json",
            request_b64=b64(req), response_b64=b64(resp), query={},
        )
        exid = int(ex["exchange_id"])
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn, exid, domain, emit_notifications=False)
            pcols = {r["name"] for r in conn.execute("PRAGMA table_info(parameter_observations)")}
            assert "value_raw" in pcols, pcols
            owner = conn.execute("SELECT * FROM parameter_observations WHERE exchange_id=? AND normalized_name='ownerid'", (exid,)).fetchone()
            assert owner and owner["value_raw"] == "101", dict(owner) if owner else None

            detail = params.parameter_detail(conn, "ownerId")
            assert detail and detail["values"] and detail["observations"]
            assert detail["values"][0]["value_raw"] == "101", detail

            buyer = identity.create_identity(conn, "Buyer A")
            ctx = identity.create_context(conn, buyer, "Buyer Colombia", role="buyer")
            learned = identity.assign_exchange(conn, exid, buyer, context_id=ctx, learn_auth=True, notes="confirmed by /me")
            assert learned["materials"] >= 2, learned
            idetail = identity.identity_detail(conn, buyer)
            assert idetail and any("session-buyer-a-secret" in (x.get("raw_value") or "") for x in idetail["materials"]), idetail
            assert any((x.get("value_raw") or "") == "101" for x in idetail["resolvers"] if x.get("resolver_type") == "jwt_claim"), idetail
            actx = identity.assignment_context(conn, exid)
            assert actx and "GET /me HTTP/1.1" in actx["exchange"]["request_text"] and actx["observations"], actx

            other = identity.create_identity(conn, "Buyer B")
            other_ctx = identity.create_context(conn, other, "Buyer B ctx")
            try:
                identity.assign_exchange(conn, exid, buyer, context_id=other_ctx)
                raise AssertionError("cross-identity context should be rejected")
            except ValueError as exc:
                assert "contexto" in str(exc).lower()

        # Render the templates that previously crashed due dict.values collisions.
        env = Environment(loader=FileSystemLoader(str(ROOT / "web" / "templates")), autoescape=select_autoescape())
        request = SimpleNamespace(url=SimpleNamespace(path="/t/lab/parameters/ownerid"))
        base = dict(
            request=request, target_base="/t/lab", target_key="lab", domain=domain, workspace=str(paths["root"]),
            project={"name":"Lab"}, targets=[], version=core.VERSION, csrf_token="x", ui_label=lambda x: x,
            review_states=[], classifications=[], priorities=[]
        )
        html = env.get_template("parameter_detail.html").render(**base, detail=detail)
        assert "101" in html and "built-in method values" not in html
        html2 = env.get_template("identity_assign.html").render(**base, assignment=actx, identities=[{"id":buyer,"name":"Buyer A"}], identity_contexts=[{"id":ctx,"identity_id":buyer,"label":"Buyer Colombia","role":"buyer","tenant":""}])
        assert "GET /me HTTP/1.1" in html2 and "session-buyer-a-secret" in html2

    print("[OK] Parameter detail renders values without dict.values collision")
    print("[OK] Raw parameter/auth values are stored locally while fingerprints remain available")
    print("[OK] Identity assignment exposes exact HTTP before labeling")
    print("[OK] Cross-identity contexts are rejected cleanly")


if __name__ == "__main__":
    main()
