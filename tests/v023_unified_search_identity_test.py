#!/usr/bin/env python3
"""Offline regression for v0.23 unified Search + Identity Contexts."""
from pathlib import Path
import base64
import json
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_hunter as hunter
import negro_identity as identity
import negro_parameters as params
import negro_search as search


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def jwt(sub: str, suffix: str) -> str:
    enc = lambda obj: base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{enc({'alg':'none','typ':'JWT'})}.{enc({'sub':sub,'role':'buyer'})}.{suffix}"


def capture(paths, domain, path, token, owner=101):
    req = f"GET {path} HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer {token}\r\n\r\n".encode()
    oid = int(path.rsplit('/', 1)[-1])
    resp = f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{"id":{oid},"ownerId":{owner}}}'.encode()
    return core.upsert_http_observation(
        paths, domain, url=f"https://api.example.test{path}", method="GET", source="burp_proxy", status_code=200,
        authenticated=True, tool="PROXY", request_content_type="application/json", response_content_type="application/json",
        request_b64=b64(req), response_b64=b64(resp), query={},
    )


def capture_me(paths, domain, token, user_id=101):
    req = f"GET /me HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer {token}\r\n\r\n".encode()
    resp = f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{"id":{user_id},"email":"ana@example.test","role":"buyer"}}'.encode()
    return core.upsert_http_observation(
        paths, domain, url="https://api.example.test/me", method="GET", source="burp_proxy", status_code=200,
        authenticated=True, tool="PROXY", request_content_type="application/json", response_content_type="application/json",
        request_b64=b64(req), response_b64=b64(resp), query={},
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="negro-v023-") as td:
        domain = "api.example.test"
        paths = core.ensure_workspace(Path(td) / "project", domain)
        t1 = jwt("101", "sig-a")
        t2 = jwt("101", "sig-b")
        ex1 = capture(paths, domain, "/orders/4101", t1, 101)
        ex2 = capture(paths, domain, "/orders/4102", t2, 101)
        ex_me = capture_me(paths, domain, t1, 101)

        with core.db_connect(paths) as conn:
            for ex in (ex1, ex2, ex_me):
                hunter.analyze_http_exchange(conn, int(ex["exchange_id"]), domain, emit_notifications=False)
                search.index_exchange(conn, int(ex["exchange_id"]))

            # Search is the universal entry: value/name matches expose structured parameter hits.
            p4101 = search.parse_query("4101")
            hits = params.search_hits(conn, p4101.text_terms)
            assert hits and any(str(h["value_preview"]) == "4101" for h in hits), hits
            powner = search.parse_query("ownerId")
            hits_owner = params.search_hits(conn, powner.text_terms)
            assert hits_owner and any(h["normalized_name"] == "ownerid" for h in hits_owner), hits_owner

            # Identity is human-defined, independent from rotating auth material.
            ida = identity.create_identity(conn, "Buyer A", kind="account")
            ctx = identity.create_context(conn, ida, "Buyer Colombia", role="buyer", tenant="co")
            learned = identity.assign_exchange(conn, int(ex1["exchange_id"]), ida, context_id=ctx, learn_auth=True)
            assert learned["materials"] >= 1 and learned["jwt_resolvers"] >= 1, learned

            # A new JWT with a different fingerprint but the same stable `sub` resolves to Buyer A.
            assert t1 != t2
            assert identity.resolve_exchange(conn, int(ex2["exchange_id"])) is not None
            row = conn.execute("SELECT * FROM exchange_identities WHERE exchange_id=?", (int(ex2["exchange_id"]),)).fetchone()
            assert row and int(row["identity_id"]) == ida, dict(row) if row else None
            assert int(row["context_id"]) == ctx, dict(row)

            # A stable actor field from /me can be taught explicitly as an identity resolver.
            me_obs = conn.execute(
                "SELECT id FROM parameter_observations WHERE exchange_id=? AND normalized_name='id' ORDER BY id LIMIT 1",
                (int(ex_me["exchange_id"]),),
            ).fetchone()
            assert me_obs
            suit = identity.resolver_suitability(conn, int(me_obs["id"]))
            assert suit["allowed"] and suit["recommended"], suit
            rid = identity.add_parameter_resolver(conn, int(me_obs["id"]), ida, context_id=ctx)
            assert rid > 0

            owner_obs = conn.execute(
                "SELECT id FROM parameter_observations WHERE exchange_id=? AND normalized_name='ownerid' ORDER BY id LIMIT 1",
                (int(ex1["exchange_id"]),),
            ).fetchone()
            assert owner_obs
            owner_suit = identity.resolver_suitability(conn, int(owner_obs["id"]))
            assert not owner_suit["allowed"] and owner_suit["kind"] == "object_or_context", owner_suit

            idb = identity.create_identity(conn, "Buyer B", kind="account")
            matrix = identity.authorization_matrix(conn, [ida, idb])
            assert matrix["rows"], matrix
            assert any(row["cells"][ida]["observed"] for row in matrix["rows"]), matrix
            assert any(not row["cells"][idb]["observed"] for row in matrix["rows"]), matrix

            stats = identity.stats(conn)
            assert stats["identities"] == 2 and stats["assigned"] >= 2, stats

        print("[OK] Search exposes structured parameter/value hits from the universal query")
        print("[OK] Identity is separate from auth material/context")
        print("[OK] Rotating JWT resolves through stable human-taught claims")
        print("[OK] /me actor observations can become resolvers while ownerId stays object ownership")
        print("[OK] Authorization Matrix reports only observed traffic and preserves No observado")


if __name__ == "__main__":
    main()
