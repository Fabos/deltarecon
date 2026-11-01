#!/usr/bin/env python3
"""Regression for v0.23.2 actor resolver learning + quieter Find Related."""
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


def capture(paths, domain, path, response_json, *, method="GET", cookie="sess-a", status=200):
    req = f"{method} {path} HTTP/1.1\r\nHost: api.example.test\r\nCookie: accesslab_session={cookie}\r\n\r\n".encode()
    body = response_json.encode()
    resp = f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n".encode() + body
    return core.upsert_http_observation(
        paths, domain, url=f"https://api.example.test{path}", method=method, source="burp_proxy", status_code=status,
        authenticated=True, tool="PROXY", request_content_type="application/json", response_content_type="application/json",
        request_b64=b64(req), response_b64=b64(resp), query={},
    )


def main():
    with tempfile.TemporaryDirectory(prefix="negro-v0232-") as td:
        domain = "api.example.test"
        paths = core.ensure_workspace(Path(td) / "project", domain)
        me = capture(paths, domain, "/me", '{"id":101,"email":"ana@example.test","displayName":"Ana Torres","phone":"3001112233","role":"customer","roleId":1}')
        orders = capture(paths, domain, "/orders", '{"orders":[{"id":4101,"reference":"MM-2026-4101","total":189900,"status":"En preparación"},{"id":4103,"reference":"MM-2026-4103","total":84900,"status":"Entregado"}]}')
        detail = capture(paths, domain, "/orders/4101", '{"id":4101,"ownerId":101,"reference":"MM-2026-4101","total":189900,"status":"En preparación"}')
        unrelated = capture(paths, domain, "/metadata/roles", '{"id":1,"role":"customer"}')
        options = capture(paths, domain, "/orders/4101", '', method="OPTIONS", status=204)

        with core.db_connect(paths) as conn:
            for ex in (me, orders, detail, unrelated, options):
                hunter.analyze_http_exchange(conn, int(ex["exchange_id"]), domain, emit_notifications=False)

            ctx = identity.assignment_context(conn, int(me["exchange_id"]))
            assert ctx
            candidates = {x["normalized_name"]: x for x in ctx["resolver_candidates"]}
            ignored = {x["normalized_name"]: x for x in ctx["resolver_ignored"]}
            assert candidates["id"]["recommended"] is True
            assert candidates["email"]["recommended"] is True
            assert candidates["phone"]["recommended"] is False
            assert "role" in ignored and "roleid" in ignored

            ana = identity.create_identity(conn, "ANA")
            selected = [int(candidates["id"]["id"]), int(candidates["email"]["id"])]
            learned = identity.assign_exchange(conn, int(me["exchange_id"]), ana, learn_auth=True, resolver_observation_ids=selected)
            assert learned["parameter_resolvers"] == 2, learned
            detail_id = identity.identity_detail(conn, ana)
            assert detail_id and len([r for r in detail_id["resolvers"] if r["resolver_type"] == "parameter"]) == 2

            owner = conn.execute("SELECT id FROM parameter_observations WHERE exchange_id=? AND normalized_name='ownerid'", (int(detail["exchange_id"]),)).fetchone()
            assert owner
            suit = identity.resolver_suitability(conn, int(owner["id"]))
            assert not suit["allowed"] and suit["kind"] == "object_or_context", suit
            try:
                identity.add_parameter_resolver(conn, int(owner["id"]), ana)
                raise AssertionError("ownerId must not become actor resolver")
            except ValueError:
                pass

            related = params.related_exchanges(conn, int(orders["exchange_id"]))
            assert related
            ids = {int(x["id"]) for x in related["related"]}
            assert int(detail["exchange_id"]) in ids, related
            assert int(options["exchange_id"]) not in ids, related
            assert int(unrelated["exchange_id"]) not in ids, related
            r = next(x for x in related["related"] if int(x["id"]) == int(detail["exchange_id"]))
            assert r["strength"] in {"strong", "medium"} and r["shared_values"] >= 2, r

        env = Environment(loader=FileSystemLoader(str(ROOT / "web" / "templates")), autoescape=select_autoescape())
        request = SimpleNamespace(url=SimpleNamespace(path="/t/lab/identities/assign"))
        base = dict(request=request, target_base="/t/lab", target_key="lab", domain=domain, workspace=str(paths["root"]), project={"name":"Lab"}, targets=[], version=core.VERSION, csrf_token="x", ui_label=lambda x:x, review_states=[], classifications=[], priorities=[])
        html = env.get_template("identity_assign.html").render(**base, assignment=ctx, identities=[{"id":ana,"name":"ANA"}], identity_contexts=[])
        assert "IDENTIFICADORES CANDIDATOS" in html and "ana@example.test" in html and "role" in html
        html_rel = env.get_template("related.html").render(**base, related=related)
        assert "Relación fuerte" in html_rel or "Relación media" in html_rel
        assert ">42<" not in html_rel

    print("[OK] /me proposes actor resolvers; id/email recommended, phone optional, role ignored")
    print("[OK] ownerId cannot become an actor resolver")
    print("[OK] Find Related removes OPTIONS and same-host/name-only noise")
    print("[OK] Find Related presents human-readable relation strength instead of numeric score")


if __name__ == "__main__":
    main()
