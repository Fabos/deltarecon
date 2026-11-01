#!/usr/bin/env python3
"""Regression for v0.33 semantic graph polish and comparison UX."""
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
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def capture(paths, domain, path, *, cookie, body, method="GET", status=200):
    req = f"{method} {path} HTTP/1.1\r\nHost: api.polish.local\r\nCookie: session={cookie}\r\n\r\n".encode()
    resp = f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{body}".encode()
    return core.upsert_http_observation(
        paths, domain, url=f"https://api.polish.local{path}", method=method,
        source="burp_proxy", status_code=status, authenticated=True, tool="PROXY",
        response_content_type="application/json", request_b64=b64(req), response_b64=b64(resp), query={},
    )


def obs_id(conn, exchange_id, normalized_name):
    row = conn.execute(
        "SELECT id FROM parameter_observations WHERE exchange_id=? AND normalized_name=? ORDER BY id LIMIT 1",
        (int(exchange_id), normalized_name),
    ).fetchone()
    assert row, (exchange_id, normalized_name)
    return int(row["id"])


def main():
    with tempfile.TemporaryDirectory(prefix="negro-v033-") as td:
        root = Path(td)
        old_targets = core.TARGETS_PATH
        core.TARGETS_PATH = root / "targets.json"
        try:
            domain = "polish.local"
            workspace = root / "workspace"
            paths = core.ensure_workspace(workspace, domain)
            d_me = capture(paths, domain, "/me", cookie="diego", body='{"id":101,"roleId":7}')
            d_order = capture(paths, domain, "/orders/4101", cookie="diego", body='{"orderId":4101,"ownerId":101}')
            a_me = capture(paths, domain, "/me", cookie="ana", body='{"id":102,"roleId":7}')
            a_order = capture(paths, domain, "/orders/4103", cookie="ana", body='{"orderId":4103,"ownerId":102}')

            with core.db_connect(paths) as conn:
                for ex in (d_me, d_order, a_me, a_order):
                    hunter.analyze_http_exchange(conn, int(ex["exchange_id"]), domain, emit_notifications=False)
                diego = identities.create_identity(conn, "Diego")
                ana = identities.create_identity(conn, "Ana")
                identities.assign_exchange(conn, int(d_me["exchange_id"]), diego, learn_auth=True)
                identities.assign_exchange(conn, int(d_order["exchange_id"]), diego, learn_auth=False)
                identities.assign_exchange(conn, int(a_me["exchange_id"]), ana, learn_auth=True)
                identities.assign_exchange(conn, int(a_order["exchange_id"]), ana, learn_auth=False)

                # Deliberately teach the same generic `id` as several ambiguous object types.
                generic_obs = obs_id(conn, a_me["exchange_id"], "id")
                for typ in ("111", "222", "Object"):
                    objects.ensure_identifier(conn, typ, "id", source_observation_id=generic_obs)
                objects.rebuild(conn)

            key = core.register_target(domain, workspace, make_current=True, name="Polish Lab", scopes=[domain, "api.polish.local"])
            client = TestClient(create_app(domain, workspace))

            data = client.get(f"/api/t/{key}/graph?scope=identity&identity_id={diego}&compare_identity_id={ana}").json()
            by_label = {n["label"]: n for n in data["nodes"] if n["type"] == "resource"}
            assert {"/me", "/orders/4101", "/orders/4103"}.issubset(by_label)
            def called(iid):
                return {e["target"] for e in data["edges"] if e["source"] == f"identity:{iid}" and e["relation"] == "called_endpoint"}
            d = called(diego); a = called(ana)
            assert by_label["/me"]["id"] in d & a
            assert by_label["/orders/4101"]["id"] in d - a
            assert by_label["/orders/4103"]["id"] in a - d

            page = client.get(f"/t/{key}/graph")
            assert page.status_code == 200
            assert "data-identity-compare-summary" in page.text
            assert ">Identidades<" in page.text and ">Flows<" in page.text and ">Objetos<" in page.text
            assert "<summary>Entender</summary>" not in page.text
            assert "<summary>Más</summary>" not in page.text

            # Default Burp selection names are contextual and disambiguated.
            payload = {
                "target_key": key,
                "action": "flow_create_selected",
                "exchange_id": int(d_me["exchange_id"]),
                "exchange_ids": f"{int(d_me['exchange_id'])},{int(d_order['exchange_id'])}",
                "name": "Flow from Burp selection",
            }
            r1 = client.post("/api/bridge/action", json=payload); assert r1.status_code == 200, r1.text
            r2 = client.post("/api/bridge/action", json=payload); assert r2.status_code == 200, r2.text
            with core.db_connect(paths) as conn:
                names = [r["name"] for r in conn.execute("SELECT name FROM flows ORDER BY id").fetchall()]
            assert names[0].startswith("Burp · GET /me → GET /orders/4101"), names
            assert names[1].endswith("#2"), names

            js = (ROOT / "web" / "static" / "graph.js").read_text()
            for phrase in ("appendNodeVisual", "identityEndpointSets", "Compartidos", "groupNodeRelations", "relationSectionsHtml", "graph-edge-identity-secondary"):
                assert phrase in js, phrase
            css = (ROOT / "web" / "static" / "style.css").read_text()
            for phrase in (".identity-card", ".endpoint-card", ".flow-card", ".object-hex", ".identity-compare-summary", ".direct-nav"):
                assert phrase in css, phrase
        finally:
            core.TARGETS_PATH = old_targets

    print("[OK] Identity compare exposes shared and identity-only endpoint sets")
    print("[OK] graph node vocabulary uses semantic SVG shapes instead of generic circles")
    print("[OK] duplicate-looking relations are grouped in the detail presentation")
    print("[OK] direct navigation replaces opaque Entender/Más menus")
    print("[OK] generic Burp flow names become contextual and unique")


if __name__ == "__main__":
    main()
