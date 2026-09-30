#!/usr/bin/env python3
"""Offline regression for v0.22 substring search + parameter intelligence."""
from pathlib import Path
import base64
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_hunter as hunter
import negro_parameters as params
import negro_search as search


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def capture(paths, domain, url, method, req, resp, status=200):
    return core.upsert_http_observation(
        paths, domain, url=url, method=method, source="burp_proxy", status_code=status,
        authenticated=True, tool="PROXY", request_content_type="application/json",
        response_content_type="application/json", request_b64=b64(req), response_b64=b64(resp), query={},
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="negro-v022-") as td:
        domain = "api.example.test"
        paths = core.ensure_workspace(Path(td) / "project", domain)
        ex1 = capture(
            paths, domain, "https://api.example.test/orders/4101", "GET",
            b"GET /orders/4101 HTTP/1.1\r\nHost: api.example.test\r\nCookie: session=buyer-a\r\n\r\n",
            b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"id":4101,"ownerId":101,"phone":"3001112233","mapApiKey":"AIzaExampleLongKey1234567890"}',
        )
        ex2 = capture(
            paths, domain, "https://api.example.test/orders/4101/action", "POST",
            b'POST /orders/4101/action HTTP/1.1\r\nHost: api.example.test\r\nCookie: session=buyer-b\r\nContent-Type: application/json\r\n\r\n{"orderId":4101,"ownerId":102,"status":"CANCELLED"}',
            b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"id":4101,"ownerId":102,"status":"CANCELLED"}',
        )
        with core.db_connect(paths) as conn:
            for ex in (ex1, ex2):
                hunter.analyze_http_exchange(conn, int(ex["exchange_id"]), domain, emit_notifications=False)
                search.index_exchange(conn, int(ex["exchange_id"]))

            # Plain/free-text search is substring based for >=3 chars.
            assert search.search(conn, "1223")["count"] >= 1, "fragment should match 3001112233"
            assert search.search(conn, "AIza")["count"] >= 1, "fragment should match longer API key"
            assert search.search(conn, "response:1112")["count"] >= 1

            # Parameter layer includes likely path IDs + response JSON scalars.
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM parameter_observations WHERE exchange_id=? ORDER BY id", (int(ex1["exchange_id"]),)
            ).fetchall()]
            assert any(r["normalized_name"] == "order_id" and r["location"].startswith("path:") for r in rows), rows
            assert any(r["normalized_name"] == "ownerid" and r["location"].startswith("response_json:") for r in rows), rows

            obs = next(r for r in rows if r["value_preview"] == "4101")
            followed = params.follow_observation(conn, int(obs["id"]))
            assert followed and len({int(x["exchange_id"]) for x in followed["occurrences"]}) >= 2, followed

            related = params.related_exchanges(conn, int(ex1["exchange_id"]))
            assert related and any(int(x["id"]) == int(ex2["exchange_id"]) for x in related["related"]), related

            diff = params.smart_diff(conn, int(ex1["exchange_id"]), int(ex2["exchange_id"]))
            assert diff and diff["changes"]
            keys = {str(x["key"]).lower() for x in diff["changes"]}
            assert any("ownerid" in k for k in keys), keys
            # Sensitive headers must not echo raw session values.
            rendered = " ".join(str(x.get("a", "")) + " " + str(x.get("b", "")) for x in diff["changes"])
            assert "buyer-a" not in rendered and "buyer-b" not in rendered, rendered

            rebuilt = params.rebuild_parameter_observations(conn)
            assert rebuilt["exchanges"] == 2 and rebuilt["observations"] > 0

        print("[OK] substring search finds fragments inside larger values")
        print("[OK] Parameter Explorer indexes path IDs + response JSON")
        print("[OK] Follow Value crosses exchanges by exact value hash")
        print("[OK] Find Related explains shared evidence")
        print("[OK] Smart Diff prioritizes structured differences and masks sensitive headers")


if __name__ == "__main__":
    main()
