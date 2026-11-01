#!/usr/bin/env python3
from __future__ import annotations
import base64
import pathlib
import tempfile
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import negro_core as core
import negro_environment as env
import negro_parameters as parameters
import negro_search as search


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def main() -> None:
    root = pathlib.Path(tempfile.mkdtemp(prefix="negro-env-context-"))
    paths = core.ensure_workspace(root, "example.com")
    qa = core.upsert_http_observation(
        paths, "example.com", url="https://api.qa.example.com/orders/123", method="GET", source="burp_proxy", status_code=200,
        request_b64=b64("GET /orders/123 HTTP/1.1\r\nHost: api.qa.example.com\r\n\r\n"),
        response_b64=b64("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"orderId\":123,\"role\":\"user\"}"),
    )
    prod = core.upsert_http_observation(
        paths, "example.com", url="https://api.example.com/orders/987", method="GET", source="burp_proxy", status_code=403,
        request_b64=b64("GET /orders/987 HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
        response_b64=b64("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"error\":\"forbidden\"}"),
    )
    with core.db_connect(paths) as conn:
        rows = [dict(x) for x in conn.execute("SELECT id,environment,environment_source FROM http_exchanges ORDER BY id")]
        assert [x["environment"] for x in rows] == ["QA", "PROD"], rows
        cps = env.counterpart_candidates(conn, qa["exchange_id"])
        assert cps and cps[0]["id"] == prod["exchange_id"] and cps[0]["normalized_path"] == "/orders/{id}", cps
        for row in rows:
            search.index_exchange(conn, row["id"])
        results = search.search(conn, "env:QA")
        assert [x["exchange_id"] for x in results["results"]] == [qa["exchange_id"]], results
        diff = parameters.smart_diff(conn, qa["exchange_id"], prod["exchange_id"])
        assert diff and diff["a"]["environment"] == "QA" and diff["b"]["environment"] == "PROD", diff
        env.set_exchange_environment(conn, prod["exchange_id"], "STAGING")
        row = dict(conn.execute("SELECT environment,environment_source FROM http_exchanges WHERE id=?", (prod["exchange_id"],)).fetchone())
        assert row == {"environment": "STAGING", "environment_source": "manual"}, row
    # A repeated observation must preserve a manual override.
    core.upsert_http_observation(
        paths, "example.com", url="https://api.example.com/orders/987", method="GET", source="burp_proxy", status_code=403,
        request_b64=b64("GET /orders/987 HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
        response_b64=b64("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"error\":\"forbidden\"}"),
    )
    with core.db_connect(paths) as conn:
        row = dict(conn.execute("SELECT environment,environment_source FROM http_exchanges WHERE id=?", (prod["exchange_id"],)).fetchone())
        assert row == {"environment": "STAGING", "environment_source": "manual"}, row
    print("[OK] Environment Context detects QA/PROD, preserves overrides, filters Search and finds normalized counterparts")


if __name__ == "__main__":
    main()
