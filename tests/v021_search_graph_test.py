#!/usr/bin/env python3
"""Offline regression for v0.21 Search Everything + graph/Burp projection."""
from pathlib import Path
import base64
import json
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_hunter as hunter
import negro_search as search
import negro_web as web


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="negro-v021-") as td:
        domain = "api.access.test"
        paths = core.ensure_workspace(Path(td) / "project", domain)
        req = (
            b"GET /orders/4101?view=full HTTP/1.1\r\n"
            b"Host: api.access.test\r\n"
            b"Cookie: accesslab_session=buyer-a\r\n"
            b"X-Tenant-Id: 77\r\n\r\n"
        )
        resp = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"id":4101,"ownerId":101,"roleId":1}'
        obs = core.upsert_http_observation(
            paths, domain, url="https://api.access.test/orders/4101?view=full", method="GET",
            source="burp_proxy", status_code=200, authenticated=True, tool="PROXY",
            request_b64=b64(req), response_b64=b64(resp), query={"view":"full"},
        )
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn, int(obs["exchange_id"]), domain, emit_notifications=False)
            search.index_exchange(conn, int(obs["exchange_id"]))
            search.index_resource(conn, int(obs["resource_id"]))
            search.index_host(conn, int(obs["host_id"]))

            assert search.search(conn, "ownerId")["count"] >= 1
            assert search.search(conn, "host:api.access.test method:GET status:200")["count"] >= 1
            assert search.search(conn, "cookie:accesslab_session")["count"] >= 1
            assert search.search(conn, "header:X-Tenant-Id")["count"] >= 1
            assert search.search(conn, "response:roleId")["count"] >= 1
            assert search.search(conn, "path:/orders/4101")["count"] >= 1

            sid = search.save_search(conn, "Orders con ownership", "response:ownerId path:/orders/")
            assert sid > 0 and search.list_saved_searches(conn)

            rebuilt = search.rebuild_search_index(conn)
            assert rebuilt["exchanges"] == 1
            assert search.search(conn, "response:ownerId")["count"] >= 1

        # Before any AI hypothesis exists, a small project map must already show
        # deterministic inventory relationships instead of an almost-empty canvas.
        overview = web._graph_data(paths, domain, scope="overview")
        types = {n["type"] for n in overview["nodes"]}
        assert {"target", "host", "resource", "operation"}.issubset(types), types
        assert any(e["relation"] == "supports" for e in overview["edges"]), overview["edges"]

        # Burp perspective is project-wide and must work without first focusing a host.
        burp = web._graph_data(paths, domain, scope="burp")
        btypes = {n["type"] for n in burp["nodes"]}
        assert "request" in btypes and "operation" in btypes and "resource" in btypes, btypes
        assert any(e["relation"] == "observed_in" for e in burp["edges"]), burp["edges"]
        assert burp["meta"]["scope"] == "burp"

        print("[OK] Search Everything finds body/header/cookie/path + structured filters")
        print("[OK] Saved searches persist and historical rebuild works")
        print("[OK] Small maps show deterministic relationships before AI")
        print("[OK] Burp map projection materializes observed traffic without hypothesis dependency")


if __name__ == "__main__":
    main()
