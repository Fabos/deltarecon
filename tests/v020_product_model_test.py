#!/usr/bin/env python3
"""Regression tests for v0.20 product model. Offline; no network/AI."""
from pathlib import Path
import base64
import tempfile
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_hunter as hunter


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="negro-v020-") as td:
        domain = "api.example.test"
        paths = core.ensure_workspace(Path(td) / "project", domain)
        request = (
            b"POST /api/orders/91823?userId=42&redirect_uri=https%3A%2F%2Fclient.example%2Fcb HTTP/1.1\r\n"
            b"Host: api.example.test\r\n"
            b"Authorization: Bearer test.jwt.value\r\n"
            b"Content-Type: application/json\r\n\r\n"
            b'{"orderId":91823,"tenantId":"acme","token":"temporary-secret"}'
        )
        response = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
            b'{"id":91823,"ownerId":42,"status":"CREATED"}'
        )
        obs = core.upsert_http_observation(
            paths,
            domain,
            url="https://api.example.test/api/orders/91823?userId=42&redirect_uri=https%3A%2F%2Fclient.example%2Fcb",
            method="POST",
            source="burp_proxy",
            status_code=200,
            authenticated=True,
            request_content_type="application/json",
            response_content_type="application/json",
            tool="PROXY",
            request_b64=b64(request),
            response_b64=b64(response),
            query={"userId": "42", "redirect_uri": "https://client.example/cb"},
        )
        exid = int(obs["exchange_id"])
        rid = int(obs["resource_id"])
        oid = int(obs["operation_id"])

        with core.db_connect(paths) as conn:
            tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            assert {"entity_states", "signal_occurrences", "evidence_snapshots", "parameter_observations"}.issubset(tables), tables

            # Parse/index parameters from an exact captured exchange.
            passive = hunter.analyze_http_exchange(conn, exid, domain, emit_notifications=True)
            assert passive["signals"], "deterministic engine evidence must be returned as Signals for Burp highlighting"
            assert core.unreviewed_signal_count(conn, exchange_id=exid) >= 1
            params = conn.execute(
                "SELECT normalized_name,location,value_preview FROM parameter_observations WHERE exchange_id=? ORDER BY normalized_name,location",
                (exid,),
            ).fetchall()
            names = {r["normalized_name"] for r in params}
            assert {"userid", "redirect_uri", "orderid", "tenantid", "token"}.issubset(names), names
            token_preview = next(r["value_preview"] for r in params if r["normalized_name"] == "token")
            assert "temporary-secret" not in token_preview, token_preview

            # A Signal is an automatic observation, not a human state.
            hunter._upsert_notification(
                conn,
                dedupe_key="v020:test:idor",
                kind="possible_idor",
                severity="medium",
                title="Possible IDOR surface",
                message="Object identifier observed on authenticated resource",
                source="selftest",
                entity_type="resource",
                entity_id=rid,
                resource_id=rid,
                operation_id=oid,
                exchange_id=exid,
                data={"rule_match": {"location": "path", "name": "orderId"}},
                emit=True,
            )
            sig = conn.execute("SELECT * FROM signal_occurrences WHERE exchange_id=? AND kind='possible_idor'", (exid,)).fetchone()
            assert sig is not None
            assert sig["reviewed_at"] is None
            assert core.get_human_state(conn, "exchange", exid)["state"] == "normal"
            assert core.unreviewed_signal_count(conn, exchange_id=exid) >= 1

            # Simulate a v0.19 workspace where only the notification existed.
            conn.execute("DELETE FROM signal_occurrences WHERE dedupe_key=?", ("v020:test:idor:exchange:" + str(exid),))
        core.init_db(paths, domain)
        with core.db_connect(paths) as conn:
            migrated = conn.execute("SELECT * FROM signal_occurrences WHERE dedupe_key=?", ("v020:test:idor:exchange:" + str(exid),)).fetchone()
            assert migrated is not None, "legacy exchange notification should backfill into Signal Occurrence"

            # Human review is explicit; important states freeze historical bytes.
            state = core.set_human_state(
                conn,
                "exchange",
                exid,
                "interesting",
                category="access_control",
                note="Needs cross-account validation",
                source="selftest",
            )
            assert state["state"] == "interesting"
            assert state["snapshot_id"]
            assert core.unreviewed_signal_count(conn, exchange_id=exid) == 0

            snap = conn.execute("SELECT * FROM evidence_snapshots WHERE id=?", (state["snapshot_id"],)).fetchone()
            assert snap is not None
            assert snap["request_hash"]
            assert snap["response_hash"]
            assert zlib.decompress(bytes(snap["request_zlib"])) == request
            assert zlib.decompress(bytes(snap["response_zlib"])) == response

            # A later human state can coexist with immutable historical snapshots.
            core.set_human_state(conn, "exchange", exid, "correlate", category="access_control", source="selftest")
            states = {r["human_state"] for r in conn.execute("SELECT human_state FROM evidence_snapshots WHERE exchange_id=?", (exid,))}
            assert {"interesting", "correlate"}.issubset(states), states

        print("[OK] Deterministic engine evidence is surfaced as pending Signals for Burp")
        print("[OK] Signals are stored separately from human state")
        print("[OK] Parameter observations are normalized and sensitive previews are masked")
        print("[OK] Important human states freeze exact historical evidence")


if __name__ == "__main__":
    main()
