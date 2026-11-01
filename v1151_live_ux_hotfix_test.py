#!/usr/bin/env python3
"""Regression Contexto compuesto · Fase 1: canonical Investigation relation graph."""
from pathlib import Path
import base64
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_hunter as hunter
import negro_identity as identities
import negro_flows as flows
import negro_runners as runners
from negro_web import _investigation_detail


def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()


def capture(paths, domain):
    req = (
        "POST /orders HTTP/1.1\r\n"
        "Host: api.context.local\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"sku":"DOG-1","quantity":1}'
    ).encode()
    resp = (
        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n"
        '{"orderId":8932,"status":"CREATED"}'
    ).encode()
    return core.upsert_http_observation(
        paths,
        domain,
        url="https://api.context.local/orders",
        method="POST",
        source="burp_proxy",
        status_code=201,
        authenticated=True,
        tool="PROXY",
        request_content_type="application/json",
        response_content_type="application/json",
        request_b64=b64(req),
        response_b64=b64(resp),
    )


def main():
    with tempfile.TemporaryDirectory(prefix="negro-context-phase1-") as td:
        root = Path(td)
        domain = "context.local"
        paths = core.ensure_workspace(root / "workspace", domain)
        ex = capture(paths, domain)

        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn, int(ex["exchange_id"]), domain, emit_notifications=False)
            hid = hunter.create_manual_hypothesis(
                conn,
                int(ex["exchange_id"]),
                title="¿Puede Buyer B modificar la orden de Buyer A?",
                why="Pregunta humana de autorización",
                next_test="Repetir change-address con Identity B",
            )
            inv_a = hunter.create_investigation(
                conn,
                title="Autorización de órdenes",
                summary="Investigar ownership en operaciones write",
                source_hypothesis_id=hid,
            )
            inv_b = hunter.create_investigation(
                conn,
                title="Integridad económica",
                summary="La misma evidencia puede participar en otra rama",
            )

            identity_id = identities.create_identity(conn, "Buyer A")
            context_id = identities.create_context(conn, identity_id, "Sesión principal", role="buyer")
            flow_id = flows.create_flow(conn, "Crear orden", description="Baseline Buyer A")
            flows.add_step(conn, flow_id, int(ex["exchange_id"]))
            runner_id = runners.create_runner_from_flow(
                conn,
                flow_id,
                alias="Order auth · baseline",
                description="Prueba ligada a Investigation",
                hypothesis_id=hid,
                investigation_id=inv_a,
            )

            now = core.now_iso()
            finding_id = int(
                conn.execute(
                    "INSERT INTO findings(title,severity,status,description,source,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                    ("Finding legado", "medium", "draft", "Compatibilidad", "manual", now, now),
                ).lastrowid
            )
            conn.execute(
                "INSERT INTO finding_entities(finding_id,entity_type,entity_id,relation,created_at) VALUES(?,?,?,?,?)",
                (finding_id, "investigation", inv_a, "source", now),
            )

            # Simulate a v0.41 workspace where legacy/origin pointers existed but the
            # generic relation edge was missing.  Force the migration to run again.
            conn.execute("DELETE FROM investigation_links WHERE investigation_id=?", (inv_a,))
            conn.execute("DELETE FROM meta WHERE key IN ('context_compound_phase1_links_base','context_compound_phase1_links_runner')")
            counts = hunter.backfill_investigation_links(conn)
            assert counts["base"] >= 2, counts
            assert counts["runner"] >= 1, counts

            migrated = {
                (r["entity_type"], int(r["entity_id"]), r["relation"])
                for r in hunter.list_investigation_links(conn, inv_a)
            }
            assert ("hypothesis", hid, "pursuing") in migrated
            assert ("runner", runner_id, "test") in migrated
            assert ("finding", finding_id, "decision") in migrated

            # Canonical graph is many-to-many: one Hypothesis/evidence item can be
            # useful in multiple Investigations without moving or copying it.
            hunter.link_investigation_entity(conn, inv_b, "hypothesis", hid, "pursuing")
            assert int(conn.execute("SELECT promoted_investigation_id FROM leads_v2 WHERE id=?", (hid,)).fetchone()[0]) == inv_a
            both = conn.execute(
                "SELECT COUNT(DISTINCT investigation_id) c FROM investigation_links WHERE entity_type='hypothesis' AND entity_id=?",
                (hid,),
            ).fetchone()["c"]
            assert int(both) == 2

            # Identity Context becomes first-class attachable context in Fase 1.
            first = hunter.link_investigation_entity(conn, inv_a, "identity_context", context_id, "context")
            second = hunter.link_investigation_entity(conn, inv_a, "identity_context", context_id, "context")
            assert first == second and first > 0
            assert conn.execute(
                "SELECT COUNT(*) c FROM investigation_links WHERE investigation_id=? AND entity_type='identity_context' AND entity_id=? AND relation='context'",
                (inv_a, context_id),
            ).fetchone()["c"] == 1

            # Bad references are rejected instead of poisoning the graph.
            try:
                hunter.link_investigation_entity(conn, inv_a, "identity_context", 999999, "context")
                raise AssertionError("missing context should have been rejected")
            except ValueError as exc:
                assert "no encontrado" in str(exc).lower()

            # Unlinking removes only membership; source/origin entities survive.
            removed = hunter.unlink_investigation_entity(conn, inv_b, "hypothesis", hid, "pursuing")
            assert removed == 1
            assert conn.execute("SELECT id FROM leads_v2 WHERE id=?", (hid,)).fetchone()
            assert int(conn.execute("SELECT promoted_investigation_id FROM leads_v2 WHERE id=?", (hid,)).fetchone()[0]) == inv_a

            # Orphaned historical pointers are ignored by migration instead of
            # breaking workspace startup.
            inv_orphan = hunter.create_investigation(conn, title="Legacy orphan")
            conn.execute("UPDATE investigations SET source_hypothesis_id=999999 WHERE id=?", (inv_orphan,))
            conn.execute("DELETE FROM meta WHERE key='context_compound_phase1_links_base'")
            hunter.backfill_investigation_links(conn)
            assert not conn.execute(
                "SELECT 1 FROM investigation_links WHERE investigation_id=? AND entity_type='hypothesis' AND entity_id=999999",
                (inv_orphan,),
            ).fetchone()

        detail = _investigation_detail(paths, inv_a)
        assert detail
        contexts = [x for x in detail["context_known"] if x["type"] == "identity_context"]
        assert contexts and contexts[0]["label"] == "Contexto · Sesión principal"
        assert contexts[0]["href"] == f"identities/view/{identity_id}"
        assert any(int(r["runner"]["id"]) == runner_id for r in detail["investigation_runners"])
        assert any(int(f["id"]) == finding_id for f in detail["investigation_findings"])

        web_source = (ROOT / "negro_web.py").read_text(encoding="utf-8")
        assert 'item["href"]=f"/t/{target_key}/investigations/' in web_source
        assert 'hypotheses#investigation-' not in web_source

    print("[OK] Investigation links are the canonical additive many-to-many context graph")
    print("[OK] legacy Hypothesis/Runner/Finding pointers are backfilled without deleting compatibility fields")
    print("[OK] Identity Context is attachable and source entities are never copied/deleted by link changes")
    print("[OK] orphaned legacy pointers are ignored safely and Investigation navigation points to the real workspace")


if __name__ == "__main__":
    main()
