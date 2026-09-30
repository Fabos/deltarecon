#!/usr/bin/env python3
"""Regression test for Rule → Signal → AI Hypothesis → Human Investigation."""
from pathlib import Path
import base64
import json
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_hunter as hunter
import negro_web as web


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="negro-v0203-") as td:
        domain = "api.example.test"
        paths = core.ensure_workspace(Path(td) / "project", domain)
        req = b"GET /api/orders/4101 HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer example\r\n\r\n"
        resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":4101,\"ownerId\":42,\"status\":\"CREATED\"}"
        obs = core.upsert_http_observation(
            paths, domain,
            url="https://api.example.test/api/orders/4101", method="GET", source="burp_proxy",
            status_code=200, authenticated=True, response_content_type="application/json", tool="PROXY",
            request_b64=b64(req), response_b64=b64(resp), query={},
        )
        exid = int(obs["exchange_id"])
        rid = int(obs["resource_id"])
        oid = int(obs["operation_id"])

        with core.db_connect(paths) as conn:
            hunter.init_schema(conn)
            tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            assert {"signal_occurrences", "investigations", "investigation_links"}.issubset(tables), tables

            # Rule output is a Signal, not a hypothesis.
            hunter._upsert_notification(
                conn, dedupe_key="v0203:object", kind="access_object_reference", severity="medium",
                title="Referencia de objeto observada", message="ID numérico en recurso autenticado",
                source="engine", entity_type="resource", entity_id=rid, resource_id=rid,
                operation_id=oid, exchange_id=exid, data={"rule_match": {"numeric_path": True}}, emit=True,
            )
            assert conn.execute("SELECT COUNT(*) c FROM signal_occurrences").fetchone()["c"] == 1

            # Explicit AI run result: facts/inference/unknowns are persisted as an AI hypothesis.
            result = {
                "hypotheses": [{
                    "title": "Posible inconsistencia de autorización horizontal en Orders",
                    "type": "authorization",
                    "strength": "medium",
                    "investigation_priority": "medium",
                    "priority_reasons": ["object id controlado por cliente"],
                    "plain_language": "El objeto se identifica desde el path y falta comparar ownership.",
                    "facts": ["GET /api/orders/4101 respondió 200 autenticado", "El ID 4101 está en el path"],
                    "inference": "Puede valer la pena comparar el mismo objeto entre dos identidades autorizadas.",
                    "unknowns": ["Quién posee order 4101", "Cómo responde Buyer B"],
                    "why_interesting": "La autorización server-side por objeto todavía no está demostrada.",
                    "suggested_investigation": "Comparar Buyer A y Buyer B manteniendo constante el orderId.",
                    "steps": [{"step": 1, "action": "Repetir GET con Buyer B", "what_to_watch": "status y ownerId"}],
                    "confirm_if": "Buyer B obtiene un objeto de Buyer A sin autorización.",
                    "discard_if": "El backend rechaza consistentemente objetos ajenos.",
                    "node_ids": [f"exchange:{exid}"],
                }]
            }
            persisted = hunter.persist_graph_ai_hypotheses(conn, result, evidence_hash="abc123", selected_node_id=f"exchange:{exid}")
            assert len(persisted) == 1
            lead_id = int(persisted[0]["lead_id"])
            lead = conn.execute("SELECT * FROM leads_v2 WHERE id=?", (lead_id,)).fetchone()
            assert lead["source"] == "AI"
            ev = json.loads(lead["evidence_json"])[0]
            assert ev["facts"] and ev["unknowns"] and ev["inference"]

            # Human promotion creates the Investigation; AI does not do this automatically.
            before = conn.execute("SELECT COUNT(*) c FROM investigations").fetchone()["c"]
            assert before == 0
            inv = hunter.promote_ai_hypothesis_to_investigation(conn, lead_id)
            assert inv["status"] == "active"
            linked = conn.execute("SELECT entity_type,COUNT(*) c FROM investigation_links WHERE investigation_id=? GROUP BY entity_type", (inv["id"],)).fetchall()
            types = {r["entity_type"] for r in linked}
            assert "exchange" in types and "resource" in types and "signal" in types, types
            lead2 = conn.execute("SELECT promoted_investigation_id FROM leads_v2 WHERE id=?", (lead_id,)).fetchone()
            assert int(lead2["promoted_investigation_id"]) == int(inv["id"])

            # Legacy ENGINE rows may remain internally for migration compatibility,
            # but Hunt must never present them as AI hypotheses.
            hunter.upsert_lead(
                conn, lead_key="legacy:engine:test", host_id=None, resource_id=rid, lead_type="legacy_rule",
                title="Legacy deterministic row", confidence="medium", review_priority="low", evidence=[],
                why="compat", next_test="none", confirm_if="none", discard_if="none", source="ENGINE",
            )

            # Promotion is idempotent and lifecycle remains human controlled.
            inv2 = hunter.promote_ai_hypothesis_to_investigation(conn, lead_id)
            assert int(inv2["id"]) == int(inv["id"])
            updated = hunter.update_investigation(conn, int(inv["id"]), status="paused", notes="Falta Buyer B")
            assert updated["status"] == "paused" and updated["notes"] == "Falta Buyer B"

        visible_hypotheses = web._hypothesis_rows(paths)
        assert visible_hypotheses and all(str(x.get("source") or "").upper() == "AI" for x in visible_hypotheses), visible_hypotheses
        assert not any(x.get("lead_type") == "legacy_rule" for x in visible_hypotheses)

        print("[OK] Rules surface deterministic Signals")
        print("[OK] AI hypotheses persist facts/inference/unknowns only after explicit AI analysis")
        print("[OK] Human promotion creates an Investigation and links real evidence/Signals")
        print("[OK] Investigation lifecycle remains human controlled")


if __name__ == "__main__":
    main()
