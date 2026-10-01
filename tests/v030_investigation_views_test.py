#!/usr/bin/env python3
"""Regression for v0.30 Investigation Views / Map 3.0 and noise reduction."""
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
import negro_objects as objects
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def capture(paths, domain, path, *, cookie, order_id, http_status=200):
    req = f"GET {path} HTTP/1.1\r\nHost: api.viewlab.local\r\nCookie: session={cookie}\r\n\r\n".encode()
    resp = f'HTTP/1.1 {http_status} OK\r\nContent-Type: application/json\r\n\r\n{{"orderId":{order_id},"status":"CREATED"}}'.encode()
    return core.upsert_http_observation(
        paths, domain, url=f"https://api.viewlab.local{path}", method="GET",
        source="burp_proxy", status_code=http_status, authenticated=True, tool="PROXY",
        response_content_type="application/json", request_b64=b64(req), response_b64=b64(resp), query={},
    )


def obs_id(conn, exchange_id, normalized_name):
    row = conn.execute(
        "SELECT id FROM parameter_observations WHERE exchange_id=? AND normalized_name=? ORDER BY id LIMIT 1",
        (int(exchange_id), normalized_name),
    ).fetchone()
    assert row
    return int(row["id"])


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="negro-v030-") as td:
        root = Path(td)
        old_targets = core.TARGETS_PATH
        core.TARGETS_PATH = root / "targets.json"
        try:
            domain = "viewlab.local"
            workspace = root / "workspace"
            paths = core.ensure_workspace(workspace, domain)
            a = capture(paths, domain, "/orders/123", cookie="ana", order_id=123, http_status=200)
            b = capture(paths, domain, "/orders/123/invoice", cookie="ana", order_id=123, http_status=200)
            with core.db_connect(paths) as conn:
                for ex in (a, b):
                    hunter.analyze_http_exchange(conn, int(ex["exchange_id"]), domain, emit_notifications=False)
                ana = identities.create_identity(conn, "Ana")
                identities.assign_exchange(conn, int(a["exchange_id"]), ana, learn_auth=True)
                identities.assign_exchange(conn, int(b["exchange_id"]), ana, learn_auth=False)
                oid = obs_id(conn, a["exchange_id"], "orderid")
                objects.ensure_identifier(conn, "Order", "orderid", source_observation_id=oid)
                # Deliberately bad/ambiguous type: keep evidence, do not promote it visually.
                objects.ensure_identifier(conn, "111", "orderid", source_observation_id=oid)
                objects.rebuild(conn)
                flow_id = flows.create_flow(conn, "Access Control · Order")
                flows.add_step(conn, flow_id, int(a["exchange_id"]))
                flows.add_step(conn, flow_id, int(b["exchange_id"]))
                objects.rebuild(conn)

            key = core.register_target(domain, workspace, make_current=True, name="View Lab", scopes=[domain, "api.viewlab.local"])
            app = create_app(domain, workspace)
            client = TestClient(app)

            graph = client.get(f"/t/{key}/graph")
            assert graph.status_code == 200, graph.text
            for phrase in ("VISTAS DE INVESTIGACIÓN", "Entiende una pregunta a la vez", "Superficie", "Identidad", "Flow", "Objeto", "Atención"):
                assert phrase in graph.text, phrase
            assert "Entender" in graph.text and "Recon e inteligencia" in graph.text

            js = (ROOT / "web" / "static" / "graph.js").read_text()
            for phrase in ("renderFlowNarrative", "flow-story-step", "renderIdentityIndex", "renderObjectIndex", "renderIntelligenceNarrative"):
                assert phrase in js, phrase

            fp = client.get(f"/api/t/{key}/graph?scope=flow&flow_id={flow_id}").json()
            steps = [e for e in fp["edges"] if e["relation"] == "flow_step"]
            assert len(steps) == 2, steps
            assert all("position" in (e.get("meta", {}).get("evidence") or {}) for e in steps)

            op = client.get(f"/api/t/{key}/graph?scope=objects").json()
            qualities = {(x["object_type"], x.get("ui_quality")) for x in op["meta"]["filter_options"]["objects"]}
            assert ("Order", "meaningful") in qualities, qualities
            assert ("111", "ambiguous") in qualities, qualities

            objects_page = client.get(f"/t/{key}/objects")
            assert objects_page.status_code == 200, objects_page.text
            assert "objetos ambiguos ocultos" in objects_page.text
            assert "Guardado" not in objects_page.text or "protagonista" not in objects_page.text  # no requirement on wording
            assert "Order" in objects_page.text

            flows_page = client.get(f"/t/{key}/flows")
            assert "Qué ocurrió y en qué orden" in flows_page.text
            assert "Ya conozco las Requests exactas" in flows_page.text

            identities_page = client.get(f"/t/{key}/identities")
            assert "Quién hizo cada Request" in identities_page.text
            assert "Identity, sesión o resolver" in identities_page.text

            home = client.get(f"/t/{key}/")
            for phrase in ("Ordenar superficie", "Entender tráfico", "Investigar una pista"):
                assert phrase in home.text
        finally:
            core.TARGETS_PATH = old_targets

    print("[OK] Map 3.0 uses question-specific views instead of one universal graph")
    print("[OK] Flow keeps ordered Request evidence for timeline rendering")
    print("[OK] ambiguous Business Objects remain stored but are de-emphasized by default")
    print("[OK] global navigation and core pages expose clearer mental models")


if __name__ == "__main__":
    main()
