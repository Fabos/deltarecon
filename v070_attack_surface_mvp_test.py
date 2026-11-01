from __future__ import annotations

import base64
from pathlib import Path
import re
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_flows as flows
import negro_flow_runtime as runtime
import negro_runners as runners
import negro_web

try:
    from fastapi.testclient import TestClient
except Exception:  # pragma: no cover
    TestClient = None


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def setup_project(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(core, "TARGETS_PATH", tmp_path / "targets.json")
    monkeypatch.setenv("NEGRO_TRAFFIC_WORKSPACE", str(tmp_path / "traffic-inbox"))
    ws = tmp_path / "workspace"
    key = core.register_target("api.test", ws, make_current=True, name="Example", scopes=["api.test"])
    paths = core.ensure_workspace(ws, "api.test", scopes=["api.test"], project_name="Example")
    return key, ws, paths


def observe(paths, path: str, req_json: str, resp_json: str):
    req = (
        f"POST {path} HTTP/1.1\r\n"
        "Host: api.test\r\n"
        "Content-Type: application/json\r\n"
        "Authorization: Bearer demo-token\r\n\r\n"
        f"{req_json}"
    ).encode()
    resp = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n\r\n"
        f"{resp_json}"
    ).encode()
    return core.upsert_http_observation(
        paths, "api.test", url=f"https://api.test{path}", method="POST", source="burp_proxy", tool="PROXY",
        request_b64=b64(req), response_b64=b64(resp), status_code=200,
        request_content_type="application/json", response_content_type="application/json", burp_in_scope=True,
    )


def test_workbench_pretty_reuses_inventory_visual_language_and_wraps():
    js = (ROOT / "web/static/app.js").read_text(encoding="utf-8")
    css = (ROOT / "web/static/style.css").read_text(encoding="utf-8")
    for token in (
        "http-token-method", "http-token-target", "http-token-protocol", "http-token-header-name",
        "http-token-sensitive", "http-token-key", "http-token-string", "data-line=",
    ):
        assert token in js
    for token in (
        ".wb-code.pretty .wb-http-line::before", "content:attr(data-line)", "overflow-wrap:anywhere",
        "word-break:break-word", ".wb-code.raw", "white-space:pre",
    ):
        assert token in css


def test_flow_and_scenario_templates_explain_data_wiring_in_user_language():
    inspector = (ROOT / "web/templates/http_inspector.html").read_text(encoding="utf-8")
    flow = (ROOT / "web/templates/flow_detail.html").read_text(encoding="utf-8")
    scenario = (ROOT / "web/templates/scenario_step_http.html").read_text(encoding="utf-8")
    assert "CONEXIONES DE DATOS" in inspector
    assert "Pedir al ejecutar" in inspector
    assert "Pasar a Step" in inspector
    assert 'name="source_side" value="request"' in inspector
    assert 'name="source_side" value="response"' in inspector
    assert "Reemplazar en la siguiente Request" in inspector
    assert "Usar para reemplazar" in inspector
    assert "ENTRA" in flow and "SALE" in flow
    assert "HEREDADO DEL FLOW" in scenario
    assert "conexiones" in scenario.lower()


def test_request_value_is_a_first_class_runtime_source(tmp_path, monkeypatch):
    _key, _ws, paths = setup_project(tmp_path, monkeypatch)
    a = observe(paths, "/one", '{"orderId":"ORD-1"}', '{"ok":true}')
    b = observe(paths, "/two", '{"orderId":"OLD"}', '{"ok":true}')
    with core.db_connect(paths) as conn:
        fid = flows.create_flow(conn, "Order")
        sid1 = flows.add_step(conn, fid, int(a["exchange_id"]))
        sid2 = flows.add_step(conn, fid, int(b["exchange_id"]))
        vid = runtime.create_variable(
            conn, fid, name="orderId", source_type="REQUEST_VALUE", default_value="ORD-1",
            producer_step_id=sid1, extraction_type="request", extraction_expr="request_json:$.orderId",
        )
        runtime.add_binding(conn, fid, sid2, vid, target_value="OLD", target_name="orderId", target_location="request_json:$.orderId")
        data = runtime.flow_runtime_data(conn, fid)
        v = next(v for v in data["variables"] if int(v["id"]) == vid)
        assert v["source_type"] == "REQUEST_VALUE"
        assert v["default_value"] == "ORD-1"
        assert v["producer_position"] == 1
        assert v["consumers"] == [2]
        seeded = runners._scenario_initial_context(conn, [{"flow_id": fid}])
        assert seeded["orderId"] == "ORD-1"


@pytest.mark.skipif(TestClient is None, reason="FastAPI TestClient unavailable")
def test_quick_forward_request_and_response_wire_to_immediate_next_step(tmp_path, monkeypatch):
    key, ws, paths = setup_project(tmp_path, monkeypatch)
    a = observe(paths, "/start", '{"orderId":"ORD-1","userId":"USR-1"}', '{"returnId":"RET-9","status":"created"}')
    b = observe(paths, "/finish", '{"orderId":"OLD","returnId":"OLD-RET"}', '{"ok":true}')
    with core.db_connect(paths) as conn:
        fid = flows.create_flow(conn, "Wire demo")
        sid1 = flows.add_step(conn, fid, int(a["exchange_id"]))
        sid2 = flows.add_step(conn, fid, int(b["exchange_id"]))

    app = negro_web.create_app("api.test", ws)
    client = TestClient(app)
    inspect = client.get(f"/t/{key}/exchange/{int(a['exchange_id'])}/inspect?flow_id={fid}&flow_step_id={sid1}")
    assert inspect.status_code == 200, inspect.text[:1000]
    m = re.search(r'name="csrf" value="([^"]+)"', inspect.text)
    assert m, inspect.text[:1000]
    csrf = m.group(1)
    assert "Pedir al ejecutar" in inspect.text
    assert f"Pasar a Step 2" in inspect.text

    r1 = client.post(
        f"/t/{key}/flows/{fid}/runtime/quick-forward",
        data={
            "csrf": csrf,
            "exchange_id": int(a["exchange_id"]), "step_id": sid1,
            "source_side": "request", "source_location": "request_json:$.orderId", "source_key": "orderId", "source_value": "ORD-1",
            "target_step_id": sid2, "target_value": "OLD", "target_name": "orderId", "target_location": "request_json:$.orderId",
        },
        follow_redirects=False,
    )
    assert r1.status_code == 303, r1.text

    r2 = client.post(
        f"/t/{key}/flows/{fid}/runtime/quick-forward",
        data={
            "csrf": csrf,
            "exchange_id": int(a["exchange_id"]), "step_id": sid1,
            "source_side": "response", "source_location": "response_json:$.returnId", "source_key": "returnId", "source_value": "RET-9",
            "target_step_id": sid2, "target_value": "OLD-RET", "target_name": "returnId", "target_location": "request_json:$.returnId",
        },
        follow_redirects=False,
    )
    assert r2.status_code == 303, r2.text

    with core.db_connect(paths) as conn:
        rows = [dict(x) for x in conn.execute(
            "SELECT id,name,source_type,default_value,producer_step_id,extraction_type,extraction_expr FROM flow_variables WHERE flow_id=? ORDER BY id",
            (fid,),
        ).fetchall()]
        assert [x["source_type"] for x in rows] == ["REQUEST_VALUE", "PREVIOUS_RESPONSE"]
        assert rows[0]["default_value"] == "ORD-1"
        assert rows[0]["extraction_expr"] == "request_json:$.orderId"
        assert rows[1]["extraction_type"] == "json"
        assert rows[1]["extraction_expr"] == "$.returnId"
        bindings = [dict(x) for x in conn.execute(
            "SELECT variable_id,flow_step_id,target_name,target_location,target_value FROM flow_step_variable_bindings WHERE flow_id=? ORDER BY id",
            (fid,),
        ).fetchall()]
        assert len(bindings) == 2
        assert all(int(x["flow_step_id"]) == sid2 for x in bindings)
        assert {(x["target_name"], x["target_value"]) for x in bindings} == {("orderId", "OLD"), ("returnId", "OLD-RET")}
