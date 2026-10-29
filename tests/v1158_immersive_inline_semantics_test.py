from __future__ import annotations

import base64
from pathlib import Path
import re
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
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
    key = core.register_target("example.test", ws, make_current=True, name="Example", scopes=["example.test"])
    core.ensure_workspace(ws, "example.test", scopes=["example.test"], project_name="Example")
    return key, ws


def payload() -> dict:
    req = (b'POST /api/orders HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n'
           b'Authorization: Bearer token-abc\r\n\r\n{"orderId":"ORD-1001","userId":"USR-7"}')
    resp = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"refundId":"RFD-9","orderId":"ORD-1001"}'
    return {"url":"https://example.test/api/orders","method":"POST","tool":"PROXY","status_code":200,
            "request_b64":b64(req),"response_b64":b64(resp),"burp_in_scope":True}


@pytest.mark.skipif(TestClient is None, reason="FastAPI TestClient unavailable")
def test_workbench_exposes_inline_values_and_can_teach_entity(tmp_path, monkeypatch):
    key, ws = setup_project(tmp_path, monkeypatch)
    client = TestClient(negro_web.create_app("example.test", ws))
    ing = client.post('/api/ingest/http', json=payload()).json()
    event_id = int(ing['capture_event_id'])
    page = client.get(f'/t/{key}/workbench', params={'event': event_id, 'hide_static': 0})
    assert page.status_code == 200
    assert 'data-workbench-inline-context' in page.text
    assert 'data-inline-popover' in page.text
    assert 'data-inline-class="auth"' in page.text
    assert 'data-inline-class="entity"' in page.text

    detail = client.get(f'/api/t/{key}/workbench/detail', params={'event_id': event_id}).json()
    values = detail['values']
    order = next(v for v in values if v['key'] == 'orderId' and v['side'] == 'request')
    assert order['value'] == 'ORD-1001'
    assert isinstance(detail['identity_options'], list)
    assert isinstance(detail['object_type_options'], list)

    csrf = re.search(r'data-csrf="([^"]+)"', page.text).group(1)
    exid = int(detail['exchange']['id'])
    batch = client.post(
        f'/t/{key}/exchange/{exid}/annotations/batch',
        data={'csrf': csrf, 'annotations_json': '[{"side":"request","location":"request_json:$.orderId","key":"orderId","value":"ORD-1001","classification":"entity","object_type":"Order"}]'},
    )
    assert batch.status_code == 200 and batch.json()['ok'] is True
    refreshed = client.get(f'/api/t/{key}/workbench/detail', params={'event_id': event_id}).json()
    assert any(a['classification'] == 'entity' and a['object_type'] == 'Order' for a in refreshed['annotations'])
    assert any(o['type_name'] == 'Order' for o in refreshed['objects'])


def test_immersive_workspace_and_navigation_compaction_contract():
    tpl = (ROOT / 'web/templates/http_workbench.html').read_text(encoding='utf-8')
    base = (ROOT / 'web/templates/base.html').read_text(encoding='utf-8')
    css = (ROOT / 'web/static/style.css').read_text(encoding='utf-8')
    js = (ROOT / 'web/static/app.js').read_text(encoding='utf-8')
    assert 'data-inline-popover' in tpl and 'data-workbench-inline-context' in tpl
    assert 'class="nav-more' in base and '<summary>Más <span>⌄</span></summary>' in base
    for label in ('Inventario','Buscar','Identidades','Objetos','Mapa','Hipótesis','Recon','Guía','Ajustes'):
        assert f'>{label}</a>' in base
    assert '.wb-grid:fullscreen' in css
    assert '.wb-shell.immersive-fullscreen .wb-context-panel' in css
    assert 'data-inline-index' in js
    assert 'applyInlineContext' in js
    assert "workspace=root.querySelector('.wb-grid')" in js
    assert "setContextHidden(true,{persist:false})" in js
    # Redundant actions are no longer first-class Workbench actions.
    assert 'Inspector avanzado</a>' not in tpl
    assert 'Add to Flow</a>' not in tpl
