from __future__ import annotations

import base64
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_web
import negro_workbench as workbench

try:
    from fastapi.testclient import TestClient
except Exception:
    TestClient = None


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode('ascii')


def setup_project(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(core, 'CONFIG_PATH', tmp_path / 'config.json')
    monkeypatch.setattr(core, 'TARGETS_PATH', tmp_path / 'targets.json')
    monkeypatch.setenv('NEGRO_TRAFFIC_WORKSPACE', str(tmp_path / 'traffic-inbox'))
    ws = tmp_path / 'workspace'
    key = core.register_target('example.test', ws, make_current=True, name='Example', scopes=['example.test'])
    core.ensure_workspace(ws, 'example.test', scopes=['example.test'], project_name='Example')
    return key, ws


@pytest.mark.skipif(TestClient is None, reason='FastAPI TestClient unavailable')
def test_timeline_exposes_compact_request_parameters(tmp_path, monkeypatch):
    key, ws = setup_project(tmp_path, monkeypatch)
    client = TestClient(negro_web.create_app('example.test', ws))
    req = (b'POST /api/auth?type=login HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n'
           b'{"codTipoDoc":"13","fromMobile":false,"id":"abc123"}')
    resp = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}'
    body = client.post('/api/ingest/http', json={
        'url':'https://example.test/api/auth?type=login','method':'POST','tool':'PROXY','status_code':200,
        'request_content_type':'application/json','response_content_type':'application/json',
        'request_b64':b64(req),'response_b64':b64(resp),'burp_in_scope':True,
    }).json()
    rows = workbench.list_traffic(target=key, hide_static=False, limit=20)['rows']
    row = next(r for r in rows if r['id'] == body['capture_event_id'])
    params = {p['name']: p['value'] for p in row.get('request_params') or []}
    assert params['type'] == 'login'
    assert params['codTipoDoc'] == '13'
    assert params['fromMobile'].lower() == 'false'


def test_live_follow_and_jwt_hotfix_contract():
    tpl = (ROOT / 'web/templates/http_workbench.html').read_text()
    js = (ROOT / 'web/static/app.js').read_text()
    css = (ROOT / 'web/static/style.css').read_text()
    assert 'data-live-follow-default' in tpl
    assert 'data-live-follow-toggle' in tpl
    assert 'wb-param-preview' in tpl
    assert 'data-jwt-error' in tpl
    for token in ('setLiveFollow(false)', 'Seguir LIVE', 'paramHtml', 'if(!jwtDialog.open)jwtDialog.showModal()', 'd.errors'):
        assert token in js
    for token in ('.wb-live-follow-toggle', '.wb-param-preview', '.wb-jwt-error'):
        assert token in css
