from __future__ import annotations

import base64
from pathlib import Path
import re
import sys

import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import negro_core as core
import negro_web
import negro_workbench as workbench

try:
    from fastapi.testclient import TestClient
except Exception:
    TestClient=None


def b64(v: bytes)->str:
    return base64.b64encode(v).decode('ascii')


def setup_project(tmp_path,monkeypatch):
    monkeypatch.setattr(core,'CONFIG_PATH',tmp_path/'config.json')
    monkeypatch.setattr(core,'TARGETS_PATH',tmp_path/'targets.json')
    monkeypatch.setenv('NEGRO_TRAFFIC_WORKSPACE',str(tmp_path/'traffic-inbox'))
    ws=tmp_path/'workspace'
    key=core.register_target('example.test',ws,make_current=True,name='Example',scopes=['example.test'])
    core.ensure_workspace(ws,'example.test',scopes=['example.test'],project_name='Example')
    return key,ws


def payload(host,path='/x',method='GET'):
    req=f'{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n'.encode()
    resp=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}'
    return {'url':f'https://{host}{path}','method':method,'tool':'PROXY','status_code':200,'request_b64':b64(req),'response_b64':b64(resp),'burp_in_scope':False}


def test_ui_has_three_visibility_modes_and_neutral_scan_deck():
    tpl=(ROOT/'web/templates/http_workbench.html').read_text(encoding='utf-8')
    css=(ROOT/'web/static/style.css').read_text(encoding='utf-8')
    js=(ROOT/'web/static/app.js').read_text(encoding='utf-8')
    for token in ('data-visibility-mode="all"','data-visibility-mode="focus"','data-visibility-mode="target"','Eliminar checkpoint','Administrar checkpoints','data-analysis-scope-remove'):
        assert token in tpl
    for token in ('.wb-shell.visibility-focus .wb-traffic-row.is-outside-target','.wb-traffic-list{background:#f4f5f6','.wb-visibility-filter','.wb-checkpoint-manager-menu'):
        assert token in css
    for token in ('setTrafficVisibility','analysisScopeRemoveUrl','removeAnalysisRule','is-outside-target'):
        assert token in js


@pytest.mark.skipif(TestClient is None,reason='FastAPI TestClient unavailable')
def test_focus_keeps_noise_target_only_filters_it(tmp_path,monkeypatch):
    key,ws=setup_project(tmp_path,monkeypatch)
    client=TestClient(negro_web.create_app('example.test',ws))
    inside=client.post('/api/ingest/http',json=payload('example.test','/inside')).json()
    outside=client.post('/api/ingest/http',json=payload('outside.test','/outside')).json()
    assert inside['target_key']==key and outside['target_key']==workbench.INBOX_KEY
    focus=client.get(f'/t/{key}/workbench',params={'visibility':'focus','hide_static':0})
    assert focus.status_code==200
    assert '/inside' in focus.text and '/outside' in focus.text
    assert 'is-target-row' in focus.text and 'is-outside-target' in focus.text
    target_only=client.get(f'/t/{key}/workbench',params={'visibility':'target','hide_static':0})
    assert target_only.status_code==200
    assert '/inside' in target_only.text and '/outside' not in target_only.text


@pytest.mark.skipif(TestClient is None,reason='FastAPI TestClient unavailable')
def test_analysis_rule_can_be_removed_and_history_returns_to_inbox(tmp_path,monkeypatch):
    key,ws=setup_project(tmp_path,monkeypatch)
    client=TestClient(negro_web.create_app('example.test',ws))
    a=client.post('/api/ingest/http',json=payload('third.test','/a')).json()
    b=client.post('/api/ingest/http',json=payload('third.test','/b')).json()
    page=client.get(f'/t/{key}/workbench',params={'event':a['capture_event_id'],'hide_static':0})
    csrf=re.search(r'data-csrf="([^"]+)"',page.text).group(1)
    assigned=client.post(f'/api/t/{key}/workbench/analysis-scope',json={'csrf':csrf,'event_id':a['capture_event_id'],'rule_type':'host'})
    assert assigned.status_code==200,assigned.text
    rule_id=int(assigned.json()['rule']['id'])
    assert workbench.get_capture_event(a['capture_event_id'])['target_key']==key
    assert workbench.get_capture_event(b['capture_event_id'])['target_key']==key
    removed=client.post(f'/api/t/{key}/workbench/analysis-scope/remove',json={'csrf':csrf,'rule_id':rule_id,'move_history':True})
    assert removed.status_code==200,removed.text
    assert removed.json()['active_recon_scope_changed'] is False
    assert workbench.get_capture_event(a['capture_event_id'])['target_key']==workbench.INBOX_KEY
    assert workbench.get_capture_event(b['capture_event_id'])['target_key']==workbench.INBOX_KEY
    c=client.post('/api/ingest/http',json=payload('third.test','/c')).json()
    assert c['target_key']==workbench.INBOX_KEY and c['analysis_routed'] is False
    assert 'third.test' not in (core.get_target(key).get('scopes') or [])


@pytest.mark.skipif(TestClient is None,reason='FastAPI TestClient unavailable')
def test_checkpoint_delete_is_visual_only(tmp_path,monkeypatch):
    key,ws=setup_project(tmp_path,monkeypatch)
    client=TestClient(negro_web.create_app('example.test',ws))
    ing=client.post('/api/ingest/http',json=payload('example.test','/keep')).json()
    cp=workbench.create_checkpoint(label='Daily cut',target_hint=key)
    page=client.get(f'/t/{key}/workbench',params={'checkpoint_id':cp['id'],'history':'checkpoint'})
    csrf=re.search(r'data-csrf="([^"]+)"',page.text).group(1)
    deleted=client.post(f'/t/{key}/workbench/checkpoints/{cp["id"]}/delete',data={'csrf':csrf},follow_redirects=False)
    assert deleted.status_code==303
    assert workbench.get_checkpoint(cp['id']) is None
    assert workbench.get_capture_event(ing['capture_event_id']) is not None
