from __future__ import annotations

import base64
from pathlib import Path
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_web

try:
    from fastapi.testclient import TestClient
except Exception:
    TestClient=None


def b64(v: bytes)->str:
    return base64.b64encode(v).decode('ascii')


def setup_project(tmp_path,monkeypatch):
    monkeypatch.setattr(core,'CONFIG_PATH',tmp_path/'config.json')
    monkeypatch.setattr(core,'TARGETS_PATH',tmp_path/'targets.json')
    monkeypatch.setenv('NEGRO_TRAFFIC_WORKSPACE',str(tmp_path/'traffic'))
    ws=tmp_path/'workspace'
    key=core.register_target('instant.test',ws,make_current=True,name='Instant',scopes=['instant.test'])
    core.ensure_workspace(ws,'instant.test',scopes=['instant.test'],project_name='Instant')
    return key,ws


def payload(i:int):
    req=f'GET /api/{i} HTTP/1.1\r\nHost: instant.test\r\nAccept: application/json\r\n\r\n'.encode()
    resp=f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{"n":{i}}}'.encode()
    return {'url':f'https://instant.test/api/{i}','method':'GET','tool':'PROXY','status_code':200,'request_b64':b64(req),'response_b64':b64(resp),'response_content_type':'application/json','burp_in_scope':True}


@pytest.mark.skipif(TestClient is None,reason='FastAPI TestClient unavailable')
def test_preview_api_returns_raw_http_without_full_context(tmp_path,monkeypatch):
    key,ws=setup_project(tmp_path,monkeypatch)
    client=TestClient(negro_web.create_app('instant.test',ws))
    ids=[]
    for i in range(3):
        r=client.post('/api/ingest/http',json=payload(i)); assert r.status_code==200,r.text
        ids.append(int(r.json()['capture_event_id']))
    r=client.get(f'/api/t/{key}/workbench/previews',params={'event_ids':','.join(map(str,ids))})
    assert r.status_code==200,r.text
    items=r.json()['items']
    assert len(items)==3
    assert 'GET /api/1 HTTP/1.1' in items[1]['request_text']
    assert '{"n":1}' in items[1]['response_text']
    assert items[1]['exchange']['status_code']==200


@pytest.mark.skipif(TestClient is None,reason='FastAPI TestClient unavailable')
def test_live_events_ship_preview_for_instant_first_click(tmp_path,monkeypatch):
    key,ws=setup_project(tmp_path,monkeypatch)
    client=TestClient(negro_web.create_app('instant.test',ws))
    r=client.post('/api/ingest/http',json=payload(7)); assert r.status_code==200
    eid=int(r.json()['capture_event_id'])
    live=client.get(f'/api/t/{key}/workbench/events',params={'after_event_id':0,'visibility':'focus','hide_static':0})
    assert live.status_code==200,live.text
    row=next(x for x in live.json()['rows'] if int(x['id'])==eid)
    assert row['preview']['event_id']==eid
    assert 'GET /api/7 HTTP/1.1' in row['preview']['request_text']


@pytest.mark.skipif(TestClient is None,reason='FastAPI TestClient unavailable')
def test_initial_page_embeds_neighbor_preview_cache(tmp_path,monkeypatch):
    key,ws=setup_project(tmp_path,monkeypatch)
    client=TestClient(negro_web.create_app('instant.test',ws))
    ids=[]
    for i in range(4):
        r=client.post('/api/ingest/http',json=payload(i)); ids.append(int(r.json()['capture_event_id']))
    page=client.get(f'/t/{key}/workbench',params={'event':ids[1]})
    assert page.status_code==200,page.text
    assert 'data-workbench-previews' in page.text
    assert 'GET /api/0 HTTP/1.1' in page.text
    assert 'GET /api/2 HTTP/1.1' in page.text


def test_browser_uses_preview_before_full_detail_and_prefetches_neighbors():
    js=(ROOT/'web/static/app.js').read_text(encoding='utf-8')
    tpl=(ROOT/'web/templates/http_workbench.html').read_text(encoding='utf-8')
    assert 'const previewCache=new Map()' in js
    assert 'if(cached)renderPreview(cached);else{root.classList.add(\'is-loading\');fetchPreviewBatch([eventId]' in js
    assert 'fastPaint(\'request\',raw.request);fastPaint(\'response\',raw.response)' in js
    assert 'prefetchAround(eventId)' in js
    assert "list?.addEventListener('pointerover'" in js
    assert 'PREVIEW_CACHE_MAX=96' in js
    assert 'data-preview-url=' in tpl
