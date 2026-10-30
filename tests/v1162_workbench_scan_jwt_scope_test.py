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


def test_scanability_contract_prioritizes_host_url_status():
    tpl=(ROOT/'web/templates/http_workbench.html').read_text(encoding='utf-8')
    css=(ROOT/'web/static/style.css').read_text(encoding='utf-8')
    js=(ROOT/'web/static/app.js').read_text(encoding='utf-8')
    assert '<span>Host</span>' in tpl and 'URL / parámetros</span><span>Status</span><span>Contexto</span>' in tpl
    assert 'minmax(170px,.95fr) minmax(380px,2.8fr) 58px' in css
    assert 'wb-row-host' in js and 'wb-row-endpoint' in js and 'wb-status' in js


def test_jwt_claims_are_serialized_and_interactive():
    wb=(ROOT/'negro_workbench.py').read_text(encoding='utf-8')
    js=(ROOT/'web/static/app.js').read_text(encoding='utf-8')
    assert '"jwt_claims": [' in wb
    assert 'ensureJwtClaimCandidate' in js
    assert 'data-jwt-claim-field-index' in js
    assert 'data-jwt-claim-value-index' in js
    assert 'openJwtClaimSemantic' in js


def test_analysis_scope_rules_are_separate_from_active_target_scopes(tmp_path,monkeypatch):
    key,_=setup_project(tmp_path,monkeypatch)
    before=list(core.get_target(key).get('scopes') or [])
    rule=workbench.add_project_rule(key,rule_type='host',hostname='third.test',source_event_id=1)
    assert rule['target_key']==key and rule['hostname']=='third.test'
    assert workbench.match_project_rule('third.test','GET','/x')['target_key']==key
    assert list(core.get_target(key).get('scopes') or [])==before
    workbench.add_project_rule(key,rule_type='endpoint',hostname='api.other.test',method='POST',path='/orders')
    assert workbench.match_project_rule('api.other.test','POST','/orders')['rule_type']=='endpoint'
    assert workbench.match_project_rule('api.other.test','GET','/orders') is None


@pytest.mark.skipif(TestClient is None,reason='FastAPI TestClient unavailable')
def test_assign_host_backfills_inbox_and_future_traffic_routes_passively(tmp_path,monkeypatch):
    key,ws=setup_project(tmp_path,monkeypatch)
    client=TestClient(negro_web.create_app('example.test',ws))
    def payload(path,method='GET'):
        req=f'{method} {path} HTTP/1.1\r\nHost: third.test\r\n\r\n'.encode()
        resp=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}'
        return {'url':f'https://third.test{path}','method':method,'tool':'PROXY','status_code':200,'request_b64':b64(req),'response_b64':b64(resp),'burp_in_scope':False}
    a=client.post('/api/ingest/http',json=payload('/a')).json()
    b=client.post('/api/ingest/http',json=payload('/b')).json()
    assert a['target_key']==workbench.INBOX_KEY and b['target_key']==workbench.INBOX_KEY
    page=client.get(f'/t/{key}/workbench',params={'event':a['capture_event_id'],'hide_static':0})
    csrf=re.search(r'data-csrf="([^"]+)"',page.text).group(1)
    moved=client.post(f'/api/t/{key}/workbench/analysis-scope',json={'csrf':csrf,'event_id':a['capture_event_id'],'rule_type':'host'})
    assert moved.status_code==200,moved.text
    body=moved.json(); assert body['moved_events']>=2 and body['active_recon_scope_changed'] is False
    project_rows=workbench.list_traffic(target=key,hide_static=False,limit=50)['rows']
    assert {'/a','/b'} <= {r['path'] for r in project_rows}
    c=client.post('/api/ingest/http',json=payload('/c')).json()
    assert c['target_key']==key and c['analysis_routed'] is True and c['unassigned'] is False
    assert 'third.test' not in (core.get_target(key).get('scopes') or [])


@pytest.mark.skipif(TestClient is None,reason='FastAPI TestClient unavailable')
def test_jwt_claim_metadata_reaches_workbench_detail(tmp_path,monkeypatch):
    key,ws=setup_project(tmp_path,monkeypatch)
    client=TestClient(negro_web.create_app('example.test',ws))
    import json
    enc=lambda obj: base64.urlsafe_b64encode(json.dumps(obj,separators=(',',':')).encode()).decode().rstrip('=')
    token=f"{enc({'alg':'none','typ':'JWT'})}.{enc({'sub':'USR-7','role':'buyer'})}.sig"
    req=f'GET /me HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {token}\r\n\r\n'.encode()
    resp=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}'
    ing=client.post('/api/ingest/http',json={'url':'https://example.test/me','method':'GET','tool':'PROXY','status_code':200,'request_b64':b64(req),'response_b64':b64(resp),'burp_in_scope':True}).json()
    detail=client.get(f'/api/t/{key}/workbench/detail',params={'event_id':ing['capture_event_id']}).json()
    jwt=next(v for v in detail['values'] if v['detected_type']=='JWT')
    claims={c['key']:c for c in jwt['jwt_claims']}
    assert claims['sub']['value']=='USR-7' and claims['sub']['default_classification']=='resolver'
    assert claims['role']['default_classification']=='context'
    assert '#jwt:sub' in claims['sub']['location']

    page=client.get(f'/t/{key}/workbench',params={'event':ing['capture_event_id'],'hide_static':0})
    csrf=re.search(r'data-csrf="([^"]+)"',page.text).group(1)
    exid=int(detail['exchange']['id'])
    taught=client.post(f'/t/{key}/exchange/{exid}/field-semantics',data={'csrf':csrf,'key':'jwt.sub','classification':'resolver','object_type':'','note':''})
    assert taught.status_code==200 and taught.json()['ok'] is True

    token2=f"{enc({'alg':'none','typ':'JWT'})}.{enc({'sub':'USR-8','role':'buyer'})}.sig2"
    req2=f'GET /me HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {token2}\r\n\r\n'.encode()
    ing2=client.post('/api/ingest/http',json={'url':'https://example.test/me','method':'GET','tool':'PROXY','status_code':200,'request_b64':b64(req2),'response_b64':b64(resp),'burp_in_scope':True}).json()
    detail2=client.get(f'/api/t/{key}/workbench/detail',params={'event_id':ing2['capture_event_id']}).json()
    jwt2=next(v for v in detail2['values'] if v['detected_type']=='JWT')
    sub2=next(c for c in jwt2['jwt_claims'] if c['key']=='sub')
    assert sub2['field_semantic']['classification']=='resolver'
    assert sub2['default_classification']=='resolver'
