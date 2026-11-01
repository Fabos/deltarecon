from __future__ import annotations
import base64, re, sys
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import negro_core as core, negro_flows as flows, negro_flow_runtime as runtime, negro_web
try:
    from fastapi.testclient import TestClient
except Exception:
    TestClient=None

def b64(x:bytes)->str:return base64.b64encode(x).decode()
def setup(tmp_path,monkeypatch):
    monkeypatch.setattr(core,'CONFIG_PATH',tmp_path/'config.json'); monkeypatch.setattr(core,'TARGETS_PATH',tmp_path/'targets.json'); monkeypatch.setenv('NEGRO_TRAFFIC_WORKSPACE',str(tmp_path/'traffic'))
    ws=tmp_path/'ws'; key=core.register_target('api.test',ws,make_current=True,name='Example',scopes=['api.test']); paths=core.ensure_workspace(ws,'api.test',scopes=['api.test'],project_name='Example'); return key,ws,paths
def obs(paths,path,body):
    req=(f'POST {path} HTTP/1.1\r\nHost: api.test\r\nContent-Type: application/json\r\n\r\n{body}').encode(); resp=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}'
    return core.upsert_http_observation(paths,'api.test',url='https://api.test'+path,method='POST',source='burp_proxy',tool='PROXY',request_b64=b64(req),response_b64=b64(resp),status_code=200,request_content_type='application/json',response_content_type='application/json',burp_in_scope=True)

def test_workbench_has_inventory_reading_controls():
    tpl=(ROOT/'web/templates/http_workbench.html').read_text()
    css=(ROOT/'web/static/style.css').read_text()
    js=(ROOT/'web/static/app.js').read_text()
    assert 'data-http-fullscreen' in tpl
    assert 'data-wb-wrap="request"' in tpl and 'data-wb-wrap="response"' in tpl
    assert 'Líneas exactas' in tpl
    assert 'data-traffic-toggle' in tpl
    assert '.wb-shell.traffic-hidden' in css
    assert 'toggleFullscreen' in js and 'setExactLines' in js

def test_flow_ui_exposes_manual_input_reuse_and_direct_injection():
    tpl=(ROOT/'web/templates/http_inspector.html').read_text()
    assert 'También reutilizar en Step' in tpl
    assert 'Inyectar un valor al ejecutar' in tpl
    assert 'data-manual-forward-form' in tpl
    assert 'bind_current' in tpl

@pytest.mark.skipif(TestClient is None,reason='FastAPI TestClient unavailable')
def test_manual_input_can_bind_current_and_next_or_next_only(tmp_path,monkeypatch):
    key,ws,paths=setup(tmp_path,monkeypatch)
    a=obs(paths,'/one','{"document":"OLD-A"}'); b=obs(paths,'/two','{"document2":"OLD-B","injected":"OLD-I"}')
    with core.db_connect(paths) as conn:
        fid=flows.create_flow(conn,'Manual reuse'); sid1=flows.add_step(conn,fid,int(a['exchange_id'])); sid2=flows.add_step(conn,fid,int(b['exchange_id']))
    client=TestClient(negro_web.create_app('api.test',ws))
    page=client.get(f'/t/{key}/exchange/{int(a["exchange_id"])}/inspect?flow_id={fid}&flow_step_id={sid1}')
    csrf=re.search(r'name="csrf" value="([^"]+)"',page.text).group(1)
    r=client.post(f'/t/{key}/flows/{fid}/runtime/quick-bind',data={
        'csrf':csrf,'exchange_id':int(a['exchange_id']),'step_id':sid1,'name':'documento','prompt':'Documento',
        'bind_current':'1','target_value':'OLD-A','target_name':'document','target_location':'request_json:$.document',
        'forward_step_id':sid2,'forward_target_value':'OLD-B','forward_target_name':'document2','forward_target_location':'request_json:$.document2'
    },follow_redirects=False)
    assert r.status_code==303
    r2=client.post(f'/t/{key}/flows/{fid}/runtime/quick-bind',data={
        'csrf':csrf,'exchange_id':int(a['exchange_id']),'step_id':sid1,'name':'codigoPrueba','prompt':'Código de prueba',
        'bind_current':'0','forward_step_id':sid2,'forward_target_value':'OLD-I','forward_target_name':'injected','forward_target_location':'request_json:$.injected'
    },follow_redirects=False)
    assert r2.status_code==303
    with core.db_connect(paths) as conn:
        data=runtime.flow_runtime_data(conn,fid)
        doc=next(v for v in data['variables'] if v['name']=='documento')
        inj=next(v for v in data['variables'] if v['name']=='codigoPrueba')
        assert doc['source_type']=='MANUAL_INPUT' and doc['consumers']==[1,2]
        assert inj['source_type']=='MANUAL_INPUT' and inj['consumers']==[2]
