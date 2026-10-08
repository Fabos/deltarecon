#!/usr/bin/env python3
from pathlib import Path
import base64, json, sys, tempfile, types
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import requests
import negro_core as core
import negro_flows as flows
import negro_runners as runners
import negro_intel as intel
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(x: bytes)->str: return base64.b64encode(x).decode()

def capture(paths,domain):
    req=("POST /orders/A-1 HTTP/1.1\r\nHost: api.scenario.local\r\nContent-Type: application/json\r\nX-Actor: A\r\n\r\n"
         '{"orderId":"A-1","action":"read"}').encode()
    resp=("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
          '{"actor":"A","orderId":"A-1","allowed":true}').encode()
    return core.upsert_http_observation(paths,domain,url='https://api.scenario.local/orders/A-1',method='POST',source='burp_proxy',status_code=200,
        authenticated=True,tool='PROXY',request_content_type='application/json',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp),query={})

class FakeResponse:
    def __init__(self,headers,data):
        self.status_code=200; self.reason='OK'; self.headers={'Content-Type':'application/json'}
        text=data.decode('iso-8859-1') if isinstance(data,bytes) else str(data or '')
        try: body=json.loads(text or '{}')
        except Exception: body={}
        payload={'actor':(headers or {}).get('X-Actor','A'),'orderId':body.get('orderId'),'mode':body.get('mode','normal'),'allowed':True}
        self.content=json.dumps(payload).encode(); self.text=self.content.decode()

class FakeSession:
    calls=[]
    def __init__(self): self.cookies=requests.cookies.RequestsCookieJar(); self.trust_env=False
    def request(self,method,url,headers=None,data=None,allow_redirects=False,timeout=20,verify=True):
        FakeSession.calls.append((method,url,dict(headers or {}),data.decode('iso-8859-1') if isinstance(data,bytes) else str(data or '')))
        return FakeResponse(headers or {},data or b'')


def main():
    with tempfile.TemporaryDirectory(prefix='negro-v066-') as td:
        root=Path(td); old_targets=core.TARGETS_PATH; old_session=requests.Session; old_cfg,old_set=intel.CONFIG_DIR,intel.SETTINGS_PATH
        try:
            core.TARGETS_PATH=root/'targets.json'; intel.CONFIG_DIR=root/'config'; intel.SETTINGS_PATH=intel.CONFIG_DIR/'settings.json'
            intel.save_settings({'runner_transport_mode':'direct','runner_verify_tls':True,'runner_timeout_seconds':5})
            domain='scenario.local'; workspace=root/'ws'; paths=core.ensure_workspace(workspace,domain)
            ex=capture(paths,domain)
            with core.db_connect(paths) as conn:
                fid=flows.create_flow(conn,'Order read')
                fsid=flows.add_step(conn,fid,int(ex['exchange_id']))
                rid=runners.create_runner_from_flow(conn,fid,alias='Cross actor order',description='Scenario lab')
                runners.update_runner(conn,rid,alias='Cross actor order',description='Scenario lab',identity_id=None,target_flow_step_id=fsid)
                data=runners.get_runner(conn,rid); rsid=int(data['steps'][0]['id'])
                preview=runners.scenario_step_preview(conn,rid,rsid)
                assert 'X-Actor: A' in preview['preview_raw']
            requests.Session=FakeSession; FakeSession.calls=[]
            run1=runners.execute_runner(paths,domain,rid)
            with core.db_connect(paths) as conn:
                runners.set_run_baseline(conn,rid,int(run1['run_id']))
                data=runners.get_runner(conn,rid); rsid=int(data['steps'][0]['id'])
                runners.add_step_patch(conn,rid,rsid,location='header',operation='set',key_name='X-Actor',value='B')
                runners.add_step_patch(conn,rid,rsid,location='json',operation='set',key_name='mode',value='"cross"')
                preview=runners.scenario_step_preview(conn,rid,rsid)
                assert 'X-Actor: B' in preview['preview_raw'] and '"mode":"cross"' in preview['preview_raw'],preview
            run2=runners.execute_runner(paths,domain,rid)
            assert FakeSession.calls[-1][2].get('X-Actor')=='B',FakeSession.calls[-1]
            assert '"mode":"cross"' in FakeSession.calls[-1][3]
            with core.db_connect(paths) as conn:
                cmp=runners.compare_runner_runs(conn,int(run1['run_id']),int(run2['run_id']))
                assert cmp['smart'] is not None
                assert cmp['patch_changes'],cmp
                assert any(x.get('kind')=='added' for x in cmp['patch_changes'])
                d=runners.get_runner(conn,rid)
                assert d['runs'][1]['is_baseline']==1 or any(x['is_baseline'] for x in d['runs'])

            key=core.register_target(domain,workspace,make_current=True,name='Scenario Lab',scopes=[domain,'api.scenario.local'])
            client=TestClient(create_app(domain,workspace))
            page=client.get(f'/t/{key}/runners/{rid}')
            assert page.status_code==200 and 'Editar HTTP' in page.text and 'Comparar con baseline' in page.text
            editor=client.get(f'/t/{key}/runners/{rid}/steps/{rsid}/http')
            assert editor.status_code==200 and 'HTTP del Escenario' in editor.text and 'X-Actor: B' in editor.text
            compare=client.get(f'/t/{key}/runners/runs/compare?a={run1["run_id"]}&b={run2["run_id"]}')
            assert compare.status_code==200 and 'Baseline vs prueba' in compare.text and 'SMART COMPARE' in compare.text
        finally:
            requests.Session=old_session; core.TARGETS_PATH=old_targets; intel.CONFIG_DIR=old_cfg; intel.SETTINGS_PATH=old_set
    print('[OK] Scenario HTTP mutations stay outside the source Flow and affect execution only')
    print('[OK] a Run can be pinned as baseline and compared against a later test Run')
    print('[OK] Run Compare reuses Smart Compare on canonical target-step evidence')

if __name__=='__main__': main()
