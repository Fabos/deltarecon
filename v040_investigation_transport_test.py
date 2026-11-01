from pathlib import Path
import base64, json, tempfile, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import requests

import negro_core as core
import negro_flows as flows
import negro_flow_runtime as runtime
import negro_runners as runners
import negro_intel as intel
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()


def capture(paths, domain, path, body, response):
    req=(f"POST {path} HTTP/1.1\r\nHost: api.live.local\r\nContent-Type: application/json\r\n\r\n{body}").encode()
    resp=(f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{response}").encode()
    return core.upsert_http_observation(paths,domain,url=f"https://api.live.local{path}",method='POST',source='burp_proxy',status_code=200,
        authenticated=True,tool='PROXY',request_content_type='application/json',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp),query={})


class FakeResponse:
    def __init__(self,url,data):
        self.status_code=200; self.reason='OK'; self.headers={'Content-Type':'application/json'}
        text=data.decode('iso-8859-1') if isinstance(data,bytes) else str(data or '')
        if url.endswith('/request-otp'):
            payload={'challengeId':'challenge-live'}
        elif url.endswith('/verify'):
            assert '654321' in text, text
            assert 'challenge-live' in text, text
            payload={'token':'jwt-live'}
        else:
            payload={'ok':True}
        self.content=json.dumps(payload).encode(); self.text=self.content.decode()


class FakeSession:
    calls=[]
    def __init__(self):
        self.cookies=requests.cookies.RequestsCookieJar(); self.trust_env=False
    def request(self,method,url,headers=None,data=None,allow_redirects=False,timeout=20,verify=True):
        FakeSession.calls.append((method,url,dict(headers or {}),data.decode('iso-8859-1') if isinstance(data,bytes) else str(data or '')))
        return FakeResponse(url,data or b'')


def test_scenario_inherits_manual_input_and_resumes_live():
    with tempfile.TemporaryDirectory(prefix='negro-v110-') as td:
        root=Path(td); old_targets=core.TARGETS_PATH; old_session=requests.Session; old_cfg,old_set=intel.CONFIG_DIR,intel.SETTINGS_PATH
        try:
            core.TARGETS_PATH=root/'targets.json'; intel.CONFIG_DIR=root/'config'; intel.SETTINGS_PATH=intel.CONFIG_DIR/'settings.json'
            intel.save_settings({'runner_transport_mode':'direct','runner_verify_tls':True,'runner_timeout_seconds':5})
            domain='live.local'; workspace=root/'ws'; paths=core.ensure_workspace(workspace,domain)
            a=capture(paths,domain,'/request-otp','{"phone":"300"}','{"challengeId":"baseline"}')
            b=capture(paths,domain,'/verify','{"otp":"111111","challenge":"challenge-old"}','{"token":"jwt-old"}')
            with core.db_connect(paths) as conn:
                runtime.init_schema(conn)
                flow_id=flows.create_flow(conn,'Login OTP')
                s1=flows.add_step(conn,flow_id,int(a['exchange_id']))
                s2=flows.add_step(conn,flow_id,int(b['exchange_id']))
                challenge=runtime.create_variable(conn,flow_id,name='challengeId',source_type='PREVIOUS_RESPONSE',producer_step_id=s1,extraction_type='json',extraction_expr='$.challengeId')
                otp=runtime.create_variable(conn,flow_id,name='otp',source_type='MANUAL_INPUT',prompt='Código OTP recibido',sensitive=True)
                runtime.add_binding(conn,flow_id,s2,challenge,target_value='challenge-old',target_name='challenge',target_location='request_json')
                runtime.add_binding(conn,flow_id,s2,otp,target_value='111111',target_name='otp',target_location='request_json')
                scenario_id=runners.create_runner_from_flow(conn,flow_id,alias='Login OTP alterado',description='Debe heredar runtime')
                run_id=runners.create_runner_run(conn,scenario_id)

            requests.Session=FakeSession; FakeSession.calls=[]
            paused=runners.execute_runner(paths,domain,scenario_id,run_id=run_id)
            assert paused['status']=='waiting_input', paused
            assert len(FakeSession.calls)==1 and FakeSession.calls[0][1].endswith('/request-otp')
            with core.db_connect(paths) as conn:
                live=runners.scenario_live_data(conn,scenario_id,run_id)
                assert live['run']['status']=='waiting_input'
                assert live['run']['waiting_prompt']=='Código OTP recibido'
                assert len(live['attempts'])==1
            key=core.register_target(domain,workspace,make_current=True,name='Live Scenario',scopes=[domain,'api.live.local'])
            client=TestClient(create_app(domain,workspace))
            waiting_page=client.get(f'/t/{key}/runners/{scenario_id}?run={run_id}')
            assert waiting_page.status_code==200 and 'INPUT REQUERIDO' in waiting_page.text and 'Código OTP recibido' in waiting_page.text
            waiting_api=client.get(f'/api/t/{key}/runners/{scenario_id}/runs/{run_id}/live')
            assert waiting_api.status_code==200 and waiting_api.json()['run']['status']=='waiting_input'
            with core.db_connect(paths) as conn:
                runners.provide_runner_input(conn,scenario_id,run_id,otp,'654321')
            done=runners.execute_runner(paths,domain,scenario_id,run_id=run_id)
            assert done['execution_class']=='application_response', done
            assert len(FakeSession.calls)==2
            assert FakeSession.calls[-1][1].endswith('/verify')
            assert '654321' in FakeSession.calls[-1][3] and 'challenge-live' in FakeSession.calls[-1][3]
            with core.db_connect(paths) as conn:
                live=runners.scenario_live_data(conn,scenario_id,run_id)
                assert live['run']['status']=='completed'
                assert len(live['attempts'])==2

            flow_page=client.get(f'/t/{key}/flows/{flow_id}')
            assert flow_page.status_code==200
            assert '¿Qué quieres probar sobre este Flow?' in flow_page.text
            assert '<details class="panel scenario-create-card"' not in flow_page.text
            scenario_page=client.get(f'/t/{key}/runners/{scenario_id}?run={run_id}')
            assert scenario_page.status_code==200
            assert 'RUNTIME HEREDADO DEL FLOW' in scenario_page.text
            assert 'data-scenario-live' in scenario_page.text
            api=client.get(f'/api/t/{key}/runners/{scenario_id}/runs/{run_id}/live')
            assert api.status_code==200 and api.json()['run']['status']=='completed'

            # Flow reproduction exposes the same live timeline contract.
            with core.db_connect(paths) as conn:
                flow_run_id=runtime.create_run(conn,flow_id)
            flow_paused=runtime.advance_run(paths,domain,flow_run_id)
            assert flow_paused['run']['status']=='waiting_input'
            flow_run_page=client.get(f'/t/{key}/flow-runs/{flow_run_id}')
            assert flow_run_page.status_code==200 and 'data-flow-live' in flow_run_page.text
            flow_live=client.get(f'/api/t/{key}/flow-runs/{flow_run_id}/live')
            assert flow_live.status_code==200 and flow_live.json()['run']['status']=='waiting_input' and len(flow_live.json()['steps'])==1
        finally:
            requests.Session=old_session; core.TARGETS_PATH=old_targets; intel.CONFIG_DIR=old_cfg; intel.SETTINGS_PATH=old_set
