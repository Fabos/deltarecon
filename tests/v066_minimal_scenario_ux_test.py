#!/usr/bin/env python3
from pathlib import Path
import base64, tempfile, sys, types, json
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import requests
import negro_core as core
import negro_flows as flows
import negro_runners as runners
import negro_identity as identity
import negro_intel as intel
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(x: bytes)->str: return base64.b64encode(x).decode()

def capture(paths,domain,path,method='GET',body=''):
    req=(f"{method} {path} HTTP/1.1\r\nHost: api.scenario.local\r\nAuthorization: Bearer captured\r\nContent-Type: application/json\r\n\r\n{body}").encode()
    resp=("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true,\"token\":\"abc\"}").encode()
    return core.upsert_http_observation(paths,domain,url=f"https://api.scenario.local{path}",method=method,source='burp_proxy',status_code=200,authenticated=True,tool='PROXY',request_content_type='application/json',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp),query={})

class FakeResponse:
    def __init__(self,url):
        self.status_code=200; self.reason='OK'; self.url=url; self.headers={'Content-Type':'application/json'}
        self.content=b'{"ok":true}'; self.text=self.content.decode()

class FakeSession:
    calls=[]
    def __init__(self): self.cookies=requests.cookies.RequestsCookieJar(); self.trust_env=False
    def request(self,method,url,headers=None,data=None,allow_redirects=False,timeout=20,verify=True):
        FakeSession.calls.append((method,url,dict(headers or {})))
        return FakeResponse(url)


def main():
    with tempfile.TemporaryDirectory(prefix='negro-v050-') as td:
        root=Path(td); old_targets=core.TARGETS_PATH; old_session=requests.Session; old_cfg,old_settings=intel.CONFIG_DIR,intel.SETTINGS_PATH
        try:
            core.TARGETS_PATH=root/'targets.json'; intel.CONFIG_DIR=root/'config'; intel.SETTINGS_PATH=intel.CONFIG_DIR/'settings.json'
            intel.save_settings({'runner_transport_mode':'direct','runner_verify_tls':True,'runner_timeout_seconds':5})
            domain='scenario.local'; ws=root/'ws'; paths=core.ensure_workspace(ws,domain)
            e1=capture(paths,domain,'/login','POST','{"otp":"111111"}')
            e2=capture(paths,domain,'/orders','POST','{"item":"A"}')
            with core.db_connect(paths) as conn:
                identity.init_schema(conn); runners.init_schema(conn)
                now=runners.now_iso()
                ia=int(conn.execute("INSERT INTO identities(name,notes,created_at,updated_at) VALUES('Fabian','',?,?)",(now,now)).lastrowid)
                ib=int(conn.execute("INSERT INTO identities(name,notes,created_at,updated_at) VALUES('Carlos','',?,?)",(now,now)).lastrowid)
                for iid,name,value in ((ia,'Authorization','Bearer jwt-A'),(ib,'Authorization','Bearer jwt-B')):
                    conn.execute("""INSERT INTO auth_materials(identity_id,context_id,material_type,material_name,fingerprint,masked_preview,raw_value,source,first_seen_at,last_seen_at,active,classification)
                                    VALUES(?,NULL,'header',?,?,?,?,?,?,?,1,'auth')""",
                                 (iid,name,f'fp-{iid}',value[:10]+'…',value,'manual',now,now))
                f1=flows.create_flow(conn,'Login')
                s1=flows.add_step(conn,f1,int(e1['exchange_id']))
                f2=flows.create_flow(conn,'Compra')
                s2=flows.add_step(conn,f2,int(e2['exchange_id']))
                rid=runners.create_runner_from_flow(conn,f1,alias='Prueba cruzada',description='Escenario simple',identity_id=ia)
                runners.add_flow_source(conn,rid,f2)
                rd=runners.get_runner(conn,rid)
                assert len(rd['source_flows'])==2,rd['source_flows']
                assert len(rd['steps'])==2,rd['steps']
                second=rd['steps'][1]
                runners.update_runner_step(conn,rid,int(second['id']),action='keep',alias_label='Crear orden como Carlos',role_label='Cliente B',identity_id=ib)
                rd=runners.get_runner(conn,rid)
                assert rd['steps'][1]['alias_label']=='Crear orden como Carlos'
                assert rd['steps'][1]['step_identity_name']=='Carlos'
                assert runners.list_runners(conn,flow_id=f2)[0]['id']==rid

            requests.Session=FakeSession; FakeSession.calls=[]
            result=runners.execute_runner(paths,domain,rid)
            assert result['counts_as_test'] is True,result
            assert len(FakeSession.calls)==2,FakeSession.calls
            assert FakeSession.calls[0][2].get('Authorization')=='Bearer jwt-A',FakeSession.calls
            assert FakeSession.calls[1][2].get('Authorization')=='Bearer jwt-B',FakeSession.calls

            key=core.register_target(domain,ws,make_current=True,name='Scenario Lab',scopes=[domain,'api.scenario.local'])
            client=TestClient(create_app(domain,ws))
            flow_page=client.get(f'/t/{key}/flows/{f1}')
            assert flow_page.status_code==200
            assert 'Crear escenario desde este Flow' in flow_page.text
            assert 'Así funciona el proceso' in flow_page.text
            assert 'Seguir identificador como Objeto de negocio' not in flow_page.text
            assert 'Editar captura y herramientas' in flow_page.text
            listing=client.get(f'/t/{key}/runners')
            assert listing.status_code==200 and 'Pruebas reutilizables' in listing.text and 'Prueba cruzada' in listing.text
            detail=client.get(f'/t/{key}/runners/{rid}')
            assert detail.status_code==200
            assert 'Flows del escenario' in detail.text and 'Login' in detail.text and 'Compra' in detail.text
            assert 'Crear orden como Carlos' in detail.text and 'Carlos' in detail.text
            inspect=client.get(f'/t/{key}/exchange/{int(e1["exchange_id"])}/inspect?flow_id={f1}&flow_step_id={s1}')
            assert inspect.status_code==200
            assert 'Valores dinámicos del Step' in inspect.text
            assert inspect.text.index('Request completa') < inspect.text.index('Valores dinámicos del Step')
        finally:
            requests.Session=old_session; core.TARGETS_PATH=old_targets; intel.CONFIG_DIR=old_cfg; intel.SETTINGS_PATH=old_settings
    print('[OK] Flow detail is minimal and object-tracking noise is removed')
    print('[OK] Scenario can combine multiple Flows without duplicating the Flow objects')
    print('[OK] Scenario Step alias and per-Step Identity override are persisted and executed')
    print('[OK] HTTP is shown before collapsed dynamic-value configuration')

if __name__=='__main__': main()
