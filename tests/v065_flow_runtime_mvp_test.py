#!/usr/bin/env python3
from pathlib import Path
import base64, json, sys, tempfile, types
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import requests
import negro_core as core
import negro_flows as flows
import negro_flow_runtime as runtime
import negro_identity as identity
import negro_intel as intel
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(x: bytes)->str: return base64.b64encode(x).decode()

def capture(paths,domain,path,method,body,response):
    req=(f"{method} {path} HTTP/1.1\r\nHost: api.flow.local\r\nContent-Type: application/json\r\n\r\n{body}").encode()
    resp=(f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{response}").encode()
    return core.upsert_http_observation(paths,domain,url=f"https://api.flow.local{path}",method=method,source='burp_proxy',status_code=200,authenticated=True,tool='PROXY',request_content_type='application/json',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp),query={})

class FakeResponse:
    def __init__(self,url,headers,data):
        self.status_code=200; self.reason='OK'; self.url=url; self.request=types.SimpleNamespace(headers=headers or {})
        self.headers={'Content-Type':'application/json'}
        if url.endswith('/request-otp'):
            payload={'challengeId':'challenge-live'}
        elif url.endswith('/verify'):
            text=data.decode('iso-8859-1') if isinstance(data,bytes) else str(data)
            assert '654321' in text and 'challenge-live' in text, text
            payload={'token':'jwt-A-live','userId':'u1'}
        else:
            payload={'ok':True}
        self.content=json.dumps(payload).encode(); self.text=self.content.decode()

class FakeSession:
    calls=[]
    def __init__(self): self.cookies=requests.cookies.RequestsCookieJar(); self.trust_env=False
    def request(self,method,url,headers=None,data=None,allow_redirects=False,timeout=20,verify=True):
        FakeSession.calls.append((method,url,dict(headers or {}),data.decode('iso-8859-1') if isinstance(data,bytes) else str(data or '')))
        return FakeResponse(url,headers or {},data or b'')


def main():
    with tempfile.TemporaryDirectory(prefix='negro-flow-runtime-') as td:
        root=Path(td); old_targets=core.TARGETS_PATH; old_session=requests.Session; old_cfg,old_set=intel.CONFIG_DIR,intel.SETTINGS_PATH
        try:
            core.TARGETS_PATH=root/'targets.json'; intel.CONFIG_DIR=root/'config'; intel.SETTINGS_PATH=intel.CONFIG_DIR/'settings.json'
            intel.save_settings({'runner_transport_mode':'direct','runner_verify_tls':True,'runner_timeout_seconds':5})
            domain='flow.local'; paths=core.ensure_workspace(root/'ws',domain)
            a=capture(paths,domain,'/request-otp','POST','{"phone":"300"}','{"challengeId":"baseline"}')
            b=capture(paths,domain,'/verify','POST','{"otp":"111111","challenge":"challenge-old"}','{"token":"jwt-old"}')
            c=capture(paths,domain,'/sensitive','POST','{"action":"x"}','{"ok":true}')
            d=capture(paths,domain,'/after','GET','','{"ok":true}')
            p=capture(paths,domain,'/points','GET','','{"ok":true}')
            with core.db_connect(paths) as conn:
                identity.init_schema(conn); runtime.init_schema(conn)
                now=runtime.now_iso()
                cur=conn.execute("INSERT INTO identities(name,notes,created_at,updated_at) VALUES('Identity B','',?,?)",(now,now)); ib=int(cur.lastrowid)
                conn.execute("""INSERT INTO auth_materials(identity_id,context_id,material_type,material_name,fingerprint,masked_preview,raw_value,source,first_seen_at,last_seen_at,active,classification)
                                VALUES(?,NULL,'header','Authorization','fp-b','Bearer jwt…','Bearer jwt-B','manual',?,?,1,'auth')""",(ib,now,now))
                login=flows.create_flow(conn,'Login reusable')
                steps=[]
                for ex in (a,b,c,d): steps.append(flows.add_step(conn,login,int(ex['exchange_id'])))
                otp=runtime.create_variable(conn,login,name='otp',source_type='MANUAL_INPUT',prompt='Código OTP recibido',sensitive=True)
                challenge=runtime.create_variable(conn,login,name='challengeId',source_type='PREVIOUS_RESPONSE',producer_step_id=steps[0],extraction_type='json',extraction_expr='$.challengeId')
                jwt=runtime.create_variable(conn,login,name='jwt',source_type='PREVIOUS_RESPONSE',producer_step_id=steps[1],extraction_type='json',extraction_expr='$.token',sensitive=True,exported=True)
                runtime.add_binding(conn,login,steps[1],challenge,target_value='challenge-old',target_name='challenge',target_location='request_json')
                runtime.add_binding(conn,login,steps[1],otp,target_value='111111',target_name='otp',target_location='request_json')
                runtime.add_binding(conn,login,steps[2],jwt,target_value='OLD-SENSITIVE-TOKEN',target_name='Authorization',target_location='request_header')
                runtime.add_binding(conn,login,steps[3],jwt,target_value='OLD-AFTER-TOKEN',target_name='Authorization',target_location='request_header')
                # captured requests did not contain our placeholders; inject explicit headers into raw baseline for substitution
                for sid, token in ((steps[2],'OLD-SENSITIVE-TOKEN'),(steps[3],'OLD-AFTER-TOKEN')):
                    exid=int(conn.execute('SELECT exchange_id FROM flow_steps WHERE id=?',(sid,)).fetchone()['exchange_id'])
                    row=conn.execute('SELECT request_b64 FROM http_exchanges WHERE id=?',(exid,)).fetchone(); raw=base64.b64decode(row['request_b64']).decode('iso-8859-1')
                    raw=raw.replace('\r\n\r\n','\r\nAuthorization: Bearer '+token+'\r\n\r\n',1)
                    conn.execute('UPDATE http_exchanges SET request_b64=? WHERE id=?',(b64(raw.encode('iso-8859-1')),exid))

                points=flows.create_flow(conn,'Points',description='Depends on login')
                ps=flows.add_step(conn,points,int(p['exchange_id']))
                pv=runtime.create_variable(conn,points,name='jwt',source_type='CONSTANT',default_value='',sensitive=True)
                runtime.add_binding(conn,points,ps,pv,target_value='OLD-POINTS-TOKEN',target_name='Authorization',target_location='request_header')
                exid=int(conn.execute('SELECT exchange_id FROM flow_steps WHERE id=?',(ps,)).fetchone()['exchange_id'])
                row=conn.execute('SELECT request_b64 FROM http_exchanges WHERE id=?',(exid,)).fetchone(); raw=base64.b64decode(row['request_b64']).decode('iso-8859-1')
                raw=raw.replace('\r\n\r\n','\r\nAuthorization: Bearer OLD-POINTS-TOKEN\r\n\r\n',1); conn.execute('UPDATE http_exchanges SET request_b64=? WHERE id=?',(b64(raw.encode('iso-8859-1')),exid))
                runtime.add_prerequisite(conn,points,login)

                rid=runtime.create_run(conn,login)
                runtime.set_override(conn,rid,steps[2],jwt,source_type='IDENTITY',identity_id=ib,identity_field='auth:Authorization')

            requests.Session=FakeSession; FakeSession.calls=[]
            r=runtime.advance_run(paths,domain,rid)
            assert r['run']['status']=='waiting_input',r['run']
            assert r['run']['waiting_variable_name']=='otp'
            with core.db_connect(paths) as conn: runtime.provide_input(conn,rid,otp,'654321')
            r=runtime.advance_run(paths,domain,rid)
            assert r['run']['status']=='completed',r['run']
            assert r['run']['exported_context']['jwt']=='jwt-A-live'
            sensitive=[x for x in FakeSession.calls if x[1].endswith('/sensitive')][0]
            after=[x for x in FakeSession.calls if x[1].endswith('/after')][0]
            assert sensitive[2].get('Authorization')=='Bearer jwt-B',sensitive
            assert after[2].get('Authorization')=='Bearer jwt-A-live',after

            # Prerequisite: parent pauses on child OTP, then receives exported jwt.
            with core.db_connect(paths) as conn: parent=runtime.create_run(conn,points)
            FakeSession.calls=[]
            parent_data=runtime.advance_run(paths,domain,parent)
            assert parent_data['run']['status']=='waiting_prerequisite',parent_data['run']
            child=[x for x in parent_data['children'] if x['status']!='completed'][0]
            child_data=runtime.get_run_by_paths(paths,int(child['id']))
            assert child_data['run']['status']=='waiting_input'
            with core.db_connect(paths) as conn: runtime.provide_input(conn,int(child['id']),otp,'654321')
            child_data=runtime.advance_run(paths,domain,int(child['id']))
            assert child_data['run']['status']=='completed'
            parent_data=runtime.advance_run(paths,domain,parent)
            assert parent_data['run']['status']=='completed',parent_data['run']
            points_call=[x for x in FakeSession.calls if x[1].endswith('/points')][-1]
            assert points_call[2].get('Authorization')=='Bearer jwt-A-live',points_call

            key=core.register_target(domain,root/'ws',make_current=True,name='Flow Runtime Lab',scopes=[domain,'api.flow.local'])
            client=TestClient(create_app(domain,root/'ws'))
            page=client.get(f'/t/{key}/flows/{login}')
            assert page.status_code==200 and 'Así funciona el proceso' in page.text and 'Cómo se ejecuta este Flow' in page.text
            run_page=client.get(f'/t/{key}/flow-runs/{rid}')
            assert run_page.status_code==200 and 'SECURITY OVERRIDES' in run_page.text and 'EVIDENCIA DEL RUN' in run_page.text
        finally:
            requests.Session=old_session; core.TARGETS_PATH=old_targets; intel.CONFIG_DIR=old_cfg; intel.SETTINGS_PATH=old_set
    print('[OK] Flow pauses after producer step for manual OTP and resumes without restarting')
    print('[OK] response extraction chains challenge/JWT into later requests')
    print('[OK] per-step Identity override affects only one step and normal JWT is restored afterwards')
    print('[OK] reusable prerequisite Flow exports JWT into a dependent Flow without duplicating login steps')

if __name__=='__main__': main()
