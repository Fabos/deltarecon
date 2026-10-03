#!/usr/bin/env python3
"""Regression for v0.39 Flow Intelligence + contextual Runner."""
from pathlib import Path
import base64, json, sys, tempfile, types
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import requests
import negro_core as core
import negro_hunter as hunter
import negro_flows as flows
import negro_runners as runners
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(x: bytes)->str: return base64.b64encode(x).decode()

def capture(paths,domain,path,method,req_body,resp_body,status=200):
    req=(f"{method} {path} HTTP/1.1\r\nHost: api.runner.local\r\nContent-Type: application/json\r\nCookie: sid=abc\r\n\r\n{req_body}").encode()
    resp=(f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{resp_body}").encode()
    return core.upsert_http_observation(paths,domain,url=f"https://api.runner.local{path}",method=method,source='burp_proxy',status_code=status,authenticated=True,tool='PROXY',request_content_type='application/json',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp),query={})

class FakeResponse:
    def __init__(self,url,method,headers,body):
        self.status_code=200; self.reason='OK'; self.url=url
        self.headers={'Content-Type':'application/json'}
        self.request=types.SimpleNamespace(headers=dict(headers))
        if '/cart' in url and method=='GET': payload={'csrf':'fresh-token','total':100}
        elif '/coupon' in url: payload={'accepted':True,'total':80,'echo':body.decode('iso-8859-1') if isinstance(body,bytes) else str(body)}
        else: payload={'status':'CONFIRMED','orderId':9001}
        self.content=json.dumps(payload).encode(); self.text=self.content.decode()

class FakeSession:
    def __init__(self): self.cookies=requests.cookies.RequestsCookieJar(); self.calls=[]
    def request(self,method,url,headers=None,data=None,allow_redirects=False,timeout=20,verify=True):
        self.calls.append((method,url,headers,data)); return FakeResponse(url,method,headers or {},data or b'')


def main():
    with tempfile.TemporaryDirectory(prefix='negro-v039-') as td:
        root=Path(td); old_targets=core.TARGETS_PATH; core.TARGETS_PATH=root/'targets.json'
        old_session=requests.Session
        try:
            domain='runner.local'; workspace=root/'workspace'; paths=core.ensure_workspace(workspace,domain)
            a=capture(paths,domain,'/cart','GET','', '{"cartId":88,"total":100,"csrf":"old"}')
            b=capture(paths,domain,'/coupon','POST','{"coupon":"BASE","csrf":"old"}', '{"accepted":true,"total":90}')
            c=capture(paths,domain,'/confirm','POST','{"cartId":88,"csrf":"old"}', '{"status":"CONFIRMED","orderId":9001}')
            with core.db_connect(paths) as conn:
                for ex in (a,b,c): hunter.analyze_http_exchange(conn,int(ex['exchange_id']),domain,emit_notifications=False)
                fid=flows.create_flow(conn,'Compra normal',description='Carrito → cupón → confirmar')
                for ex in (a,b,c): flows.add_step(conn,fid,int(ex['exchange_id']))
                idea={
                    'question':'¿Puede reutilizarse el cupón varias veces?','alias':'Cupón · reutilización','category':'replay','priority':'high',
                    'rationale':'El Flow aplica cupón antes de confirmar.','facts':['POST /coupon observado'],'unknowns':['No sabemos si hay límite server-side'],
                    'test_goal':'Repetir /coupon manteniendo el mismo carrito.','confirm_if':'El total sigue disminuyendo.','discard_if':'El segundo uso es rechazado.',
                    'runner':{'description':'Repetir la aplicación de cupón con dos valores.',
                              'step_actions':[{'position':1,'action':'keep','repeat_count':1,'notes':''},{'position':2,'action':'repeat','repeat_count':2,'notes':'replay'},{'position':3,'action':'keep','repeat_count':1,'notes':''}],
                              'variables':[{'target_position':2,'target_name':'coupon','target_value':'BASE','mode':'values','values':['WELCOME10','NEWUSER20'],'source_position':None,'source_name':'','regex_pattern':'','why':'alternar cupones'}],
                              'review_before_run':['Usar cuenta de prueba']}}
                hid=runners.create_hypothesis_from_idea(conn,flow_id=fid,idea=idea)
                rid=runners.create_runner_from_flow(conn,fid,alias=idea['alias'],description=idea['runner']['description'],hypothesis_id=hid,origin='ai_flow',ai_idea=idea,step_actions=idea['runner']['step_actions'],variables=idea['runner']['variables'])
                detail=runners.get_runner(conn,rid)
                assert detail and detail['runner']['alias']=='Cupón · reutilización'
                assert [s['action'] for s in detail['steps']]==['keep','repeat','keep']
                assert detail['steps'][1]['repeat_count']==2
                assert detail['steps'][1]['variables'][0]['values']==['WELCOME10','NEWUSER20']
                payload,evhash=hunter.build_flow_logic_payload(conn,domain,fid)
                assert evhash and 'previous_runners' in payload and 'Cupón · reutilización' in payload
                assert 'Cookie: <redacted>' in payload and 'Cookie: sid=abc' not in payload
                assert 'POST /coupon' in payload

            requests.Session=FakeSession
            result=runners.execute_runner(paths,domain,rid)
            assert result['requests']==4,result
            assert result['result_flow_id']
            with core.db_connect(paths) as conn:
                data=runners.get_runner(conn,rid)
                assert data['runs'] and data['runs'][0]['request_count']==4,data['runs']
                outflow=flows.get_flow(conn,int(result['result_flow_id']))
                assert outflow and len(outflow['steps'])==4
                bodies=[]
                for rr in conn.execute("SELECT e.request_b64 FROM runner_run_requests x JOIN http_exchanges e ON e.id=x.exchange_id WHERE x.run_id=? ORDER BY x.id",(int(result['run_id']),)).fetchall():
                    bodies.append(base64.b64decode(rr['request_b64']).decode('iso-8859-1'))
                assert any('WELCOME10' in x for x in bodies),bodies
                assert any('NEWUSER20' in x for x in bodies),bodies
                payload_after,_=hunter.build_flow_logic_payload(conn,domain,fid)
                assert 'WELCOME10' in payload_after or 'NEWUSER20' in payload_after, 'AI context must include bounded HTTP evidence from prior Runs'
                assert '"outcome":"unreviewed"' in payload_after
                assert 'Cookie: <redacted>' in payload_after and 'Cookie: sid=abc' not in payload_after

            key=core.register_target(domain,workspace,make_current=True,name='Runner Lab',scopes=[domain,'api.runner.local'])
            client=TestClient(create_app(domain,workspace))
            flow_page=client.get(f'/t/{key}/flows/{fid}')
            assert flow_page.status_code==200
            assert 'Explorar lógica de este Flujo' in flow_page.text
            assert 'Cupón · reutilización' in flow_page.text
            runner_page=client.get(f'/t/{key}/runners/{rid}')
            assert runner_page.status_code==200
            assert 'PLAN DEL RUNNER' in runner_page.text and 'EJECUCIÓN EXPLÍCITA' in runner_page.text
            assert 'Variables dinámicas'.lower() in runner_page.text.lower()
            listing=client.get(f'/t/{key}/runners')
            assert listing.status_code==200 and 'Experimentos reproducibles' in listing.text
        finally:
            requests.Session=old_session; core.TARGETS_PATH=old_targets
    print('[OK] Flow Intelligence context includes real sanitized HTTP plus prior Runner memory')
    print('[OK] AI-selected question can become a Hypothesis + Runner draft without executing automatically')
    print('[OK] Runner can keep/omit/repeat Flow steps, cycle parameter values, and feed each result back into Negro')
    print('[OK] every Run produces a result Flow that can be compared with the baseline')

if __name__=='__main__': main()
