#!/usr/bin/env python3
"""Regression for v0.40: Request actions, Investigation workspace, AI Idea memory and transport-aware Runs."""
from pathlib import Path
import base64, json, sys, tempfile, types
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import requests
import negro_core as core
import negro_hunter as hunter
import negro_flows as flows
import negro_objects as objects
import negro_runners as runners
import negro_intel as intel
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(x: bytes)->str: return base64.b64encode(x).decode()

def capture(paths,domain,path='/company/users',method='POST'):
    body='{"accountId":881,"username":"alice","orderId":4101,"email":"alice@example.test"}'
    req=(f"{method} {path}?userId=101 HTTP/1.1\r\nHost: api.v040.local\r\nContent-Type: application/json\r\nCookie: sid=abc\r\n\r\n{body}").encode()
    resp=("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"+'{"businessKey":"BK-928812","userId":101,"email":"alice@example.test"}').encode()
    return core.upsert_http_observation(paths,domain,url=f"https://api.v040.local{path}?userId=101",method=method,source='burp_proxy',status_code=200,authenticated=True,tool='PROXY',request_content_type='application/json',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp),query={'userId':'101'})

class GatewayResponse:
    def __init__(self,url,method,headers):
        self.status_code=504; self.reason='Gateway Timeout'; self.url=url
        self.headers={'Content-Type':'text/html','Server':'gateway'}
        self.request=types.SimpleNamespace(headers=dict(headers or {}))
        self.text=f'<html><h1>504 Gateway Timeout</h1><p>Error connecting to {url}</p></html>'
        self.content=self.text.encode()

class GatewaySession:
    def __init__(self):
        self.cookies=requests.cookies.RequestsCookieJar(); self.calls=[]; self.proxies={}; self.trust_env=False
    def request(self,method,url,headers=None,data=None,allow_redirects=False,timeout=20,verify=True):
        self.calls.append((method,url)); return GatewayResponse(url,method,headers or {})


def main():
  with tempfile.TemporaryDirectory(prefix='negro-v040-') as td:
    root=Path(td); old_targets=core.TARGETS_PATH; old_session=requests.Session
    old_cfg_dir,old_settings=intel.CONFIG_DIR,intel.SETTINGS_PATH
    try:
      core.TARGETS_PATH=root/'targets.json'; intel.CONFIG_DIR=root/'config'; intel.SETTINGS_PATH=intel.CONFIG_DIR/'settings.json'
      intel.save_settings({'runner_transport_mode':'direct','runner_verify_tls':True,'runner_timeout_seconds':5})
      domain='v040.local'; workspace=root/'workspace'; paths=core.ensure_workspace(workspace,domain)
      ex=capture(paths,domain)
      with core.db_connect(paths) as conn:
        hunter.analyze_http_exchange(conn,int(ex['exchange_id']),domain,emit_notifications=False)
        candidates=objects.entity_candidates_for_exchange(conn,int(ex['exchange_id']))
        names={str(c['normalized_name']).lower() for c in candidates}
        assert {'userid','accountid','orderid'} & names, names
        cand=next(c for c in candidates if str(c['normalized_name']).lower() in {'userid','orderid','accountid','username','email'})
        entity=objects.track_observation(conn,int(cand['id']),str(cand['suggested_type']),allow_manual=True)
        obs=conn.execute("SELECT exchange_id FROM business_object_observations WHERE business_object_id=? ORDER BY id DESC LIMIT 1",(int(entity['business_object_id']),)).fetchone()
        assert obs and int(obs['exchange_id'])==int(ex['exchange_id'])

        sid=hunter.create_manual_signal(conn,int(ex['exchange_id']),title='businessKey observada',note='Evidencia para continuar la investigación')
        before=conn.execute('SELECT COUNT(*) c FROM signal_occurrences WHERE id=?',(sid,)).fetchone()['c']
        hunter.set_signal_decision(conn,sid,decision='dismissed',reason='No aporta con la evidencia actual')
        row=conn.execute('SELECT * FROM signal_occurrences WHERE id=?',(sid,)).fetchone()
        assert before==1 and row and row['human_decision']=='dismissed' and row['decision_reason']

        hid=hunter.create_manual_hypothesis(conn,int(ex['exchange_id']),title='¿businessKey controla acceso?',why='La Request la necesita',next_test='Cambiar businessKey entre cuentas')
        iid=hunter.create_investigation(conn,title='Company users access',summary='Investigar relación entre sesión y businessKey',source_hypothesis_id=hid)
        hunter.link_investigation_entity(conn,iid,'exchange',int(ex['exchange_id']),'evidence')
        hunter.link_investigation_entity(conn,iid,'signal',sid,'evidence')
        hunter.link_investigation_entity(conn,iid,'business_object',int(entity['business_object_id']),'context')

        fid=flows.create_flow(conn,'Company users flow',description='Baseline')
        flows.add_step(conn,fid,int(ex['exchange_id']))
        hunter.link_investigation_entity(conn,iid,'flow',fid,'context')
        result={'summary':'Preguntas sobre el control de acceso','ideas':[{
          'question':'¿businessKey puede reutilizarse entre cuentas?','alias':'businessKey · cross-account','category':'access_control','priority':'high',
          'rationale':'La key aparece junto a accountId.','facts':['businessKey observada'],'unknowns':['ownership'],
          'test_goal':'Reutilizar key bajo otra identidad','confirm_if':'Respuesta válida','discard_if':'403','runner':{'description':'Reusar key','step_actions':[],'variables':[]}
        }]}
        p1=hunter.persist_flow_ai_batch(conn,flow_id=fid,model='test-model',evidence_hash='hash1',result=result,context_snapshot='{}')
        batch=hunter.list_ai_idea_batches(conn,flow_id=fid)[0]; idea=batch['ideas'][0]
        assert int(batch['investigation_id'])==iid and idea['status']=='new'
        hunter.update_ai_idea_state(conn,int(idea['id']),status='dismissed',reason='Ya comprobé ownership por otra vía')
        p2=hunter.persist_flow_ai_batch(conn,flow_id=fid,model='test-model',evidence_hash='hash2',result=result,context_snapshot='{"new":true}')
        newest=hunter.list_ai_idea_batches(conn,flow_id=fid)[0]['ideas'][0]
        assert newest['reconsidered_from_idea_id']==idea['id']

        rid=runners.create_runner_from_flow(conn,fid,alias='businessKey · replay',description='Prueba de transporte',hypothesis_id=hid,investigation_id=iid)

      # A generic gateway 504 is transport evidence and must never become canonical application evidence.
      requests.Session=GatewaySession
      before_exchanges=0
      with core.db_connect(paths) as conn: before_exchanges=conn.execute('SELECT COUNT(*) c FROM http_exchanges').fetchone()['c']
      run_result=runners.execute_runner(paths,domain,rid)
      assert run_result['counts_as_test'] is False and run_result['execution_class']=='transport_error',run_result
      with core.db_connect(paths) as conn:
        after=conn.execute('SELECT COUNT(*) c FROM http_exchanges').fetchone()['c']
        assert after==before_exchanges,(before_exchanges,after)
        run=conn.execute('SELECT * FROM runner_runs WHERE id=?',(int(run_result['run_id']),)).fetchone()
        assert run and not run['counts_as_test'] and run['execution_class']=='transport_error'
        try:
          runners.update_run_outcome(conn,int(run['id']),'negative')
          raise AssertionError('invalid transport run must not be markable negative')
        except ValueError: pass
        payload,_=hunter.build_flow_logic_payload(conn,domain,fid)
        assert '"counts_as_test":false' in payload and '"outcome":"not_counted"' in payload

      key=core.register_target(domain,workspace,make_current=True,name='V040 Lab',scopes=[domain,'api.v040.local'])
      client=TestClient(create_app(domain,workspace))
      page=client.get(f'/t/{key}/resource/{int(ex["resource_id"])}?exchange={int(ex["exchange_id"])}')
      assert page.status_code==200,page.text[:500]
      for label in ('＋ Entity','⚡ Señal','◆ Hypothesis','▶ Runner','Investigation','Finding'):
        assert label in page.text,label
      assert 'REQUEST COMPLETA' in page.text and 'RESPONSE COMPLETA' in page.text
      sig=client.get(f'/t/{key}/signals/{sid}'); assert sig.status_code==200 and 'DECISIÓN HUMANA' in sig.text and 'Descartar' in sig.text
      inv=client.get(f'/t/{key}/investigations/{iid}'); assert inv.status_code==200
      for heading in ('CONTEXTO CONOCIDO','QUÉ ESTOY INVESTIGANDO','PRUEBAS REALIZADAS','IDEAS DE LA IA','DECISIONES FINALES'):
        assert heading in inv.text,heading
      flow=client.get(f'/t/{key}/flows/{fid}'); assert flow.status_code==200 and 'HISTORIAL PERSISTENTE' in flow.text and 'Exploración IA #' in flow.text
      runner=client.get(f'/t/{key}/runners/{rid}'); assert runner.status_code==200
      assert 'Error de transporte' in runner.text and 'No cuenta como prueba' in runner.text and 'Reintentar' in runner.text and 'TRANSPORTE' in runner.text
    finally:
      requests.Session=old_session; core.TARGETS_PATH=old_targets; intel.CONFIG_DIR=old_cfg_dir; intel.SETTINGS_PATH=old_settings
  print('[OK] Request Workbench exposes Entity/Signal/Hypothesis/Runner/Investigation/Finding actions')
  print('[OK] Signal discard is preserved as human memory, not deletion')
  print('[OK] Investigation workspace separates known context, pursued hypotheses, tests, AI ideas and Findings')
  print('[OK] AI Ideas persist by generation and dismissed ideas can be explicitly reconsidered after new evidence')
  print('[OK] generic gateway 504 is classified as transport failure, excluded from app evidence/coverage, and remains retryable')

if __name__=='__main__': main()
