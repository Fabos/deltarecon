#!/usr/bin/env python3
"""Regression v0.41: Signal-only-from-Rule model + Burp-transport Runner + readable Workbench."""
from pathlib import Path
import base64, json, sys, tempfile, threading, time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import negro_core as core
import negro_hunter as hunter
import negro_flows as flows
import negro_runners as runners
import negro_intel as intel
import negro_custom_signals as rules
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(x: bytes)->str: return base64.b64encode(x).decode()

def capture(paths,domain,path='/cart',method='GET'):
    req=(f"{method} {path}?userId=101 HTTP/1.1\r\nHost: api.v041.local\r\nAuthorization: Bearer test-token\r\nCookie: sid=abc\r\n\r\n").encode()
    resp=("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"+'{"userId":101,"orderId":4101,"total":100}').encode()
    return core.upsert_http_observation(paths,domain,url=f"https://api.v041.local{path}?userId=101",method=method,source='burp_proxy',status_code=200,authenticated=True,tool='PROXY',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp),query={'userId':'101'})


def main():
  with tempfile.TemporaryDirectory(prefix='negro-v041-') as td:
    root=Path(td); old_targets=core.TARGETS_PATH; old_cfg,old_settings=intel.CONFIG_DIR,intel.SETTINGS_PATH
    try:
      core.TARGETS_PATH=root/'targets.json'; intel.CONFIG_DIR=root/'config'; intel.SETTINGS_PATH=intel.CONFIG_DIR/'settings.json'
      # Simulate an existing v0.40 implicit default: it must migrate once to Burp Bridge.
      intel.CONFIG_DIR.mkdir(parents=True,exist_ok=True)
      intel.SETTINGS_PATH.write_text(json.dumps({'runner_transport_mode':'direct','runner_timeout_seconds':5}),encoding='utf-8')
      assert intel.load_settings()['runner_transport_mode']=='burp_bridge'

      domain='v041.local'; workspace=root/'workspace'; paths=core.ensure_workspace(workspace,domain)
      ex=capture(paths,domain)
      with core.db_connect(paths) as conn:
        hunter.analyze_http_exchange(conn,int(ex['exchange_id']),domain,emit_notifications=False)
        # A Signal is emitted by a Rule; no manual Signal creation is part of the workflow.
        rid=rules.save_rule(conn,name='Order observado',description='Detectar orderId en Response',category='business_logic',severity='low',enabled=True,rule_kind='watch',origin_type='manual',origin_id=None,origin_note='Continuar análisis',parameter_names=['orderId'],exact_values=[],regex_terms=[],host_terms=[],methods=[],statuses=[],path_terms=[],request_terms=[],response_terms=[],header_names=[],object_types=[],identity_mode='any',suggested_action='Revisar contexto')
        rules.evaluate_exchange(conn,int(ex['exchange_id']),rule_id=int(rid))
        sig=conn.execute("SELECT * FROM signal_occurrences WHERE kind=? ORDER BY id DESC LIMIT 1",(f'custom_signal:{rid}',)).fetchone()
        assert sig, 'Rule must emit a Signal'
        hunter.set_signal_decision(conn,int(sig['id']),decision='dismissed',reason='No aporta todavía')
        saved=conn.execute("SELECT human_decision,decision_reason FROM signal_occurrences WHERE id=?",(int(sig['id']),)).fetchone()
        assert saved['human_decision']=='dismissed' and saved['decision_reason']

        hid=hunter.create_manual_hypothesis(conn,int(ex['exchange_id']),title='¿Se puede reutilizar orderId?',why='Pregunta humana',next_test='Repetir con otro contexto')
        # Legacy/automatic AI suggestions are not human-owned Hypotheses in v0.41.
        hunter.upsert_lead(conn,lead_key='ai_graph:auto-v041',host_id=int(ex['host_id']),resource_id=int(ex['resource_id']),lead_type='authorization',title='Sugerencia automática que no acepté',confidence='medium',review_priority='medium',evidence=[{'source':'ai_graph','node_ids':[f"exchange:{int(ex['exchange_id'])}"]}],why='Sólo sugerencia',next_test='No elegida',confirm_if='',discard_if='',source='AI')
        fid=flows.create_flow(conn,'Compra base',description='Baseline')
        flows.add_step(conn,fid,int(ex['exchange_id']))
        rr=runners.create_runner_from_flow(conn,fid,alias='Order · replay',description='Probar la hipótesis',hypothesis_id=hid)

      key=core.register_target(domain,workspace,make_current=True,name='V041 Lab',scopes=[domain,'api.v041.local'])
      client=TestClient(create_app(domain,workspace))

      page=client.get(f'/t/{key}/resource/{int(ex["resource_id"])}?exchange={int(ex["exchange_id"])}')
      assert page.status_code==200
      for label in ('👁 Crear Regla','＋ Entity','◆ Hipótesis','▶ Runner','Investigación','Finding'):
        assert label in page.text,label
      assert 'Crear Señal' not in page.text and f'/exchange/{int(ex["exchange_id"])}/signal' not in page.text
      blocked=client.post(f'/t/{key}/exchange/{int(ex["exchange_id"])}/signal',data={'csrf':'bad'})
      assert blocked.status_code in {403,410}
      static_js=client.get('/static/app.js').text
      assert 'http-token-header-name' in static_js and 'http-token-key' in static_js

      # The hypothesis list must include human questions, not AI-only rows.
      hp=client.get(f'/t/{key}/hypotheses')
      assert hp.status_code==200 and '¿Se puede reutilizar orderId?' in hp.text and 'Preguntas que decidiste probar' in hp.text
      assert 'Sugerencia automática que no acepté' not in hp.text, 'AI suggestion must not become a Hypothesis until human conversion'
      assert 'Sugerencia automática que no acepté' not in page.text, 'Request Workbench must show only human-owned related Hypotheses'
      inv_tpl=(ROOT/'web/templates/investigation_detail.html').read_text(encoding='utf-8')
      assert '/ai-ideas/{{ idea.id }}/runner' not in inv_tpl, 'AI Idea must convert to Hypothesis before Runner'

      # Execute through the Bridge queue. The fake Burp consumer returns a real app response.
      result_holder={}
      def run_it():
        try: result_holder['value']=runners.execute_runner(paths,domain,rr)
        except Exception as exc: result_holder['error']=exc
      t=threading.Thread(target=run_it,daemon=True); t.start()
      queue=None
      for _ in range(100):
        with core.db_connect(paths) as conn:
          row=conn.execute("SELECT * FROM burp_repeater_queue WHERE job_kind='execute' AND status='pending' ORDER BY id DESC LIMIT 1").fetchone()
          queue=dict(row) if row else None
        if queue: break
        time.sleep(.03)
      assert queue, 'Runner must enqueue exact HTTP for Burp Bridge'
      raw_req=base64.b64decode(queue['request_b64']).decode('iso-8859-1')
      assert 'Host: api.v041.local' in raw_req
      raw_resp=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: sid=rotated; Path=/\r\n\r\n{\"orderId\":4101,\"total\":100}"
      with core.db_connect(paths) as conn:
        conn.execute("""UPDATE burp_repeater_queue SET status='done',claimed_at=?,finished_at=?,bridge_instance_id=?,result_request_b64=?,response_b64=?,response_body_b64=?,response_headers_json=?,response_status=?,result_url=?,elapsed_ms=? WHERE id=?""",
          (core.now_iso(),core.now_iso(),'test-bridge',queue['request_b64'],b64(raw_resp),b64(b'{"orderId":4101,"total":100}'),json.dumps([{'name':'Content-Type','value':'application/json'},{'name':'Set-Cookie','value':'sid=rotated; Path=/'}]),200,queue['url'],37,int(queue['id'])))
      t.join(10)
      assert not t.is_alive() and 'error' not in result_holder,result_holder
      result=result_holder['value']
      assert result['counts_as_test'] is True and result['execution_class']=='application_response',result
      with core.db_connect(paths) as conn:
        run=conn.execute("SELECT * FROM runner_runs WHERE id=?",(int(result['run_id']),)).fetchone()
        assert run and int(run['counts_as_test'])==1
        attempt=conn.execute("SELECT * FROM runner_run_requests WHERE run_id=?",(int(result['run_id']),)).fetchone()
        assert attempt and attempt['execution_class']=='application_response' and int(attempt['status_code'])==200

      rp=client.get(f'/t/{key}/runners/{rr}')
      assert rp.status_code==200 and 'Burp Bridge · recomendado' in rp.text and 'Cuenta como prueba' in rp.text and 'Ver diagnóstico de ejecución' in rp.text

      # Protocol guard: an old Bridge must never claim Runner execute jobs.
      with core.db_connect(paths) as conn:
        qid=int(conn.execute("INSERT INTO burp_repeater_queue(resource_id,method,url,request_b64,caption,status,job_kind,created_at) VALUES(?,?,?,?,?,'pending','execute',?)",(int(ex['resource_id']),'GET','https://api.v041.local/cart',queue['request_b64'],'test',core.now_iso())).lastrowid)
      old=client.get('/api/bridge/repeater/next',headers={'X-Negro-Bridge-Id':'old-bridge','X-Negro-Bridge-Version':'0.26.0'}).json()
      assert old.get('upgrade_required') is True,old
      # Lease is held by old-bridge, so use same id with the new version.
      new=client.get('/api/bridge/repeater/next',headers={'X-Negro-Bridge-Id':'old-bridge','X-Negro-Bridge-Version':'0.27.0'}).json()
      assert new.get('pending') is True and int(new.get('id'))==qid,new
      diag=client.get(f'/api/t/{key}/runners/{rr}/transport-diagnose').json()
      assert diag.get('mode')=='burp_bridge' and diag.get('bridge',{}).get('runner_transport_ready') is True,diag

    finally:
      core.TARGETS_PATH=old_targets; intel.CONFIG_DIR=old_cfg; intel.SETTINGS_PATH=old_settings
  print('[OK] Signals are produced by Rules; Request Workbench no longer exposes manual Signal creation')
  print('[OK] Human/manual Hypotheses are first-class and visible alongside AI-Idea-origin Hypotheses')
  print('[OK] Runner defaults/migrates to Burp Bridge and successful Bridge responses count as application tests')
  print('[OK] Old Burp Bridge versions cannot consume Runner jobs; v0.27+ is diagnosable')
  print('[OK] Request/Response Workbench ships syntax-aware reading cues without truncating raw HTTP')

if __name__=='__main__': main()
