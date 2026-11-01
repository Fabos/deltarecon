#!/usr/bin/env python3
"""Regression for v0.37 Spanish-first Rules + past/present/future coverage."""
from pathlib import Path
import base64, re, sys, tempfile, time, urllib.parse

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import negro_core as core
import negro_hunter as hunter
import negro_custom_signals as rules
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(x: bytes)->str: return base64.b64encode(x).decode()

def capture(paths,domain,path,body,status=200,method='GET'):
    req=f"{method} {path} HTTP/1.1\r\nHost: api.rules.local\r\n\r\n".encode()
    resp=f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{body}".encode()
    return core.upsert_http_observation(paths,domain,url=f"https://api.rules.local{path}",method=method,source='burp_proxy',status_code=status,authenticated=False,tool='PROXY',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp),query={})


def main():
    with tempfile.TemporaryDirectory(prefix='negro-v037-') as td:
        root=Path(td); old=core.TARGETS_PATH; core.TARGETS_PATH=root/'targets.json'
        try:
            domain='rules.local'; workspace=root/'workspace'; paths=core.ensure_workspace(workspace,domain)
            hist=capture(paths,domain,'/bootstrap','{"businessKey":"BK-HIST-928"}')
            with core.db_connect(paths) as conn:
                hunter.analyze_http_exchange(conn,int(hist['exchange_id']),domain,emit_notifications=False)
                host_id=int(conn.execute("SELECT id FROM hosts WHERE hostname='api.rules.local'").fetchone()['id'])
                js_path=root/'remembered.js'; js_path.write_text('const companySecret = "BK-HIST-928";')
                conn.execute("INSERT INTO js_assets(host_id,url,source,local_path,local_analysis_json,discovered_at,analyzed_at) VALUES(?,?,?,?,?,?,?)",
                             (host_id,'https://api.rules.local/app.js','js_local',str(js_path),'{}',core.now_iso(),core.now_iso()))
            key=core.register_target(domain,workspace,make_current=True,name='Rules Lab',scopes=[domain,'api.rules.local'])
            client=TestClient(create_app(domain,workspace))

            page=client.get(f'/t/{key}/signals/custom')
            assert page.status_code==200
            assert 'Pasado + presente + futuro' in page.text
            assert 'Valor exacto' in page.text and 'Regla' in page.text and 'Señal' in page.text
            csrf=re.search(r'name="csrf" value="([^"]+)"',page.text).group(1)

            res=client.post(f'/t/{key}/signals/custom/save',data={
                'csrf':csrf,'rule_id':'0','name':'Recordar businessKey','description':'Avisarme cuando aparezca este valor',
                'category':'business_logic','severity':'low','enabled':'on','rule_kind':'watch','origin_type':'manual',
                'origin_id':'','origin_note':'Me falta para continuar GET /company/users','exact_values':'BK-HIST-928',
                'parameter_names':'','regex_terms':'','host_terms':'','methods':'','statuses':'','path_terms':'',
                'request_terms':'','response_terms':'','header_names':'','object_types':'','identity_mode':'any',
                'suggested_action':'Volver a la Request bloqueada.'
            },follow_redirects=False)
            assert res.status_code==303,res.text
            loc=res.headers['location']; q=urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
            assert q.get('job'),loc
            job=q['job'][0]
            for _ in range(100):
                js=client.get(f'/api/jobs/{job}').json()
                if js.get('status') in {'done','error'}: break
                time.sleep(.03)
            assert js.get('status')=='done',js
            with core.db_connect(paths) as conn:
                rid=int(conn.execute("SELECT id FROM custom_signal_rules WHERE name='Recordar businessKey'").fetchone()['id'])
                oldsig=conn.execute("SELECT COUNT(*) c FROM signal_occurrences WHERE kind=?",(f'custom_signal:{rid}',)).fetchone()['c']
                assert oldsig==2,oldsig  # historical Request + historical JavaScript

                # Future evidence is evaluated incrementally with the same rule.
            fut=capture(paths,domain,'/other','{"secret":"BK-HIST-928"}')
            with core.db_connect(paths) as conn:
                hunter.analyze_http_exchange(conn,int(fut['exchange_id']),domain,emit_notifications=False)
                out=rules.evaluate_exchange(conn,int(fut['exchange_id']))
                assert rid in out['rule_ids'],out
                sigs=conn.execute("SELECT COUNT(*) c FROM signal_occurrences WHERE kind=?",(f'custom_signal:{rid}',)).fetchone()['c']
                assert sigs==3,sigs

                lead,_=hunter.upsert_lead(conn,lead_key='v037:h1',host_id=None,resource_id=int(hist['resource_id']),lead_type='business_logic',title='Necesito businessKey',confidence='medium',review_priority='medium',evidence=[{'exchange_id':int(hist['exchange_id'])}],why='Falta una pieza',next_test='Completar request',confirm_if='Funciona',discard_if='No aplica',source='MANUAL')
                hunter.add_hypothesis_requirement(conn,lead,key_pattern='businessKey',description='Key para continuar')

            from_req=client.get(f'/t/{key}/signals/custom?from_exchange={int(hist["exchange_id"])}')
            assert 'CREADA DESDE REQUEST' in from_req.text and f'Request #{int(hist["exchange_id"])}' in from_req.text
            from_h=client.get(f'/t/{key}/signals/custom?from_hypothesis={lead}')
            assert 'CREADA DESDE HIPÓTESIS' in from_h.text and 'businessKey' in from_h.text

            home=client.get(f'/t/{key}/')
            assert 'Flujos' in home.text and 'Investigación' in home.text
            assert 'Espacios de trabajo' not in home.text  # proyectos ya no se mezclan con el dashboard actual
            projects=client.get('/projects')
            assert projects.status_code==200
            assert 'Una investigación, varios hosts' in projects.text
            assert 'api.rules.local' in projects.text and 'Rules Lab' in projects.text
            assert 'Reglas integradas de Negro' in page.text or 'REGLAS INTEGRADAS DE NEGRO' in page.text
            settings=client.get(f'/t/{key}/settings')
            assert 'Abrir Reglas de señales' in settings.text
            assert 'Alertas transparentes y editables' not in settings.text
        finally:
            core.TARGETS_PATH=old

    print('[OK] A saved Rule automatically backfills historical Requests + analyzed JavaScript without touching the target')
    print('[OK] The same enabled Rule keeps evaluating future evidence incrementally')
    print('[OK] Rules support exact values and can be created from a Request or Hypothesis context')
    print('[OK] Main visible terminology is Spanish-first while Request/Response/Burp remain standard')
    print('[OK] Project management is separated from the active-project dashboard')
    print('[OK] Built-in and personal Rules are discoverable from one Signal Rules screen')

if __name__=='__main__': main()
