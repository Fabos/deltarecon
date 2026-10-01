#!/usr/bin/env python3
"""Regression for v0.35 intelligence-aware map + Hypothesis Engine 2.0 context fusion."""
from pathlib import Path
import base64, json, sys, tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import negro_core as core
import negro_hunter as hunter
import negro_identity as identities
import negro_flows as flows
import negro_objects as objects
import negro_custom_signals as custom_signals
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(x: bytes)->str: return base64.b64encode(x).decode()

def capture(paths,domain,path,cookie,body,status=200,method='GET'):
    req=f"{method} {path} HTTP/1.1\r\nHost: api.context.local\r\nCookie: sid={cookie}\r\n\r\n".encode()
    resp=f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{body}".encode()
    return core.upsert_http_observation(paths,domain,url=f"https://api.context.local{path}",method=method,source='burp_proxy',status_code=status,authenticated=True,tool='PROXY',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp),query={})


def main():
    with tempfile.TemporaryDirectory(prefix='negro-v035-') as td:
        root=Path(td); old_targets=core.TARGETS_PATH; core.TARGETS_PATH=root/'targets.json'
        try:
            domain='context.local'; workspace=root/'workspace'; paths=core.ensure_workspace(workspace,domain)
            d=capture(paths,domain,'/orders/4101','diego','{"orderId":4101,"ownerId":101,"status":"OPEN"}',200)
            a=capture(paths,domain,'/orders/4101','ana','{"orderId":4101,"ownerId":101,"status":"OPEN"}',403)
            inv=capture(paths,domain,'/orders/4101/invoice','diego','{"orderId":4101,"invoiceId":9001}',200)
            with core.db_connect(paths) as conn:
                for ex in (d,a,inv): hunter.analyze_http_exchange(conn,int(ex['exchange_id']),domain,emit_notifications=False)
                diego=identities.create_identity(conn,'Diego'); ana=identities.create_identity(conn,'Ana')
                identities.assign_exchange(conn,int(d['exchange_id']),diego,learn_auth=True)
                identities.assign_exchange(conn,int(inv['exchange_id']),diego,learn_auth=False)
                identities.assign_exchange(conn,int(a['exchange_id']),ana,learn_auth=True)
                po=conn.execute("SELECT id FROM parameter_observations WHERE exchange_id=? AND normalized_name='orderid' ORDER BY id LIMIT 1",(int(d['exchange_id']),)).fetchone()
                objects.ensure_identifier(conn,'Order','orderid',source_observation_id=int(po['id'])); objects.rebuild(conn)
                flow=flows.create_flow(conn,'Leer pedido',identity_id=diego)
                flows.add_step(conn,flow,int(d['exchange_id'])); flows.add_step(conn,flow,int(inv['exchange_id']))
                rule=custom_signals.save_rule(conn,name='Order ID autenticado',category='access_control',severity='low',parameter_names=['orderId'],identity_mode='present',suggested_action='Comparar identidades')
                custom_signals.evaluate_exchange(conn,int(d['exchange_id']),rule_id=rule)
                signal=conn.execute("SELECT id FROM signal_occurrences WHERE exchange_id=? ORDER BY id LIMIT 1",(int(d['exchange_id']),)).fetchone(); sid=int(signal['id'])
                result={'hypotheses':[{
                    'title':'Comparar ownership del pedido','type':'authorization','strength':'medium','investigation_priority':'high',
                    'priority_reasons':['cross-account','object reference'],'plain_language':'Comparar el mismo pedido entre Diego y Ana.',
                    'facts':['Diego observó 200 y Ana 403 en /orders/4101','Existe un Signal sobre orderId'],
                    'inference':'El endpoint de invoice puede merecer comparación con el mismo objeto.','unknowns':['Cómo responde invoice bajo Ana'],
                    'why_interesting':'Hay contexto de identidad, objeto y señal para el mismo pedido.','suggested_investigation':'Repetir invoice con Ana manteniendo orderId.',
                    'steps':[{'step':1,'action':'Enviar la Request de invoice con la sesión de Ana','what_to_watch':'status y datos retornados'}],
                    'confirm_if':'Ana recibe datos del pedido ajeno.','discard_if':'El backend rechaza consistentemente el acceso.',
                    'node_ids':[f'signal:{sid}',f'identity:{diego}',f'identity:{ana}',f'exchange:{int(d["exchange_id"])}'],
                    'context_sources':['http','identity','business_object','signal','authorization_outcome']
                }]}
                persisted=hunter.persist_graph_ai_hypotheses(conn,result,evidence_hash='v035-test',selected_node_id=f'exchange:{int(d["exchange_id"])}')
                assert persisted and persisted[0]['resource_id']==int(d['resource_id']), persisted
                payload,_=hunter.build_graph_ai_payload(conn,domain,{'counts':{},'nodes':[], 'edges':[]},selected_node_id=f'identity:{diego}')
                env=json.loads(payload.split('\n',1)[1]); ctx=env['correlated_context']
                assert ctx['summary']['identities']>=2 and ctx['summary']['flows']>=1 and ctx['summary']['business_objects']>=1 and ctx['summary']['signals']>=1,ctx['summary']
                shared=next(x for x in ctx['authorization_outcomes'] if x['path']=='/orders/4101')
                statuses={x['name']:set(x['statuses']) for x in shared['identities']}
                assert statuses['Diego']=={200} and statuses['Ana']=={403},statuses
                assert any(x['id']==f'signal:{sid}' for x in ctx['signals'])
                assert hunter.GRAPH_AI_PROMPT_VERSION.endswith('v0.35.0')
                schema=hunter._graph_ideas_json_schema()['properties']['hypotheses']['items']
                assert 'context_sources' in schema['required']
            key=core.register_target(domain,workspace,make_current=True,name='Context Lab',scopes=[domain,'api.context.local'])
            client=TestClient(create_app(domain,workspace))
            g=client.get(f'/api/t/{key}/graph?scope=identity&identity_id={diego}&compare_identity_id={ana}').json()
            rn=next(n for n in g['nodes'] if n['type']=='resource' and n['label']=='/orders/4101')
            assert rn['meta']['signal_count']>=1 and rn['meta']['hypothesis_count']>=1,rn['meta']
            req=next(n for n in g['nodes'] if n['id']==f'exchange:{int(d["exchange_id"])}')
            assert req['meta']['signal_count']>=1 and req['meta']['hypothesis_count']>=1,req['meta']
            hunt=client.get(f'/t/{key}/hypotheses')
            assert hunt.status_code==200 and f'id="signal-{sid}"' in hunt.text
            assert 'CONTEXTO CORRELACIONADO' in hunt.text and 'Auth outcome' in hunt.text
            js=(ROOT/'web/static/graph.js').read_text()
            for phrase in ('has-signal','has-hypothesis','Inteligencia asociada','node-intel-badge'):
                assert phrase in js,phrase
        finally:
            core.TARGETS_PATH=old_targets
    print('[OK] Map highlights Requests/endpoints with Signals and AI hypotheses')
    print('[OK] Graph detail links directly to associated Hunt intelligence')
    print('[OK] Hypothesis Engine 2.0 payload correlates identities, flows, objects, signals and authorization outcomes')

if __name__=='__main__': main()
