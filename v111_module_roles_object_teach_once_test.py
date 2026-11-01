#!/usr/bin/env python3
"""Regression for v0.36 Investigation Memory / Correlation Engine."""
from pathlib import Path
import base64, json, sys, tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import negro_core as core
import negro_hunter as hunter
import negro_identity as identities
import negro_objects as objects
import negro_search as search
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(x: bytes)->str: return base64.b64encode(x).decode()

def capture(paths,domain,host,path,cookie,body,status=200,method='GET'):
    req=f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nCookie: sid={cookie}\r\n\r\n".encode()
    resp=f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{body}".encode()
    return core.upsert_http_observation(
        paths,domain,url=f"https://{host}{path}",method=method,source='burp_proxy',status_code=status,
        authenticated=True,tool='PROXY',response_content_type='application/json',request_b64=b64(req),
        response_b64=b64(resp),query={}
    )


def main():
    with tempfile.TemporaryDirectory(prefix='negro-v036-') as td:
        root=Path(td); old_targets=core.TARGETS_PATH; core.TARGETS_PATH=root/'targets.json'
        try:
            domain='target.local'; workspace=root/'workspace'; paths=core.ensure_workspace(workspace,domain)
            producer=capture(paths,domain,'tracking.target.local','/shipments/history','b',
                             '{"shipment_id":81922,"order_id":728193813,"seller_id":19281}',200)
            consumer=capture(paths,domain,'api.orders.target.local','/orders/cancel?order_id=728193813','a',
                             '{"ok":true}',200,method='POST')
            with core.db_connect(paths) as conn:
                for ex in (producer,consumer):
                    hunter.analyze_http_exchange(conn,int(ex['exchange_id']),domain,emit_notifications=False)
                account_a=identities.create_identity(conn,'Account A')
                account_b=identities.create_identity(conn,'Account B')
                identities.assign_exchange(conn,int(producer['exchange_id']),account_b,learn_auth=True)
                identities.assign_exchange(conn,int(consumer['exchange_id']),account_a,learn_auth=True)
                objects.index_exchange_identifiers(conn,int(producer['exchange_id']))
                objects.index_exchange_identifiers(conn,int(consumer['exchange_id']))

                summary=objects.identifier_key_summary(conn,'order_id')
                assert summary and summary['requests']==2 and summary['hosts']==2 and summary['identities']==2,summary
                assert summary['output_observations']>=1 and summary['input_observations']>=1,summary

                lead,_=hunter.upsert_lead(
                    conn,lead_key='ai:v036:horizontal-order',host_id=None,resource_id=int(consumer['resource_id']),
                    lead_type='authorization',title='Possible horizontal authorization issue',confidence='medium',
                    review_priority='high',evidence=[{'exchange_id':int(consumer['exchange_id'])}],
                    why='Need an order_id observed under another identity.',next_test='Try the same cancel operation with that order ID.',
                    confirm_if='Cross-account action succeeds.',discard_if='Ownership is enforced.',source='AI'
                )
                req_id=hunter.add_hypothesis_requirement(
                    conn,lead,key_pattern='order_id',description='order_id observado bajo Account B',
                    identity_mode='specific',identity_id=account_b
                )
                req=dict(conn.execute('SELECT * FROM hypothesis_requirements WHERE id=?',(req_id,)).fetchone())
                assert req['status']=='matched' and req['matched_signal_id'],req

                signals=[dict(r) for r in conn.execute("SELECT * FROM signal_occurrences WHERE signal_level='correlation' ORDER BY id").fetchall()]
                assert len(signals)>=2,signals
                assert any(json.loads(x['evidence_json']).get('correlation_type')=='hypothesis_requirement_match' for x in signals)
                assert any(json.loads(x['evidence_json']).get('correlation_type')=='produced_then_consumed' for x in signals)

                # Search knowledge includes missing-piece vocabulary, while identifier memory is independently searchable.
                search.rebuild_search_index(conn)
                sr=search.search(conn,'order_id',limit=50)
                assert any(x['entity_type']=='hypothesis' for x in sr['results']),sr['results']
                remembered=objects.search_identifier_memory(conn,'728193813')
                assert remembered and remembered[0]['requests']>=2,remembered

                schema=hunter._graph_ideas_json_schema()['properties']['hypotheses']['items']
                assert 'needed_pieces' in schema['required']
                assert hunter.GRAPH_AI_PROMPT_VERSION.endswith('v0.36.0')

            key=core.register_target(domain,workspace,make_current=True,name='Memory Lab',scopes=[domain,'tracking.target.local','api.orders.target.local'])
            client=TestClient(create_app(domain,workspace))

            hunt=client.get(f'/t/{key}/hypotheses')
            assert hunt.status_code==200
            assert 'Qué me falta para continuar' in hunt.text
            assert 'order_id' in hunt.text and 'Correlation' in hunt.text

            page=client.get(f'/t/{key}/search?q=order_id')
            assert page.status_code==200 and 'MEMORIA DE IDENTIFICADORES' in page.text
            assert 'Negro recuerda dónde apareció' in page.text

            graph=client.get(f'/api/t/{key}/graph?scope=surface').json()
            prod_node=next(n for n in graph['nodes'] if n['type']=='resource' and n['label']=='/shipments/history')
            cons_node=next(n for n in graph['nodes'] if n['type']=='resource' and n['label']=='/orders/cancel')
            assert prod_node['meta']['correlation_count']>=1,prod_node['meta']
            assert cons_node['meta']['correlation_count']>=1,cons_node['meta']

            js=(ROOT/'web/static/graph.js').read_text()
            html=(ROOT/'web/templates/graph.html').read_text()
            css=(ROOT/'web/static/style.css').read_text()
            for phrase in ('correlationCount','node-intel-flag','intelligenceRelevantIds','intelligenceBadgesHtml'):
                assert phrase in js,phrase
            assert 'data-graph-intelligence-only' in html
            assert 'Sólo con inteligencia' in html
            assert 'node-intel-flag-bg.correlation' in css
        finally:
            core.TARGETS_PATH=old_targets

    print('[OK] Identifier memory indexes input/output incrementally across hosts and identities')
    print('[OK] Hypothesis missing pieces are matched retrospectively and emit deduplicated Correlation Signals')
    print('[OK] Search/Hunt/Map expose Investigation Memory without claiming vulnerabilities')
    print('[OK] Surface/Flow intelligence markers stay prominent and can be isolated')

if __name__=='__main__': main()
