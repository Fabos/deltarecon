#!/usr/bin/env python3
"""Regression: Graph v0.41.4 expands a key/value into observed cross-context relations."""
from pathlib import Path
import base64, sys, tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_hunter as hunter
import negro_identity as identities
import negro_objects as objects
from negro_web import _graph_semantic_data, create_app
from fastapi.testclient import TestClient

def b64(x:bytes)->str:return base64.b64encode(x).decode()

def capture(paths,path,method,status,body='',response='{}'):
    bb=body.encode()
    req=(f"{method} {path} HTTP/1.1\r\nHost: shop.negro.lab\r\nContent-Type: application/json\r\nContent-Length: {len(bb)}\r\n\r\n".encode()+bb)
    resp=(f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{response}".encode())
    return core.upsert_http_observation(paths,'shop.negro.lab',url=f'http://shop.negro.lab{path}',method=method,source='burp_proxy',status_code=status,authenticated=True,tool='PROXY',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp))

def analyze(paths, item, identity_id=None):
    with core.db_connect(paths) as conn:
        hunter.analyze_http_exchange(conn,int(item['exchange_id']),'shop.negro.lab',emit_notifications=False)
        if identity_id:
            identities.assign_exchange(conn,int(item['exchange_id']),int(identity_id),learn_auth=False,source='test')
        objects.index_exchange_identifiers(conn,int(item['exchange_id']))

def main():
    assert core.VERSION=='0.42.0'
    with tempfile.TemporaryDirectory(prefix='negro-v046-') as td:
        paths=core.ensure_workspace(Path(td)/'workspace','shop.negro.lab')
        with core.db_connect(paths) as conn:
            a=identities.create_identity(conn,'Buyer A')
            b=identities.create_identity(conn,'Buyer B')
        created=capture(paths,'/api/orders','POST',201,'{"shippingAddress":"Calle A"}','{"orderId":"ORD-1001","ownerId":"buyer-a","status":"CREATED"}')
        refund=capture(paths,'/api/refunds','POST',201,'{"sourceOrderId":"ORD-1001","returnId":"RET-5001"}','{"refundId":"RFD-9001","orderId":"ORD-1001","status":"REFUNDED"}')
        history=capture(paths,'/api/history','GET',200,'','{"orderRef":"ORD-1001","returnId":"RET-5001"}')
        analyze(paths,created,a);analyze(paths,refund,b);analyze(paths,history,b)

        graph=_graph_semantic_data(paths,'shop.negro.lab',scope='discovery',discovery_query='ORD-1001',limit=180)
        assert graph['meta']['scope']=='discovery'
        pivot=next(n for n in graph['nodes'] if n['type']=='identifier')
        assert pivot['meta']['requests']>=3,pivot
        assert pivot['meta']['endpoints']>=3,pivot
        endpoint_edges=[e for e in graph['edges'] if e['source']==pivot['id'] and e['relation']=='appeared_in_endpoint']
        assert len(endpoint_edges)>=3,endpoint_edges
        details='\n'.join(x['detail'] for x in graph['meta']['discovery_insights'])
        assert 'saliendo' in details and 'entrada' in details,details
        assert 'keys' in details and 'sourceorderid' in details and 'orderref' in details,details
        assert 'identidades' in details,details
        assert any(n['type']=='parameter' for n in graph['nodes']),[n['type'] for n in graph['nodes']]

        # Investigation focus must now resolve to an actual contextual graph.
        with core.db_connect(paths) as conn:
            iid=hunter.create_investigation(conn,title='Autorización de órdenes',summary='test')
            hunter.link_investigation_entity(conn,iid,'exchange',int(refund['exchange_id']),'evidence')
        inv_graph=_graph_semantic_data(paths,'shop.negro.lab',scope='investigation',investigation_id=iid)
        assert any(n['id']==f'investigation:{iid}' for n in inv_graph['nodes'])
        assert any(n['id']==f"exchange:{refund['exchange_id']}" for n in inv_graph['nodes'])

        old_targets=core.TARGETS_PATH
        try:
            core.TARGETS_PATH=Path(td)/'targets.json'
            key=core.register_target('shop.negro.lab',Path(td)/'workspace',make_current=True,name='Graph Test',scopes=['shop.negro.lab'])
            client=TestClient(create_app('shop.negro.lab',Path(td)/'workspace'))
            page=client.get(f'/t/{key}/graph?discover=ORD-1001')
            assert page.status_code==200
            assert 'Descubrir' in page.text and 'Expandir una key o valor' in page.text
            api=client.get(f'/api/t/{key}/graph?scope=discovery&q=ORD-1001')
            assert api.status_code==200 and api.json()['meta']['discovery_query']=='ORD-1001'
            focus=client.get(f'/api/t/{key}/graph?focus=investigation:{iid}')
            assert focus.status_code==200 and focus.json()['meta']['scope']=='investigation'
        finally:
            core.TARGETS_PATH=old_targets

    tpl=(ROOT/'web/templates/graph.html').read_text()
    js=(ROOT/'web/static/graph.js').read_text()
    follow=(ROOT/'web/templates/parameter_follow.html').read_text()
    flow=(ROOT/'web/templates/flow_detail.html').read_text()
    investigation=(ROOT/'web/templates/investigation_detail.html').read_text()
    assert 'data-graph-preset="discovery"' in tpl
    assert 'Descubrir dónde más aparece' in js
    assert 'Abrir relaciones en grafo' in follow
    assert 'Pivotes para descubrir relaciones' in flow and '/graph?observation={{ v.id }}' in flow
    assert 'PRÓXIMAS RAMAS' in investigation and 'Qué puedes retomar ahora' in investigation
    print('[OK] Descubrir sigue un valor aunque cambie de key y cruza endpoints/identidades')
    print('[OK] Graph muestra keys cercanas como pivotes sin promoverlas automáticamente')
    print('[OK] Investigation focus abre un grafo contextual real')
    print('[OK] Follow Value y pasos de Flow pueden saltar al grafo de relaciones')
    print('[OK] Investigation resume próximas ramas desde Hypotheses existentes, sin inventar conclusiones')

if __name__=='__main__':main()
