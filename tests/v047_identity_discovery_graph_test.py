#!/usr/bin/env python3
"""Regression v0.41.5: identity memory is automatic and Discovery exposes typed, navigable evidence."""
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

def capture(paths,path,method,status,*,cookie='',body='',response='{}'):
    bb=body.encode(); headers=f"Host: shop.negro.lab\r\nContent-Type: application/json\r\n"
    if cookie: headers+=f"Cookie: {cookie}\r\n"
    req=(f"{method} {path} HTTP/1.1\r\n{headers}Content-Length: {len(bb)}\r\n\r\n".encode()+bb)
    resp=f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{response}".encode()
    item=core.upsert_http_observation(paths,'shop.negro.lab',url=f'http://shop.negro.lab{path}',method=method,source='burp_proxy',status_code=status,authenticated=bool(cookie),tool='PROXY',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp))
    with core.db_connect(paths) as conn:
        hunter.analyze_http_exchange(conn,int(item['exchange_id']),'shop.negro.lab',emit_notifications=False)
    return item

def main():
    assert core.VERSION=='0.44.1'
    with tempfile.TemporaryDirectory(prefix='negro-v047-') as td:
        paths=core.ensure_workspace(Path(td)/'workspace','shop.negro.lab')
        with core.db_connect(paths) as conn:
            a=identities.create_identity(conn,'Buyer A')
            b=identities.create_identity(conn,'Buyer B')

        # Historical traffic exists before the human teaches either session.
        created=capture(paths,'/api/orders','POST',201,cookie='lab_buyer=A',body='{"shippingAddress":"Calle A"}',response='{"orderId":"ORD-1001","ownerId":"buyer-a","status":"CREATED"}')
        owner_note=capture(paths,'/api/orders/ORD-1001/note','PATCH',200,cookie='lab_buyer=A',body='{"orderId":"ORD-1001","note":"x"}',response='{"orderId":"ORD-1001","ownerId":"buyer-a","ok":true}')
        denied=capture(paths,'/api/orders/ORD-1001','GET',403,cookie='lab_buyer=B',response='{"error":"ownership_denied","orderId":"ORD-1001"}')
        change=capture(paths,'/api/orders/ORD-1001/change-address','POST',200,cookie='lab_buyer=B',body='{"shippingAddress":"B","orderId":"ORD-1001"}',response='{"orderId":"ORD-1001","performedBy":"buyer-b","ownerId":"buyer-a"}')
        cancel=capture(paths,'/api/orders/ORD-1001/cancel','POST',200,cookie='lab_buyer=B',body='{"orderId":"ORD-1001"}',response='{"orderId":"ORD-1001","status":"CANCELLED","performedBy":"buyer-b","ownerId":"buyer-a"}')
        ret=capture(paths,'/api/returns','POST',201,cookie='lab_buyer=B',body='{"orderId":"ORD-1001"}',response='{"returnId":"RET-5001","orderId":"ORD-1001","requestedBy":"buyer-b","orderOwnerId":"buyer-a"}')
        refund=capture(paths,'/api/refunds','POST',200,cookie='lab_buyer=B',body='{"orderId":"ORD-1001","returnId":"RET-5001"}',response='{"refundId":"RFD-9001","orderId":"ORD-1001","status":"REFUNDED","performedBy":"buyer-b","orderOwnerId":"buyer-a"}')
        verify=capture(paths,'/api/orders/ORD-1001','GET',200,cookie='lab_buyer=A',response='{"orderId":"ORD-1001","ownerId":"buyer-a","status":"REFUNDED"}')

        # One trusted assignment per account teaches the cookie; history must resolve automatically.
        with core.db_connect(paths) as conn:
            learned_b=identities.assign_exchange(conn,int(change['exchange_id']),b,learn_auth=True,source='manual')
            learned_a=identities.assign_exchange(conn,int(verify['exchange_id']),a,learn_auth=True,source='manual')
            assert learned_b['history_resolved']>=3, learned_b
            assert learned_a['history_resolved']>=1, learned_a
            b_ids={int(r['exchange_id']) for r in conn.execute('SELECT exchange_id FROM exchange_identities WHERE identity_id=?',(b,)).fetchall()}
            assert int(denied['exchange_id']) in b_ids and int(refund['exchange_id']) in b_ids and int(ret['exchange_id']) in b_ids,b_ids
            # Historical identifier memory must immediately know the actor after resolution.
            idx=conn.execute('SELECT identity_id FROM identifier_observation_index WHERE exchange_id=? AND normalized_name IN (\'orderid\',\'order_id\') LIMIT 1',(int(refund['exchange_id']),)).fetchone()
            assert idx and int(idx['identity_id'])==b,idx

        graph=_graph_semantic_data(paths,'shop.negro.lab',scope='discovery',discovery_query='ORD-1001',limit=220)
        pivot=next(n for n in graph['nodes'] if n['type']=='identifier')
        rel={(e['source'],e['target'],e['relation']) for e in graph['edges']}
        assert (f'identity:{a}',pivot['id'],'owns_observed') in rel,rel
        assert (f'identity:{b}',pivot['id'],'read_denied') in rel,rel
        assert (f'identity:{b}',pivot['id'],'changed_address') in rel,rel
        assert (f'identity:{b}',pivot['id'],'cancelled_object') in rel,rel
        assert (f'identity:{b}',pivot['id'],'created_return') in rel,rel
        assert (f'identity:{b}',pivot['id'],'refunded_object') in rel,rel
        assert graph['meta']['discovery_contrasts'],graph['meta']
        assert any(x['path'].endswith('/note') and int(x['identity_id'])==b for x in graph['meta']['discovery_branches']),graph['meta']['discovery_branches']
        refund_resource=next(n for n in graph['nodes'] if n['type']=='resource' and n['label']=='/api/refunds')
        ev=refund_resource['meta'].get('discovery_evidence') or {}
        assert ev.get('requests') and ev.get('identifiers'),ev
        pairs={(x['key'],x['value']) for x in ev['identifiers']}
        assert ('returnid','RET-5001') in pairs and ('refundid','RFD-9001') in pairs,pairs

        identity_graph=_graph_semantic_data(paths,'shop.negro.lab',scope='identity',identity_id=b,limit=220)
        assert any(n['type']=='session' and 'lab_buyer' in n['label'] for n in identity_graph['nodes']),identity_graph['nodes']

        with core.db_connect(paths) as conn:
            detail=identities.identity_detail(conn,b)
            assert detail['activity']['requests']>=4,detail['activity']
            assert detail['activity']['endpoints']>=4,detail['activity']
            assert any(str(x.get('value'))=='ORD-1001' for x in detail['activity']['pivots']),detail['activity']['pivots']

        old_targets=core.TARGETS_PATH
        try:
            core.TARGETS_PATH=Path(td)/'targets.json'
            key=core.register_target('shop.negro.lab',Path(td)/'workspace',make_current=True,name='Identity Discovery',scopes=['shop.negro.lab'])
            client=TestClient(create_app('shop.negro.lab',Path(td)/'workspace'))
            identities_page=client.get(f'/t/{key}/identities')
            identity_page=client.get(f'/t/{key}/identities/view/{b}')
            discovery_page=client.get(f'/t/{key}/graph?discover=ORD-1001')
            assert identities_page.status_code==200 and 'Atribución automática' in identities_page.text
            assert identity_page.status_code==200 and 'ACTIVIDAD CONOCIDA' in identity_page.text and 'ORD-1001' in identity_page.text
            assert discovery_page.status_code==200 and 'Descubrir' in discovery_page.text
        finally:
            core.TARGETS_PATH=old_targets

    js=(ROOT/'web/static/graph.js').read_text()
    css=(ROOT/'web/static/style.css').read_text()
    ident=(ROOT/'web/templates/identities.html').read_text()
    iddetail=(ROOT/'web/templates/identity_detail.html').read_text()
    assert 'data-discover-key' in js and 'Ruta de exploración' in js and 'Ramas todavía no comparadas' in js
    assert 'Nuevo desde tu última visita' in js and 'discoveryPreviousSeen' in js
    assert "relation==='owns_observed'" in js or "'owns_observed'" in js
    assert '.graph-empty[hidden]' in css and 'discovery-endpoint-evidence' in css
    assert 'Recalcular atribución' in ident and 'Atribución automática' in ident
    assert 'ACTIVIDAD CONOCIDA' in iddetail and 'PIVOTES OBSERVADOS' in iddetail
    print('[OK] Identity aprende una sesión una vez y resuelve automáticamente historial compatible')
    print('[OK] Discovery distingue owner observado, actor, lectura denegada y escrituras aceptadas')
    print('[OK] Discovery enumera ramas de autorización todavía no comparadas sin ejecutar pruebas')
    print('[OK] Panel de endpoint conserva Requests y pivotes key/value navegables')
    print('[OK] Identity graph muestra auth material como sesión/contexto, no como otra identidad')

if __name__=='__main__':main()
