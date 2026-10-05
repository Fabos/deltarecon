#!/usr/bin/env python3
"""Regression v0.44.0: Burp contextual actions + Phase 7 event preparation."""
from pathlib import Path
import base64, json, sys, tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_hunter as hunter
from negro_web import create_app
from fastapi.testclient import TestClient

def b64(x:bytes)->str:return base64.b64encode(x).decode()

def capture(paths,path='/api/orders/ORD-1001/change-address',method='POST',status=200):
    body=b'{"orderId":"ORD-1001","shippingAddress":"B"}'
    req=(f"{method} {path} HTTP/1.1\r\nHost: shop.negro.lab\r\nCookie: lab_buyer=B\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode()+body)
    resp=(f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n".encode()+b'{"ok":true,"orderId":"ORD-1001","ownerId":"buyer-a","returnId":"RET-5001"}')
    return core.upsert_http_observation(paths,'shop.negro.lab',url=f'http://shop.negro.lab{path}',method=method,source='burp_proxy',status_code=status,authenticated=True,tool='PROXY',request_content_type='application/json',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp))

def payload(key,result,action,**extra):
    return {'target_key':key,'action':action,'resource_id':int(result['resource_id']),'operation_id':int(result['operation_id']),'exchange_id':int(result['exchange_id']),**extra}

def main():
    assert core.VERSION=='0.44.1'
    with tempfile.TemporaryDirectory(prefix='negro-v052-') as td:
        root=Path(td); ws=root/'workspace'; paths=core.ensure_workspace(ws,'shop.negro.lab')
        result=capture(paths)
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn,int(result['exchange_id']),'shop.negro.lab',emit_notifications=False)
            iid=hunter.create_investigation(conn,title='Autorización de órdenes',summary='Burp context')
            hid=hunter.create_manual_hypothesis(conn,int(result['exchange_id']),title='¿Puede B modificar Order de A?',why='cross-account',next_test='comparar')
            hunter.link_investigation_entity(conn,iid,'hypothesis',hid,'pursuing')
            obs=conn.execute("SELECT id FROM parameter_observations WHERE exchange_id=? AND lower(normalized_name)='orderid' ORDER BY id LIMIT 1",(int(result['exchange_id']),)).fetchone()
            assert obs
            obs_id=int(obs['id'])

        old=core.TARGETS_PATH
        try:
            core.TARGETS_PATH=root/'targets.json'; key=core.register_target('shop.negro.lab',ws,make_current=True,name='Phase6',scopes=['shop.negro.lab'])
            client=TestClient(create_app('shop.negro.lab',ws))
            assert client.get(f'/api/bridge/investigations/{key}').status_code==200
            assert client.get(f'/api/bridge/hypotheses/{key}').status_code==200
            ctx=client.get(f'/api/bridge/exchange-context/{key}/{result["exchange_id"]}'); assert ctx.status_code==200
            assert any(int(x['id'])==obs_id for x in ctx.json()['parameters'])

            r=client.post('/api/bridge/action',json=payload(key,result,'investigation_attach',investigation_id=iid)); assert r.status_code==200,r.text
            r=client.post('/api/bridge/action',json=payload(key,result,'hypothesis_attach',hypothesis_id=hid)); assert r.status_code==200,r.text
            r=client.post('/api/bridge/action',json=payload(key,result,'hypothesis_create',title='¿Puede B cancelar Order de A?',why='mismo objeto',next_test='cancel',investigation_id=iid)); assert r.status_code==200,r.text
            hid2=int(r.json()['hypothesis_id'])
            r=client.post('/api/bridge/action',json=payload(key,result,'entity_create',observation_id=obs_id,entity_type='Order',investigation_id=iid)); assert r.status_code==200,r.text
            assert int(r.json()['business_object_id'])>0
            r=client.post('/api/bridge/action',json=payload(key,result,'follow_value',observation_id=obs_id,selected='ORD-1001',mode='value')); assert r.status_code==200 and '/parameters/follow/' in r.json()['web_path']
            r=client.post('/api/bridge/action',json=payload(key,result,'watch_create',watch_type='key',pattern='returnId',description='esperar returnId',hypothesis_id=hid2,as_requirement=True)); assert r.status_code==200,r.text
            assert int(r.json()['watch_id'])>0 and int(r.json()['requirement_id'])>0
            r=client.post('/api/bridge/action',json=payload(key,result,'add_note',note='Nota rápida desde Burp',investigation_id=iid)); assert r.status_code==200,r.text

            with core.db_connect(paths) as conn:
                assert conn.execute("SELECT 1 FROM investigation_links WHERE investigation_id=? AND entity_type='exchange' AND entity_id=?",(iid,int(result['exchange_id']))).fetchone()
                h=json.loads(conn.execute("SELECT evidence_json FROM leads_v2 WHERE id=?",(hid,)).fetchone()['evidence_json'])
                assert any(int(x.get('exchange_id') or 0)==int(result['exchange_id']) for x in h)
                assert conn.execute("SELECT 1 FROM context_watches WHERE lead_id=? AND pattern='returnid'",(hid2,)).fetchone()
                assert conn.execute("SELECT 1 FROM notes WHERE entity_type='investigation' AND entity_id=? AND body LIKE '%Nota rápida desde Burp%'",(iid,)).fetchone()
                assert conn.execute("SELECT 1 FROM events WHERE event_type='burp_context_action' AND entity_type='exchange' AND entity_id=?",(int(result['exchange_id']),)).fetchone()

            # Re-ingesting the exact request exposes context counters for Burp annotations.
            raw_req=b64(("POST /api/orders/ORD-1001/change-address HTTP/1.1\r\nHost: shop.negro.lab\r\nCookie: lab_buyer=B\r\nContent-Type: application/json\r\nContent-Length: 44\r\n\r\n".encode()+b'{"orderId":"ORD-1001","shippingAddress":"B"}'))
            raw_resp=b64(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true,"orderId":"ORD-1001","ownerId":"buyer-a","returnId":"RET-5001"}')
            ing=client.post('/api/ingest/http',json={'url':'http://shop.negro.lab/api/orders/ORD-1001/change-address','method':'POST','tool':'PROXY','status_code':200,'authenticated':True,'request_content_type':'application/json','response_content_type':'application/json','request_b64':raw_req,'response_b64':raw_resp,'context_sync':True})
            assert ing.status_code==200,ing.text
            j=ing.json(); assert j['accepted'] is True and j['investigation_count']>=1 and j['hypothesis_count']>=1
        finally:
            core.TARGETS_PATH=old

    src=(ROOT/'burp-extension/src/main/java/com/negro/bridge/NegroBurpBridge.java').read_text()
    for text in ['Añadir a Investigation…','Crear Hypothesis…','Adjuntar a Hypothesis…','Crear Entity desde key/valor…','Seguir key / valor…','Watch de key / valor…','selectionOffsets()','NEGRO · CONTEXTO · INV ']: assert text in src,text
    assert 'v0.29.0' in src
    print('[OK] Burp context menu covers Investigation/Hypothesis/Entity/Follow Value/Watch/Note')
    print('[OK] Backend keeps canonical links/evidence and emits Phase 7 audit events')
    print('[OK] Ingest exposes INV/HYP/CTX/FIND counters for subtle Burp annotations')

if __name__=='__main__': main()
