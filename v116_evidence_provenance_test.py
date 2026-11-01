#!/usr/bin/env python3
"""Regression v0.44.0: Replay as Identity + Phase 7 memory closure."""
from pathlib import Path
import base64, json, sys, tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_hunter as hunter
import negro_identity as identities
import negro_objects as objects
import negro_replay as replay
from negro_web import create_app, _dashboard_data, _investigation_timeline
from fastapi.testclient import TestClient

def b64(x:bytes)->str:return base64.b64encode(x).decode()

def capture(paths,path,method,status,*,token='',body='',response='{}'):
    bb=body.encode()
    auth=f"Authorization: Bearer {token}\r\n" if token else ''
    req=(f"{method} {path} HTTP/1.1\r\nHost: shop.test\r\n{auth}Content-Type: application/json\r\nContent-Length: {len(bb)}\r\n\r\n".encode()+bb)
    resp=f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{response}".encode()
    item=core.upsert_http_observation(paths,'shop.test',url=f'http://shop.test{path}',method=method,source='burp_proxy',status_code=status,authenticated=bool(token),tool='PROXY',request_content_type='application/json',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp))
    with core.db_connect(paths) as conn:
        hunter.analyze_http_exchange(conn,int(item['exchange_id']),'shop.test',emit_notifications=False)
    return item

def main():
    assert core.VERSION=='0.44.4',core.VERSION
    with tempfile.TemporaryDirectory(prefix='negro-v053-') as td:
        root=Path(td); ws=root/'workspace'; paths=core.ensure_workspace(ws,'shop.test')
        original=capture(paths,'/api/orders/123','GET',200,token='TOKEN_A',response='{"orderId":"123","ownerId":"user-a","status":"PAID"}')
        confirm=capture(paths,'/api/orders/123/confirm','POST',200,token='TOKEN_A',body='{"orderId":"123"}',response='{"orderId":"123","ownerId":"user-a","status":"CONFIRMED"}')
        auth_b=capture(paths,'/api/me','GET',200,token='TOKEN_B',response='{"userId":"user-b"}')
        # A third identity uses Cookie only; Replay must not silently switch a Bearer request to Cookie.
        cookie_req=(b'GET /api/me HTTP/1.1\r\nHost: shop.test\r\nCookie: session_c=COOKIE_C\r\n\r\n')
        cookie_item=core.upsert_http_observation(paths,'shop.test',url='http://shop.test/api/me',method='GET',source='burp_proxy',status_code=200,authenticated=True,tool='PROXY',request_b64=b64(cookie_req),response_b64=b64(b'HTTP/1.1 200 OK\r\n\r\n{}'))
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn,int(cookie_item['exchange_id']),'shop.test',emit_notifications=False)
        with core.db_connect(paths) as conn:
            a=identities.create_identity(conn,'User A'); b=identities.create_identity(conn,'User B'); c=identities.create_identity(conn,'User C')
            identities.assign_exchange(conn,int(original['exchange_id']),a,learn_auth=True,source='manual')
            identities.assign_exchange(conn,int(auth_b['exchange_id']),b,learn_auth=True,source='manual')
            identities.assign_exchange(conn,int(cookie_item['exchange_id']),c,learn_auth=True,source='manual')
            mismatch=replay.prepare_context(conn,int(original['exchange_id']),c)
            assert mismatch['auth_mechanism_matched'] is False
            assert 'Authorization:' not in mismatch['prepared_request_text'] and 'session_c=COOKIE_C' not in mismatch['prepared_request_text']
            # Teach Order as Business Object once; Replay must preserve it.
            obs=conn.execute("SELECT id FROM parameter_observations WHERE exchange_id=? AND lower(normalized_name)='orderid' ORDER BY id LIMIT 1",(int(original['exchange_id']),)).fetchone()
            assert obs
            tracked=objects.track_observation(conn,int(obs['id']),'Order',allow_manual=True)
            assert tracked.get('business_object_id')
            ctx=replay.prepare_context(conn,int(original['exchange_id']),b)
            assert 'Bearer TOKEN_B' in ctx['prepared_request_text']
            assert '/api/orders/123' in ctx['prepared_request_text']
            assert '123' in ctx['prepared_request_text']
            assert ctx['objects'] and any(str(x.get('identifier_raw') or x.get('identifier_preview'))=='123' for x in ctx['objects'])
            rid=replay.create_replay(conn,int(original['exchange_id']),b)
            q=replay.queue_replay(conn,rid)
            http_before=conn.execute('SELECT COUNT(*) c FROM http_exchanges').fetchone()['c']
            # Simulate Bridge v0.29 response without inserting a discovery exchange.
            replay_resp=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"orderId":"123","ownerId":"user-a"}'
            conn.execute("UPDATE burp_repeater_queue SET status='done',response_b64=?,response_status=200,elapsed_ms=42,finished_at=? WHERE id=?",(b64(replay_resp),replay.now_iso(),int(q['queue_id'])))
            done=replay.complete_from_queue(conn,int(q['queue_id']))
            assert done and done['test_validity']=='allowed',done
            assert done['comparison']['body_similarity_pct']>=0
            assert conn.execute('SELECT COUNT(*) c FROM http_exchanges').fetchone()['c']==http_before
            # State-dependent negative result is not an authorization conclusion.
            srid=replay.create_replay(conn,int(confirm['exchange_id']),b)
            sq=replay.queue_replay(conn,srid)
            invalid=b'HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\n\r\n{"error":"already_confirmed"}'
            conn.execute("UPDATE burp_repeater_queue SET status='done',response_b64=?,response_status=409,elapsed_ms=15,finished_at=? WHERE id=?",(b64(invalid),replay.now_iso(),int(sq['queue_id'])))
            state=replay.complete_from_queue(conn,int(sq['queue_id']))
            assert state['test_validity']=='state_invalid',state
            hid=replay.create_hypothesis_from_replay(conn,srid,title='¿Puede User B confirmar Order de A?',why='Prueba cross-account',next_test='Crear Order fresca y repetir')
            h=conn.execute('SELECT status,result_notes FROM leads_v2 WHERE id=?',(hid,)).fetchone()
            assert h and str(h['status'])=='candidate' and 'no concluyente' in str(h['result_notes']).lower()
            iid=hunter.create_investigation(conn,title='Autorización Orders',summary='Replay context')
            hunter.link_investigation_entity(conn,iid,'hypothesis',hid,'pursuing')
            hunter.link_investigation_entity(conn,iid,'authorization_replay',srid,'authorization_test')
            replay.update_replay(conn,srid,hypothesis_id=hid,investigation_id=iid)
            tl=_investigation_timeline(conn,iid)
            assert any(x['kind']=='authorization_replay' for x in tl),tl

        old=core.TARGETS_PATH
        try:
            core.TARGETS_PATH=root/'targets.json'; key=core.register_target('shop.test',ws,make_current=True,name='Replay',scopes=['shop.test'])
            client=TestClient(create_app('shop.test',ws))
            # Request Workbench exposes Replay.
            page=client.get(f'/t/{key}/resource/{original["resource_id"]}?exchange={original["exchange_id"]}')
            assert page.status_code==200 and 'Replay as Identity' in page.text
            chooser=client.get(f'/t/{key}/replays/new?exchange_id={original["exchange_id"]}&identity_id={b}')
            assert chooser.status_code==200 and 'OBJETO PRESERVADO' in chooser.text and 'Bearer' in chooser.text
            detail=client.get(f'/t/{key}/replays/{rid}')
            assert detail.status_code==200 and 'COMPARACIÓN' in detail.text and 'Origen · Negro Replay' in detail.text
            dash=_dashboard_data(paths)
            assert 'memory_investigations' in dash and 'memory_next' in dash and 'recent_replays' in dash
            home=client.get(f'/t/{key}/')
            assert home.status_code==200 and 'MEMORIA DE HUNTING' in home.text and 'Replay as Identity' in home.text
            inv=client.get(f'/t/{key}/investigations/{iid}')
            assert inv.status_code==200 and 'IA contextual' in inv.text and 'AUTHORIZATION REPLAYS' in inv.text
        finally:
            core.TARGETS_PATH=old

    java=(ROOT/'burp-extension/src/main/java/com/negro/bridge/NegroBurpBridge.java').read_text()
    for text in ['v0.30.0','Replay as Identity','Compare Identity…','replay_prepare','replay_execute','Sin autenticación','Elegir / comparar…']:
        assert text in java,text
    assert '"execute".equalsIgnoreCase(jobKind) || "replay_execute".equalsIgnoreCase(jobKind)' in java
    assert '0.30.0' in (ROOT/'burp-extension/build-extension.sh').read_text()
    print('[OK] Replay swaps auth but preserves target object/path/body')
    print('[OK] Replay traffic is evidence outside normal discovery and Flow Capture')
    print('[OK] STATE INVALID stays inconclusive and keeps Hypothesis pending')
    print('[OK] Investigation timeline + Home memory include Authorization Replay context')
    print('[OK] Burp Bridge v0.30 exposes manual Replay as Identity + Compare Identity')

if __name__=='__main__': main()
