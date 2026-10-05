#!/usr/bin/env python3
"""Regression v0.41.8: Phase 3 Watches + reviewable Context Matches."""
from pathlib import Path
import base64, sys, tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_hunter as hunter
from negro_web import _hypothesis_rows,_investigation_detail,create_app
from fastapi.testclient import TestClient

def b64(x:bytes)->str:return base64.b64encode(x).decode()

def capture(paths,path,method,status,req_body='',resp_body='{}'):
    body=req_body.encode()
    req=(f"{method} {path} HTTP/1.1\r\nHost: shop.negro.lab\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode()+body)
    resp=(f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{resp_body}".encode())
    return core.upsert_http_observation(paths,'shop.negro.lab',url=f'http://shop.negro.lab{path}',method=method,source='burp_proxy',status_code=status,authenticated=True,tool='PROXY',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp))

def analyze(paths,ex):
    with core.db_connect(paths) as conn:
        hunter.analyze_http_exchange(conn,int(ex['exchange_id']),'shop.negro.lab',emit_notifications=False)
        return hunter.evaluate_correlation_memory(conn,int(ex['exchange_id']))

def main():
    assert core.VERSION=='0.44.0'
    with tempfile.TemporaryDirectory(prefix='negro-v050-') as td:
        paths=core.ensure_workspace(Path(td)/'workspace','shop.negro.lab')
        missing=capture(paths,'/api/refunds','POST',400,'{"orderId":"ORD-1001"}','{"error":"missing_field","field":"returnId"}')
        analyze(paths,missing)
        with core.db_connect(paths) as conn:
            hid=hunter.create_manual_hypothesis(conn,int(missing['exchange_id']),title='¿Puede B ejecutar refund de A?',why='write cross-account',next_test='Conseguir returnId')
            iid=hunter.create_investigation(conn,title='Autorización de órdenes',summary='phase3')
            hunter.link_investigation_entity(conn,iid,'hypothesis',hid,'pursuing')
            rid=hunter.add_hypothesis_requirement(conn,hid,key_pattern='returnId',description='returnId válido',requirement_type='key')
            watch=conn.execute('SELECT * FROM context_watches WHERE requirement_id=?',(rid,)).fetchone()
            assert watch and watch['status']=='active' and watch['watch_type']=='key',dict(watch) if watch else None
            assert conn.execute('SELECT COUNT(*) c FROM context_matches WHERE requirement_id=?',(rid,)).fetchone()['c']==0

        ret=capture(paths,'/api/returns','POST',201,'{"orderId":"ORD-1001"}','{"returnId":"RET-5001","orderId":"ORD-1001"}')
        r=analyze(paths,ret); assert r['context_matches']>=1,r
        with core.db_connect(paths) as conn:
            dep=dict(conn.execute('SELECT * FROM hypothesis_requirements WHERE id=?',(rid,)).fetchone())
            assert dep['status']=='pending' and dep['matched_observation_id'] is None,dep
            cm=conn.execute("SELECT * FROM context_matches WHERE requirement_id=? AND status='candidate' ORDER BY id DESC LIMIT 1",(rid,)).fetchone()
            assert cm and cm['matched_value_raw']=='RET-5001',dict(cm) if cm else None
            # Requirement matches are not Signals anymore.
            assert not conn.execute("SELECT id FROM signal_occurrences WHERE exchange_id=? AND title LIKE 'Pieza pendiente encontrada:%'",(int(ret['exchange_id']),)).fetchone()

        h=next(x for x in _hypothesis_rows(paths) if int(x['id'])==hid)
        assert h['display_state']=='review' and h['requirements_candidates']>=1,h
        with core.db_connect(paths) as conn:
            hunter.review_context_match(conn,int(cm['id']),decision='accepted')
            dep=dict(conn.execute('SELECT * FROM hypothesis_requirements WHERE id=?',(rid,)).fetchone())
            assert dep['status']=='matched' and dep['matched_observation_id'],dep
        h=next(x for x in _hypothesis_rows(paths) if int(x['id'])==hid)
        assert h['display_state']=='ready',h

        # A generic Investigation Watch does not block any Hypothesis, but still
        # creates reviewable context when a matching endpoint appears.
        with core.db_connect(paths) as conn:
            wid=hunter.add_context_watch(conn,watch_type='endpoint',pattern='/history',description='Cualquier historial nuevo',investigation_id=iid,scan_history=False)
        hist=capture(paths,'/api/history/returns','GET',200,'','{"authorizationCode":"KX92"}')
        analyze(paths,hist)
        with core.db_connect(paths) as conn:
            cm2=conn.execute("SELECT * FROM context_matches WHERE watch_id=? AND status='candidate'",(wid,)).fetchone()
            assert cm2, 'direct investigation Watch did not match endpoint'
        inv=_investigation_detail(paths,iid)
        assert inv and any(int(x['id'])==int(cm2['id']) for x in inv['investigation_context_matches']),inv

        # JSON-key dependency can be rejected without unblocking the Hypothesis.
        with core.db_connect(paths) as conn:
            rid2=hunter.add_hypothesis_requirement(conn,hid,key_pattern='authorizationCode',description='código',requirement_type='json_key')
            c2=conn.execute("SELECT * FROM context_matches WHERE requirement_id=? AND status='candidate' ORDER BY id DESC LIMIT 1",(rid2,)).fetchone()
            assert c2 and c2['matched_value_raw']=='KX92',dict(c2) if c2 else None
            hunter.review_context_match(conn,int(c2['id']),decision='dismissed')
            dep2=conn.execute('SELECT status FROM hypothesis_requirements WHERE id=?',(rid2,)).fetchone(); assert dep2['status']=='pending'

        old=core.TARGETS_PATH
        try:
            core.TARGETS_PATH=Path(td)/'targets.json'
            key=core.register_target('shop.negro.lab',Path(td)/'workspace',make_current=True,name='Phase3',scopes=['shop.negro.lab'])
            client=TestClient(create_app('shop.negro.lab',Path(td)/'workspace'))
            hp=client.get(f'/t/{key}/hypotheses'); assert hp.status_code==200
            assert 'DEPENDENCIAS + WATCHES' in hp.text and 'JSON key' in hp.text
            ip=client.get(f'/t/{key}/investigations/{iid}'); assert ip.status_code==200
            assert 'WATCHES' in ip.text and 'Coincidencias que merecen revisión' in ip.text
        finally: core.TARGETS_PATH=old

    hyp_tpl=(ROOT/'web/templates/hypotheses.html').read_text(); assert 'Aceptar contexto' in hyp_tpl and 'Descartar coincidencia' in hyp_tpl
    js=(ROOT/'web/static/graph.js').read_text(); css=(ROOT/'web/static/style.css').read_text()
    assert 'fullscreenReflow' in js and 'autoLayout(); render(); fit();' in js
    assert ':has(.graph-detail > .graph-detail-empty)' in css
    print('[OK] Dependency -> Watch -> candidate Context Match -> human accept -> Lista para probar')
    print('[OK] Rejecting a Context Match keeps the dependency blocked')
    print('[OK] Investigation Watches support endpoint matching without creating Signals')
    print('[OK] fullscreen reflows graph and hides empty detail panel')

if __name__=='__main__': main()
