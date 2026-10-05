#!/usr/bin/env python3
"""Regression v0.42.0: Phase 4 exploration memory + Phase 5 Runner experiments + fullscreen layout."""
from pathlib import Path
import base64, sys, tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_hunter as hunter
import negro_parameters as params
import negro_flows as flows
import negro_runners as runners
from negro_web import _investigation_detail, create_app
from fastapi.testclient import TestClient

def b64(x:bytes)->str:return base64.b64encode(x).decode()

def capture(paths,path,method,status,req_body='',resp_body='{}'):
    body=req_body.encode()
    req=(f"{method} {path} HTTP/1.1\r\nHost: shop.negro.lab\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode()+body)
    resp=(f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{resp_body}".encode())
    return core.upsert_http_observation(paths,'shop.negro.lab',url=f'http://shop.negro.lab{path}',method=method,source='burp_proxy',status_code=status,authenticated=True,tool='PROXY',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp))

def main():
    assert core.VERSION=='0.42.0'
    with tempfile.TemporaryDirectory(prefix='negro-v051-') as td:
        root=Path(td); workspace=root/'workspace'; paths=core.ensure_workspace(workspace,'shop.negro.lab')
        a=capture(paths,'/api/orders','POST',201,'{"address":"A"}','{"orderId":"ORD-1001","ownerId":"buyer-a"}')
        b=capture(paths,'/api/orders/ORD-1001','GET',403,'','{"error":"ownership_denied","orderId":"ORD-1001"}')
        c=capture(paths,'/api/orders/ORD-1001/change-address','POST',200,'{"shippingAddress":"B"}','{"orderId":"ORD-1001","performedBy":"buyer-b","ownerId":"buyer-a"}')
        with core.db_connect(paths) as conn:
            for ex in (a,b,c): hunter.analyze_http_exchange(conn,int(ex['exchange_id']),'shop.negro.lab',emit_notifications=False)
            iid=hunter.create_investigation(conn,title='Autorización de órdenes',summary='phase45')
            fid=flows.create_flow(conn,'Cambio de dirección',description='baseline')
            flows.add_step(conn,fid,int(a['exchange_id'])); flows.add_step(conn,fid,int(c['exchange_id']))
            hunter.link_investigation_entity(conn,iid,'flow',fid,'context')
            hid=hunter.create_manual_hypothesis(conn,int(c['exchange_id']),title='¿Puede B modificar Order de A?',why='cross-account',next_test='Repetir con B')
            hunter.link_investigation_entity(conn,iid,'hypothesis',hid,'pursuing')
            # Find one ORD-1001 observation and persist Follow Value as Investigation memory.
            ob=conn.execute("SELECT id FROM parameter_observations WHERE COALESCE(value_raw,value_preview)='ORD-1001' ORDER BY id LIMIT 1").fetchone(); assert ob
            follow=params.follow_observation(conn,int(ob['id'])); assert follow and len(follow['occurrences'])>=3
            eid=hunter.save_investigation_exploration(conn,iid,exploration_type='follow_value',title='Exploración · usos de orderId',query_text='ORD-1001',source={'observation_id':int(ob['id']),'href':f"parameters/follow/{int(ob['id'])}"},snapshot={'occurrence_count':len(follow['occurrences']),'exchange_ids':[int(x['exchange_id']) for x in follow['occurrences']]},notes='Seguir la Order entre APIs')
            assert eid>0
            diff=params.smart_diff(conn,int(b['exchange_id']),int(c['exchange_id'])); assert diff
            eid2=hunter.save_investigation_exploration(conn,iid,exploration_type='smart_compare',title='B lectura vs escritura',query_text=f"#{b['exchange_id']} ↔ #{c['exchange_id']}",source={'a':int(b['exchange_id']),'b':int(c['exchange_id']),'href':f"parameters/diff?a={b['exchange_id']}&b={c['exchange_id']}"},snapshot={'business_changes':diff['business_changes'],'alias_candidates':diff['alias_candidates']},notes='Comparar autorización')
            assert eid2>eid
            rid=runners.create_runner_from_flow(conn,fid,alias='B → change-address de A',description='Responder la Hypothesis',hypothesis_id=hid,investigation_id=iid,origin='investigation_experiment',experiment_goal='¿Puede B modificar Order de A?',expected_support='HTTP 2xx y cambio persistente',expected_refute='403/404 sin cambio')
            rd=runners.get_runner(conn,rid); assert rd
            assert rd['runner']['hypothesis_id']==hid and rd['runner']['investigation_id']==iid
            assert rd['runner']['experiment_goal'].startswith('¿Puede B')
            inv=_investigation_detail(paths,iid); assert inv
            assert len(inv['investigation_explorations'])==2
            assert inv['investigation_flow_options'][0]['id']==fid
            assert any(x['runner']['id']==rid for x in inv['investigation_runners'])
            assert any(x['kind']=='exploration' for x in inv['investigation_timeline'])

        old=core.TARGETS_PATH
        try:
            core.TARGETS_PATH=root/'targets.json'; key=core.register_target('shop.negro.lab',workspace,make_current=True,name='Phase45',scopes=['shop.negro.lab'])
            client=TestClient(create_app('shop.negro.lab',workspace))
            fp=client.get(f'/t/{key}/parameters/follow/{int(ob["id"])}'); assert fp.status_code==200 and 'Guardar esta exploración' in fp.text
            dp=client.get(f'/t/{key}/parameters/diff?a={int(b["exchange_id"])}&b={int(c["exchange_id"])}'); assert dp.status_code==200 and 'Guardar esta comparación' in dp.text
            ip=client.get(f'/t/{key}/investigations/{iid}'); assert ip.status_code==200
            assert '03 · EXPLORACIONES' in ip.text and 'Exploración · usos de orderId' in ip.text and '+ Crear experimento Runner' in ip.text
            rp=client.get(f'/t/{key}/runners/{rid}'); assert rp.status_code==200
            assert 'Qué pregunta intenta responder este Runner' in rp.text and 'HTTP 2xx y cambio persistente' in rp.text
        finally: core.TARGETS_PATH=old

    css=(ROOT/'web/static/style.css').read_text(); js=(ROOT/'web/static/graph.js').read_text()
    assert '.graph-workspace:fullscreen .graph-canvas-shell{position:absolute!important;inset:0!important;display:block!important' in css
    assert '.graph-workspace:fullscreen .graph-canvas-wrap{position:absolute!important;inset:0!important' in css
    assert 'fullscreenCanvasObserver' in js
    print('[OK] Fullscreen canvas fills the stage instead of an intrinsic auto grid row')
    print('[OK] Follow Value and Smart Compare persist as lightweight Investigation explorations')
    print('[OK] Investigation timeline remembers explorations without copying HTTP evidence')
    print('[OK] Runner is an explicit experiment linked Investigation -> Hypothesis -> Runner -> Flow')

if __name__=='__main__': main()
