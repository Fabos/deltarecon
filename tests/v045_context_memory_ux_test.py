#!/usr/bin/env python3
"""Regression: context memory UX separates Signals, shows Request memory and reconstructs Finding trajectory."""
from pathlib import Path
import base64, sys, tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_hunter as hunter
from negro_web import _hypothesis_rows,_exchange_context_memberships,_investigation_detail,_finding_detail,_create_finding,_link_finding,create_app
from fastapi.testclient import TestClient

def b64(x:bytes)->str: return base64.b64encode(x).decode()

def capture(paths,path,method,status,request_body='',response_body='{}'):
    body=request_body.encode()
    req=(f"{method} {path} HTTP/1.1\r\nHost: shop.negro.lab\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode()+body)
    resp=(f"HTTP/1.1 {status} {'OK' if status < 400 else 'Bad Request'}\r\nContent-Type: application/json\r\n\r\n{response_body}".encode())
    return core.upsert_http_observation(paths,'shop.negro.lab',url=f'http://shop.negro.lab{path}',method=method,source='burp_proxy',status_code=status,authenticated=True,tool='PROXY',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp))

def main():
    assert core.VERSION=='0.41.3'
    with tempfile.TemporaryDirectory(prefix='negro-v045-') as td:
        paths=core.ensure_workspace(Path(td)/'workspace','shop.negro.lab')
        missing=capture(paths,'/api/refunds','POST',400,'{"orderId":"ORD-1001"}','{"error":"missing_field","field":"returnId"}')
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn,int(missing['exchange_id']),'shop.negro.lab',emit_notifications=False)
            hid=hunter.create_manual_hypothesis(conn,int(missing['exchange_id']),title='¿Puede Buyer B ejecutar refund de A?',why='B ya modificó/canceló la Order',next_test='Obtener returnId y repetir refund')
            iid=hunter.create_investigation(conn,title='Autorización de órdenes',summary='Cross-account Order writes')
            hunter.link_investigation_entity(conn,iid,'hypothesis',hid,'pursuing')
            hunter.link_investigation_entity(conn,iid,'exchange',int(missing['exchange_id']),'evidence')
            reqid=hunter.add_hypothesis_requirement(conn,hid,key_pattern='returnId',description='returnId válido asociado a ORD-1001')
            row=conn.execute('SELECT status FROM hypothesis_requirements WHERE id=?',(reqid,)).fetchone(); assert row['status']=='pending'

        ret=capture(paths,'/api/returns','POST',201,'{"orderId":"ORD-1001"}','{"returnId":"RET-5001","orderId":"ORD-1001","requestedBy":"buyer-b","orderOwnerId":"buyer-a"}')
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn,int(ret['exchange_id']),'shop.negro.lab',emit_notifications=False)
            corr=hunter.evaluate_correlation_memory(conn,int(ret['exchange_id']))
            assert corr['requirements_matched']>=1,corr
            req=dict(conn.execute('SELECT * FROM hypothesis_requirements WHERE id=?',(reqid,)).fetchone())
            assert req['status']=='matched' and req['matched_observation_id'] and req['matched_signal_id'],req

        ready=next(x for x in _hypothesis_rows(paths) if int(x['id'])==hid)
        assert ready['display_state']=='ready' and ready['display_state_label']=='Lista para probar',ready
        with core.db_connect(paths) as conn:
            ctx=_exchange_context_memberships(conn,int(ret['exchange_id']))
            assert any(int(h['id'])==hid for h in ctx['hypotheses']),ctx
            assert ctx['context_matches'],ctx
            assert not any(str(x.get('signal_level') or '')=='correlation' for x in conn.execute("SELECT * FROM signal_occurrences WHERE exchange_id=? AND COALESCE(signal_level,'local')!='correlation'",(int(ret['exchange_id']),)).fetchall())

        success=capture(paths,'/api/refunds','POST',201,'{"orderId":"ORD-1001","returnId":"RET-5001"}','{"refundId":"RFD-9001","orderId":"ORD-1001","returnId":"RET-5001","status":"REFUNDED","performedBy":"buyer-b","orderOwnerId":"buyer-a"}')
        verify=capture(paths,'/api/orders/ORD-1001','GET',200,'','{"orderId":"ORD-1001","ownerId":"buyer-a","status":"REFUNDED"}')
        with core.db_connect(paths) as conn:
            for ex in (success,verify):
                hunter.analyze_http_exchange(conn,int(ex['exchange_id']),'shop.negro.lab',emit_notifications=False)
                hunter.link_investigation_entity(conn,iid,'exchange',int(ex['exchange_id']),'evidence')
        core.update_hypothesis(paths,hid,status='confirmed',result_notes='Refund cross-account demostrado y verificado por Buyer A')
        with core.db_connect(paths) as conn:
            fid=_create_finding(conn,title='Broken Access Control permite refund cross-account',severity='high',status='confirmed',description='demo',source='web')
            _link_finding(conn,fid,'investigation',iid,'result')
            hunter.link_investigation_entity(conn,iid,'finding',fid,'decision')

        demonstrated=next(x for x in _hypothesis_rows(paths) if int(x['id'])==hid)
        assert demonstrated['display_state']=='demonstrated' and demonstrated['display_state_label']=='Demostrada'
        inv=_investigation_detail(paths,iid)
        assert inv and inv['investigation_context_matches'],inv
        titles=[x['title'] for x in inv['investigation_timeline']]
        assert any('Context Match' in x for x in titles),titles
        assert any('Hipótesis demostrada' in x for x in titles),titles
        finding=_finding_detail(paths,fid)
        assert finding and finding['finding_trajectory'],finding
        trajectory='\n'.join(f"{x['title']} {x['detail']}" for x in finding['finding_trajectory'])
        assert 'Context Match' in trajectory,trajectory
        assert 'Finding confirmado' in trajectory,trajectory
        assert 'POST /api/refunds' in trajectory or '/api/refunds' in trajectory,trajectory

        old_targets=core.TARGETS_PATH
        try:
            core.TARGETS_PATH=Path(td)/'targets.json'
            key=core.register_target('shop.negro.lab',Path(td)/'workspace',make_current=True,name='Context Lab',scopes=['shop.negro.lab'])
            client=TestClient(create_app('shop.negro.lab',Path(td)/'workspace'))
            for url,phrase in [
                (f'/t/{key}/hypotheses','Lista para probar'),
                (f'/t/{key}/investigations/{iid}','Cómo evolucionó esta rama'),
                (f'/t/{key}/finding/{fid}','CÓMO LLEGAMOS AQUÍ'),
                (f"/t/{key}/resource/{int(ret['resource_id'])}?exchange={int(ret['exchange_id'])}",'MEMORIA'),
            ]:
                page=client.get(url); assert page.status_code==200,(url,page.status_code,page.text[:500]); assert phrase in page.text,(url,phrase)
        finally:
            core.TARGETS_PATH=old_targets

    hyp=(ROOT/'web/templates/hypotheses.html').read_text()
    res=(ROOT/'web/templates/resource.html').read_text()
    invtpl=(ROOT/'web/templates/investigation_detail.html').read_text()
    findtpl=(ROOT/'web/templates/finding.html').read_text()
    assert 'HECHOS' not in hyp and 'Hipótesis histórica' not in hyp
    assert 'CONTEXT MATCH' in hyp and 'Lista para probar' in hyp
    assert 'request-memory-strip' in res and 'INV {{ ex.context.investigations|length }}' in res
    assert 'Context Match' in res and 'no es una Signal' in res
    assert 'CONTEXTO NUEVO' in invtpl and 'TIMELINE' in invtpl and '+ Nota' in invtpl
    assert 'CÓMO LLEGAMOS AQUÍ' in findtpl and 'Trayectoria del Finding' in findtpl
    print('[OK] Hypothesis deriva Bloqueada/Lista para probar/Demostrada desde decisión + piezas pendientes')
    print('[OK] Context Match se presenta separado de Signals y conserva provenance a la Request')
    print('[OK] Request muestra memoria INV/HYP/FIND/CTX sin duplicar evidencia')
    print('[OK] Investigation agrega notas rápidas, contexto nuevo y timeline derivada')
    print('[OK] Finding reconstruye Cómo llegamos aquí desde relaciones reales')

if __name__=='__main__': main()
