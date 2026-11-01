#!/usr/bin/env python3
"""Regression for v0.38 minimal rules + Request Workbench provenance."""
from pathlib import Path
import base64, re, sys, tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import negro_core as core
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(x: bytes)->str:
    return base64.b64encode(x).decode()


def capture(paths,domain,*,tool,source,body: bytes):
    req=b"GET /api/users HTTP/1.1\r\nHost: api.workbench.local\r\nCookie: sid=test\r\n\r\n"
    resp=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"+body
    return core.upsert_http_observation(
        paths,domain,url="https://api.workbench.local/api/users",method="GET",source=source,
        status_code=200,authenticated=True,tool=tool,response_content_type="application/json",
        request_b64=b64(req),response_b64=b64(resp),query={}
    )


def main():
    with tempfile.TemporaryDirectory(prefix='negro-v038-') as td:
        root=Path(td); old=core.TARGETS_PATH; core.TARGETS_PATH=root/'targets.json'
        try:
            domain='workbench.local'; workspace=root/'workspace'; paths=core.ensure_workspace(workspace,domain)
            # Long payload verifies the page no longer silently clips the persisted Response.
            marker='END-OF-RESPONSE-v038'
            payload=(('{"users":["' + ('x'*330000) + '"],"marker":"'+marker+'"}').encode())
            first=capture(paths,domain,tool='PROXY',source='burp_proxy',body=payload)
            capture(paths,domain,tool='PROXY',source='burp_proxy',body=payload)
            capture(paths,domain,tool='REPEATER',source='burp_repeater',body=payload)

            with core.db_connect(paths) as conn:
                ex=conn.execute('SELECT id,seen_count FROM http_exchanges').fetchone()
                assert int(ex['seen_count'])==3,dict(ex)
                prov={str(r['tool']):int(r['seen_count']) for r in conn.execute('SELECT tool,seen_count FROM http_exchange_provenance WHERE exchange_id=?',(int(ex['id']),)).fetchall()}
                assert prov.get('PROXY')==2,prov
                assert prov.get('REPEATER')==1,prov
                rid=int(conn.execute("SELECT id FROM resources WHERE path='/api/users'").fetchone()['id'])

            key=core.register_target(domain,workspace,make_current=True,name='Workbench Lab',scopes=[domain,'api.workbench.local'])
            client=TestClient(create_app(domain,workspace))

            rules=client.get(f'/t/{key}/signals/custom')
            assert rules.status_code==200
            assert '1 visible' in rules.text, rules.text[:2000]
            assert 'Errores con detalles internos' in rules.text
            assert 'Autorización por método HTTP' not in rules.text
            assert 'Referencia de objeto / posible IDOR' not in rules.text
            assert '>Desactivar<' in rules.text and '>Eliminar<' in rules.text
            csrf=re.search(r'name="csrf" value="([^"]+)"',rules.text).group(1)

            # Integrated example can be paused, removed from this project, and restored.
            r=client.post(f'/t/{key}/signals/builtin/error_disclosure/toggle',data={'csrf':csrf},follow_redirects=False)
            assert r.status_code==303
            paused=client.get(f'/t/{key}/signals/custom')
            assert '>Activar<' in paused.text
            csrf2=re.search(r'name="csrf" value="([^"]+)"',paused.text).group(1)
            r=client.post(f'/t/{key}/signals/builtin/error_disclosure/delete',data={'csrf':csrf2},follow_redirects=False)
            assert r.status_code==303
            hidden=client.get(f'/t/{key}/signals/custom')
            assert 'No hay Reglas integradas visibles' in hidden.text
            assert 'Reglas integradas eliminadas' in hidden.text
            csrf3=re.search(r'name="csrf" value="([^"]+)"',hidden.text).group(1)
            r=client.post(f'/t/{key}/signals/builtin/error_disclosure/restore',data={'csrf':csrf3},follow_redirects=False)
            assert r.status_code==303
            assert 'Errores con detalles internos' in client.get(f'/t/{key}/signals/custom').text

            page=client.get(f'/t/{key}/resource/{rid}')
            assert page.status_code==200
            html=page.text
            assert 'REQUEST WORKBENCH' in html
            assert 'Request y Response completos' in html
            assert marker in html, 'full Response marker was clipped'
            assert 'Proxy ×2' in html, 'Proxy provenance not grouped'
            assert 'Repeater ×1' in html, 'Repeater provenance not grouped'
            assert '3 ejecuciones' in html and '1 variantes' in html
            assert 'burp_proxy' not in html and 'burp_repeater' not in html
            assert 'Buscar en Request…' in html and 'Buscar en Response…' in html
            assert 'Enviar a Repeater' in html and 'Crear Regla' in html
            assert 'Comparación inteligente' in html and 'Requests relacionadas' in html
            assert 'Guía opcional de pruebas' not in html
            assert 'Recordatorios de pruebas' not in html
            assert 'Ejecutar CORS' not in html and 'cors-run' not in html
            assert 'SEÑALES' in html and 'Hipótesis relacionadas' in html
        finally:
            core.TARGETS_PATH=old

    print('[OK] v0.38 ships one clear integrated Rule with activate/deactivate/delete/restore controls')
    print('[OK] exact repeated HTTP evidence is aggregated by Burp tool provenance instead of duplicated cards')
    print('[OK] Request Workbench renders complete Request/Response evidence with search/copy/fullscreen controls')
    print('[OK] legacy testing guide/reminders/CORS execution noise is removed while Signals + Hypotheses remain')

if __name__=='__main__':
    main()
