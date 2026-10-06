#!/usr/bin/env python3
from pathlib import Path
import base64, tempfile, sys
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_web
import negro_http_inspector as inspector
try:
    from fastapi.testclient import TestClient
except Exception:
    TestClient=None

def b64(x: bytes)->str: return base64.b64encode(x).decode()

def main():
    if TestClient is None:
        print('[SKIP] TestClient unavailable'); return
    with tempfile.TemporaryDirectory(prefix='negro-v061-') as td:
        root=Path(td)
        core.CONFIG_PATH=root/'config.json'; core.TARGETS_PATH=root/'targets.json'
        ws=root/'workspace'; key=core.register_target('example.test',ws,make_current=True,name='Example')
        paths=core.ensure_workspace(ws,'example.test')
        req=b'GET /orders/ORD-7 HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer abc\r\n\r\n'
        resp=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"orderId":"ORD-7"}'
        r=core.upsert_http_observation(paths,'example.test',url='https://example.test/orders/ORD-7',method='GET',source='burp_proxy',tool='PROXY',status_code=200,request_b64=b64(req),response_b64=b64(resp),query={})
        exid=int(r['exchange_id'])
        with core.db_connect(paths) as conn:
            iid=conn.execute("INSERT INTO identities(name,kind,notes,created_at,updated_at) VALUES('Fabian','account','',datetime('now'),datetime('now'))").lastrowid
            inspector.save_annotation(conn,exid,side='request',location='request_header:Authorization',key='Authorization',value='Bearer abc',classification='auth',identity_id=iid)
            inspector.save_annotation(conn,exid,side='response',location='response_json:$.orderId',key='orderId',value='ORD-7',classification='entity',object_type='Order')
            rid=int(conn.execute("SELECT o.resource_id FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id WHERE e.id=?",(exid,)).fetchone()['resource_id'])
        app=negro_web.create_app('example.test',ws); client=TestClient(app)
        page=client.get(f'/t/{key}/resource/{rid}?exchange={exid}')
        assert page.status_code==200
        assert 'data-highlight-identity' in page.text and 'data-highlight-objects' in page.text
        assert 'Historial de variantes' not in page.text  # only one variant
        objects=client.get(f'/t/{key}/objects')
        assert objects.status_code==200 and 'objects-candidates-secondary' in objects.text
        ctx=client.post('/api/bridge/context',content=f'https://example.test/orders/ORD-7\tGET\t{b64(req)}')
        assert ctx.status_code==200,ctx.text
        text=ctx.json()['text']
        assert 'Negro Context' in text and '[AUTH] Authorization' in text and '[ENTITY] orderId' in text
        print('[OK] HTTP focus toggles render and Burp context endpoint returns learned annotations')
        print('[OK] Objects candidates are secondary/collapsible')
if __name__=='__main__': main()
