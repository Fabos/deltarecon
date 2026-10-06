#!/usr/bin/env python3
from pathlib import Path
import base64, tempfile, sys
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_web
import negro_http_inspector as inspector
from fastapi.testclient import TestClient

def b64(x: bytes)->str: return base64.b64encode(x).decode()

with tempfile.TemporaryDirectory(prefix='negro-v064-') as td:
    root=Path(td); core.CONFIG_PATH=root/'config.json'; core.TARGETS_PATH=root/'targets.json'
    ws=root/'workspace'; key=core.register_target('example.test',ws,make_current=True,name='Example')
    paths=core.ensure_workspace(ws,'example.test')
    req=b'POST /login HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer abc\r\nContent-Type: application/json\r\nContent-Length: 14\r\n\r\n{"user":"fab"}'
    resp=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"token":"abc"}'
    r=core.upsert_http_observation(paths,'example.test',url='https://example.test/login',method='POST',source='burp_proxy',tool='PROXY',status_code=200,request_b64=b64(req),response_b64=b64(resp),query={})
    exid=int(r['exchange_id'])
    with core.db_connect(paths) as conn:
        iid=conn.execute("INSERT INTO identities(name,kind,notes,created_at,updated_at) VALUES('Fabian','account','',datetime('now'),datetime('now'))").lastrowid
        inspector.save_annotation(conn,exid,side='request',location='request_header:Authorization',key='Authorization',value='Bearer abc',classification='auth',identity_id=iid)
        rid=int(conn.execute("SELECT o.resource_id FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id WHERE e.id=?",(exid,)).fetchone()['resource_id'])
    app=negro_web.create_app('example.test',ws); client=TestClient(app)
    page=client.get(f'/t/{key}/resource/{rid}?exchange={exid}')
    assert page.status_code==200
    assert 'http-annotation http-ann-auth' in page.text and 'AUTH · Fabian' in page.text
    # Same semantic request, different HTTP version + host/content-length representation.
    req2=b'POST /login HTTP/2\r\nHost: example.test\r\nAuthorization: Bearer abc\r\nContent-Type: application/json\r\nContent-Length: 999\r\n\r\n{"user":"fab"}'
    ctx=client.post('/api/bridge/context',content=f'https://example.test/login\tPOST\t{b64(req2)}')
    assert ctx.status_code==200,ctx.text
    data=ctx.json(); assert data.get('found') is True,data
    assert 'canonical-request' in data.get('text','')
    assert 'AUTH · Fabian' in data.get('request_html','')
    detail=client.get(f'/t/{key}/identities/view/{iid}')
    assert 'QUÉ IDENTIFICA A FABIAN' in detail.text and 'Authorization' in detail.text and 'Bearer abc' in detail.text
    js=(ROOT/'web/static/app.js').read_text()
    assert "content.querySelector('.http-annotation')" in js
    print('[OK] Workbench preserves backend annotations, Burp canonical fallback finds same request, Identity audits evidence')
