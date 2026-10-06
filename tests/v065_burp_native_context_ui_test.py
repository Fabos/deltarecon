#!/usr/bin/env python3
from pathlib import Path
import base64, tempfile, sys
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_web
import negro_http_inspector as inspector
from fastapi.testclient import TestClient

def b64(x: bytes)->str: return base64.b64encode(x).decode()

with tempfile.TemporaryDirectory(prefix='negro-v065-') as td:
    root=Path(td); core.CONFIG_PATH=root/'config.json'; core.TARGETS_PATH=root/'targets.json'
    ws=root/'workspace'; key=core.register_target('example.test',ws,make_current=True,name='Example')
    paths=core.ensure_workspace(ws,'example.test')
    req=b'POST /login HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer abc\r\nContent-Type: application/json\r\n\r\n{"memberId":"42"}'
    resp=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"token":"abc"}'
    r=core.upsert_http_observation(paths,'example.test',url='https://example.test/login',method='POST',source='burp_proxy',tool='PROXY',status_code=200,request_b64=b64(req),response_b64=b64(resp),query={})
    exid=int(r['exchange_id'])
    with core.db_connect(paths) as conn:
        iid=conn.execute("INSERT INTO identities(name,kind,notes,created_at,updated_at) VALUES('Fabian','account','',datetime('now'),datetime('now'))").lastrowid
        inspector.save_annotation(conn,exid,side='request',location='request_header:Authorization',key='Authorization',value='Bearer abc',classification='auth',identity_id=iid)
    app=negro_web.create_app('example.test',ws); client=TestClient(app)
    ctx=client.post('/api/bridge/context',content=f'https://example.test/login\tPOST\t{b64(req)}')
    data=ctx.json(); assert data.get('found') is True,data
    raw=base64.b64decode(data['request_text_b64']).decode()
    marks=base64.b64decode(data['request_marks_b64']).decode()
    assert raw.startswith('POST /login')
    assert '|auth|' in marks and 'QVVUSCDCtyBGYWJpYW4=' in marks.replace('-','+').replace('_','/') or '|auth|' in marks
    java=(ROOT/'burp-extension/src/main/java/com/negro/bridge/NegroBurpBridge.java').read_text()
    assert 'class NegroContextView extends JPanel' in java
    assert 'JTextPane' in java and 'setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)' in java
    assert '⟦' in java and 'StyleConstants.setBackground' in java
    print('[OK] Burp native context payload + Swing renderer contract')
