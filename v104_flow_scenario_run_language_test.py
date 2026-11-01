#!/usr/bin/env python3
from pathlib import Path
import base64, tempfile, sys
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_web
try:
    from fastapi.testclient import TestClient
except Exception:
    TestClient=None

def b64(x): return base64.b64encode(x).decode()
def main():
    if TestClient is None:
        print('[SKIP] TestClient unavailable'); return
    with tempfile.TemporaryDirectory(prefix='negro-v060-web-') as td:
        root=Path(td)
        core.CONFIG_PATH=root/'config.json'; core.TARGETS_PATH=root/'targets.json'
        ws=root/'workspace'; key=core.register_target('example.test',ws,make_current=True,name='Example')
        paths=core.ensure_workspace(ws,'example.test')
        req=b'POST /me HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{"memberId":"101"}'
        resp=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"token":"abc.def.ghi","memberId":"101"}'
        r=core.upsert_http_observation(paths,'example.test',url='https://example.test/me',method='POST',source='burp_proxy',status_code=200,authenticated=True,tool='PROXY',request_content_type='application/json',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp),query={})
        exid=int(r['exchange_id'])
        app=negro_web.create_app('example.test',ws); client=TestClient(app)
        res=client.get(f'/t/{key}/exchange/{exid}/inspect')
        assert res.status_code==200, res.text[:500]
        assert 'HTTP INSPECTOR' in res.text and 'memberId' in res.text and 'RESPONSE' in res.text
        # CSRF is embedded in page; extract it.
        import re
        csrf=re.search(r'name="csrf" value="([^"]+)"',res.text).group(1)
        with core.db_connect(paths) as conn:
            iid=conn.execute("INSERT INTO identities(name,kind,notes,created_at,updated_at) VALUES('Buyer A','account','',datetime('now'),datetime('now'))").lastrowid
        post=client.post(f'/t/{key}/exchange/{exid}/annotate',data={'csrf':csrf,'side':'request','location':'request_json:$.memberId','key':'memberId','value':'101','classification':'resolver','identity_id':str(iid),'object_type':'','note':''},follow_redirects=False)
        assert post.status_code==303, post.text
        res2=client.get(post.headers['location'])
        assert res2.status_code==200 and 'guardado como RESOLVER' in res2.text
        resource_id=core.db_connect(paths).execute if False else None
        with core.db_connect(paths) as conn:
            rid=int(conn.execute("SELECT o.resource_id FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id WHERE e.id=?",(exid,)).fetchone()['resource_id'])
        res3=client.get(f'/t/{key}/resource/{rid}?exchange={exid}')
        assert res3.status_code==200 and 'http-ann-resolver' in res3.text and 'HTTP Inspector' in res3.text
        print('[OK] Inspector GET renders Request/Response and key/value table')
        print('[OK] Inspector POST persists researcher classification through web route')
if __name__=='__main__': main()
