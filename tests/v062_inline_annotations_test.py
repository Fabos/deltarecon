#!/usr/bin/env python3
from pathlib import Path
import base64, json, sys, tempfile
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_http_inspector as hi
import negro_identity as identity
try:
    from fastapi.testclient import TestClient
    import negro_web
except Exception:
    TestClient=None

def b64(x: bytes): return base64.b64encode(x).decode()
def jwt(sub='1121903105'):
    enc=lambda o: base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).decode().rstrip('=')
    return f"{enc({'alg':'HS256','typ':'JWT'})}.{enc({'sub':sub,'role':'customer'})}.sig"

def main():
  with tempfile.TemporaryDirectory(prefix='negro-v062-') as td:
    root=Path(td); core.CONFIG_PATH=root/'config.json'; core.TARGETS_PATH=root/'targets.json'
    ws=root/'ws'; key=core.register_target('example.test',ws,make_current=True,name='Example'); paths=core.ensure_workspace(ws,'example.test')
    tok=jwt()
    req1=b'POST /login HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{"memberId":"1121903105"}'
    resp1=(f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{"token":"{tok}"}}').encode()
    r1=core.upsert_http_observation(paths,'example.test',url='https://example.test/login',method='POST',source='burp_proxy',tool='PROXY',status_code=200,request_b64=b64(req1),response_b64=b64(resp1),query={})
    ex1=int(r1['exchange_id'])
    req2=(f'GET /me HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {tok}\r\n\r\n').encode()
    resp2=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"memberId":"1121903105"}'
    r2=core.upsert_http_observation(paths,'example.test',url='https://example.test/me',method='GET',source='burp_proxy',tool='PROXY',status_code=200,request_b64=b64(req2),response_b64=b64(resp2),query={})
    ex2=int(r2['exchange_id'])
    with core.db_connect(paths) as conn:
      iid=identity.create_identity(conn,'Fabian')
      d=hi.extract_exchange(conn,ex1)
      token=next(v for v in d['values'] if v['side']=='response' and v['key']=='token')
      member=next(v for v in d['values'] if v['side']=='request' and v['key']=='memberId')
      hi.save_annotation(conn,ex1,side=token['side'],location=token['location'],key=token['key'],value=token['value'],classification='auth',identity_id=iid)
      hi.save_annotation(conn,ex1,side=member['side'],location=member['location'],key=member['key'],value=member['value'],classification='resolver',identity_id=iid)
      anns=hi.learned_annotations(conn,ex2)
      assert any(a['classification']=='auth' and a.get('identity_name')=='Fabian' for a in anns), anns
      assert any(a['classification']=='resolver' and a.get('identity_name')=='Fabian' for a in anns), anns
      h=hi.highlighted_html(hi.extract_exchange(conn,ex2)['request_text'],anns,'request')
      assert 'AUTH · Fabian' in h and 'http-ann-auth' in h, h
      # Path/key precision: unrelated same value should not become resolver when key differs.
      req3=b'GET /x HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{"orderId":"1121903105"}'
      rr=core.upsert_http_observation(paths,'example.test',url='https://example.test/x',method='GET',source='burp_proxy',tool='PROXY',status_code=200,request_b64=b64(req3),response_b64=b64(b'HTTP/1.1 200 OK\r\n\r\n'),query={})
      anns3=hi.learned_annotations(conn,int(rr['exchange_id']))
      assert not any(a['classification']=='resolver' for a in anns3), anns3
    if TestClient:
      app=negro_web.create_app('example.test',ws); c=TestClient(app)
      ctx=c.post('/api/bridge/context',content=f'https://example.test/me\tGET\t{b64(req2)}')
      assert ctx.status_code==200,ctx.text
      j=ctx.json(); assert 'request_html' in j and 'AUTH · Fabian' in j['request_html'], j.keys()
    print('[OK] learned AUTH/RESOLVER propagate to future HTTP with key/path precision')
    print('[OK] inline renderer exposes AUTH · Fabian and Bridge returns annotated HTML')
if __name__=='__main__': main()
