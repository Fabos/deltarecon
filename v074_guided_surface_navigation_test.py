from pathlib import Path
import tempfile,base64,json,sys
sys.path.insert(0,'.')
import negro_core as core, negro_http_inspector as hi, negro_identity as ident, negro_web
from fastapi.testclient import TestClient
b64=lambda b: base64.b64encode(b).decode()
def jwt(sub,nonce):
 e=lambda o:base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).decode().rstrip('=')
 return f"{e({'alg':'HS256','typ':'JWT'})}.{e({'sub':sub,'nonce':nonce})}.sig"
with tempfile.TemporaryDirectory() as td:
 root=Path(td); core.CONFIG_PATH=root/'config.json'; core.TARGETS_PATH=root/'targets.json'; ws=root/'ws'; key=core.register_target('example.test',ws,make_current=True,name='Example'); paths=core.ensure_workspace(ws,'example.test')
 t1=jwt('101','a'); t2=jwt('101','b')
 req1=b'POST /login HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{}'; resp1=(f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{"token":"{t1}"}}').encode()
 r1=core.upsert_http_observation(paths,'example.test',url='https://example.test/login',method='POST',source='burp_proxy',tool='PROXY',status_code=200,request_b64=b64(req1),response_b64=b64(resp1),query={}); ex1=int(r1['exchange_id'])
 req2=b'POST /login HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{}'; resp2=(f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{"token":"{t2}"}}').encode()
 r2=core.upsert_http_observation(paths,'example.test',url='https://example.test/login',method='POST',source='burp_proxy',tool='PROXY',status_code=200,request_b64=b64(req2),response_b64=b64(resp2),query={}); ex2=int(r2['exchange_id'])
 with core.db_connect(paths) as c:
  iid=ident.create_identity(c,'Fabian')
  d=hi.extract_exchange(c,ex1); token=next(v for v in d['values'] if v['key']=='token'); hi.save_annotation(c,ex1,side=token['side'],location=token['location'],key=token['key'],value=token['value'],classification='auth',identity_id=iid)
  # teach jwt.sub directly from a synthetic annotation entry via save_annotation with location/key/value
  hi.save_annotation(c,ex1,side='response',location='response_json:$.token#jwt:sub',key='sub',value='101',classification='resolver',identity_id=iid)
  anns=hi.learned_annotations(c,ex2)
  assert any(a['classification']=='auth' and a.get('identity_name')=='Fabian' and 'JWT claim' in a.get('match_reason','') for a in anns),anns
 app=negro_web.create_app('example.test',ws); cl=TestClient(app)
 rd=cl.get(f'/t/{key}/identities/view/{iid}'); assert rd.status_code==200; assert 'Lo que tú enseñaste que identifica a Fabian' in rd.text and 'RESOLVER' in rd.text
 rr=cl.get(f'/t/{key}/resource/{r2["resource_id"]}?exchange={ex2}'); assert rr.status_code==200; assert 'AUTH · Fabian' in rr.text, rr.text[:1000]
 ctx=cl.post('/api/bridge/context',content=f'https://example.test/login\tPOST\t{b64(req2)}'); assert 'AUTH · Fabian' in ctx.json()['response_html']
 print('ok')
