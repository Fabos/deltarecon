#!/usr/bin/env python3
from pathlib import Path
import base64, json, sys, tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_http_inspector as hi
import negro_identity as identity
import negro_objects as objects
import negro_parameters as params

def b64(x: bytes): return base64.b64encode(x).decode()
def jwt(sub='101'):
    enc=lambda o: base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).decode().rstrip('=')
    return f"{enc({'alg':'none'})}.{enc({'sub':sub,'role':'buyer','tenantId':'co','iat':123})}.sig"

def main():
    with tempfile.TemporaryDirectory(prefix='negro-http-inspector-') as td:
        paths=core.ensure_workspace(Path(td)/'p','example.test')
        token=jwt()
        req=b'POST /orders?debug=1 HTTP/1.1\r\nHost: api.example.test\r\nContent-Type: application/json\r\nCookie: _ga=noise; session=sess123\r\n\r\n{"orderId":"ORD-999","memberId":"101"}'
        resp=(f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: csrf=abc\r\n\r\n{{"accessToken":"{token}","orderId":"ORD-999","status":"CREATED"}}').encode()
        result=core.upsert_http_observation(paths,'example.test',url='https://api.example.test/orders?debug=1',method='POST',source='burp_proxy',status_code=200,authenticated=True,tool='PROXY',request_content_type='application/json',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp),query={'debug':['1']})
        exid=int(result['exchange_id'])
        # second exchange with same resolver value but no auth should resolve automatically
        req2=b'POST /orders/next HTTP/1.1\r\nHost: api.example.test\r\nContent-Type: application/json\r\n\r\n{"orderId":"ORD-1000","memberId":"101"}'
        resp2=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"status":"CREATED"}'
        result2=core.upsert_http_observation(paths,'example.test',url='https://api.example.test/orders/next',method='POST',source='burp_proxy',status_code=200,authenticated=False,tool='PROXY',request_content_type='application/json',response_content_type='application/json',request_b64=b64(req2),response_b64=b64(resp2),query={})
        ex2=int(result2['exchange_id'])
        with core.db_connect(paths) as conn:
            params.persist_exchange_parameters(conn,exid)
            data=hi.extract_exchange(conn,exid)
            assert data
            vals={(v['side'],v['key']):v for v in data['values']}
            assert ('response','accessToken') in vals, vals.keys()
            assert vals[('response','accessToken')]['jwt']['claims']['sub']=='101'
            assert ('request','orderId') in vals and ('response','orderId') in vals
            iid=identity.create_identity(conn,'Buyer A')
            v=vals[('response','accessToken')]
            hi.save_annotation(conn,exid,side=v['side'],location=v['location'],key=v['key'],value=v['value'],classification='auth',identity_id=iid)
            auth=conn.execute("SELECT * FROM auth_materials WHERE identity_id=? AND material_type='bearer'",(iid,)).fetchone()
            assert auth and auth['classification']=='auth'
            # explicit request JSON resolver should resolve later traffic at the same semantic location
            mv=vals[('request','memberId')]
            hi.save_annotation(conn,exid,side=mv['side'],location=mv['location'],key=mv['key'],value=mv['value'],classification='resolver',identity_id=iid)
            auto2=identity.resolve_exchange(conn,ex2)
            assert auto2 and int(auto2['identity_id'])==iid, auto2
            # claim resolver from response JWT
            hi.save_annotation(conn,exid,side='response',location=v['location']+'#jwt:sub',key='jwt.sub',value='101',classification='resolver',identity_id=iid)
            rr=conn.execute("SELECT * FROM identity_resolvers WHERE identity_id=? AND selector=?",(iid,v['location']+'#jwt:sub')).fetchone()
            assert rr and rr['enabled']==1
            # changing to ignore disables derived resolver
            hi.save_annotation(conn,exid,side='response',location=v['location']+'#jwt:sub',key='jwt.sub',value='101',classification='ignore')
            rr=conn.execute("SELECT * FROM identity_resolvers WHERE identity_id=? AND selector=?",(iid,v['location']+'#jwt:sub')).fetchone()
            assert rr and rr['enabled']==0 and rr['classification']=='ignore'
            # memberId resolver is still active, so the anchor remains resolvable. Now ignore it too.
            hi.save_annotation(conn,exid,side=mv['side'],location=mv['location'],key=mv['key'],value=mv['value'],classification='ignore')
            future=conn.execute("SELECT * FROM exchange_identities WHERE exchange_id=?",(ex2,)).fetchone()
            assert future is None, dict(future) if future else None
            # promote orderId to Entity
            ov=vals[('request','orderId')]
            hi.save_annotation(conn,exid,side=ov['side'],location=ov['location'],key=ov['key'],value=ov['value'],classification='entity',object_type='Order')
            assert conn.execute("SELECT COUNT(*) c FROM business_object_types WHERE name_key='order' ").fetchone()['c'] == 1
            d2=hi.extract_exchange(conn,exid)
            assert any(a['classification']=='entity' for a in d2['annotations'])
            rendered=hi.highlighted_html(d2['request_text'],d2['annotations'],'request')
            assert 'http-ann-entity' in rendered and 'ORD-999' in rendered
        print('[OK] response JWT extracted with claims')
        print('[OK] AUTH/RESOLVER decisions persist and resolver -> IGNORE removes semantic edge')
        print('[OK] request/response key-value extraction promotes Entity and highlights HTTP')
if __name__=='__main__': main()
