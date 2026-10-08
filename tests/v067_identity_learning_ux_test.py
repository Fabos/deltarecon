from pathlib import Path
import tempfile,base64,json,sys
sys.path.insert(0,'.')
import negro_core as core, negro_http_inspector as hi, negro_identity as ident, negro_web
from fastapi.testclient import TestClient

b64=lambda b: base64.b64encode(b).decode()
def jwt(sub,nonce):
    enc=lambda o:base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).decode().rstrip('=')
    return f"{enc({'alg':'HS256','typ':'JWT'})}.{enc({'sub':sub,'nonce':nonce})}.sig"
def add(paths,url,method,req,resp,status=200):
    r=core.upsert_http_observation(paths,'example.test',url=url,method=method,source='burp_proxy',tool='PROXY',status_code=status,request_b64=b64(req),response_b64=b64(resp),query={})
    return int(r['exchange_id'])

with tempfile.TemporaryDirectory() as td:
    root=Path(td); core.CONFIG_PATH=root/'config.json'; core.TARGETS_PATH=root/'targets.json'; ws=root/'ws'; key=core.register_target('example.test',ws,make_current=True,name='Example'); paths=core.ensure_workspace(ws,'example.test')
    ex1=add(paths,'https://example.test/me','POST',b'POST /me HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{"memberId":"101"}',b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}')
    ex2=add(paths,'https://example.test/profile','POST',b'POST /profile HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{"customerNumber":"101"}',b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}')
    t1=jwt('101','a'); t2=jwt('101','b')
    ex3=add(paths,'https://example.test/login','POST',b'POST /login HTTP/1.1\r\nHost: example.test\r\n\r\n',f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{"token":"{t1}"}}'.encode())
    ex4=add(paths,'https://example.test/refresh','POST',b'POST /refresh HTTP/1.1\r\nHost: example.test\r\n\r\n',f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{"accessToken":"{t2}"}}'.encode())
    with core.db_connect(paths) as c:
        iid=ident.create_identity(c,'Fabian')
        d1=hi.extract_exchange(c,ex1); mv=next(v for v in d1['values'] if v['key']=='memberId')
        hi.save_annotation(c,ex1,side=mv['side'],location=mv['location'],key=mv['key'],value=mv['value'],classification='resolver',identity_id=iid)

        d2=hi.extract_exchange(c,ex2); anns2=hi.learned_annotations(c,ex2); summary2=hi.decorate_inspector_identity_state(c,d2,anns2,{})
        cv=next(v for v in d2['values'] if v['key']=='customerNumber')
        assert cv['ui_state']=='suggested',cv
        assert cv['identity_suggestion']['identity_name']=='Fabian'
        assert not any(a.get('classification')=='resolver' and a.get('key_name')=='customerNumber' for a in anns2),anns2

        # A fresh JWT whose strong claim uniquely matches the confirmed resolver is learned automatically as AUTH.
        auto3=hi.auto_learn_jwt_auth(c,ex3); assert any(x.get('state')=='auto_auth' and x.get('identity_name')=='Fabian' for x in auto3.values()),auto3
        anns3=hi.learned_annotations(c,ex3); assert any(a.get('classification')=='auth' and a.get('identity_name')=='Fabian' for a in anns3),anns3
        d3=hi.extract_exchange(c,ex3); summary3=hi.decorate_inspector_identity_state(c,d3,anns3,auto3)
        tv=next(v for v in d3['values'] if v['key']=='token'); assert tv['ui_state']=='recognized' and tv['auto_jwt']['identity_name']=='Fabian',tv
        assert next(cl for cl in tv['jwt_claims'] if cl['key']=='sub')['ui_state']=='recognized'

        # Rotation does not need manual teaching and the dossier remains compact by auth family.
        hi.learned_annotations(c,ex4)
        detail=ident.identity_detail(c,iid)
        assert len(detail['grouped_evidence']['auth'])==1,detail['grouped_evidence']['auth']
        assert detail['grouped_evidence']['auth'][0].get('history_count',0)>=1

    app=negro_web.create_app('example.test',ws); cl=TestClient(app)
    page=cl.get(f'/t/{key}/exchange/{ex2}/inspect?identity_id={iid}')
    assert page.status_code==200
    assert 'POR REVISAR' in page.text and 'MATCH · Fabian' in page.text and 'Confirmar RESOLVER' in page.text
    assert 'Ya marcados / reconocidos' in page.text
    assert 'Buscar Fabian, memberId' in page.text
    jwt_page=cl.get(f'/t/{key}/exchange/{ex3}/inspect?identity_id={iid}')
    assert jwt_page.status_code==200
    assert 'AUTO · AUTH · Fabian' in jwt_page.text
    assert 'jwt-claim-key' in jwt_page.text and 'jwt-claim-value' in jwt_page.text
    print('ok')
