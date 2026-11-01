#!/usr/bin/env python3
"""Regression: researcher-controlled Identity evidence classification/editing."""
from pathlib import Path
import base64, json, sys, tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_identity as identity


def b64(b: bytes)->str: return base64.b64encode(b).decode()
def jwt(sub='101'):
    enc=lambda o: base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).decode().rstrip('=')
    return f"{enc({'alg':'none'})}.{enc({'sub':sub,'role':'buyer','tenantId':'co','iat':123})}.sig"

def capture(paths, domain, n, token=None):
    auth=f"Authorization: Bearer {token}\r\n" if token else ""
    req=(f"GET /account/{n} HTTP/1.1\r\nHost: api.example.test\r\n{auth}Cookie: _ga=GA1.noise; rxNumDocumento=1121903105; acceptedCookies=true\r\n\r\n").encode()
    resp=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}'
    return core.upsert_http_observation(paths,domain,url=f"https://api.example.test/account/{n}",method='GET',source='burp_proxy',status_code=200,authenticated=True,tool='PROXY',request_content_type='application/json',response_content_type='application/json',request_b64=b64(req),response_b64=b64(resp),query={})

def main():
    with tempfile.TemporaryDirectory(prefix='negro-v054-') as td:
        domain='api.example.test'; paths=core.ensure_workspace(Path(td)/'project',domain)
        ex1=capture(paths,domain,1,jwt()); ex2=capture(paths,domain,2,None)
        with core.db_connect(paths) as conn:
            iid=identity.create_identity(conn,'Buyer A')
            identity.assign_exchange(conn,int(ex1['exchange_id']),iid,learn_auth=False,source='burp')
            cands=identity.identity_evidence_candidates(conn,int(ex1['exchange_id']))
            by_name={(c['kind'],c['name']):c for c in cands}
            assert by_name[('material','_ga')]['default_classification']=='ignore', by_name
            assert by_name[('material','acceptedCookies')]['default_classification']=='ignore', by_name
            assert by_name[('jwt_claim','sub')]['default_classification']=='resolver', by_name
            assert by_name[('jwt_claim','role')]['default_classification']=='context', by_name
            assert by_name[('jwt_claim','iat')]['default_classification']=='ignore', by_name
            rx=by_name[('material','rxNumDocumento')]
            decisions={c['candidate_id']:'ignore' for c in cands}
            decisions[rx['candidate_id']]='resolver'
            learned=identity.apply_evidence_decisions(conn,int(ex1['exchange_id']),iid,decisions,source='burp_create')
            assert learned['resolver']==1, learned
            row=identity.resolve_exchange(conn,int(ex2['exchange_id']))
            assert row and int(row['identity_id'])==iid, row
            mat=conn.execute("SELECT id,classification FROM auth_materials WHERE identity_id=? AND material_name='rxNumDocumento' ORDER BY id LIMIT 1",(iid,)).fetchone()
            assert mat and mat['classification']=='resolver', dict(mat) if mat else None
            identity.set_evidence_classification(conn,iid,'material',int(mat['id']),'ignore')
            auto=conn.execute("SELECT * FROM exchange_identities WHERE exchange_id=?",(int(ex2['exchange_id']),)).fetchone()
            assert auto is None, dict(auto) if auto else None
            anchor=conn.execute("SELECT * FROM exchange_identities WHERE exchange_id=?",(int(ex1['exchange_id']),)).fetchone()
            assert anchor and int(anchor['identity_id'])==iid and anchor['source']=='burp', dict(anchor) if anchor else None
            idx=conn.execute("SELECT DISTINCT identity_id FROM identifier_observation_index WHERE exchange_id=?",(int(ex2['exchange_id']),)).fetchall()
            assert all(r['identity_id'] is None for r in idx), [dict(r) for r in idx]
        print('[OK] tracking/noise defaults to IGNORE while stable JWT claims are typed')
        print('[OK] researcher can classify material as RESOLVER and resolve compatible traffic')
        print('[OK] changing RESOLVER -> IGNORE removes derived Identity edges/index but preserves manual anchor')
if __name__=='__main__': main()
