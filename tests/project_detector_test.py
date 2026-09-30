#!/usr/bin/env python3
from pathlib import Path
import base64, json, tempfile, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_hunter as hunter
import negro_intel as intel
import negro_rules as rules


def b64(b: bytes)->str: return base64.b64encode(b).decode()

def ingest(paths, domain, host, origin=None, acao=None, path='/api/me', query=None):
    req_headers=[]; resp_headers=[]
    if origin: req_headers.append({'name':'Origin','value':origin})
    if acao:
        resp_headers += [{'name':'Access-Control-Allow-Origin','value':acao},{'name':'Access-Control-Allow-Credentials','value':'true'}]
    target=path + (('?' + query) if query else '')
    req=(f"GET {target} HTTP/1.1\r\nHost: {host}\r\nCookie: sid=test\r\n" + (f"Origin: {origin}\r\n" if origin else '') + "\r\n").encode()
    resp=("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" + (f"Access-Control-Allow-Origin: {acao}\r\nAccess-Control-Allow-Credentials: true\r\n" if acao else '') + "\r\n{\"id\":1}").encode()
    return core.upsert_http_observation(paths,domain,url=f'https://{host}{target}',method='GET',source='burp_proxy',status_code=200,authenticated=True,tool='PROXY',request_b64=b64(req),response_b64=b64(resp),request_headers=req_headers,response_headers=resp_headers,response_content_type='application/json',query=query)

def main():
    with tempfile.TemporaryDirectory(prefix='negro-project-') as td:
        root=Path(td)
        paths=core.ensure_workspace(root/'p1','app.alpha.test',scopes=['app.alpha.test','api.beta.test'],project_name='ACME Pentest')
        assert core.workspace_scopes(paths,'app.alpha.test') == ['app.alpha.test','api.beta.test']
        ingest(paths,'app.alpha.test','api.beta.test')
        with core.db_connect(paths) as conn:
            hosts={r['hostname'] for r in conn.execute('select hostname from hosts')}
        assert 'api.beta.test' in hosts, hosts

        # Cross-origin between project scopes is first-party noise.
        y=ingest(paths,'app.alpha.test','api.beta.test','https://app.alpha.test','https://app.alpha.test')
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn,int(y['exchange_id']),'app.alpha.test',emit_notifications=True)
            assert conn.execute("select count(*) c from leads_v2 where lead_type='cors'").fetchone()['c']==0

        old_path=intel.SETTINGS_PATH
        intel.SETTINGS_PATH=root/'settings.json'
        try:
            # Personal library teaches Negro a program vocabulary term.
            intel.save_settings({'detector_rule_library':{
                'access_object_reference':{'add':{'identifier_keys':['memberId']},'conditions':{'require_authenticated':True}},
                'cors':{'conditions':{'require_credentials':True}}
            }})
            with core.db_connect(paths) as conn:
                cfg=hunter.detector_settings('access_object_reference',conn)
                assert any(x.lower()=='memberid' for x in cfg['lists']['identifier_keys']), cfg
                assert 'memberId' in cfg['provenance']['identifier_keys']['personal']

                # Project can suppress a globally useful term without deleting it from personal knowledge.
                project={'access_object_reference':{'exclude':{'identifier_keys':['memberId']}}}
                conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('detector_rules_json',?)",(json.dumps(project),))
                cfg2=hunter.detector_settings('access_object_reference',conn)
                assert all(x.lower()!='memberid' for x in cfg2['lists']['identifier_keys']), cfg2

            # A different new project automatically inherits personal knowledge.
            paths2=core.ensure_workspace(root/'p2','shop.gamma.test',project_name='Second project')
            with core.db_connect(paths2) as conn:
                cfg3=hunter.detector_settings('access_object_reference',conn)
                assert any(x.lower()=='memberid' for x in cfg3['lists']['identifier_keys']), cfg3
            m=ingest(paths2,'shop.gamma.test','shop.gamma.test',path='/api/member',query='memberId=42')
            with core.db_connect(paths2) as conn:
                hunter.analyze_http_exchange(conn,int(m['exchange_id']),'shop.gamma.test',emit_notifications=False)
                lead=conn.execute("SELECT evidence_json FROM leads_v2 WHERE lead_type='access_object_reference' ORDER BY id DESC LIMIT 1").fetchone()
                assert lead is not None
                ev=json.loads(lead['evidence_json'])
                matches=ev[0]['rule_match']['parameter_matches']
                assert any(x.get('reason')=='exact:memberId' for x in matches), matches

            # Project exclusion must suppress even the generic *Id suffix fallback.
            noisy=ingest(paths,'app.alpha.test','api.beta.test',path='/api/member',query='memberId=42')
            with core.db_connect(paths) as conn:
                before=conn.execute("SELECT COUNT(*) c FROM leads_v2 WHERE lead_type='access_object_reference'").fetchone()['c']
                hunter.analyze_http_exchange(conn,int(noisy['exchange_id']),'app.alpha.test',emit_notifications=False)
                after=conn.execute("SELECT COUNT(*) c FROM leads_v2 WHERE lead_type='access_object_reference'").fetchone()['c']
                assert after==before,(before,after)

            # Per-project disable remains possible and suppresses external CORS.
            with core.db_connect(paths) as conn:
                row=conn.execute("SELECT value FROM meta WHERE key='detector_rules_json'").fetchone()
                project=json.loads(row['value']) if row and row['value'] else {}
                project['cors']={'enabled':False}
                conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('detector_rules_json',?)",(json.dumps(project),))
            z=ingest(paths,'app.alpha.test','api.beta.test','https://evil.example','https://evil.example')
            with core.db_connect(paths) as conn:
                hunter.analyze_http_exchange(conn,int(z['exchange_id']),'app.alpha.test',emit_notifications=True)
                assert conn.execute("select count(*) c from leads_v2 where lead_type='cors'").fetchone()['c']==0

        finally:
            intel.SETTINGS_PATH=old_path

        print('[OK] Project multi-scope ingestion')
        print('[OK] Project-aware first-party CORS')
        print('[OK] Personal knowledge inheritance')
        print('[OK] Project exclusions and detector overrides')

if __name__=='__main__': main()
