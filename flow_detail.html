#!/usr/bin/env python3
from pathlib import Path
import base64, json, tempfile, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_hunter as hunter
import negro_intel as intel


def b64(b: bytes)->str: return base64.b64encode(b).decode()

def ingest(paths, domain):
    req=("GET /api/member?memberId=42 HTTP/1.1\r\nHost: app.recalc.test\r\nCookie: sid=test\r\n\r\n").encode()
    resp=("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"memberId\":42,\"name\":\"me\"}").encode()
    return core.upsert_http_observation(
        paths,domain,url='https://app.recalc.test/api/member?memberId=42',method='GET',source='burp_proxy',
        status_code=200,authenticated=True,tool='PROXY',request_b64=b64(req),response_b64=b64(resp),
        response_content_type='application/json',query='memberId=42')


def main():
    with tempfile.TemporaryDirectory(prefix='negro-recalc-') as td:
        root=Path(td)
        old_path=intel.SETTINGS_PATH
        intel.SETTINGS_PATH=root/'settings.json'
        try:
            intel.save_settings({'detector_rule_library':{
                'access_object_reference':{'add':{'identifier_keys':['memberId']}}
            }})
            paths=core.ensure_workspace(root/'ws','app.recalc.test',project_name='Recalc test')
            item=ingest(paths,'app.recalc.test')
            with core.db_connect(paths) as conn:
                hunter.init_schema(conn)
                hunter.analyze_http_exchange(conn,int(item['exchange_id']),'app.recalc.test',emit_notifications=False)
                lead=conn.execute("SELECT id,lead_key,rule_active FROM leads_v2 WHERE lead_type='access_object_reference'").fetchone()
                assert lead and int(lead['rule_active'])==1
                lead_id=int(lead['id'])
                conn.execute("UPDATE leads_v2 SET status='interesting',result_notes='Mi nota humana' WHERE id=?",(lead_id,))

                # This project learns that memberId is noise. Recalc must retire the signal without deleting history.
                project={'access_object_reference':{'exclude':{'identifier_keys':['memberId']}}}
                conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('detector_rules_json',?)",(json.dumps(project),))
                result=hunter.recalculate_intelligence(conn,'app.recalc.test')
                row=conn.execute("SELECT rule_active,status,result_notes FROM leads_v2 WHERE id=?",(lead_id,)).fetchone()
                assert int(row['rule_active'])==0,row
                assert row['status']=='interesting',row
                assert row['result_notes']=='Mi nota humana',row
                assert result['no_longer_matching']>=1,result

                # Remove the project exception. The same stored request should reactivate the existing hypothesis.
                conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('detector_rules_json','{}')")
                result2=hunter.recalculate_intelligence(conn,'app.recalc.test')
                row2=conn.execute("SELECT rule_active,status,result_notes FROM leads_v2 WHERE id=?",(lead_id,)).fetchone()
                assert int(row2['rule_active'])==1,row2
                assert row2['status']=='interesting',row2
                assert row2['result_notes']=='Mi nota humana',row2
                assert result2['reactivated']>=1,result2
                assert result2['network_requests']==0 and result2['ai_calls']==0,result2
        finally:
            intel.SETTINGS_PATH=old_path
    print('[OK] Local intelligence recalculation retires/reactivates rules without deleting human work')

if __name__=='__main__': main()
