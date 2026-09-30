#!/usr/bin/env python3
from pathlib import Path
import base64, json, tempfile, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_core as core
import negro_hunter as hunter
import negro_web as web


def b64(b: bytes)->str:
    return base64.b64encode(b).decode()


def main():
    with tempfile.TemporaryDirectory(prefix='negro-secret-prov-') as td:
        paths=core.ensure_workspace(Path(td)/'proj','app.example.test',project_name='Secret provenance')
        key='AIza' + ('A'*31) + 'vYUI'  # 39 chars total, valid detector shape
        body=f'''<!doctype html><script>window.google=window.google||{{}};google.maps=google.maps||{{}};google.maps.Load(function(){{}}, "https://maps.googleapis.com", "{key}");</script>'''
        req=b'GET /maps-page HTTP/1.1\r\nHost: app.example.test\r\nCookie: sid=test\r\n\r\n'
        resp=(f'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{body}').encode()
        obs=core.upsert_http_observation(
            paths,'app.example.test',url='https://app.example.test/maps-page',method='GET',source='burp_proxy',status_code=200,
            authenticated=True,tool='PROXY',request_b64=b64(req),response_b64=b64(resp),response_content_type='text/html'
        )
        exid=int(obs['exchange_id'])
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn,exid,'app.example.test',emit_notifications=False)
            lead=conn.execute("SELECT id,resource_id,evidence_json FROM leads_v2 WHERE lead_type='secret_or_client_config' ORDER BY id DESC LIMIT 1").fetchone()
            assert lead is not None
            ev=json.loads(lead['evidence_json'])[0]
            assert ev['exchange_id']==exid
            assert ev['masked_value'].startswith('AIza…')
            assert ev['pattern'].startswith('\\bAIza')
            assert ev['body_offset'] >= 0
            assert key not in ev['context_snippet']
            assert 'AIza…vYUI' in ev['context_snippet']
            details=hunter.secret_evidence_details(conn,ev)
            assert details and details['match_found'] is True
            assert details['exchange_id']==exid
            assert details['resource_id']==int(lead['resource_id'])
            assert details['masked_value'].startswith('AIza…')
            assert details['fingerprint']==ev['fingerprint']
            assert key not in details['context_snippet']
            assert 'Google Maps JavaScript API' in details['context_hint']
            rid=int(lead['resource_id'])
        rows=web._hypothesis_rows(paths)
        secret_row=next(x for x in rows if x['lead_type']=='secret_or_client_config')
        assert secret_row['primary_exchange_id']==exid, secret_row
        assert secret_row['evidence_refs'][0]['exchange_id']==exid, secret_row['evidence_refs']
        assert secret_row['secret_evidence'][0]['match_found'] is True
        detail_view=web._resource_detail(paths,rid,focus_exchange_id=exid)
        focused=[ex for op in detail_view['operations'] for ex in op['exchanges'] if ex.get('focused')]
        assert focused and focused[0]['id']==exid
        assert focused[0]['match_evidence'] and focused[0]['match_evidence'][0]['exchange_id']==exid
        print('[OK] Secret match stores masked provenance')
        print('[OK] Historical secret evidence resolves exact exchange/context')
        print('[OK] Raw secret is not persisted in context snippet')

if __name__=='__main__':
    main()
