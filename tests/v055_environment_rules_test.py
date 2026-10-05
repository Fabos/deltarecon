#!/usr/bin/env python3
from __future__ import annotations
import base64, pathlib, tempfile, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import negro_core as core
import negro_environment as env
import negro_search as search

def b64(s): return base64.b64encode(s.encode()).decode()

def add(paths, url):
    host=url.split('/')[2]
    return core.upsert_http_observation(paths,'empresa.com',url=url,method='GET',source='burp_proxy',status_code=200,
        request_b64=b64(f'GET /orders/1 HTTP/1.1\r\nHost: {host}\r\n\r\n'),response_b64=b64('HTTP/1.1 200 OK\r\n\r\n{}'))

def main():
    root=pathlib.Path(tempfile.mkdtemp(prefix='negro-env-rules-'))
    paths=core.ensure_workspace(root,'empresa.com')
    qa=add(paths,'https://cert-api.empresa.com/orders/1')
    prod=add(paths,'https://api.empresa.com/orders/1')
    manual=add(paths,'https://special.empresa.com/orders/1')
    with core.db_connect(paths) as conn:
        env.set_exchange_environment(conn, manual['exchange_id'], 'STAGING')
        stats=env.replace_project_rules(conn, '*.empresa.com = PROD\ncert-*.empresa.com = QA', 'UNKNOWN', now='2026-10-05T12:00:00')
        # First-match semantics: broad rule first wins.
        assert conn.execute('SELECT environment FROM http_exchanges WHERE id=?',(qa['exchange_id'],)).fetchone()['environment']=='PROD'
        stats=env.replace_project_rules(conn, 'cert-*.empresa.com = QA\n*.empresa.com = PROD', 'UNKNOWN', now='2026-10-05T12:01:00')
        row=conn.execute('SELECT environment,environment_source FROM http_exchanges WHERE id=?',(qa['exchange_id'],)).fetchone()
        assert dict(row)=={'environment':'QA','environment_source':'rule'}, dict(row)
        row=conn.execute('SELECT environment,environment_source FROM http_exchanges WHERE id=?',(manual['exchange_id'],)).fetchone()
        assert dict(row)=={'environment':'STAGING','environment_source':'manual'}, dict(row)
        assert search.search(conn,'env:QA')['results'][0]['exchange_id']==qa['exchange_id']
    # New traffic uses saved project rules automatically.
    qa2=add(paths,'https://cert-new.empresa.com/orders/1')
    with core.db_connect(paths) as conn:
        row=conn.execute('SELECT environment,environment_source FROM http_exchanges WHERE id=?',(qa2['exchange_id'],)).fetchone()
        assert dict(row)=={'environment':'QA','environment_source':'rule'}, dict(row)
    print('[OK] Environment Rules reclassify history on save, preserve manual overrides and classify new traffic')
if __name__=='__main__': main()
