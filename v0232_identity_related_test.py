#!/usr/bin/env python3
from __future__ import annotations
import base64, pathlib, tempfile, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import negro_core as core
import negro_scope as scope
import negro_search as search

def b64(s): return base64.b64encode(s.encode()).decode()

def main():
    root=pathlib.Path(tempfile.mkdtemp(prefix='negro-scope-sync-'))
    paths=core.ensure_workspace(root,'example.com')
    a=core.upsert_http_observation(paths,'example.com',url='https://api.example.com/orders/1',method='GET',source='burp_proxy',tool='PROXY',status_code=200,burp_in_scope=True,request_b64=b64('GET /orders/1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n'),response_b64=b64('HTTP/1.1 200 OK\r\n\r\n'))
    b=core.upsert_http_observation(paths,'example.com',url='https://api.example.com/analytics',method='POST',source='burp_proxy',tool='PROXY',status_code=204,burp_in_scope=False,request_b64=b64('POST /analytics HTTP/1.1\r\nHost: api.example.com\r\n\r\n'),response_b64=b64('HTTP/1.1 204 No Content\r\n\r\n'))
    with core.db_connect(paths) as conn:
        rows=[dict(r) for r in conn.execute('SELECT id,burp_scope_status FROM http_exchanges ORDER BY id')]
        assert [x['burp_scope_status'] for x in rows]==['IN_SCOPE','EXCLUDED'],rows
        search.index_exchange(conn,a['exchange_id']); search.index_exchange(conn,b['exchange_id'])
        assert [r['exchange_id'] for r in search.search(conn,'scope:in')['results']]==[a['exchange_id']]
        assert [r['exchange_id'] for r in search.search(conn,'scope:excluded')['results']]==[b['exchange_id']]
        rid=conn.execute("SELECT r.id FROM resources r WHERE r.url='https://api.example.com/analytics'").fetchone()['id']
        ids=scope.set_resource_scope(conn,rid,'IN_SCOPE')
        for eid in ids: search.index_exchange(conn,eid)
        assert [r['exchange_id'] for r in search.search(conn,'scope:in')['results']]==[a['exchange_id'],b['exchange_id']]
    print('[OK] Burp scope is persisted per exchange, searchable, and historical status can be reconciled')
if __name__=='__main__': main()
