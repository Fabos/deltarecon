#!/usr/bin/env python3
from pathlib import Path
import base64
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import negro_core as core
import negro_flows as flows
import negro_flow_runtime as runtime


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def capture(paths, domain, path):
    req=f"GET {path} HTTP/1.1\r\nHost: api.v108.local\r\n\r\n".encode()
    resp=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    return core.upsert_http_observation(paths,domain,url=f"https://api.v108.local{path}",method="GET",source="burp_proxy",status_code=200,authenticated=False,tool="PROXY",request_b64=b64(req),response_b64=b64(resp),query={})


def test_flow_ui_has_bulk_selection_and_pointer_drag():
    text=(ROOT/'web/templates/flow_detail.html').read_text()
    css=(ROOT/'web/static/style.css').read_text()
    assert 'data-flow-select-step' in text
    assert 'data-flow-select-all' in text
    assert 'Quitar seleccionadas del Flow' in text
    assert 'pointerdown' in text and 'pointermove' in text and 'pointerup' in text
    assert 'setPointerCapture' in text
    assert 'draggable="true" data-drag-handle' not in text
    assert 'touch-action:none' in css


def test_bulk_remove_keeps_blocked_and_removes_safe_steps():
    with tempfile.TemporaryDirectory(prefix='negro-v108-') as td:
        domain='api.v108.local'
        paths=core.ensure_workspace(Path(td)/'project',domain)
        ex=[capture(paths,domain,f'/x/{i}') for i in range(3)]
        with core.db_connect(paths) as conn:
            fid=flows.create_flow(conn,'Bulk cleanup')
            sids=[flows.add_step(conn,fid,int(x['exchange_id'])) for x in ex]
            runtime.init_schema(conn)
            now='2026-10-25T00:00:00Z'
            cur=conn.execute("INSERT INTO flow_variables(flow_id,name,source_type,default_value,created_at,updated_at) VALUES(?,?,?,?,?,?)",(fid,'token','CONSTANT','x',now,now))
            vid=int(cur.lastrowid)
            conn.execute("INSERT INTO flow_step_variable_bindings(flow_id,flow_step_id,variable_id,target_value,created_at,updated_at) VALUES(?,?,?,?,?,?)",(fid,sids[1],vid,'x',now,now))
            result=flows.remove_steps_bulk(conn,fid,sids)
            assert set(result['removed'])=={sids[0],sids[2]}
            assert [b['step_id'] for b in result['blocked']]==[sids[1]]
            left=conn.execute('SELECT id,position FROM flow_steps WHERE flow_id=? ORDER BY position',(fid,)).fetchall()
            assert [(int(r['id']),int(r['position'])) for r in left]==[(sids[1],1)]
