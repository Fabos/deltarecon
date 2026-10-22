from pathlib import Path
import sqlite3
import tempfile
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import negro_core as core
import negro_recon as recon
from negro_web import create_app
from fastapi.testclient import TestClient


def test_out_of_order_http_evidence_does_not_skip_guided_steps():
    conn=sqlite3.connect(':memory:'); conn.row_factory=sqlite3.Row
    recon.init_schema(conn)
    # Fake successful HTTP run without completing discovery/DNS.
    conn.execute("""INSERT INTO recon_tool_runs(phase,tool,root_domain,run_group,command_json,status,return_code,record_count,stdout_path,stderr_path,error,started_at,finished_at)
                    VALUES('http','httpx','example.com','g','[]','ok',0,1,'','','','now','now')""")
    conn.commit()
    phases=recon.phase_progress(conn,'example.com')
    root=next(p for p in phases if p['key']=='root')
    discovery=next(p for p in phases if p['key']=='discovery')
    http=next(p for p in phases if p['key']=='http')
    assert root['state'] in {'ready','missing_tool'}
    assert discovery['state']=='blocked'
    assert http['state']=='evidence'
    assert not http['done']


def test_recon_roots_are_separate_from_general_scopes():
    with tempfile.TemporaryDirectory(prefix='negro-v074-roots-') as td:
        old=core.TARGETS_PATH
        try:
            core.TARGETS_PATH=Path(td)/'targets.json'
            ws=Path(td)/'ws'
            key=core.register_target('example.com',ws,scopes=['example.com','api.example.com','partner.invalid'])
            target=core.get_target(key)
            assert target['scopes']==['example.com','api.example.com','partner.invalid']
            assert target['recon_roots']==['example.com']
            core.update_target_project(key,scopes=target['scopes']+['example.net'],recon_roots=['example.com','example.net'])
            target=core.get_target(key)
            assert target['recon_roots']==['example.com','example.net']
        finally:
            core.TARGETS_PATH=old


def test_phase_has_dedicated_audit_page_and_main_card_links_to_it():
    with tempfile.TemporaryDirectory(prefix='negro-v074-web-') as td:
        old=core.TARGETS_PATH
        try:
            core.TARGETS_PATH=Path(td)/'targets.json'
            ws=Path(td)/'ws'; core.ensure_workspace(ws,'example.com')
            key=core.register_target('example.com',ws,scopes=['example.com'])
            client=TestClient(create_app('example.com',ws))
            page=client.get(f'/t/{key}/surface')
            assert page.status_code==200
            assert f'/t/{key}/surface/phase/root?root=example.com' in page.text
            detail=client.get(f'/t/{key}/surface/phase/root?root=example.com')
            assert detail.status_code==200
            assert 'Comando y salida real' in detail.text
            assert 'EVIDENCIA NORMALIZADA' in detail.text
            assert 'Disponibilidad local' in detail.text
        finally:
            core.TARGETS_PATH=old


def test_surface_js_expands_host_layers_on_click():
    js=(ROOT/'web'/'static'/'surface.js').read_text(encoding='utf-8')
    assert 'expandedHosts.add(n.key)' in js
    assert "if(!collapsed || expandedHosts.has(h.hostname)) addHostLayers" in js
