from pathlib import Path
import sqlite3
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_recon as recon
from negro_web import create_app
from fastapi.testclient import TestClient


def test_nmap_is_late_and_dns_follows_discovery():
    conn=sqlite3.connect(':memory:'); conn.row_factory=sqlite3.Row
    recon.init_schema(conn)
    phases=recon.surface_data(conn,'example.com')['phases']
    keys=[p['key'] for p in phases]
    assert keys.index('discovery') < keys.index('dns') < keys.index('http') < keys.index('services')
    assert 'discovery_expand' not in keys
    assert keys.index('historical_dns') < keys.index('infra') < keys.index('web') < keys.index('services')
    assert keys[-1] == 'services'


def test_imported_hosts_do_not_mark_discovery_phase_done_without_execution():
    conn=sqlite3.connect(':memory:'); conn.row_factory=sqlite3.Row
    recon.init_schema(conn)
    recon.import_subfinder_text(conn,'api.example.com\n','example.com')
    phase=next(p for p in recon.surface_data(conn,'example.com')['phases'] if p['key']=='discovery')
    assert phase['count'] == 1
    assert phase['state'] != 'done'


def test_phase_card_exposes_real_latest_stdout():
    with tempfile.TemporaryDirectory(prefix='negro-v073-') as td:
        root=Path(td); paths=core.ensure_workspace(root/'ws','example.com')
        fake=root/'subfinder'; fake.write_text("#!/bin/sh\nprintf 'api.example.com\\nwww.example.com\\n'\n",encoding='utf-8'); fake.chmod(0o755)
        old=recon._tool_path
        try:
            recon._tool_path=lambda name: str(fake) if name=='subfinder' else None
            with core.db_connect(paths) as conn:
                recon.init_schema(conn)
                conn.execute("""INSERT INTO recon_tool_runs(phase,tool,root_domain,run_group,command_json,status,return_code,record_count,stdout_path,stderr_path,error,started_at,finished_at) VALUES('root','curl','example.com','root','[]','ok',0,1,'','','','now','now')""")
                conn.commit()
                recon.run_phase(conn,'example.com',paths,'discovery')
                phase=next(p for p in recon.surface_data(conn,'example.com')['phases'] if p['key']=='discovery')
            assert phase['state']=='done'
            assert 'api.example.com' in phase['latest_runs'][0]['stdout_preview']
            assert 'subfinder' in phase['latest_runs'][0]['command']
        finally:
            recon._tool_path=old


def test_surface_shows_root_selector_and_add_scope_form():
    with tempfile.TemporaryDirectory(prefix='negro-v073-web-') as td:
        workspace=Path(td)/'ws'; core.ensure_workspace(workspace,'example.com',scopes=['example.com','example.net'])
        old=core.TARGETS_PATH
        try:
            core.TARGETS_PATH=Path(td)/'targets.json'
            key=core.register_target('example.com',workspace,make_current=True,name='Multi root',scopes=['example.com','example.net'],recon_roots=['example.com','example.net'])
            client=TestClient(create_app('example.com',workspace))
            page=client.get(f'/t/{key}/surface?root=example.net')
            assert page.status_code==200
            assert 'example.net' in page.text
            assert 'Añadir dominio al proyecto' in page.text
            assert 'Ver resultado' in page.text
        finally:
            core.TARGETS_PATH=old
