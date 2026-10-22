from pathlib import Path
import sqlite3
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

import negro_core as core
import negro_recon as recon
from negro_web import create_app



def test_ungrouped_family_hosts_receive_layout_positions_and_roots_persist_open_state():
    js = (ROOT / 'web/static/surface.js').read_text(encoding='utf-8')
    assert "e.source.startsWith('family:')&&e.target.startsWith('host:')" in js
    assert 'expandedRootsStateKey' in js
    assert 'persistExpandedRoots()' in js


def test_manual_hostname_becomes_discovery_evidence_and_dns_candidate():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    recon.init_schema(conn)
    result = recon.add_manual_hostnames(conn, 'example.com', ['api.example.com', 'qa.example.com'], 'mencionado en reunión')
    assert result['added'] == 2
    rows = conn.execute("SELECT source,kind,value,raw_json FROM recon_evidence ORDER BY id").fetchall()
    assert len(rows) == 2
    assert all(r['source'] == 'manual' and r['kind'] == 'discovered_hostname' for r in rows)
    hosts = recon._first_party_hostnames(conn, 'example.com')
    assert hosts == ['api.example.com', 'qa.example.com']
    surface = recon.surface_data(conn, 'example.com', ['example.com'])
    assert {x['hostname'] for x in surface['manual_hosts']} == {'api.example.com', 'qa.example.com'}
    phase = next(p for p in surface['phases'] if p['key'] == 'discovery')
    assert phase['secondary_counts']['Manual'] == 2


def test_surface_remembers_active_root_cookie_and_manual_add_route():
    with tempfile.TemporaryDirectory(prefix='negro-v086-') as td:
        old = core.TARGETS_PATH
        try:
            core.TARGETS_PATH = Path(td) / 'targets.json'
            workspace = Path(td) / 'ws'
            core.ensure_workspace(workspace, 'alpha.test', scopes=['alpha.test', 'beta.test'])
            key = core.register_target('alpha.test', workspace, make_current=True, name='Multi', scopes=['alpha.test', 'beta.test'], recon_roots=['alpha.test', 'beta.test'])
            client = TestClient(create_app('alpha.test', workspace))

            page = client.get(f'/t/{key}/surface?root=beta.test')
            assert page.status_code == 200
            assert 'beta.test' in page.text
            # A later navigation without ?root keeps beta.test as the active recon root.
            remembered = client.get(f'/t/{key}/surface')
            assert remembered.status_code == 200
            assert '<h2>beta.test</h2>' in remembered.text

            csrf = remembered.text.split('name="csrf" value="',1)[1].split('"',1)[0]
            add = client.post(
                f'/t/{key}/surface/host/add',
                data={'csrf': csrf, 'root': 'beta.test', 'manual_hosts': 'api.beta.test\nqa.beta.test', 'note': 'reunión interna'},
                follow_redirects=True,
            )
            assert add.status_code == 200
            assert 'Hosts añadidos manualmente' in add.text
            assert 'api.beta.test' in add.text
            assert 'reunión interna' in add.text
        finally:
            core.TARGETS_PATH = old
