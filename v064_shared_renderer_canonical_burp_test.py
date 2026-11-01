from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_recon as recon
from negro_web import create_app
from fastapi.testclient import TestClient


def _conn():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    recon.init_schema(conn)
    return conn


def test_crtsh_502_is_source_unavailable_not_zero_result(monkeypatch, tmp_path):
    conn = _conn()
    fake = subprocess.CompletedProcess(
        args=['curl'], returncode=22, stdout='',
        stderr='curl: (22) The requested URL returned error: 502\n'
    )
    monkeypatch.setattr(recon.subprocess, 'run', lambda *a, **k: fake)
    run = recon._run_tool(
        conn, {'raw': str(tmp_path)}, 'discovery', 'crt.sh',
        ['/usr/bin/curl', 'https://crt.sh/'], timeout=30,
        root_domain='example.com', run_group='g1'
    )
    assert run['status'] == 'unavailable'
    row = conn.execute("SELECT status,error FROM recon_tool_runs WHERE tool='crt.sh'").fetchone()
    assert row['status'] == 'unavailable'
    assert 'temporalmente' in row['error'].lower()


def test_amass_concatenated_progress_is_removed_from_clean_view():
    noisy = (
        '1372 / 1473 [------------------------------------>________________] 93.14% 0 p/s'
        '1372 / 1473 [------------------------------------>________________] 93.14% 0 p/s'
        '\ruseful diagnostic: source foo rate limited\n'
    )
    clean = recon._compact_audit_stderr('amass', noisy)
    assert '93.14%' not in clean
    assert 'p/s' not in clean
    assert 'useful diagnostic' in clean


def test_discovery_crtsh_uses_retries():
    src = (ROOT / 'negro_recon.py').read_text(encoding='utf-8')
    assert '"--retry", "3"' in src
    assert '"--retry-delay", "2"' in src
    assert 'run_discovery_source' in src


def test_discovery_detail_has_individual_retry_controls():
    with tempfile.TemporaryDirectory(prefix='negro-v087-') as td:
        workspace = Path(td) / 'workspace'
        core.ensure_workspace(workspace, 'example.com')
        old_targets = core.TARGETS_PATH
        try:
            core.TARGETS_PATH = Path(td) / 'targets.json'
            key = core.register_target('example.com', workspace, make_current=True, name='v087', scopes=['example.com'])
            client = TestClient(create_app('example.com', workspace))
            page = client.get(f'/t/{key}/surface/phase/discovery?root=example.com')
            assert page.status_code == 200
            assert '/surface/discovery/source' in page.text
            assert ('Ejecutar esta fuente' in page.text or 'Reintentar esta fuente' in page.text)
            assert '/surface/discovery/source' in page.text
            assert 'Fuentes útiles' in page.text
        finally:
            core.TARGETS_PATH = old_targets
