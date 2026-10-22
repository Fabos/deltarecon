from pathlib import Path
import sqlite3
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_recon as recon


def _conn():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    recon.init_schema(conn)
    return conn


def test_run_tool_timeout_preserves_partial_stdout(monkeypatch, tmp_path):
    conn = _conn()
    exc = subprocess.TimeoutExpired(
        cmd=['amass'], timeout=900,
        output='api.example.com\nqa.example.com\n',
        stderr='10 / 20 [---->____] 50.00% 2 p/s\r'
    )
    monkeypatch.setattr(recon.subprocess, 'run', lambda *a, **k: (_ for _ in ()).throw(exc))
    run = recon._run_tool(conn, {'raw': str(tmp_path)}, 'discovery', 'amass', ['/bin/amass'], timeout=900, root_domain='example.com')
    assert run['status'] == 'partial'
    assert 'api.example.com' in run['stdout']
    row = conn.execute("SELECT status,record_count,error FROM recon_tool_runs WHERE tool='amass'").fetchone()
    assert row['status'] == 'partial'
    assert row['record_count'] == 2
    assert '900s' in row['error']


def test_amass_progress_is_hidden_from_inline_audit():
    noisy = '10 / 20 [---->____] 50.00% 2 p/s\rreal diagnostic\n20 / 20 [--------] 100.00% 1 p/s\r'
    clean = recon._compact_audit_stderr('amass', noisy)
    assert '50.00%' not in clean
    assert '100.00%' not in clean
    assert 'real diagnostic' in clean


def test_amass_gets_longer_discovery_timeout():
    source = (ROOT / 'negro_recon.py').read_text(encoding='utf-8')
    assert '"discovery", "amass", cmd, timeout=max(timeout, 900)' in source


def test_root_hostname_is_not_duplicated_as_family_child_and_gets_layers():
    js = (ROOT / 'web/static/surface.js').read_text(encoding='utf-8')
    assert "const rootAsset=rootHosts.find(h=>h.hostname===rr)||null;" in js
    assert "const childHosts=rootHosts.filter(h=>h.hostname!==rr);" in js
    assert "if(rootAsset) addHostLayers(scene,rootAsset,rid,layers);" in js
    assert "if(n.meta?.host) renderDetail(n.meta.host); else renderNodeDetail(n,scene);" in js
