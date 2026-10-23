from pathlib import Path
import sqlite3
import negro_recon as recon

ROOT = Path(__file__).resolve().parents[1]


def db():
    c = sqlite3.connect(':memory:')
    c.row_factory = sqlite3.Row
    recon.init_schema(c)
    return c


def test_surface_data_exposes_only_strong_backend_as_confirmed(monkeypatch):
    conn = db()
    recon.upsert_asset(conn, 'hostname', 'terpelpanama.com', 'terpelpanama.com', {'dns_state':'RESOLVED'})
    conn.commit()
    findings = [
        {'hostname':'terpelpanama.com','ip':'201.225.241.35','classification':'DIRECT_BACKEND_CANDIDATE','confidence':'HIGH','tls_hostname_match':True,'content_hash_match':True,'nmap_eligibility':'CANDIDATE_AFTER_SCOPE_VALIDATION'},
        {'hostname':'terpelpanama.com','ip':'9.9.9.9','classification':'DIRECT_BACKEND_CANDIDATE','confidence':'HIGH','tls_hostname_match':True,'content_hash_match':False,'nmap_eligibility':'CANDIDATE_AFTER_SCOPE_VALIDATION'},
    ]
    monkeypatch.setattr(recon, 'infrastructure_findings', lambda _c, root: findings if root == 'terpelpanama.com' else [])
    data = recon.surface_data(conn, 'terpelpanama.com', ['terpelpanama.com'])
    host = next(h for h in data['hosts'] if h['hostname']=='terpelpanama.com')
    assert set(host['possible_origin_ips']) == {'201.225.241.35','9.9.9.9'}
    assert host['confirmed_origin_ips'] == ['201.225.241.35']


def test_surface_graph_has_branch_focus_and_confirmed_origin_visuals():
    js = (ROOT/'web/static/surface.js').read_text(encoding='utf-8')
    css = (ROOT/'web/static/style.css').read_text(encoding='utf-8')
    html = (ROOT/'web/templates/surface.html').read_text(encoding='utf-8')
    assert 'data-surface-focus-branch' in html
    assert 'let branchFocus = true' in js
    assert 'if(rootAsset && !(focusHost && focusRoot===rr)) addHostLayers' in js
    assert "(!focusHost || h.hostname===focusHost)" in js
    assert 'focus-muted' in js and '.surface-node.focus-muted' in css
    assert 'confirmed_origin_ips' in js
    assert 'CONFIRMED_DIRECT_BACKEND' in js
    assert 'surface-origin-badge' in js and '.surface-node.ip.confirmed-origin' in css
    assert 'IP DIRECTA CONFIRMADA' in js
