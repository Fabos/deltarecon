import json
import sqlite3
from pathlib import Path
import negro_recon as nr

ROOT = Path(__file__).resolve().parents[1]


def test_whois_prefers_organization_over_terse_netname():
    parsed = nr._parse_whois_bundle('''===WHOIS 128.245.112.15===\nNetName: SALESF-3\nOrganization: Salesforce, Inc. (SALESF-3)\n===END WHOIS===\n''')
    assert parsed['128.245.112.15']['owner'].startswith('Salesforce, Inc.')
    assert nr._provider_kind([parsed['128.245.112.15']['owner']]) == 'saas'


def test_read_time_normalizes_legacy_salesforce_direct_finding():
    conn=sqlite3.connect(':memory:'); conn.row_factory=sqlite3.Row; nr.init_schema(conn)
    host='view.marketing.example.com'; ip='128.245.112.15'; root='example.com'
    hid=nr.upsert_asset(conn,'hostname',host,label=host,metadata={})
    nr.add_evidence(conn,hid,'infra_analysis','infrastructure_classification',ip,{
        'classification':'DIRECT_BACKEND_CANDIDATE',
        'confidence':'HIGH',
        'confidence_score':0.98,
        'owner':'SALESF-3',
        'providers':[],
        'nmap_eligibility':'CANDIDATE_AFTER_SCOPE_VALIDATION',
        'bypass_possible':True,
        'reasons':['legacy'],
    })
    conn.commit()
    f=nr.infrastructure_findings(conn,root)[0]
    assert f['classification']=='THIRD_PARTY_PLATFORM'
    assert f['nmap_eligibility']=='DO_NOT_SCAN_THIRD_PARTY'
    assert f['bypass_possible'] is False


def test_graph_merges_edge_provider_and_groups_current_historical_ips():
    js=(ROOT/'web/static/surface.js').read_text(encoding='utf-8')
    css=(ROOT/'web/static/style.css').read_text(encoding='utf-8')
    assert "return 'Cloudflare'" in js
    assert "CURRENT EDGE · ${currentEdge.length}" in js
    assert "HISTORICAL EDGE · ${historicalEdge.length}" in js
    assert "expandedInfraGroups.has(groupKey)" in js
    assert "SECURED_BY" in js
    assert "Do not render Cloudflare twice" in js
    assert ".surface-node.edgegroup" in css
    assert ".surface-node.control" in css


def test_apex_layers_are_added_once():
    js=(ROOT/'web/static/surface.js').read_text(encoding='utf-8')
    needle="if(expandedHosts.has(rootAsset.hostname) && (!focusHost || rootAsset.hostname===focusHost)) addHostLayers(scene,rootAsset,apexId,layers);"
    assert js.count(needle)==1
