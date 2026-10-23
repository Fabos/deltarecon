import sqlite3
from pathlib import Path
import negro_recon as recon


def db():
    c=sqlite3.connect(':memory:'); c.row_factory=sqlite3.Row; recon.init_schema(c); return c


def seed_cloudflare_host(conn):
    hid=recon.upsert_asset(conn,'hostname','terpelpanama.com','terpelpanama.com',{'dns_state':'RESOLVED','cdn':True,'cdn_name':'Cloudflare','sources':['dnsx','httpx']})
    edge=recon.upsert_asset(conn,'ip','104.18.28.76','104.18.28.76',{'sources':['dnsx']})
    recon.link(conn,hid,'RESOLVES_TO',edge,'dnsx')
    pid=recon.upsert_asset(conn,'provider','cloudflare','Cloudflare',{'provider_type':'cdn'})
    recon.link(conn,hid,'PROXIED_BY',pid,'httpx')
    conn.commit(); return hid


def fake_tools(name):
    return f'/usr/bin/{name}'


def fake_run(conn, paths, phase, tool, command, **kwargs):
    if tool=='whois-enrichment':
        return {'status':'ok','stdout':'''===WHOIS 104.18.28.76===\nOrgName: Cloudflare, Inc.\nOriginAS: AS13335\n===END WHOIS===\n===WHOIS 201.225.241.35===\nowner: Cable & Wireless Panama\naut-num: AS11556\ncountry: PA\n===END WHOIS===\n''','stderr':'','error':'','command':command}
    if tool=='direct-correlation':
        return {'status':'ok','stdout':'''===INFRA terpelpanama.com\t201.225.241.35===\nFRONT_CODE\t200\nDIRECT_HTTPS_CODE\t200\nDIRECT_HTTP_CODE\t200\nFRONT_HASH\tabc123\nDIRECT_HTTPS_HASH\tabc123\nDIRECT_HTTP_HASH\tdef456\nFRONT_LAST_MODIFIED\tTue, 07 Jul 2026 14:31:02 GMT\nDIRECT_LAST_MODIFIED\tTue, 07 Jul 2026 14:31:02 GMT\nDIRECT_SERVER\tApache/2.4.6 (CentOS)\nCERT\tsubject=CN=www.terpelpanama.com\nCERT\tissuer=CN=Network Solutions DV Server CA 2\nCERT\t    DNS:www.terpelpanama.com, DNS:terpelpanama.com\n===END INFRA===\n''','stderr':'','error':'','command':command}
    raise AssertionError(tool)


def test_manual_ip_can_be_correlated_behind_cloudflare(monkeypatch,tmp_path):
    conn=db(); seed_cloudflare_host(conn)
    recon.add_manual_ip_candidate(conn,'terpelpanama.com','201.225.241.35',hostname='terpelpanama.com',note='meeting')
    monkeypatch.setattr(recon,'_tool_path',fake_tools)
    monkeypatch.setattr(recon,'_run_tool',fake_run)
    result=recon.run_infrastructure_phase(conn,'terpelpanama.com',{'raw':tmp_path},run_group='g1')
    assert result['direct_candidates']==1
    findings=recon.infrastructure_findings(conn,'terpelpanama.com')
    by_ip={x['ip']:x for x in findings}
    assert by_ip['104.18.28.76']['classification']=='EDGE_SHARED'
    cand=by_ip['201.225.241.35']
    assert cand['classification']=='DIRECT_BACKEND_CANDIDATE'
    assert cand['tls_hostname_match'] is True
    assert cand['content_hash_match'] is True
    assert cand['bypass_possible'] is True
    assert cand['nmap_eligibility']=='CANDIDATE_AFTER_SCOPE_VALIDATION'


def test_historical_only_stays_passive_until_explicit_probe(monkeypatch,tmp_path):
    conn=db(); hid=recon.upsert_asset(conn,'hostname','example.com','example.com',{'dns_state':'RESOLVED'})
    iid=recon.upsert_asset(conn,'ip','203.0.113.55','203.0.113.55')
    # use a globally routable documentation-looking substitute accepted by ipaddress? 203.0.113/24 is not global in Python,
    # so seed a real-looking public address directly at relationship layer for this deterministic unit test.
    iid=recon.upsert_asset(conn,'ip','8.8.4.4','8.8.4.4')
    recon.link(conn,hid,'HISTORICAL_RESOLVES_TO',iid,'urlscan_history',confidence=.7,confidence_type='historical'); conn.commit()
    monkeypatch.setattr(recon,'_tool_path',fake_tools)
    calls=[]
    def runner(conn, paths, phase, tool, command, **kwargs):
        calls.append(tool)
        if tool=='whois-enrichment':
            return {'status':'ok','stdout':'===WHOIS 8.8.4.4===\nOrgName: Example Hosting\nOriginAS: AS64500\n===END WHOIS===\n','stderr':'','error':'','command':command}
        raise AssertionError('historical-only IP must not be actively probed by default')
    monkeypatch.setattr(recon,'_run_tool',runner)
    result=recon.run_infrastructure_phase(conn,'example.com',{'raw':tmp_path},run_group='g2')
    assert calls==['whois-enrichment']
    assert result['pending_historical']==1
    finding=recon.infrastructure_findings(conn,'example.com')[0]
    assert finding['classification']=='HISTORICAL_IP'
    assert finding['nmap_eligibility']=='NOT_READY'


def test_infra_phase_is_ready_before_deep_web_enumeration(monkeypatch):
    conn=db()
    phases=recon.phase_progress(conn,'example.com')
    keys=[x['key'] for x in phases]
    assert keys.index('historical_dns') < keys.index('infra') < keys.index('web') < keys.index('services')
    infra=next(x for x in phases if x['key']=='infra')
    assert infra['implemented'] is True
