import sqlite3
import negro_recon as recon


def db():
    c=sqlite3.connect(':memory:'); c.row_factory=sqlite3.Row; recon.init_schema(c); return c


def test_probe_parser_accepts_literal_backslash_t_from_v093():
    text = r'''===INFRA terpelpanama.com\t201.225.241.35===
FRONT_CODE\t200
DIRECT_HTTPS_CODE\t200
FRONT_HASH\tabc123
DIRECT_HTTPS_HASH\tabc123
CERT\t    DNS:www.terpelpanama.com, DNS:terpelpanama.com
===END INFRA==='''.replace('FRONT_CODE\\t','FRONT_CODE\t').replace('DIRECT_HTTPS_CODE\\t','DIRECT_HTTPS_CODE\t').replace('FRONT_HASH\\t','FRONT_HASH\t').replace('DIRECT_HTTPS_HASH\\t','DIRECT_HTTPS_HASH\t').replace('CERT\\t','CERT\t')
    parsed = recon._parse_infra_probe_bundle(text)
    item = parsed[('terpelpanama.com','201.225.241.35')]
    assert item['front_hash']=='abc123'
    assert item['direct_https_hash']=='abc123'
    assert 'terpelpanama.com' in item['cert_sans']


def test_current_salesforce_owner_is_third_party_and_not_probed(monkeypatch,tmp_path):
    conn=db()
    hid=recon.upsert_asset(conn,'hostname','click.marketing.example.com','click.marketing.example.com',{'dns_state':'RESOLVED'})
    iid=recon.upsert_asset(conn,'ip','128.245.96.12','128.245.96.12')
    recon.link(conn,hid,'RESOLVES_TO',iid,'dnsx'); conn.commit()
    monkeypatch.setattr(recon,'_tool_path',lambda n:f'/usr/bin/{n}')
    calls=[]
    def runner(conn,paths,phase,tool,command,**kwargs):
        calls.append(tool)
        if tool=='whois-enrichment':
            return {'status':'ok','stdout':'===WHOIS 128.245.96.12===\nOrgName: Salesforce, Inc.\n===END WHOIS===\n','stderr':'','error':'','command':command}
        raise AssertionError('Salesforce third-party IP must not be direct-probed')
    monkeypatch.setattr(recon,'_run_tool',runner)
    result=recon.run_infrastructure_phase(conn,'example.com',{'raw':tmp_path},run_group='g')
    finding=recon.infrastructure_findings(conn,'example.com')[0]
    assert finding['classification']=='THIRD_PARTY_PLATFORM'
    assert finding['nmap_eligibility']=='DO_NOT_SCAN_THIRD_PARTY'
    assert result['direct_candidates']==0
    assert calls==['whois-enrichment']


def test_probed_historical_ip_without_strong_match_stays_historical(monkeypatch,tmp_path):
    conn=db()
    hid=recon.upsert_asset(conn,'hostname','example.com','example.com',{'dns_state':'RESOLVED'})
    iid=recon.upsert_asset(conn,'ip','8.8.8.8','8.8.8.8')
    recon.link(conn,hid,'HISTORICAL_RESOLVES_TO',iid,'virustotal_history',confidence=.8,confidence_type='historical'); conn.commit()
    monkeypatch.setattr(recon,'_tool_path',lambda n:f'/usr/bin/{n}')
    def runner(conn,paths,phase,tool,command,**kwargs):
        if tool=='whois-enrichment':
            return {'status':'ok','stdout':'===WHOIS 8.8.8.8===\nOrgName: Example Network\n===END WHOIS===\n','stderr':'','error':'','command':command}
        if tool=='direct-correlation':
            return {'status':'ok','stdout':'===INFRA example.com\\t8.8.8.8===\nFRONT_CODE\t200\nDIRECT_HTTPS_CODE\t200\nDIRECT_HTTP_CODE\t200\nFRONT_HASH\tfront\nDIRECT_HTTPS_HASH\tdifferent\nCERT\tsubject=CN=other.example\nCERT\t    DNS:other.example\n===END INFRA===\n','stderr':'','error':'','command':command}
        raise AssertionError(tool)
    monkeypatch.setattr(recon,'_run_tool',runner)
    recon.run_infrastructure_phase(conn,'example.com',{'raw':tmp_path},run_group='g2',probe_historical=True)
    finding=recon.infrastructure_findings(conn,'example.com')[0]
    assert finding['classification']=='HISTORICAL_IP'
    assert finding['nmap_eligibility']=='NOT_READY'
