import sqlite3
from pathlib import Path
import negro_recon as nr


def test_salesforce_owner_always_beats_direct_backend_signals(tmp_path, monkeypatch):
    conn=sqlite3.connect(':memory:'); conn.row_factory=sqlite3.Row; nr.init_schema(conn)
    host='click.marketing.example.com'; ip='128.245.96.12'; root='example.com'
    hid=nr.upsert_asset(conn,'hostname',host,label=host,metadata={})
    iid=nr.upsert_asset(conn,'ip',ip,label=ip,metadata={})
    evid=nr.add_evidence(conn,hid,'historical_dns','historical_a',ip,{})
    nr.link(conn,hid,'HISTORICAL_RESOLVES_TO',iid,'historical_dns',confidence=1.0,confidence_type='observed',evidence_id=evid)

    def fake_run_tool(conn_, paths, phase, tool, command, **kwargs):
        if tool=='whois-enrichment':
            return {'status':'ok','stdout':f'===WHOIS {ip}===\nOrgName: Salesforce, Inc.\n===END WHOIS===\n','stderr':'','error':'','command':command}
        if tool=='direct-correlation':
            raise AssertionError('Known SaaS IP must not be direct-probed')
        return {'status':'ok','stdout':'','stderr':'','error':'','command':command}
    monkeypatch.setattr(nr,'_run_tool',fake_run_tool)
    monkeypatch.setattr(nr.shutil,'which',lambda x: '/usr/bin/'+x if x in {'whois','bash','curl','openssl','timeout'} else None)
    res=nr.run_infrastructure_phase(conn,root,{'raw':tmp_path},probe_historical=True)
    findings=nr.infrastructure_findings(conn,root)
    assert len(findings)==1
    f=findings[0]
    assert f['classification']=='THIRD_PARTY_PLATFORM'
    assert f['nmap_eligibility']=='DO_NOT_SCAN_THIRD_PARTY'
    assert res['direct_candidates']==0


def test_current_salesforce_never_becomes_direct_backend_even_with_probe_payload(tmp_path, monkeypatch):
    conn=sqlite3.connect(':memory:'); conn.row_factory=sqlite3.Row; nr.init_schema(conn)
    host='view.marketing.example.com'; ip='128.245.112.15'; root='example.com'
    hid=nr.upsert_asset(conn,'hostname',host,label=host,metadata={})
    iid=nr.upsert_asset(conn,'ip',ip,label=ip,metadata={})
    evid=nr.add_evidence(conn,hid,'dns','a_record',ip,{})
    nr.link(conn,hid,'RESOLVES_TO',iid,'dns',confidence=1.0,confidence_type='observed',evidence_id=evid)

    calls=[]
    def fake_run_tool(conn_, paths, phase, tool, command, **kwargs):
        calls.append(tool)
        if tool=='whois-enrichment':
            return {'status':'ok','stdout':f'===WHOIS {ip}===\nOrgName: Salesforce, Inc.\n===END WHOIS===\n','stderr':'','error':'','command':command}
        if tool=='direct-correlation':
            raise AssertionError('Known SaaS IP must not be direct-probed')
        return {'status':'ok','stdout':'','stderr':'','error':'','command':command}
    monkeypatch.setattr(nr,'_run_tool',fake_run_tool)
    monkeypatch.setattr(nr.shutil,'which',lambda x: '/usr/bin/'+x if x in {'whois','bash','curl','openssl','timeout'} else None)
    nr.run_infrastructure_phase(conn,root,{'raw':tmp_path},probe_historical=True)
    f=nr.infrastructure_findings(conn,root)[0]
    assert f['classification']=='THIRD_PARTY_PLATFORM'
    assert f['nmap_eligibility']=='DO_NOT_SCAN_THIRD_PARTY'
    assert 'direct-correlation' not in calls
