from pathlib import Path
import sqlite3
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_recon as recon


def _conn():
    conn=sqlite3.connect(':memory:'); conn.row_factory=sqlite3.Row
    recon.init_schema(conn)
    return conn


def test_baseline_batch_is_persistent_and_reports_project_status():
    conn=_conn()
    batch=recon.create_baseline_batch(conn,['alpha.test','beta.test'])
    assert len(batch['jobs'])==2
    data=recon.project_baseline_data(conn,['alpha.test','beta.test'])
    assert data['active'] is True
    assert data['counts']['queued']==2
    assert set(data['latest_by_root'])=={'alpha.test','beta.test'}




def test_interrupted_baseline_becomes_retryable():
    conn=_conn()
    recon.create_baseline_batch(conn,['example.com'])
    assert recon.project_baseline_data(conn,['example.com'])['active'] is True
    assert recon.recover_interrupted_baseline_jobs(conn)==1
    data=recon.project_baseline_data(conn,['example.com'])
    assert data['active'] is False
    assert data['failed_roots']==['example.com']
    assert 'Reintentar fallidos' in data['latest_by_root']['example.com']['error']


def test_baseline_root_runs_breadth_pipeline_and_refreshes_dns_after_tls(monkeypatch,tmp_path):
    conn=_conn()
    job=recon.create_baseline_batch(conn,['example.com'])['jobs'][0]
    calls=[]

    def root_phase(conn,root,paths,**kw):
        calls.append('root')
        recon.upsert_asset(conn,'hostname',root,root,{'sources':['root_recon'],'dns_state':'RESOLVED'})
        conn.commit(); return {'records':1}
    def discovery(conn,root,paths,**kw):
        calls.append('discovery'); recon.import_discovered_hosts(conn,['api.example.com'],root,'subfinder'); return {'records':1}
    def active(conn,root,paths,**kw):
        calls.append('active_discovery'); recon.import_discovered_hosts(conn,['qa.example.com'],root,'active_bruteforce'); return {'records':1}
    def dns(conn,root,paths,**kw):
        calls.append('dns')
        for host in recon._first_party_hostnames(conn,root):
            row=conn.execute("SELECT id,metadata_json FROM recon_assets WHERE asset_type='hostname' AND asset_key=?",(host,)).fetchone()
            meta=recon._merge_meta(recon._loads(row['metadata_json']),{'dns_state':'RESOLVED'})
            conn.execute('UPDATE recon_assets SET metadata_json=? WHERE id=?',(recon.json.dumps(meta),row['id']))
        hid=recon.upsert_asset(conn,'hostname','api.example.com','api.example.com',{'dns_state':'RESOLVED'})
        tid=recon.upsert_asset(conn,'hostname','orphan.vendor.invalid','orphan.vendor.invalid',{})
        recon.link(conn,hid,'CNAME_TO',tid,'dnsx'); conn.commit(); return {'records':1}
    def tls(conn,root,paths,**kw):
        calls.append('tls'); recon.import_discovered_hosts(conn,['san.example.com'],root,'tls_san'); return {'records':1}
    def takeover(conn,root,paths,**kw):
        calls.append('takeover'); return {'records':1,'candidates':1}
    def historical_dns(conn,root,paths,**kw):
        calls.append('historical_dns'); return {'records':1,'unique_ips':1}
    def infra(conn,root,paths,**kw):
        calls.append('infra')
        assert kw.get('probe_historical') is False
        assert kw.get('active_correlation') is False
        return {'records':1,'direct_candidates':1,'active_correlation':False}
    def http(conn,root,paths,**kw):
        calls.append('http')
        for host in recon._first_party_hostnames(conn,root,resolved_only=True):
            row=conn.execute("SELECT id,metadata_json FROM recon_assets WHERE asset_type='hostname' AND asset_key=?",(host,)).fetchone()
            meta=recon._merge_meta(recon._loads(row['metadata_json']),{'status_code':200,'http_state':'OBSERVED'})
            conn.execute('UPDATE recon_assets SET metadata_json=? WHERE id=?',(recon.json.dumps(meta),row['id']))
        conn.commit(); return {'records':1}

    monkeypatch.setattr(recon,'run_root_phase',root_phase)
    monkeypatch.setattr(recon,'run_discovery_phase',discovery)
    monkeypatch.setattr(recon,'run_active_discovery_phase',active)
    monkeypatch.setattr(recon,'run_dns_phase',dns)
    monkeypatch.setattr(recon,'run_tls_phase',tls)
    monkeypatch.setattr(recon,'run_takeover_analysis',takeover)
    monkeypatch.setattr(recon,'run_http_phase',http)
    monkeypatch.setattr(recon,'run_historical_dns_phase',historical_dns)
    monkeypatch.setattr(recon,'run_infrastructure_phase',infra)

    result=recon.run_project_baseline_root(conn,'example.com',{'raw':str(tmp_path/'raw')},job['id'])
    assert result['status']=='done'
    assert calls==['root','discovery','active_discovery','dns','tls','dns','takeover','http','historical_dns','infra']
    state=recon.project_baseline_data(conn,['example.com'])['latest_by_root']['example.com']
    assert state['status']=='done'
    assert state['percent']==100


def test_project_surface_exposes_triage_without_calling_it_a_vulnerability():
    conn=_conn()
    recon.import_discovered_hosts(conn,['api-qa.example.com'],'example.com','active_bruteforce')
    row=conn.execute("SELECT id,metadata_json FROM recon_assets WHERE asset_type='hostname' AND asset_key='api-qa.example.com'").fetchone()
    meta=recon._merge_meta(recon._loads(row['metadata_json']),{'dns_state':'RESOLVED','status_code':500,'environment':'QA','takeover_state':'CANDIDATE'})
    conn.execute('UPDATE recon_assets SET metadata_json=? WHERE id=?',(recon.json.dumps(meta),row['id']))
    conn.commit()
    data=recon.surface_data(conn,'example.com',['example.com'])
    item=next(h for h in data['project_hosts'] if h['hostname']=='api-qa.example.com')
    assert item['interest_level']=='HIGH'
    assert item['interest_score']>=6
    assert 'ambiente QA' in item['interest_reasons']
    assert data['project_summary']['takeover_candidates']==1
    assert data['top_interest'][0]['hostname']=='api-qa.example.com'


def test_surface_template_contains_project_baseline_controls_and_live_polling():
    template=(ROOT/'web/templates/surface.html').read_text()
    js=(ROOT/'web/static/surface.js').read_text()
    web=(ROOT/'negro_web.py').read_text()
    assert 'Ejecutar baseline del scope' in template
    assert 'Reintentar fallidos' in template
    assert 'Targets para triage' in template
    assert 'surface/baseline/start' in web
    assert 'surface/baseline/retry' in web
    assert 'max_workers=2' in web
    assert 'data-baseline-panel' in js
    assert 'data-baseline-api' in template
