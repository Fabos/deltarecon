from pathlib import Path
import sqlite3
import sys
import json

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_recon as recon


def _conn():
    conn=sqlite3.connect(':memory:'); conn.row_factory=sqlite3.Row
    recon.init_schema(conn)
    return conn


def _fake_recording_runner(outputs):
    def fake(conn, paths, phase, tool, command, **kwargs):
        stdout=outputs.get(tool,'')
        raw=Path(paths['raw'])/'surface-runs'; raw.mkdir(parents=True,exist_ok=True)
        out=raw/f'{tool}.out'; err=raw/f'{tool}.err'; out.write_text(stdout); err.write_text('')
        started=recon._now()
        run_id=recon._record_tool_run(conn,phase,tool,command,'ok',0,len([x for x in stdout.splitlines() if x.strip()]),str(out),str(err),'',started,recon._now(),root_domain=kwargs.get('root_domain','example.com'),run_group=kwargs.get('run_group','g'))
        return {'id':run_id,'status':'ok','return_code':0,'stdout':stdout,'stderr':'','command':command,'error':''}
    return fake


def test_urlscan_history_imports_historical_relationship_without_current_origin_claim(monkeypatch,tmp_path):
    conn=_conn()
    payload={
        'results':[
            {'page':{'domain':'example.com','ip':'203.0.113.10','asn':'AS64500','asnname':'Example ISP','country':'CO'},'task':{'time':'2024-01-01T00:00:00Z'}},
            {'page':{'domain':'api.example.com','ip':'198.51.100.44'},'task':{'time':'2023-02-03T00:00:00Z'}},
            {'page':{'domain':'other.net','ip':'8.8.8.8'},'task':{'time':'2023-02-03T00:00:00Z'}},
        ]
    }
    # Documentation-range IPs are not globally routable according to ipaddress,
    # so use public examples for the actual import assertions.
    payload['results'][0]['page']['ip']='8.8.8.8'
    payload['results'][1]['page']['ip']='1.1.1.1'
    monkeypatch.setattr(recon,'_tool_path',lambda name:'/usr/bin/curl' if name=='curl' else None)
    monkeypatch.setattr(recon,'_run_tool',_fake_recording_runner({'urlscan-history':json.dumps(payload)}))
    monkeypatch.delenv('VIRUSTOTAL_API_KEY',raising=False)
    monkeypatch.delenv('SECURITYTRAILS_API_KEY',raising=False)
    result=recon.run_historical_dns_phase(conn,'example.com',{'raw':str(tmp_path/'raw')},run_group='hist')
    assert result['unique_ips']==2
    rels=conn.execute("SELECT relation FROM recon_relationships").fetchall()
    assert {r['relation'] for r in rels}=={'HISTORICAL_RESOLVES_TO'}
    assert not conn.execute("SELECT 1 FROM recon_relationships WHERE relation='RESOLVES_TO'").fetchone()
    data=recon.surface_data(conn,'example.com',['example.com'])
    root=next(h for h in data['hosts'] if h['hostname']=='example.com')
    api=next(h for h in data['hosts'] if h['hostname']=='api.example.com')
    assert root['historical_ips']==['8.8.8.8']
    assert api['historical_ips']==['1.1.1.1']
    assert root['ips']==[]


def test_vt_resolution_parser_preserves_source_timestamp():
    payload={'data':[{'attributes':{'date':1591813960,'host_name':'example.com','ip_address':'8.8.4.4','resolver':'VirusTotal'}}]}
    rows=recon._parse_virustotal_resolutions(json.dumps(payload),'example.com')
    assert rows[0]['ip']=='8.8.4.4'
    assert rows[0]['hostname']=='example.com'
    assert rows[0]['observed_at_source'].startswith('2020-')


def test_historical_dns_phase_is_after_http_and_before_deep_web_work():
    conn=_conn()
    keys=[p['key'] for p in recon.phase_progress(conn,'example.com')]
    assert keys.index('historical_dns') == keys.index('http') + 1
    assert keys.index('historical_dns') < keys.index('web')
    assert keys.index('historical_dns') < keys.index('infra')


def test_historical_phase_ui_explains_no_automatic_nmap():
    template=(ROOT/'web/templates/surface_phase.html').read_text()
    surface=(ROOT/'web/templates/surface.html').read_text()
    js=(ROOT/'web/static/surface.js').read_text()
    assert 'DNS/IP histórico' in surface
    assert 'no la convierte en target de Nmap automáticamente' in template
    assert 'HISTORICAL_RESOLVES_TO' in js
    assert 'IP histórica' in js


def test_manual_ip_is_candidate_evidence_not_current_resolution():
    conn=_conn()
    item=recon.add_manual_ip_candidate(conn,'example.com','8.8.8.8',hostname='api.example.com',note='mencionada en reunión')
    assert item['relation']=='CANDIDATE_INFRA_IP'
    rel=conn.execute("SELECT relation,confidence_type FROM recon_relationships").fetchone()
    assert rel['relation']=='CANDIDATE_INFRA_IP'
    assert rel['confidence_type']=='manual'
    data=recon.surface_data(conn,'example.com',['example.com'])
    host=next(h for h in data['hosts'] if h['hostname']=='api.example.com')
    assert host['candidate_ips']==['8.8.8.8']
    assert host['ips']==[]
    assert 'manual_ip' in host['sources']


def test_surface_has_manual_ip_evidence_form_and_route():
    template=(ROOT/'web/templates/surface.html').read_text()
    web=(ROOT/'negro_web.py').read_text()
    assert 'Añadir IP conocida / evidencia' in template
    assert 'CANDIDATE_INFRA_IP' in template
    assert '/surface/ip/add' in web
