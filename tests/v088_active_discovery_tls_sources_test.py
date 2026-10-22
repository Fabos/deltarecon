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


def _fake_recording_runner(outputs):
    def fake(conn, paths, phase, tool, command, **kwargs):
        stdout=outputs.get(tool,'')
        raw=Path(paths['raw'])/'surface-runs'; raw.mkdir(parents=True,exist_ok=True)
        out=raw/f'{tool}.out'; err=raw/f'{tool}.err'; out.write_text(stdout); err.write_text('')
        started=recon._now()
        run_id=recon._record_tool_run(conn,phase,tool,command,'ok',0,len([x for x in stdout.splitlines() if x.strip()]),str(out),str(err),'',started,recon._now(),root_domain=kwargs.get('root_domain','example.com'),run_group=kwargs.get('run_group','g'))
        return {'id':run_id,'status':'ok','return_code':0,'stdout':stdout,'stderr':'','command':command,'error':''}
    return fake


def test_guided_sequence_places_active_and_tls_before_http():
    conn=_conn()
    keys=[p['key'] for p in recon.phase_progress(conn,'example.com')]
    assert keys[:6] == ['root','discovery','active_discovery','dns','tls','http']
    assert keys[-1] == 'services'


def test_active_discovery_imports_only_resolving_names_and_lists_sources(monkeypatch,tmp_path):
    conn=_conn()
    recon.import_discovered_hosts(conn,['api-dev.example.com','api-qa.example.com'],'example.com','subfinder')
    monkeypatch.setattr(recon,'_tool_path',lambda name: f'/bin/{name}' if name in {'alterx','dnsx'} else None)
    outputs={
        'alterx':'api-prod.example.com\napi-stage.example.com\nnoise.other.com\n',
        'dnsx-permutations':'api-prod.example.com\n',
        'dnsx-bruteforce':'admin.example.com\n',
    }
    monkeypatch.setattr(recon,'_run_tool',_fake_recording_runner(outputs))
    paths={'raw':str(tmp_path/'raw')}
    result=recon.run_active_discovery_phase(conn,'example.com',paths,run_group='a')
    assert result['records']==2
    assert recon._discovery_source_hosts(conn,'example.com','active_permutation') == ['api-prod.example.com']
    assert recon._discovery_source_hosts(conn,'example.com','active_bruteforce') == ['admin.example.com']
    detail=recon.phase_detail_data(conn,'example.com','active_discovery')
    summary={x['source']:x for x in detail['source_summary']}
    assert summary['active_permutation']['hosts']==['api-prod.example.com']
    assert summary['active_bruteforce']['hosts']==['admin.example.com']
    assert all('api-stage.example.com' not in x['hosts'] for x in summary.values())


def test_tls_sans_become_candidates_without_downgrading_existing_dns(monkeypatch,tmp_path):
    conn=_conn()
    recon.upsert_asset(conn,'hostname','api.example.com','api.example.com',{'dns_state':'RESOLVED'})
    tls='''===HOST api.example.com===\nsubject=CN = api.example.com\nissuer=CN = Test CA\nnotBefore=Oct 1 00:00:00 2026 GMT\nnotAfter=Oct 1 00:00:00 2027 GMT\nsha256 Fingerprint=AA:BB:CC\nX509v3 Subject Alternative Name:\n    DNS:api.example.com, DNS:auth.example.com, DNS:*.example.com\n===END===\n'''
    monkeypatch.setattr(recon,'_tool_path',lambda name: '/usr/bin/openssl' if name=='openssl' else None)
    monkeypatch.setattr(recon,'_run_tool',_fake_recording_runner({'openssl':tls}))
    paths={'raw':str(tmp_path/'raw')}
    result=recon.run_tls_phase(conn,'example.com',paths,run_group='tls')
    assert 'auth.example.com' in result['san_hosts']
    api=conn.execute("SELECT metadata_json FROM recon_assets WHERE asset_type='hostname' AND asset_key='api.example.com'").fetchone()
    auth=conn.execute("SELECT metadata_json FROM recon_assets WHERE asset_type='hostname' AND asset_key='auth.example.com'").fetchone()
    assert recon._loads(api['metadata_json'])['dns_state']=='RESOLVED'
    assert recon._loads(auth['metadata_json'])['dns_state']=='DISCOVERED'
    detail=recon.phase_detail_data(conn,'example.com','tls')
    assert detail['source_summary'][0]['hosts'] == ['api.example.com','auth.example.com'] or 'auth.example.com' in detail['source_summary'][0]['hosts']
