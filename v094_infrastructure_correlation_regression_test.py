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


def _runner(outputs):
    def fake(conn, paths, phase, tool, command, **kwargs):
        stdout=outputs.get(tool,'')
        raw=Path(paths['raw'])/'surface-runs'; raw.mkdir(parents=True,exist_ok=True)
        out=raw/f'{tool}.out'; err=raw/f'{tool}.err'; out.write_text(stdout); err.write_text('')
        started=recon._now()
        run_id=recon._record_tool_run(conn,phase,tool,command,'ok',0,len([x for x in stdout.splitlines() if x.strip()]),str(out),str(err),'',started,recon._now(),root_domain=kwargs.get('root_domain','example.com'),run_group=kwargs.get('run_group','g'))
        return {'id':run_id,'status':'ok','return_code':0,'stdout':stdout,'stderr':'','command':command,'error':''}
    return fake


def test_takeover_analysis_reuses_external_cname_and_marks_nxdomain(monkeypatch,tmp_path):
    conn=_conn()
    recon.import_discovered_hosts(conn,['old.example.com'],'example.com','subfinder')
    recon.import_dnsx_text(conn,'old.example.com [CNAME] [missing.vendor.invalid]\n','example.com')
    monkeypatch.setattr(recon,'_tool_path',lambda name: f'/usr/bin/{name}' if name in {'dig','curl'} else None)
    outputs={
        'dig-upstream':'old.example.com\tmissing.vendor.invalid\tNXDOMAIN\t\n',
        'curl-fingerprint':'===TAKEOVER old.example.com\tmissing.vendor.invalid===\ncurl: (6) Could not resolve host\n===END TAKEOVER===\n',
    }
    monkeypatch.setattr(recon,'_run_tool',_runner(outputs))
    result=recon.run_takeover_analysis(conn,'example.com',{'raw':str(tmp_path/'raw')},run_group='t')
    assert result['candidates']==1
    findings=recon.takeover_findings(conn,'example.com')
    assert findings[0]['hostname']=='old.example.com'
    assert findings[0]['candidate'] is True
    assert findings[0]['confidence']=='MEDIUM'
    assert findings[0]['claimability']=='NOT_VALIDATED'


def test_takeover_fingerprint_is_high_candidate_but_never_confirmed(monkeypatch,tmp_path):
    conn=_conn()
    recon.import_discovered_hosts(conn,['docs.example.com'],'example.com','subfinder')
    recon.import_dnsx_text(conn,'docs.example.com [CNAME] [acme.github.io]\n','example.com')
    monkeypatch.setattr(recon,'_tool_path',lambda name: f'/usr/bin/{name}' if name in {'dig','curl'} else None)
    outputs={
        'dig-upstream':'docs.example.com\tacme.github.io\tNOERROR\t185.199.108.153\n',
        'curl-fingerprint':"===TAKEOVER docs.example.com\tacme.github.io===\nThere isn't a GitHub Pages site here.\n===END TAKEOVER===\n",
    }
    monkeypatch.setattr(recon,'_run_tool',_runner(outputs))
    result=recon.run_takeover_analysis(conn,'example.com',{'raw':str(tmp_path/'raw')},run_group='t')
    item=result['items'][0]
    assert item['confidence']=='HIGH'
    assert item['fingerprint']['provider']=='GitHub Pages'
    assert item['confirmed'] is False
    assert item['claimability']=='NOT_VALIDATED'


def test_dns_detail_exposes_takeover_panel_data(monkeypatch,tmp_path):
    conn=_conn()
    recon.import_discovered_hosts(conn,['old.example.com'],'example.com','subfinder')
    recon.import_dnsx_text(conn,'old.example.com [CNAME] [missing.vendor.invalid]\n','example.com')
    monkeypatch.setattr(recon,'_tool_path',lambda name: f'/usr/bin/{name}' if name in {'dig','curl','dnsx'} else None)
    monkeypatch.setattr(recon,'_run_tool',_runner({
        'dig-upstream':'old.example.com\tmissing.vendor.invalid\tNXDOMAIN\t\n',
        'curl-fingerprint':'===TAKEOVER old.example.com\tmissing.vendor.invalid===\n===END TAKEOVER===\n',
    }))
    recon.run_takeover_analysis(conn,'example.com',{'raw':str(tmp_path/'raw')},run_group='t')
    detail=recon.phase_detail_data(conn,'example.com','dns')
    assert detail['takeover']['executed'] is True
    assert detail['takeover']['external_cnames']==1
    assert detail['takeover']['candidates']==1
    template=(ROOT/'web/templates/surface_phase.html').read_text()
    assert 'Analizar takeover con evidencia actual' in template
    assert 'claimability = NOT_VALIDATED' in template
