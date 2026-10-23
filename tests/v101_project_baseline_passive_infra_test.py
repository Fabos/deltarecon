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


def test_baseline_steps_end_in_passive_infrastructure_classification():
    keys=[k for k,_ in recon.BASELINE_STEPS]
    assert keys[-2:]==['historical_dns','infra']


def test_infra_passive_mode_never_builds_direct_probe_run(monkeypatch,tmp_path):
    conn=_conn()
    hid=recon.upsert_asset(conn,'hostname','example.com','example.com',{'root_domain':'example.com','dns_state':'RESOLVED'})
    iid=recon.upsert_asset(conn,'ip','93.184.216.34','93.184.216.34',{})
    recon.link(conn,hid,'RESOLVES_TO',iid,'dnsx',confidence=1.0,confidence_type='observed')
    conn.commit()

    calls=[]
    def fake_run_tool(conn,paths,phase,tool,command,**kw):
        calls.append(tool)
        return {'status':'ok','stdout':'','stderr':'','returncode':0}
    monkeypatch.setattr(recon,'_run_tool',fake_run_tool)
    monkeypatch.setattr(recon,'_tool_path',lambda name: f'/usr/bin/{name}')

    out=recon.run_infrastructure_phase(conn,'example.com',{'raw':str(tmp_path/'raw')},active_correlation=False)
    assert out['active_correlation'] is False
    assert 'direct-correlation' not in calls
    # WHOIS enrichment is still permitted in the project-wide classification pass.
    assert 'whois-enrichment' in calls


def test_surface_copy_explains_passive_infra_cutoff():
    text=(ROOT/'web/templates/surface.html').read_text()
    assert 'clasificación de infraestructura pasiva' in text
    assert 'correlación activa de origins/IPs históricas' in text
    assert 'Nmap' in text
