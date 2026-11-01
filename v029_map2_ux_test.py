import sqlite3
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_recon as recon


def test_dns_phase_dig_fallback_prevents_false_nodata(tmp_path):
    conn=sqlite3.connect(':memory:'); conn.row_factory=sqlite3.Row
    recon.init_schema(conn)
    recon.import_subfinder_text(
        conn,
        'api.example.com\nwww.example.com\nold.example.com\n',
        'example.com',
    )
    old_path=recon._tool_path
    old_run=recon._run_tool
    try:
        recon._tool_path=lambda name: '/fake/'+name if name in {'dnsx','dig'} else old_path(name)
        def fake_run(conn_, paths, phase, tool, command, **kwargs):
            if tool=='dnsx':
                return {'status':'ok','stdout':'','stderr':'','command':command,'error':'','return_code':0}
            if tool=='dig-records':
                return {
                    'status':'ok',
                    'stdout':'api.example.com [A] [203.0.113.10]\nwww.example.com [CNAME] [edge.example.net]\n',
                    'stderr':'','command':command,'error':'','return_code':0,
                }
            if tool=='dig-status':
                return {'status':'ok','stdout':'old.example.com\tNXDOMAIN\n','stderr':'','command':command,'error':'','return_code':0}
            raise AssertionError(tool)
        recon._run_tool=fake_run
        paths={'raw': str(tmp_path)}
        result=recon.run_dns_phase(conn,'example.com',paths)
        assert result['resolved_hosts']==2
        assert result['dig_fallback_records']==2
        rows={r['asset_key']: recon._loads(r['metadata_json']) for r in conn.execute("SELECT asset_key,metadata_json FROM recon_assets WHERE asset_type='hostname'")}
        assert rows['api.example.com']['dns_state']=='RESOLVED'
        assert rows['www.example.com']['dns_state']=='RESOLVED'
        assert rows['old.example.com']['dns_state']=='NXDOMAIN'
    finally:
        recon._tool_path=old_path
        recon._run_tool=old_run
