import sqlite3
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import negro_recon as recon


def test_discovery_expand_is_optional_not_numbered_or_blocking():
    conn=sqlite3.connect(':memory:'); conn.row_factory=sqlite3.Row
    recon.init_schema(conn)
    phases=recon.phase_progress(conn,'example.com')
    keys=[p['key'] for p in phases]
    assert 'discovery_expand' not in keys
    assert keys[:6]==['root','discovery','active_discovery','dns','tls','http']
    discovery=next(p for p in phases if p['key']=='discovery')
    assert 'optional_tool_info' in discovery
