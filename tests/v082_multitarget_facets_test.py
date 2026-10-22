import sqlite3
from pathlib import Path
import negro_recon as recon

ROOT=Path(__file__).resolve().parents[1]

def test_surface_data_contains_project_hosts_across_roots():
    conn=sqlite3.connect(':memory:'); conn.row_factory=sqlite3.Row
    recon.init_schema(conn)
    recon.import_subfinder_text(conn,'api-dev.alpha.test\napi-qa.alpha.test\n','alpha.test')
    recon.import_subfinder_text(conn,'www.beta.test\nshop.beta.test\n','beta.test')
    data=recon.surface_data(conn,'alpha.test',['alpha.test','beta.test'])
    assert {h['root_domain'] for h in data['project_hosts']}=={'alpha.test','beta.test'}
    assert {h['hostname'] for h in data['hosts']}=={'api-dev.alpha.test','api-qa.alpha.test'}
    assert data['filters']['roots']==['alpha.test','beta.test']

def test_surface_uses_searchable_multiselect_facets():
    html=(ROOT/'web/templates/surface.html').read_text(encoding='utf-8')
    js=(ROOT/'web/static/surface.js').read_text(encoding='utf-8')
    for name in ['root','technology','server','provider','environment','status','family','source']:
        assert f'data-filter-facet="{name}"' in html
    assert 'Seleccionar visibles' in js
    assert 'selectedFilters' in js
    assert 'surface-facet-search' in js
    assert "return vals.some(v=>sel.has(v));" in js

def test_surface_project_graph_supports_collapsible_roots():
    js=(ROOT/'web/static/surface.js').read_text(encoding='utf-8')
    assert 'const expandedRoots = new Set([rootDomain]);' in js
    assert "node('project','project'" in js
    assert "if(n.type==='root'){if(expandedRoots.has(n.key))expandedRoots.delete(n.key);else expandedRoots.add(n.key)" in js
    assert 'Trabajar este target' in js
