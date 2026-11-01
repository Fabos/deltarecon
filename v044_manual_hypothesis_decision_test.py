from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def read(rel):
    return (ROOT / rel).read_text(encoding='utf-8')

def test_module_roles_are_explicit_in_ui():
    graph = read('web/templates/graph.html')
    surface = read('web/templates/surface.html')
    search = read('web/templates/search.html')
    objects = read('web/templates/objects.html')
    assert 'MAPA DE INVESTIGACIÓN' in graph
    assert 'Este mapa no reemplaza Superficie' in graph
    assert 'data-graph-preset="surface"' not in graph
    assert '¿qué existe y qué me falta revisar?' in surface
    assert '¿Dónde apareció esto?' in search
    assert 'ENSÉÑALO UNA VEZ' in objects
    assert 'Tipo aprendido → instancias automáticas' in objects

def test_graph_defaults_to_relationship_view():
    js = read('web/static/graph.js')
    assert "let preset = 'identity';" in js
    assert "let inferred='identity';" in js
    assert "`${api}?scope=identities`" in js

def test_objects_engine_applies_taught_identifiers_to_new_exchanges():
    src = read('negro_objects.py')
    assert 'def refresh_exchange(conn, exchange_id: int)' in src
    assert 'Apply currently taught Business Object identifiers to one captured exchange.' in src
    web = read('negro_web.py')
    assert 'object_tools.refresh_exchange(conn, int(result["exchange_id"]))' in web
