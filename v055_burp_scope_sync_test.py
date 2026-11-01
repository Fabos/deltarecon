from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def test_surface_initial_graph_is_family_first_and_supports_inline_drilldown():
    js=(ROOT/'web'/'static'/'surface.js').read_text(encoding='utf-8')
    assert 'const expandedFamilies = new Set();' in js
    assert "families.set('__ungrouped__',singletons)" in js
    assert 'if(!expandedFamilies.has(family)) return;' in js
    assert "if(n.type==='family'){toggleFamily(n.key);return;}" in js
    assert 'function toggleFamily(name)' in js
    assert "Otros / sin agrupar" in js


def test_surface_edges_have_readable_contrast():
    css=(ROOT/'web'/'static'/'style.css').read_text(encoding='utf-8')
    assert 'v0.75 surface graph readability' in css
    assert 'stroke-width:1.45' in css
