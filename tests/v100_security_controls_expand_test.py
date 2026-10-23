from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_expanded_security_controls_have_a_layout_column():
    js=(ROOT/'web/static/surface.js').read_text(encoding='utf-8')
    assert "types:['edgegroup','server','control']" in js
    assert "Expanded SECURITY CONTROLS children" in js


def test_security_group_toggle_still_uses_shared_expand_state():
    js=(ROOT/'web/static/surface.js').read_text(encoding='utf-8')
    assert "if(n.type==='layergroup')" in js
    assert "expandedInfraGroups.has(n.key)" in js
    assert "expandedInfraGroups.add(n.key)" in js
    assert "expandedInfraGroups.delete(n.key)" in js
