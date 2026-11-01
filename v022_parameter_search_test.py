from pathlib import Path

JS = Path(__file__).resolve().parents[1] / 'web' / 'static' / 'surface.js'

def test_family_activation_is_owned_by_pointerup_before_rerender():
    text = JS.read_text(encoding='utf-8')
    assert 'drag.activate?.();' in text
    assert "else if(ev?.type==='pointerup')" in text
    assert 'suppressClickUntil=Date.now()+320' in text


def test_pointerup_does_not_unconditionally_rerender_before_click():
    text = JS.read_text(encoding='utf-8')
    start = text.index('const endPointer=ev=>')
    end = text.index("svg.addEventListener('pointerup',endPointer)", start)
    block = text[start:end]
    assert 'nodeDrag=null;renderGraph();' not in block
    assert 'if(drag.moved)' in block


def test_family_activation_still_toggles_family():
    text = JS.read_text(encoding='utf-8')
    assert "if(n.type==='family'){toggleFamily(n.key);return;}" in text
    assert 'expandedFamilies.add(name)' in text
    assert 'expandedFamilies.delete(name)' in text
