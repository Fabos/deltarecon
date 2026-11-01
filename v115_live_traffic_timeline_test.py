from pathlib import Path

JS = Path(__file__).resolve().parents[1] / 'web' / 'static' / 'surface.js'


def _block(text: str, start_marker: str, end_marker: str) -> str:
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    return text[start:end]


def test_host_drilldown_does_not_autofit_viewport():
    text = JS.read_text(encoding='utf-8')
    block = _block(text, 'const activateNode=()=>{', "g.addEventListener('pointerdown'")
    assert 'renderDetail(n.meta)' in block
    assert 'renderGraph()' in block
    assert 'fit(' not in block


def test_family_expand_collapse_does_not_autofit_viewport():
    text = JS.read_text(encoding='utf-8')
    block = _block(text, 'function toggleFamily(name){', 'function enterFamily(name){')
    assert 'renderGraph()' in block
    assert 'fit(' not in block
