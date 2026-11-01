from pathlib import Path

JS = Path(__file__).resolve().parents[1] / "web" / "static" / "surface.js"


def test_background_click_respects_synthetic_click_suppression_window():
    text = JS.read_text(encoding="utf-8")
    marker = "svg.addEventListener('click',e=>{"
    start = text.index(marker)
    end = text.index("svg.addEventListener('wheel'", start)
    block = text[start:end]
    assert "if(Date.now()<suppressClickUntil)return;" in block
    assert "selectedHost='';renderDetail(null);renderGraph();" in block


def test_host_pointerup_activation_renders_detail_before_rerender():
    text = JS.read_text(encoding="utf-8")
    start = text.index("const activateNode=()=>{")
    end = text.index("g.addEventListener('pointerdown'", start)
    block = text[start:end]
    assert "selectedHost=n.key" in block
    assert "renderDetail(n.meta)" in block
    assert "renderGraph()" in block
