from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def test_preview_uses_styled_renderer_and_loading_skeleton():
    js=(ROOT/'web/static/app.js').read_text(encoding='utf-8')
    css=(ROOT/'web/static/style.css').read_text(encoding='utf-8')
    assert 'const basicLineHtml=' in js
    assert "code.innerHTML=rendered.replace" in js
    assert "fastPaint('request',raw.request);fastPaint('response',raw.response)" in js
    assert 'showHttpLoading()' in js
    assert 'wb-http-loading-state' in js
    assert '.wb-http-loading-state' in css
    assert '.wb-http-skeleton' in css
    assert 'richRendered=true' in js
    assert '||richRendered)return' in js

def test_preview_no_longer_uses_plain_text_content():
    js=(ROOT/'web/static/app.js').read_text(encoding='utf-8')
    start=js.index('const fastPaint=')
    end=js.index('const renderPreview=',start)
    block=js[start:end]
    assert 'textContent=String(text||\'\')' not in block
    assert 'basicLineHtml' in block
