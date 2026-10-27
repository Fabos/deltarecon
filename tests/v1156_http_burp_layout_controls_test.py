from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_workbench_preference_keys_are_declared_before_first_use():
    js = (ROOT / 'web/static/app.js').read_text(encoding='utf-8')
    declaration = "const markKey=`negro:wb:marks:${targetKey}`,splitKey=`negro:wb:split:${targetKey}`,contextKey='negro:wb:context-hidden',trafficKey='negro:wb:traffic-collapsed',wrapKey='negro:wb:exact-lines';"
    assert js.count(declaration) == 1
    assert js.index(declaration) < js.index("const exactLinesDefault=localStorage.getItem(wrapKey)")


def test_http_split_is_request_left_response_right_and_controls_remain_present():
    tpl = (ROOT / 'web/templates/http_workbench.html').read_text(encoding='utf-8')
    css = (ROOT / 'web/static/style.css').read_text(encoding='utf-8')
    js = (ROOT / 'web/static/app.js').read_text(encoding='utf-8')
    for token in (
        'data-pane-layout="split"', 'data-pane-layout="request"', 'data-pane-layout="response"',
        'data-http-fullscreen', 'data-wb-wrap="request"', 'data-wb-wrap="response"',
        'data-view-mode="request"', 'data-view-mode="response"', 'data-traffic-toggle', 'data-context-toggle'
    ):
        assert token in tpl
    assert 'flex-direction:row' in css
    assert 'cursor:col-resize' in css
    assert 'ev.clientX-rect.left' in js
    assert "closest('button[data-pane-layout]')" in js
    assert "closest('[data-pane-layout]')" not in js
    assert "ev.key.toLowerCase()==='t'" in js
    assert "ev.key.toLowerCase()==='c'" in js
    assert "ev.key.toLowerCase()==='f'" in js


def test_http_workbench_does_not_render_generic_page_help():
    base = (ROOT / 'web/templates/base.html').read_text(encoding='utf-8')
    assert "and '/workbench' not in request.url.path" in base
