from pathlib import Path


def test_surface_host_second_click_collapses_technical_layers_but_keeps_detail():
    root = Path(__file__).resolve().parents[1]
    js = (root / 'web/static/surface.js').read_text(encoding='utf-8')
    assert 'const wasExpanded=expandedHosts.has(n.key)' in js
    assert 'if(wasExpanded) expandedHosts.delete(n.key)' in js
    assert 'else expandedHosts.add(n.key)' in js
    assert 'selectedHost=n.key' in js
    assert 'renderDetail(n.meta)' in js


def test_surface_nodes_have_local_brand_identity_without_external_assets():
    root = Path(__file__).resolve().parents[1]
    js = (root / 'web/static/surface.js').read_text(encoding='utf-8')
    css = (root / 'web/static/style.css').read_text(encoding='utf-8')
    assert 'const brandVisual = value =>' in js
    for token in ['cloudflare','fastly','aws','gcp','php','nodejs','react','keycloak','sap','platformsh']:
        assert f"brand-{token}" in css
    assert 'surface-brand-mark' in js
    assert 'http://' not in js[js.index('const brandVisual = value =>'):js.index('function fillSelect')]
