from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_inspector_search_uses_server_index_and_force_hide():
    tpl = (ROOT / 'web/templates/http_inspector.html').read_text()
    css = (ROOT / 'web/static/style.css').read_text()
    assert 'data-search="{{ v.search_blob|e }}"' in tpl
    assert "r.style.setProperty('display','none','important')" in tpl
    assert '.inspector-value-row.is-filtered-out' in css


def test_jwt_claim_layout_is_single_column_resilient():
    css = (ROOT / 'web/static/style.css').read_text()
    assert '.jwt-claim-row{display:grid!important;grid-template-columns:minmax(0,1fr)!important' in css
    assert '.jwt-claim-copy{display:grid!important;grid-template-columns:minmax(0,1fr)!important' in css
    assert 'overflow-wrap:anywhere!important' in css


def test_identity_search_blob_includes_jwt_claims():
    src = (ROOT / 'negro_http_inspector.py').read_text()
    assert 'item["search_blob"]' in src
    assert 'jwt.{claim.get' in src
