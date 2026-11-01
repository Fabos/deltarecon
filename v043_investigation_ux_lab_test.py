from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_workbench_traffic_is_a_top_collapsible_deck():
    tpl = (ROOT / 'web/templates/http_workbench.html').read_text(encoding='utf-8')
    css = (ROOT / 'web/static/style.css').read_text(encoding='utf-8')
    js = (ROOT / 'web/static/app.js').read_text(encoding='utf-8')

    assert 'data-traffic-compact' in tpl
    assert 'Endpoint / parámetros' in tpl
    assert 'data-traffic-toggle title="Recoger Traffic Inbox (T)"' in tpl
    assert '.wb-traffic-panel{\n  grid-column:1/-1;grid-row:1;' in css
    assert '.wb-http-panel{grid-column:1;grid-row:2' in css
    assert '.wb-shell.traffic-collapsed .wb-grid{grid-template-rows:43px minmax(0,1fr)}' in css
    assert '.wb-shell.traffic-collapsed .wb-traffic-compact{display:grid}' in css
    assert "trafficKey='negro:wb:traffic-collapsed'" in js
    assert "ev.key.toLowerCase()==='t'" in js
    assert 'setTrafficCollapsed' in js


def test_live_rows_match_wide_traffic_table_contract():
    js = (ROOT / 'web/static/app.js').read_text(encoding='utf-8')
    for token in ('wb-row-host', 'wb-row-endpoint', 'paramHtml(r.request_params)', 'wb-tags', 'wb-status'):
        assert token in js
    assert 'updateTrafficCompact' in js
    assert 'data-compact-unread' in js
