from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_graph_suppresses_cloudflare_server_duplicate():
    js=(ROOT/'web/static/surface.js').read_text(encoding='utf-8')
    assert "if(isEdgeProvider(server) && providers.some" in js
    assert "Once an architectural edge node exists" in js


def test_security_controls_are_grouped_and_collapsible():
    js=(ROOT/'web/static/surface.js').read_text(encoding='utf-8')
    css=(ROOT/'web/static/style.css').read_text(encoding='utf-8')
    assert "SECURITY CONTROLS · ${controls.length}" in js
    assert "kind:'security'" in js
    assert "expandedInfraGroups.has(groupKey)" in js
    assert ".surface-node.layergroup-security" in css


def test_non_edge_historical_ips_are_grouped_and_collapsible():
    js=(ROOT/'web/static/surface.js').read_text(encoding='utf-8')
    css=(ROOT/'web/static/style.css').read_text(encoding='utf-8')
    assert "HISTORICAL INFRA · ${historicalInfra.length}" in js
    assert "kind:'historical-infra'" in js
    assert "HISTORICAL_RESOLVES_TO" in js
    assert ".surface-node.layergroup-historical-infra" in css
