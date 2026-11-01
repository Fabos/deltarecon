from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_root_is_structural_and_apex_is_real_host_child():
    js = (ROOT / "web/static/surface.js").read_text(encoding="utf-8")
    assert "ROOT is structural only" in js
    assert "root_host:true" in js
    assert "'ROOT_HOST','observed'" in js
    assert "addHostLayers(scene,rootAsset,apexId,layers)" in js
    assert "addHostLayers(scene,rootAsset,rid,layers)" not in js


def test_cdn_and_direct_backend_have_distinct_graph_paths():
    js = (ROOT / "web/static/surface.js").read_text(encoding="utf-8")
    css = (ROOT / "web/static/style.css").read_text(encoding="utf-8")
    assert "DIRECT_BYPASS" in js
    assert "'directpath'" in js
    assert "'edgepath'" in js
    assert "providerIds" in js and "EDGE_IP" in js
    assert "DIRECTO / BYPASS" in js
    assert "VÍA EDGE" in js
    assert ".surface-edge.directpath" in css
    assert ".surface-edge.edgepath" in css


def test_branch_focus_returns_focus_state_and_follows_nested_architecture():
    js = (ROOT / "web/static/surface.js").read_text(encoding="utf-8")
    assert "return {nodes,edges,collapsed:grouped,multiRoot,roots,focusHost,focusRoot}" in js
    assert "const structuralSource=/^(project|root|family):/.test(e.source)" in js
    assert "focusIds.has(e.source)&&!structuralSource" in js
    assert "structuralSource&&focusIds.has(e.target)" in js
