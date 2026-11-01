from pathlib import Path


def test_surface_host_environment_badges_and_leaf_drilldown():
    root = Path(__file__).resolve().parents[1]
    js = (root / "web/static/surface.js").read_text(encoding="utf-8")
    css = (root / "web/static/style.css").read_text(encoding="utf-8")
    assert "surface-env-badge" in js
    assert "hostEnv==='STAGING'?'STG':hostEnv" in js
    assert "hostEnv!=='UNKNOWN'" in js
    assert "selectedHost=n.key" in js
    assert "expandedHosts.add(n.key)" in js
    assert "renderDetail(n.meta)" in js
    assert ".surface-env-badge.dev rect" in css
    assert ".surface-env-badge.qa rect" in css
    assert ".surface-env-badge.staging rect" in css
    assert ".surface-env-badge.prod rect" in css
