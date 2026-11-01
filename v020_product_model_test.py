from pathlib import Path


def test_jwt_claim_layout_resets_legacy_grid_areas():
    css = Path("web/static/style.css").read_text(encoding="utf-8")
    marker = "v0.52.3 · JWT claims layout"
    assert marker in css
    tail = css.split(marker, 1)[1]
    assert "grid-template-columns:minmax(0,1fr)!important" in tail
    assert "grid-area:auto!important" in tail
    assert "display:flex!important" in tail
    assert "flex-direction:column!important" in tail


def test_version_0523():
    core = Path("negro_core.py").read_text(encoding="utf-8")
    assert 'VERSION = "0.52.3"' in core
