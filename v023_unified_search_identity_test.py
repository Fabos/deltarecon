from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def test_slate_scan_deck_avoids_bright_white_and_strengthens_scan_hierarchy():
    css=(ROOT/'web/static/style.css').read_text(encoding='utf-8')
    assert 'v0.116.5 · Samsung-comfort slate scan deck' in css
    assert '--wb-scan-deck:#171c21' in css
    assert '--wb-scan-active:#263a4b' in css
    assert '.wb-row-host{' in css and 'font-weight:820!important' in css
    assert '.wb-traffic-row>.wb-status{font-size:10px!important;font-weight:850!important' in css
    assert '.wb-visibility-filter button.active{background:#2a3946' in css
    # Regression guard: the v0.116.4 bright deck must not return.
    assert '.wb-traffic-list{background:#f4f5f6' not in css
    assert '.wb-traffic-row{background:#f8f9fa' not in css
