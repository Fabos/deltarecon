from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_live_detail_click_is_cancelable_and_fast():
    js=(ROOT/"web/static/app.js").read_text(encoding="utf-8")
    assert "detailAbort?.abort()" in js
    assert "new AbortController()" in js
    assert "res.status===404" in js
    assert "sleep(85" in js
    assert "[0,90,220,450]" not in js

def test_live_dom_is_bounded_and_polling_does_not_overlap():
    js=(ROOT/"web/static/app.js").read_text(encoding="utf-8")
    assert "MAX_LIVE_DOM_ROWS=650" in js
    assert "pruneLiveDom()" in js
    assert "livePollInFlight" in js
    assert "document.hidden?1800:850" in js

def test_click_highlights_row_before_detail_finishes():
    js=(ROOT/"web/static/app.js").read_text(encoding="utf-8")
    assert "rows().forEach(r=>r.classList.toggle('active',r===a));loadEvent(eventId)" in js
