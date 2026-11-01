from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def test_jwt_is_explicit_button_with_capture_fallback():
    js=(ROOT/'web/static/app.js').read_text(encoding='utf-8')
    css=(ROOT/'web/static/style.css').read_text(encoding='utf-8')
    assert 'class="wb-compact-value is-jwt wb-jwt-trigger"' in js
    assert 'data-jwt-open="1"' in js
    assert "document.addEventListener('click',ev=>" in js
    assert "closest?.('[data-jwt-open]')" in js
    assert '.wb-jwt-trigger{' in css


def test_bottom_counter_is_review_queue_not_arrival_counter():
    js=(ROOT/'web/static/app.js').read_text(encoding='utf-8')
    tpl=(ROOT/'web/templates/http_workbench.html').read_text(encoding='utf-8')
    assert 'const pendingReviewIds=new Set()' in js
    assert 'pendingReviewIds.add(Number(r.id))' in js
    assert 'pendingReviewIds.delete(id)' in js
    assert 'markPendingReviewed(eventId)' in js
    assert "const next=[...pendingReviewIds].sort((a,b)=>a-b)[0]" in js
    assert 'pendingNew' not in js
    assert 'por revisar' in tpl
