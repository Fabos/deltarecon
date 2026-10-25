from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_flow_step_template_is_compact_and_non_duplicated():
    text = (ROOT / 'web/templates/flow_detail.html').read_text()
    assert 'class="flow-request-summary"' in text
    assert 'class="flow-path"' in text
    assert 'Request #{{ s.exchange_id }}' in text
    assert '{% if s.label %}<h3 class="flow-step-title">{{ s.label }}</h3>{% endif %}' in text
    assert "<h3>{{ s.label or (s.method ~ ' ' ~ s.path) }}</h3>" not in text


def test_flow_steps_force_full_width_and_ellipsis_long_paths():
    css = (ROOT / 'web/static/style.css').read_text()
    assert '.flow-sortable{display:flex!important;flex-direction:column;align-items:stretch;width:100%;min-width:0}' in css
    assert '.minimal-flow-step{width:100%;max-width:none;box-sizing:border-box;' in css
    assert 'text-overflow:ellipsis!important' in css
    assert 'white-space:nowrap!important' in css


def test_drag_handle_remains_the_drag_entrypoint():
    text = (ROOT / 'web/templates/flow_detail.html').read_text()
    assert 'data-drag-handle' in text
    assert "event.target.closest?.('[data-drag-handle]')" in text
    assert 'setPointerCapture' in text
