from __future__ import annotations

import base64
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_evidence as evidence
import negro_web
import negro_workbench as workbench

try:
    from fastapi.testclient import TestClient
except Exception:  # pragma: no cover
    TestClient = None


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode('ascii')


def setup_project(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(core, 'CONFIG_PATH', tmp_path / 'config.json')
    monkeypatch.setattr(core, 'TARGETS_PATH', tmp_path / 'targets.json')
    monkeypatch.setenv('NEGRO_TRAFFIC_WORKSPACE', str(tmp_path / 'traffic-inbox'))
    ws = tmp_path / 'workspace'
    key = core.register_target('example.test', ws, make_current=True, name='Example', scopes=['example.test'])
    core.ensure_workspace(ws, 'example.test', scopes=['example.test'], project_name='Example')
    return key, ws


def req(order='ORD-1001') -> bytes:
    return f'GET /api/orders/{order}?view=full HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer USER_A\r\n\r\n'.encode()


def response(status=200) -> bytes:
    return f'HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{{"orderId":"ORD-1001"}}'.encode()


def payload(request: bytes, *, tool='PROXY', status=200, **extra):
    return {
        'url': 'https://example.test' + request.decode('iso-8859-1').split(' ')[1],
        'method': 'GET', 'tool': tool, 'status_code': status,
        'request_b64': b64(request), 'response_b64': b64(response(status)), 'burp_in_scope': True,
        **extra,
    }


@pytest.mark.skipif(TestClient is None, reason='FastAPI TestClient unavailable')
def test_proxy_mutation_is_experiment_with_semantic_diff(tmp_path, monkeypatch):
    key, ws = setup_project(tmp_path, monkeypatch)
    client = TestClient(negro_web.create_app('example.test', ws))
    original = req('ORD-1001')
    sent = req('ORD-2002')
    out = client.post('/api/ingest/http', json=payload(sent,
        original_request_b64=b64(original), provenance_source='PROXY_MANUAL_MUTATION',
        interaction_kind='EXPERIMENT', bridge_message_id='42')).json()
    assert out['accepted'] is True
    assert out['interaction_kind'] == 'EXPERIMENT'
    ev = workbench.get_capture_event(out['capture_event_id'])
    assert ev['provenance_source'] == 'PROXY_MANUAL_MUTATION'
    assert ev['bridge_message_id'] == '42'
    diff = __import__('json').loads(ev['mutation_diff_json'])
    assert any(d['field'] == 'path' and d['before'].endswith('ORD-1001') and d['after'].endswith('ORD-2002') for d in diff)


@pytest.mark.skipif(TestClient is None, reason='FastAPI TestClient unavailable')
def test_repeater_is_experiment_and_exact_parent_is_preserved(tmp_path, monkeypatch):
    key, ws = setup_project(tmp_path, monkeypatch)
    client = TestClient(negro_web.create_app('example.test', ws))
    normal = client.post('/api/ingest/http', json=payload(req(), provenance_source='PROXY', interaction_kind='OBSERVED')).json()
    rep = client.post('/api/ingest/http', json=payload(req(), tool='REPEATER')).json()
    ev = workbench.get_capture_event(rep['capture_event_id'])
    assert ev['interaction_kind'] == 'EXPERIMENT'
    assert ev['provenance_source'] == 'REPEATER'
    assert ev['parent_event_id'] == normal['capture_event_id']
    assert float(ev['parent_confidence']) == 1.0


def test_transport_semantic_object_evidence_are_independent(tmp_path, monkeypatch):
    key, ws = setup_project(tmp_path, monkeypatch)
    # Directly exercise the new evidence layer with a denied transport/application result
    # that nevertheless returned tracked-object data.
    paths = workbench.ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        workbench._init_workbench_schema(conn)
        evidence.init_schema(conn)
        event = {'id': 9, 'target_key': key, 'exchange_id': 3, 'status_code': 422}
        ev = evidence.save_experiment_evidence(conn, event=event, object_type='Order', object_value='ORD-1001',
            semantic_result='DENIED', object_evidence='RETURNED', outcome='CONFIRMED')
        rel = evidence.promote_relation(conn, target_key=key, subject_type='Identity', subject_ref='Buyer B',
            predicate='leaked_from', object_type='Order', object_ref='ORD-1001', evidence_id=ev['id'], expectedness='UNEXPECTED')
    assert ev['transport_status'] == 422
    assert ev['semantic_result'] == 'DENIED'
    assert ev['object_evidence'] == 'RETURNED'
    assert rel['status'] == 'CONFIRMED' and rel['expectedness'] == 'UNEXPECTED'

@pytest.mark.skipif(TestClient is None, reason='FastAPI TestClient unavailable')
def test_url_query_and_path_values_are_inline_and_field_semantics_are_distinct(tmp_path, monkeypatch):
    key, ws = setup_project(tmp_path, monkeypatch)
    client = TestClient(negro_web.create_app('example.test', ws))
    ing = client.post('/api/ingest/http', json=payload(req('ORD-1001'))).json()
    event_id = int(ing['capture_event_id'])
    page = client.get(f'/t/{key}/workbench', params={'event': event_id})
    assert page.status_code == 200
    detail = client.get(f'/api/t/{key}/workbench/detail', params={'event_id': event_id}).json()

    query = next(v for v in detail['values'] if v['location'] == 'request_query:view')
    path = next(v for v in detail['values'] if v['location'].startswith('request_path:') and v['value'] == 'ORD-1001')
    assert query['key'] == 'view' and query['value'] == 'full'
    assert path['key'] == 'order_id'

    import re as _re
    csrf = _re.search(r'data-csrf="([^"]+)"', page.text).group(1)
    exid = int(detail['exchange']['id'])

    # Teaching the key is a field rule, not a concrete Identity attribution.
    r = client.post(f'/t/{key}/exchange/{exid}/field-semantics', data={
        'csrf': csrf, 'key': 'view', 'classification': 'context', 'object_type': '', 'note': ''
    })
    assert r.status_code == 200 and r.json()['ok'] is True

    # Teaching order_id as an Object field should reuse Business Object aliases
    # and track both the current and later path instances.
    r = client.post(f'/t/{key}/exchange/{exid}/field-semantics', data={
        'csrf': csrf, 'key': 'order_id', 'classification': 'entity', 'object_type': 'Order', 'note': ''
    })
    assert r.status_code == 200 and r.json()['ok'] is True

    refreshed = client.get(f'/api/t/{key}/workbench/detail', params={'event_id': event_id}).json()
    assert any(x['normalized_key'] == 'view' and x['classification'] == 'context' for x in refreshed['field_semantics'])
    assert any(x['normalized_key'] == 'order_id' and x['classification'] == 'entity' and x['object_type'] == 'Order' for x in refreshed['field_semantics'])
    assert any(a['classification'] == 'context' and a['key_name'] == 'view' and not a.get('identity_id') for a in refreshed['annotations'])
    assert any(o['type_name'] == 'Order' and (o.get('identifier_raw') or o.get('identifier_preview')) == 'ORD-1001' for o in refreshed['objects'])

    second = client.post('/api/ingest/http', json=payload(req('ORD-2002'))).json()
    d2 = client.get(f'/api/t/{key}/workbench/detail', params={'event_id': int(second['capture_event_id'])}).json()
    assert any(o['type_name'] == 'Order' and (o.get('identifier_raw') or o.get('identifier_preview')) == 'ORD-2002' for o in d2['objects'])


def test_workbench_has_clickable_field_and_url_contract():
    js = (ROOT / 'web/static/app.js').read_text(encoding='utf-8')
    css = (ROOT / 'web/static/style.css').read_text(encoding='utf-8')
    tpl = (ROOT / 'web/templates/http_workbench.html').read_text(encoding='utf-8')
    assert 'data-inline-field-index' in js
    assert 'renderRequestTarget' in js
    assert 'request_query:' in js
    assert 'request_path:' in js
    assert 'openInlineField' in js
    assert '/field-semantics' in js
    assert '.wb-inline-field-key' in css
    assert 'data-inline-field-hint' in tpl
