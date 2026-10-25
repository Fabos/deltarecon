#!/usr/bin/env python3
from pathlib import Path
import base64
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_flows as flows
import negro_hunter as hunter


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def capture(paths, domain, request_target, body=''):
    path = request_target.split('?', 1)[0]
    req = f"POST {request_target} HTTP/1.1\r\nHost: api.v109.local\r\nContent-Type: application/json\r\n\r\n{body}".encode()
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    query = request_target.split('?', 1)[1] if '?' in request_target else ''
    return core.upsert_http_observation(
        paths, domain, url=f"https://api.v109.local{request_target}", method="POST", source="burp_proxy", status_code=200,
        authenticated=False, tool="PROXY", request_content_type="application/json", response_content_type="application/json",
        request_b64=b64(req), response_b64=b64(resp), query=query,
    )


def test_flow_step_exposes_request_parameters_with_masked_sensitive_preview():
    with tempfile.TemporaryDirectory(prefix='negro-v109-') as td:
        domain = 'api.v109.local'
        paths = core.ensure_workspace(Path(td) / 'project', domain)
        ex = capture(paths, domain, '/orders?orderId=123&view=full', '{"amount":9000,"token":"super-secret-token"}')
        with core.db_connect(paths) as conn:
            hunter.analyze_http_exchange(conn, int(ex['exchange_id']), domain, emit_notifications=False)
            fid = flows.create_flow(conn, 'Order')
            flows.add_step(conn, fid, int(ex['exchange_id']))
            data = flows.get_flow(conn, fid)
            params = data['steps'][0]['request_parameters']
            pairs = {(p['name'], p['value']) for p in params}
            assert ('orderId', '123') in pairs, params
            assert ('view', 'full') in pairs, params
            assert ('amount', '9000') in pairs, params
            token = next(p for p in params if p['name'] == 'token')
            assert 'super-secret-token' not in token['value'], token
            assert '•' in token['value'] or '…' in token['value'], token


def test_flow_template_renders_parameter_summary_and_overflow():
    text = (ROOT / 'web/templates/flow_detail.html').read_text(encoding='utf-8')
    assert 'flow-request-params' in text
    assert 'PARÁMETROS' in text
    assert 's.request_parameters[:6]' in text
    assert '+{{ s.request_parameters|length - 6 }} más' in text
    css = (ROOT / 'web/static/style.css').read_text(encoding='utf-8')
    assert '.flow-param-chip' in css
    assert '.flow-param-popover' in css
