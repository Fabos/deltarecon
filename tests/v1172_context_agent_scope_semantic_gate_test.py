import base64
from pathlib import Path

import negro_core as core
import negro_context_agent as ca


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def add(paths, url, method, req, resp, status=200, req_ct='application/json', resp_ct='application/json', allow_out_of_scope=False):
    return core.upsert_http_observation(
        paths, 'example.test', url=url, method=method, source='burp', status_code=status,
        authenticated=True, request_content_type=req_ct, response_content_type=resp_ct,
        request_b64=b64(req), response_b64=b64(resp), allow_out_of_scope=allow_out_of_scope,
    )


def test_context_agent_only_analyzes_project_or_burp_scope(tmp_path: Path):
    paths = core.ensure_workspace(tmp_path, 'example.test', scopes=['example.test'], project_name='Example')
    add(paths, 'https://example.test/login', 'POST',
        'POST /login HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{"memberId":"U-7"}',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"accountId":"A-9"}')
    # Captured into the same project DB, but host is outside configured project scope.
    add(paths, 'https://analytics.invalid/collect', 'POST',
        'POST /collect HTTP/1.1\r\nHost: analytics.invalid\r\nContent-Type: application/json\r\n\r\n{"visitorId":"TRACK-999"}',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"trackingId":"TRACK-999"}', allow_out_of_scope=True)
    with core.db_connect(paths) as conn:
        bundle = ca.build_analysis_bundle(conn, mode='full')
        values = {c['value_sample'] for c in bundle['candidates']}
        assert 'U-7' in values and 'A-9' in values
        assert 'TRACK-999' not in values
        assert bundle['stats']['excluded_scope_observations'] > 0
        assert bundle['stats']['scope_observations'] < bundle['stats']['total_observations']


def test_semantic_gate_defers_transport_and_static_noise_but_keeps_business_fields(tmp_path: Path):
    paths = core.ensure_workspace(tmp_path, 'example.test', scopes=['example.test'], project_name='Example')
    add(paths, 'https://example.test/static/app.abc123.js', 'GET',
        'GET /static/app.abc123.js HTTP/1.1\r\nHost: example.test\r\nAccept: */*\r\nSec-Fetch-Dest: script\r\nX-Trace-Id: 123456789abcdef0\r\n\r\n',
        'HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nCache-Control: public,max-age=3600\r\nETag: 123456789abcdef0\r\n\r\nconsole.log(1)',
        req_ct='text/plain', resp_ct='application/javascript')
    add(paths, 'https://example.test/api/login', 'POST',
        'POST /api/login HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nX-Request-Id: deadbeefcafebabe\r\n\r\n{"loginName":"alice","deviceRef":"DEV-91"}',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Trace-Id: feedfacecafebeef\r\n\r\n{"memberId":"U-7","accountId":"A-9","status":"ACTIVE"}')
    with core.db_connect(paths) as conn:
        bundle = ca.build_analysis_bundle(conn, mode='full')
        vals = {c['value_sample'] for c in bundle['candidates']}
        assert {'U-7','A-9','ACTIVE'}.issubset(vals)
        assert 'deadbeefcafebabe' not in vals
        assert 'feedfacecafebeef' not in vals
        assert bundle['stats']['deferred_candidates'] > 0
        # Ledger preserves more than what is sent to AI.
        assert bundle['stats']['scope_observations'] > bundle['stats']['selected_candidates']


def test_deferred_unknown_candidate_wakes_when_behavioral_evidence_appears(tmp_path: Path):
    paths = core.ensure_workspace(tmp_path, 'example.test', scopes=['example.test'], project_name='Example')
    add(paths, 'https://example.test/a', 'GET',
        'GET /a HTTP/1.1\r\nHost: example.test\r\n\r\n',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"opaqueThing":"ZXCVBN"}')
    with core.db_connect(paths) as conn:
        first = ca.build_analysis_bundle(conn, mode='full')
        assert 'ZXCVBN' not in {c['value_sample'] for c in first['candidates']}
    add(paths, 'https://example.test/b', 'POST',
        'POST /b HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{"opaqueThing":"ZXCVBN"}',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')
    with core.db_connect(paths) as conn:
        second = ca.build_analysis_bundle(conn, mode='full')
        cand = next(c for c in second['candidates'] if c['value_sample'] == 'ZXCVBN')
        assert cand['produced_then_consumed'] is True
        assert 'produced_then_consumed' in cand['selection_reasons']
