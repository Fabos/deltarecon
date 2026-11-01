import base64
from pathlib import Path

import negro_core as core
import negro_context_agent as ca
import negro_workbench as workbench


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def add(paths, domain, url, method='GET', body='{}', *, burp_in_scope=None, allow_out_of_scope=True):
    req = f"{method} / HTTP/1.1\r\nHost: {url.split('/')[2]}\r\nContent-Type: application/json\r\n\r\n{body}"
    resp = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}'
    return core.upsert_http_observation(
        paths, domain, url=url, method=method, source='burp_proxy', status_code=200,
        authenticated=True, request_content_type='application/json', response_content_type='application/json',
        request_b64=b64(req), response_b64=b64(resp), burp_in_scope=burp_in_scope,
        allow_out_of_scope=allow_out_of_scope,
    )


def test_hybrid_scope_accepts_project_target_workbench_rule_and_burp(tmp_path: Path, monkeypatch):
    paths = core.ensure_workspace(tmp_path/'ws', 'terpel.com.co', scopes=['terpel.com.co'], project_name='Terpel')
    add(paths, 'terpel.com.co', 'https://api.terpel.com.co/profile', body='{"accountId":"A-1"}')
    add(paths, 'terpel.com.co', 'https://www.viveterpel.com/login', method='POST', body='{"memberId":"M-1"}')
    add(paths, 'terpel.com.co', 'https://partner.example/bridge', body='{"partnerRef":"P-1"}', burp_in_scope=True)
    add(paths, 'terpel.com.co', 'https://noise.example/collect', body='{"trackingId":"T-1"}')
    add(paths, 'terpel.com.co', 'https://blocked.terpel.com.co/private', body='{"accountId":"SHOULD-NOT"}', burp_in_scope=False)

    monkeypatch.setattr(core, 'get_target', lambda key: {
        'domain':'terpel.com.co','scopes':['terpel.com.co'],'workspace':str(tmp_path/'ws'),'name':'Terpel'
    } if key == 'terpel' else None)
    monkeypatch.setattr(workbench, 'list_project_rules', lambda key='': [
        {'target_key':'terpel','rule_type':'host','hostname':'www.viveterpel.com','method':'','path':''}
    ] if key == 'terpel' else [])

    with core.db_connect(paths) as conn:
        bundle = ca.build_analysis_bundle(conn, mode='full', target_key='terpel')
        stats = bundle['stats']
        values = {c['value_sample'] for c in bundle['candidates']}
        assert 'A-1' in values                      # configured project target
        assert 'M-1' in values                      # Workbench host rule
        assert 'P-1' in values                      # Burp IN_SCOPE
        assert 'T-1' not in values                  # no scope source
        assert 'SHOULD-NOT' in values               # explicit Negro target overrides stale Burp EXCLUDED
        assert stats['scope_observations_by_source']['project_target'] > 0
        assert stats['scope_observations_by_source']['workbench_rule'] > 0
        assert stats['scope_observations_by_source']['burp_in_scope'] > 0
        assert stats['burp_excluded_exchanges'] > 0
        assert stats['burp_excluded_overridden_exchanges'] > 0
        assert any(x['host'] == 'noise.example' for x in stats['excluded_hosts'])


def test_endpoint_rule_is_exact_and_does_not_widen_whole_host(tmp_path: Path, monkeypatch):
    paths = core.ensure_workspace(tmp_path/'ws2', 'root.invalid', scopes=['root.invalid'], project_name='Pilot')
    add(paths, 'root.invalid', 'https://api.viveterpel.com/login', method='POST', body='{"memberId":"M-2"}')
    add(paths, 'root.invalid', 'https://api.viveterpel.com/telemetry', method='POST', body='{"memberId":"NOPE"}')
    monkeypatch.setattr(core, 'get_target', lambda key: {
        'domain':'root.invalid','scopes':['root.invalid'],'workspace':str(tmp_path/'ws2'),'name':'Pilot'
    } if key == 'pilot' else None)
    monkeypatch.setattr(workbench, 'list_project_rules', lambda key='': [
        {'target_key':'pilot','rule_type':'endpoint','hostname':'api.viveterpel.com','method':'POST','path':'/login'}
    ] if key == 'pilot' else [])
    with core.db_connect(paths) as conn:
        bundle = ca.build_analysis_bundle(conn, mode='full', target_key='pilot')
        vals = {c['value_sample'] for c in bundle['candidates']}
        assert 'M-2' in vals
        assert 'NOPE' not in vals


def test_scope_explainability_template_mentions_all_sources():
    root = Path(__file__).resolve().parents[1]
    tpl = (root/'web/templates/context_agent.html').read_text()
    assert 'Target del proyecto' in tpl
    assert 'Reglas Workbench' in tpl
    assert 'Burp IN_SCOPE' in tpl
    assert 'Hosts fuera del gate' in tpl
    assert 'Context Agent v1.5' in tpl
