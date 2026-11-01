import base64
from pathlib import Path

import negro_core as core
import negro_context_agent as ca
import negro_workbench as workbench


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def add(paths, domain, url, *, burp_in_scope=None):
    host = url.split('/')[2]
    req = f'POST /login HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\r\n{{"memberId":"M-1174"}}'
    resp = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"accountId":"A-1174"}'
    return core.upsert_http_observation(
        paths, domain, url=url, method='POST', source='burp_proxy', status_code=200,
        authenticated=True, request_content_type='application/json', response_content_type='application/json',
        request_b64=b64(req), response_b64=b64(resp), burp_in_scope=burp_in_scope,
        allow_out_of_scope=True,
    )


def test_www_subdomain_is_covered_by_root_even_if_burp_says_excluded(tmp_path: Path, monkeypatch):
    paths = core.ensure_workspace(tmp_path/'ws', 'terpel.com', scopes=['terpel.com', 'viveterpel.com'], project_name='Terpel')
    add(paths, 'terpel.com', 'https://www.viveterpel.com/api/login', burp_in_scope=False)
    add(paths, 'terpel.com', 'https://noise.example/login', burp_in_scope=False)

    monkeypatch.setattr(core, 'get_target', lambda key: {
        'domain': 'terpel.com', 'scopes': ['terpel.com', 'viveterpel.com'],
        'workspace': str(tmp_path/'ws'), 'name': 'Terpel'
    } if key == 'terpel' else None)
    monkeypatch.setattr(workbench, 'list_project_rules', lambda key='': [])

    with core.db_connect(paths) as conn:
        allowed, stats, reasons = ca._ai_scope_exchange_ids(conn, target_key='terpel')
        rows = conn.execute("""SELECT e.id,h.hostname FROM http_exchanges e
                              JOIN resource_operations o ON o.id=e.operation_id
                              JOIN resources r ON r.id=o.resource_id
                              JOIN hosts h ON h.id=r.host_id""").fetchall()
        ids = {r['hostname']: int(r['id']) for r in rows}
        assert ids['www.viveterpel.com'] in allowed
        assert 'project_target' in reasons[ids['www.viveterpel.com']]
        assert 'burp_excluded_overridden' in reasons[ids['www.viveterpel.com']]
        assert ids['noise.example'] not in allowed
        assert reasons[ids['noise.example']] == ['burp_excluded']
        assert stats['burp_excluded_overridden_exchanges'] == 1
        assert stats['burp_excluded_veto_exchanges'] == 1


def test_scope_root_normalization_supports_url_and_wildcard():
    assert ca._host_in_project_scope('www.viveterpel.com', ['viveterpel.com'])
    assert ca._host_in_project_scope('api.viveterpel.com', ['https://viveterpel.com/app'])
    assert ca._host_in_project_scope('deep.api.viveterpel.com', ['*.viveterpel.com'])
    assert not ca._host_in_project_scope('evilviveterpel.com', ['viveterpel.com'])
    assert not ca._host_in_project_scope('viveterpel.com.evil.example', ['viveterpel.com'])


def test_more_dropdown_is_not_clipped_by_direct_nav():
    root = Path(__file__).resolve().parents[1]
    css = (root/'web/static/style.css').read_text()
    base = (root/'web/templates/base.html').read_text()
    assert 'class="nav-more' in base
    assert '.direct-nav{display:flex;align-items:center;gap:2px;min-width:0;overflow:visible;' in css
    assert '.main-nav.direct-nav{overflow:visible;flex-wrap:wrap;' in css
    assert '.nav-more-menu{position:absolute' in css
