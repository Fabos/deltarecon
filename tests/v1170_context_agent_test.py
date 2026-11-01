import base64
from pathlib import Path

import negro_core as core
import negro_context_agent as ca
import negro_http_inspector as hi


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def add(paths, url, method, req, resp, status=200, req_ct='application/json', resp_ct='application/json'):
    return core.upsert_http_observation(
        paths, 'example.test', url=url, method=method, source='burp', status_code=status,
        authenticated=True, request_content_type=req_ct, response_content_type=resp_ct,
        request_b64=b64(req), response_b64=b64(resp),
    )


def test_context_agent_value_lifecycle_aliases_and_sources(tmp_path: Path):
    paths = core.ensure_workspace(tmp_path, 'example.test', scopes=['example.test'], project_name='Example')
    add(paths, 'https://example.test/orders?member=U-77', 'POST',
        'POST /orders?member=U-77 HTTP/1.1\r\nHost: example.test\r\nX-Tenant: ORG-9\r\nContent-Type: application/json\r\n\r\n{"accountId":"A-99"}',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"orderId":"ORD-123","status":"PENDING"}')
    add(paths, 'https://example.test/orders/ORD-123', 'GET',
        'GET /orders/ORD-123 HTTP/1.1\r\nHost: example.test\r\n\r\n',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"id":"ORD-123","status":"PAID"}')
    with core.db_connect(paths) as conn:
        bundle = ca.build_analysis_bundle(conn)
        order = [c for c in bundle['candidates'] if c['value_sample'] == 'ORD-123']
        assert len(order) == 1
        assert {'orderId', 'order_id', 'id'}.issubset(set(order[0]['aliases']))
        assert order[0]['produced_then_consumed'] is True
        keys = {r['key_name'] for r in conn.execute('SELECT key_name FROM semantic_observations')}
        assert {'member', 'X-Tenant', 'accountId', 'orderId', 'status'}.issubset(keys)


def test_context_agent_incremental_delta_keeps_impacted_old_context(tmp_path: Path):
    paths = core.ensure_workspace(tmp_path, 'example.test', scopes=['example.test'], project_name='Example')
    add(paths, 'https://example.test/orders', 'POST',
        'POST /orders HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{"accountId":"A-99"}',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"orderId":"ORD-123"}')
    with core.db_connect(paths) as conn:
        first = ca.build_analysis_bundle(conn)
        conn.execute(
            "INSERT INTO semantic_agent_runs(agent_version,mode,model,status,watermark_exchange_after,watermark_observation_after,created_at,finished_at) VALUES(?,?,?,?,?,?,?,?)",
            (ca.AGENT_VERSION, 'incremental', 'gpt-6.1-sol', 'completed', first['watermark_after']['exchange'], first['watermark_after']['observation'], ca.now_iso(), ca.now_iso()),
        )
    add(paths, 'https://example.test/refund', 'POST',
        'POST /refund HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{"orderRef":"ORD-123","refundId":"RF-77"}',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"refundId":"RF-77","state":"APPROVED"}')
    with core.db_connect(paths) as conn:
        second = ca.build_analysis_bundle(conn)
        vals = {c['value_sample']: c for c in second['candidates']}
        assert second['stats']['new_observations'] > 0
        assert 'RF-77' in vals
        assert 'ORD-123' in vals
        assert {'orderId', 'orderRef'}.issubset(set(vals['ORD-123']['aliases']))


def test_high_confidence_ai_semantics_project_into_workbench_without_overwriting_manual(tmp_path: Path):
    paths = core.ensure_workspace(tmp_path, 'example.test', scopes=['example.test'], project_name='Example')
    add(paths, 'https://example.test/orders', 'POST',
        'POST /orders HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{"accountId":"A-99"}',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"orderId":"ORD-123"}')
    with core.db_connect(paths) as conn:
        bundle = ca.build_analysis_bundle(conn)
        order = next(c for c in bundle['candidates'] if c['value_sample'] == 'ORD-123')
        rid = conn.execute("INSERT INTO semantic_agent_runs(agent_version,mode,model,status,created_at) VALUES(?,?,?,?,?)", (ca.AGENT_VERSION,'incremental','gpt-6.1-sol','running',ca.now_iso())).lastrowid
        ca._persist_result(conn, rid, bundle, {'summary':'ok','inferences':[{'candidate_id':order['candidate_id'],'category':'business_object','semantic_type':'Order','role':'identifier','confidence':0.97,'explanation':'lifecycle','evidence_observation_ids':order['observation_ids']}],'relationships':[]})
        inf = conn.execute("SELECT * FROM semantic_inferences WHERE candidate_id=? ORDER BY id DESC LIMIT 1", (order['candidate_id'],)).fetchone()
        # Model confidence alone is not enough: Negro combines it with local evidence.
        assert inf['model_confidence'] == 0.97
        assert inf['confidence'] <= inf['model_confidence']
        ca.decide_inference(conn, int(inf['id']), 'confirmed')
        synthetic = ca.synthetic_annotations_for_exchange(conn, 1)
        assert any(a['semantic_type'] == 'Order' and a['ai_confidence'] == inf['confidence'] for a in synthetic)
        # A manual mark on the same exact observation suppresses the AI overlay.
        obs = conn.execute("SELECT * FROM semantic_observations WHERE exchange_id=1 AND key_name='orderId'").fetchone()
        hi.save_annotation(conn, 1, side=obs['side'], location=obs['location'], key=obs['key_name'], value=obs['value_raw'], classification='entity', object_type='Purchase', source='http_inspector')
        synthetic2 = ca.synthetic_annotations_for_exchange(conn, 1)
        assert not any(a['key_name'] == 'orderId' for a in synthetic2)


def test_context_agent_cost_budget_blocks_before_model_call(tmp_path: Path, monkeypatch):
    paths = core.ensure_workspace(tmp_path, 'example.test', scopes=['example.test'], project_name='Example')
    add(paths, 'https://example.test/orders', 'GET',
        'GET /orders?accountId=A-99 HTTP/1.1\r\nHost: example.test\r\n\r\n',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"accountId":"A-99"}')
    called = {'model': False}
    monkeypatch.setattr(ca, 'run_model', lambda *a, **k: called.__setitem__('model', True))
    with core.db_connect(paths) as conn:
        try:
            ca.execute(conn, budget_usd=0.000001)
            assert False, 'expected budget block'
        except RuntimeError as exc:
            assert 'supera tu límite' in str(exc)
        assert called['model'] is False


def test_http_inspector_extracts_multipart_and_xml():
    multi = 'POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=abc\r\n\r\n--abc\r\nContent-Disposition: form-data; name="orderRef"\r\n\r\nORD-9\r\n--abc--\r\n'
    vals = hi.extract_message(multi, 'request')
    assert any(v['key'] == 'orderRef' and v['value'] == 'ORD-9' for v in vals)
    xml = 'HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\n<root><memberId>U-7</memberId><state>ACTIVE</state></root>'
    vals2 = hi.extract_message(xml, 'response')
    assert any(v['key'] == 'memberId' and v['value'] == 'U-7' for v in vals2)
    assert any(v['key'] == 'state' and v['value'] == 'ACTIVE' for v in vals2)


def test_incremental_impact_graph_keeps_old_related_neighbor(tmp_path: Path):
    paths = core.ensure_workspace(tmp_path, 'example.test', scopes=['example.test'], project_name='Example')
    add(paths, 'https://example.test/orders', 'POST',
        'POST /orders HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{"accountId":"A-99"}',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"orderId":"ORD-123"}')
    with core.db_connect(paths) as conn:
        first = ca.build_analysis_bundle(conn)
        account = next(c for c in first['candidates'] if c['value_sample'] == 'A-99')
        order = next(c for c in first['candidates'] if c['value_sample'] == 'ORD-123')
        rid = conn.execute("INSERT INTO semantic_agent_runs(agent_version,mode,model,status,created_at) VALUES(?,?,?,?,?)", (ca.AGENT_VERSION,'incremental','gpt-6.1-sol','running',ca.now_iso())).lastrowid
        ca._persist_result(conn, rid, first, {
            'summary':'ok',
            'inferences':[
                {'candidate_id':account['candidate_id'],'category':'business_object','semantic_type':'Account','role':'owner_scope','confidence':0.97,'explanation':'account context','evidence_observation_ids':account['observation_ids']},
                {'candidate_id':order['candidate_id'],'category':'business_object','semantic_type':'Order','role':'identifier','confidence':0.98,'explanation':'order lifecycle','evidence_observation_ids':order['observation_ids']},
            ],
            'relationships':[{'src_candidate_id':account['candidate_id'],'relation':'owns','dst_candidate_id':order['candidate_id'],'dst_literal':None,'confidence':0.95,'explanation':'observed together','evidence_observation_ids':account['observation_ids']+order['observation_ids']}],
        })
        conn.execute("UPDATE semantic_agent_runs SET status='completed',watermark_exchange_after=?,watermark_observation_after=?,finished_at=? WHERE id=?", (first['watermark_after']['exchange'],first['watermark_after']['observation'],ca.now_iso(),rid))
    add(paths, 'https://example.test/refund', 'POST',
        'POST /refund HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{"orderRef":"ORD-123","refundId":"RF-77"}',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"refundId":"RF-77"}')
    with core.db_connect(paths) as conn:
        second = ca.build_analysis_bundle(conn)
        values = {c['value_sample']: c for c in second['candidates']}
        assert 'ORD-123' in values and 'RF-77' in values
        # A-99 is not in the new request; it survives because it is a semantic graph neighbor.
        assert 'A-99' in values
        assert second['stats']['graph_neighbor_candidates'] >= 1


def test_incremental_reconsiders_old_traffic_when_flow_context_changes(tmp_path: Path):
    paths = core.ensure_workspace(tmp_path, 'example.test', scopes=['example.test'], project_name='Example')
    add(paths, 'https://example.test/orders', 'GET',
        'GET /orders?accountId=A-99 HTTP/1.1\r\nHost: example.test\r\n\r\n',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"orderId":"ORD-123"}')
    with core.db_connect(paths) as conn:
        first = ca.build_analysis_bundle(conn)
        rid = conn.execute("INSERT INTO semantic_agent_runs(agent_version,mode,model,status,watermark_exchange_after,watermark_observation_after,created_at,finished_at) VALUES(?,?,?,?,?,?,?,?)",
            (ca.AGENT_VERSION,'incremental','gpt-6.1-sol','completed',first['watermark_after']['exchange'],first['watermark_after']['observation'],ca.now_iso(),ca.now_iso())).lastrowid
        exid = conn.execute('SELECT id FROM http_exchanges ORDER BY id DESC LIMIT 1').fetchone()['id']
        flow_id = conn.execute("INSERT INTO flows(name,created_at,updated_at) VALUES(?,?,?)", ('Checkout',ca.now_iso(),ca.now_iso())).lastrowid
        conn.execute("INSERT INTO flow_steps(flow_id,position,exchange_id,included,created_at,updated_at) VALUES(?,?,?,?,?,?)", (flow_id,1,exid,1,ca.now_iso(),ca.now_iso()))
        second = ca.build_analysis_bundle(conn)
        assert second['stats']['new_observations'] == 0
        assert second['stats']['flow_context_updates'] > 0
        assert second['candidates']
        assert any(flow_id in c['flow_ids'] for c in second['candidates'])


def test_context_agent_ui_contract_and_workbench_relation_rendering():
    root = Path(__file__).resolve().parents[1]
    page = (root/'web/templates/context_agent.html').read_text(encoding='utf-8')
    wb = (root/'web/templates/http_workbench.html').read_text(encoding='utf-8')
    js = (root/'web/static/app.js').read_text(encoding='utf-8')
    assert 'Calcular antes de ejecutar' in page
    assert 'Límite por ejecución · USD' in page
    assert 'Inteligente · incremental' in page
    assert 'Cost Ledger' in page or 'COST LEDGER' in page
    assert 'AI Context' in wb and 'RELACIONES' in wb
    assert "r.relation||'related_to'" in js


def test_sensitive_auth_values_are_redacted_from_agent_bundle(tmp_path: Path):
    import json
    enc=lambda obj: base64.urlsafe_b64encode(json.dumps(obj,separators=(',',':')).encode()).decode().rstrip('=')
    token=f"{enc({'alg':'none'})}.{enc({'sub':'USR-7','role':'buyer'})}.sig"
    paths = core.ensure_workspace(tmp_path, 'example.test', scopes=['example.test'], project_name='Example')
    add(paths, 'https://example.test/me', 'GET',
        f'GET /me HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer {token}\r\nCookie: session=VERYSECRETSESSION123456\r\n\r\n',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"memberId":"USR-7"}')
    with core.db_connect(paths) as conn:
        bundle=ca.build_analysis_bundle(conn)
        blob=json.dumps(bundle)
        assert token not in blob
        assert 'VERYSECRETSESSION123456' not in blob
        assert 'USR-7' in blob  # JWT claim / business reference remains analyzable.


def test_context_agent_derives_state_transition_for_same_object(tmp_path: Path):
    paths = core.ensure_workspace(tmp_path, 'example.test', scopes=['example.test'], project_name='Example')
    add(paths, 'https://example.test/orders', 'POST',
        'POST /orders HTTP/1.1\r\nHost: example.test\r\n\r\n',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"orderId":"ORD-1","status":"PENDING"}')
    add(paths, 'https://example.test/orders/ORD-1', 'GET',
        'GET /orders/ORD-1 HTTP/1.1\r\nHost: example.test\r\n\r\n',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"orderId":"ORD-1","status":"PAID"}')
    with core.db_connect(paths) as conn:
        bundle=ca.build_analysis_bundle(conn)
        tr=next(t for t in bundle['state_transitions'] if t['object_value']=='ORD-1')
        assert tr['from']=='PENDING' and tr['to']=='PAID'
        assert len(tr['evidence_observation_ids'])==4
