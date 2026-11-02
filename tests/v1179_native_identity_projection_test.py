import base64
from pathlib import Path

import negro_core as core
import negro_context_agent as ca
import negro_identity as identity_tools
import negro_native_projection as projection


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def add(paths, req, resp):
    return core.upsert_http_observation(
        paths, 'example.test', url='https://example.test/api/clientData', method='POST', source='burp', status_code=200,
        authenticated=True, request_content_type='application/json', response_content_type='application/json',
        request_b64=b64(req), response_b64=b64(resp),
    )


def _insert_inference(conn, obs, semantic_type, role, confidence=0.90, category='identity'):
    rid=conn.execute("SELECT COALESCE(MAX(id),0) id FROM semantic_agent_runs").fetchone()['id']
    if not rid:
        rid=conn.execute("INSERT INTO semantic_agent_runs(agent_version,mode,model,status,created_at) VALUES(?,?,?,?,?)",(ca.AGENT_VERSION,'incremental','gpt-6-luna','completed',ca.now_iso())).lastrowid
    conn.execute(
        """INSERT INTO semantic_inferences(candidate_id,normalized_key,value_hash,value_preview,category,semantic_type,role,model_confidence,evidence_confidence,confidence,status,source,explanation,evidence_json,run_id,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,'ai',?,?,?, ?,?)""",
        (obs['candidate_id'],obs['normalized_key'],obs['value_hash'],obs['value_preview'],category,semantic_type,role,confidence,confidence,confidence,'suggested','test',f"[{int(obs['id'])}]",rid,ca.now_iso(),ca.now_iso()),
    )


def test_existing_semantic_memory_creates_one_provisional_native_identity(tmp_path: Path):
    paths=core.ensure_workspace(tmp_path,'example.test',scopes=['example.test'],project_name='Example')
    add(paths,
        'POST /api/clientData HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{"documentNumber":"112233"}',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"memberId":"M-77","documentNumber":"112233","email":"user@example.test"}')
    with core.db_connect(paths) as conn:
        ca.build_analysis_bundle(conn)
        rows={r['key_name']:dict(r) for r in conn.execute("SELECT * FROM semantic_observations WHERE key_name IN ('memberId','documentNumber','email') ORDER BY id")}
        _insert_inference(conn,rows['memberId'],'Member','member identifier',0.91)
        _insert_inference(conn,rows['documentNumber'],'MemberDocumentNumber','personal identifier',0.88)
        _insert_inference(conn,rows['email'],'CustomerEmail','contact attribute',0.82)
        result=projection.project_current_memory(conn,force=True)
        assert result['created']==1
        assert conn.execute("SELECT COUNT(*) c FROM identities").fetchone()['c']==1
        meta=conn.execute("SELECT * FROM identity_ai_meta").fetchone()
        assert meta['status']=='provisional'
        attrs=[dict(r) for r in conn.execute("SELECT * FROM identity_ai_attributes ORDER BY id")]
        assert {a['attribute_kind'] for a in attrs} >= {'resolver','attribute'}
        links=[dict(r) for r in conn.execute("SELECT relation FROM identity_semantic_links")]
        assert 'identified_by' in {x['relation'] for x in links}
        assert 'has_contact' in {x['relation'] for x in links}
        resolved=conn.execute("SELECT * FROM exchange_identities WHERE exchange_id=1").fetchone()
        assert resolved is not None
        sem=ca.semantics_for_exchange(conn,1)
        assert sem['native_identity'] is not None
        assert any(r.get('relation')=='has_contact' for r in sem['relations'])


def test_projection_enriches_manual_identity_instead_of_creating_duplicate(tmp_path: Path):
    paths=core.ensure_workspace(tmp_path,'example.test',scopes=['example.test'],project_name='Example')
    add(paths,
        'POST /api/clientData HTTP/1.1\r\nHost: example.test\r\n\r\n',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"memberId":"M-77"}')
    with core.db_connect(paths) as conn:
        ca.build_analysis_bundle(conn)
        iid=identity_tools.create_identity(conn,'Known Member',kind='person')
        identity_tools.assign_exchange(conn,1,iid,learn_auth=False,source='manual')
        obs=dict(conn.execute("SELECT * FROM semantic_observations WHERE key_name='memberId' LIMIT 1").fetchone())
        _insert_inference(conn,obs,'Member','member identifier',0.92)
        result=projection.project_current_memory(conn,force=True)
        assert result['created']==0 and result['enriched']==1
        assert conn.execute("SELECT COUNT(*) c FROM identities").fetchone()['c']==1
        meta=conn.execute("SELECT * FROM identity_ai_meta WHERE identity_id=?",(iid,)).fetchone()
        assert meta is not None and meta['status']=='existing'


def test_ai_context_ranks_business_above_technical_and_folds_transport(tmp_path: Path):
    paths=core.ensure_workspace(tmp_path,'example.test',scopes=['example.test'],project_name='Example')
    add(paths,
        'POST /api/clientData HTTP/1.1\r\nHost: example.test\r\nPriority: u=1\r\n\r\n',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nStrict-Transport-Security: max-age=123\r\n\r\n{"memberId":"M-77"}')
    with core.db_connect(paths) as conn:
        ca.build_analysis_bundle(conn)
        rows={r['key_name']:dict(r) for r in conn.execute("SELECT * FROM semantic_observations WHERE key_name IN ('memberId','Strict-Transport-Security')")}
        _insert_inference(conn,rows['memberId'],'Member','member identifier',0.91,'identity')
        _insert_inference(conn,rows['Strict-Transport-Security'],'TransportSecurityPolicy','response security policy',0.85,'context')
        sem=ca.semantics_for_exchange(conn,1)
        assert any(i['semantic_type']=='Member' for i in sem['summary_inferences'])
        assert not any(i['semantic_type']=='TransportSecurityPolicy' for i in sem['summary_inferences'])
        assert any(i['semantic_type']=='TransportSecurityPolicy' for i in sem['technical_inferences'])


def test_v1179_ui_contract():
    root=Path(__file__).resolve().parents[1]
    page=(root/'web/templates/context_agent.html').read_text()
    wb=(root/'web/templates/http_workbench.html').read_text()
    js=(root/'web/static/app.js').read_text()
    assert 'Context Agent v1.9' in page
    assert 'Native Projection' in page
    assert 'HIGH VALUE' in wb
    assert 'Contexto técnico' in wb
    assert 'wb-native-ai' in js

def test_source_and_target_actor_roles_do_not_auto_merge(tmp_path: Path):
    paths=core.ensure_workspace(tmp_path,'example.test',scopes=['example.test'],project_name='Example')
    core.upsert_http_observation(
        paths,'example.test',url='https://example.test/transfer',method='POST',source='burp',status_code=200,authenticated=True,
        request_content_type='application/json',response_content_type='application/json',
        request_b64=b64('POST /transfer HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{"sourceMemberId":"M-A","targetMemberId":"M-B"}'),
        response_b64=b64('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}'))
    with core.db_connect(paths) as conn:
        ca.build_analysis_bundle(conn)
        rows={r['key_name']:dict(r) for r in conn.execute("SELECT * FROM semantic_observations WHERE key_name IN ('sourceMemberId','targetMemberId')")}
        _insert_inference(conn,rows['sourceMemberId'],'Member','source actor',0.91)
        _insert_inference(conn,rows['targetMemberId'],'Member','target actor',0.91)
        result=projection.project_current_memory(conn,force=True)
        assert result['created']==2
        assert conn.execute("SELECT COUNT(*) c FROM identities").fetchone()['c']==2
