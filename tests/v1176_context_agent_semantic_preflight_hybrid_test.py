import base64
from pathlib import Path

import negro_core as core
import negro_context_agent as ca


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def add(paths, url, method, req, resp, status=200):
    return core.upsert_http_observation(
        paths, 'example.test', url=url, method=method, source='burp', status_code=status,
        authenticated=True, request_content_type='application/json', response_content_type='application/json',
        request_b64=b64(req), response_b64=b64(resp),
    )


def test_repeated_logging_telemetry_sleeps_but_login_business_values_survive(tmp_path: Path):
    paths=core.ensure_workspace(tmp_path,'example.test',scopes=['example.test'],project_name='Example')
    for i in range(6):
        add(paths,'https://example.test/api/logging','POST',
            f'POST /api/logging HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{{"event":"info","message":"render-{i}","timestamp":"2026-11-01T12:00:0{i}Z"}}',
            'HTTP/1.1 204 No Content\r\nContent-Type: text/plain\r\n\r\n',204)
    add(paths,'https://example.test/login','POST',
        'POST /login HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{"memberId":"M-7","accountId":"A-9"}',
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"memberId":"M-7","accountId":"A-9","status":"ACTIVE"}',200)
    with core.db_connect(paths) as conn:
        bundle=ca.build_analysis_bundle(conn,mode='full')
        vals={c['value_sample'] for c in bundle['candidates']}
        assert 'M-7' in vals and 'A-9' in vals and 'ACTIVE' in vals
        assert not any(str(v).startswith('render-') for v in vals)
        assert bundle['stats']['dormant_telemetry_candidates'] > 0
        assert bundle['stats']['dormant_telemetry_observations'] > 0
        # /login must never be classified as /log telemetry.
        assert ca._looks_telemetry_path('/login') is False


def test_role_aliases_collapse_into_one_semantic_family_without_corrupting_token():
    assert ca._semantic_key_family('fromMemberId') == 'member'
    assert ca._semantic_key_family('toMemberId') == 'member'
    assert ca._semantic_key_family('memberId') == 'member'
    assert ca._semantic_key_family('token') == 'token'
    candidates=[]
    for idx,key in enumerate(('fromMemberId','toMemberId','memberId')):
        candidates.append({
            'candidate_id':f'v_{idx}','normalized_key':ca._norm_key(key),'key':key,'aliases':[key],
            'value_sample':f'M-{idx}','value_kind':'scalar','occurrences':1,'request_occurrences':1,
            'response_occurrences':0,'produced_then_consumed':False,
            'endpoints':[{'method':'POST','path':'/transfer','side':'request','location':f'request_json:$.{key}','exchange_id':1}],
            'flow_ids':[1],'manual_ground_truth':[],'observation_ids':[idx+1],'score':5.0,'selection_reasons':['flow_context'],
        })
    units,mapping=ca._build_concept_units(candidates)
    assert len(units)==1
    assert units[0]['instance_count']==3
    assert len(mapping)==3


def test_hybrid_estimate_analyzes_all_families_with_luna_and_only_reserves_sol_subset(tmp_path: Path, monkeypatch):
    paths=core.ensure_workspace(tmp_path,'example.test',scopes=['example.test'],project_name='Example')
    monkeypatch.setattr(ca.intel,'load_settings',lambda:{'usd_cop_rate':3160.05})
    with core.db_connect(paths) as conn:
        ca.init_schema(conn)
        now=ca.now_iso()
        # 80 different schema families, all relevant, to exercise hybrid reserve.
        for i in range(80):
            key=f'businessField{i}Id'
            value=f'OBJ-{i:03d}'
            norm=ca._norm_key(key); vh=ca.http_inspector.sha(value)
            cid=ca._candidate_id(norm,vh,value=value,kind='scalar',location=f'request_json:$.{key}')
            conn.execute(
                '''INSERT INTO semantic_observations(exchange_id,side,location,key_name,normalized_key,candidate_id,value_hash,value_preview,value_raw,value_kind,method,hostname,path,flow_ids_json,first_seen_at,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (i+1,'request',f'request_json:$.{key}',key,norm,cid,vh,value,value,'scalar','POST','example.test',f'/business/{i}','[1]',now,now),
            )
        bundle=ca.build_analysis_bundle(conn,mode='full')
        hybrid=ca.estimate_bundle(bundle,model=ca.HYBRID_MODEL)
        sol=ca.estimate_bundle(bundle,model=ca.SOL_MODEL)
        assert hybrid['luna_concepts']==bundle['stats']['model_concepts']
        assert hybrid['sol_reserve_concepts'] <= ca.HYBRID_SOL_MAX_RESERVE
        assert hybrid['sol_reserve_concepts'] < hybrid['luna_concepts']
        assert hybrid['expected_total_cop_est'] < sol['expected_total_cop_est']
        assert hybrid['pipeline_mode']=='luna_then_selective_sol'


def test_sol_escalation_prefers_ambiguity_and_boundaries_without_dropping_luna_coverage():
    units=[]
    inferences=[]
    for i in range(20):
        key='organizationId' if i==0 else f'field{i}Id'
        cid=f'c_{i}'
        units.append({'candidate_id':cid,'normalized_key':ca._norm_key(key),'score':6.0,'flow_priority':i<2,'produced_then_consumed':i<3,'existing_inference_summary':[]})
        inferences.append({'candidate_id':cid,'category':'authorization_boundary' if i==0 else 'business_object','semantic_type':'Organization' if i==0 else 'Thing','confidence':0.78 if i<3 else 0.96})
    bundle={'model_units':units}
    ids=ca._select_sol_escalations(bundle,{'inferences':inferences,'relationships':[]})
    assert 'c_0' in ids
    assert 'c_1' in ids and 'c_2' in ids
    assert len(ids) <= ca._sol_reserve_count(20)


def test_hybrid_execute_luna_covers_every_family_and_sol_refines_only_ambiguous(tmp_path: Path, monkeypatch):
    paths=core.ensure_workspace(tmp_path,'example.test',scopes=['example.test'],project_name='Example')
    monkeypatch.setattr(ca.intel,'load_settings',lambda:{'usd_cop_rate':3160.05})
    with core.db_connect(paths) as conn:
        ca.init_schema(conn); now=ca.now_iso()
        for i,key in enumerate(('organizationId','accountId','memberId','orderId','statusCode','deviceId')):
            value=f'V-{i:02d}'; norm=ca._norm_key(key); vh=ca.http_inspector.sha(value)
            cid=ca._candidate_id(norm,vh,value=value,kind='scalar',location=f'request_json:$.{key}')
            conn.execute(
                '''INSERT INTO semantic_observations(exchange_id,side,location,key_name,normalized_key,candidate_id,value_hash,value_preview,value_raw,value_kind,method,hostname,path,flow_ids_json,first_seen_at,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (i+1,'request',f'request_json:$.{key}',key,norm,cid,vh,value,value,'scalar','POST','example.test','/business/action','[1]',now,now),
            )
        calls=[]
        def fake_run(bundle, *, model, output_tokens, reasoning_effort):
            calls.append((model,[c['candidate_id'] for c in bundle.get('candidates') or []]))
            inf=[]
            for c in bundle.get('candidates') or []:
                is_org='organization' in str(c.get('normalized_key') or '')
                inf.append({
                    'candidate_id':c['candidate_id'],
                    'category':'authorization_boundary' if is_org else 'business_object',
                    'semantic_type':'Organization' if is_org else 'Thing',
                    'role':'boundary' if is_org else 'identifier',
                    'confidence':0.76 if (model==ca.LUNA_MODEL and is_org) else 0.96,
                    'explanation':'test',
                    'evidence_observation_ids':list(c.get('observation_ids') or [])[:2],
                })
            return {'summary':model,'inferences':inf,'relationships':[]},{'input_tokens':100,'output_tokens':50,'total_tokens':150}
        monkeypatch.setattr(ca,'run_model',fake_run)
        result=ca.execute(conn,mode='full',model=ca.HYBRID_MODEL,budget_cop=100000)
        assert result['completeness']['coverage_pct']==100.0
        assert result['completeness']['truncated'] is False
        luna_ids={cid for model,ids in calls if model==ca.LUNA_MODEL for cid in ids}
        sol_ids={cid for model,ids in calls if model==ca.SOL_MODEL for cid in ids}
        bundle=ca.build_analysis_bundle(conn,mode='full')
        all_ids={u['candidate_id'] for u in bundle['model_units']}
        assert luna_ids==all_ids
        assert sol_ids and sol_ids < luna_ids
        assert result['completeness']['sol_refined']==len(sol_ids)
