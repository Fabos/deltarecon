from pathlib import Path

import negro_core as core
import negro_context_agent as ca


def seed_candidates(conn, count=135):
    ca.init_schema(conn)
    now=ca.now_iso()
    for i in range(count):
        value=f"OBJ-{i:04d}"
        vh=ca.http_inspector.sha(value)
        conn.execute(
            """INSERT INTO semantic_observations(
                exchange_id,side,location,key_name,normalized_key,candidate_id,value_hash,value_preview,value_raw,value_kind,
                method,hostname,path,flow_ids_json,first_seen_at,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (i+1,'request',f'query:objectId{i}',f'objectId{i}',f'objectid{i}',f'v_{vh[:16]}',vh,value,value,'scalar','GET','example.test',f'/objects/{i}','[]',now,now),
        )


def test_context_agent_has_no_fixed_120_candidate_cap_and_batches_all(tmp_path: Path):
    paths=core.ensure_workspace(tmp_path,'example.test',scopes=['example.test'],project_name='Example')
    with core.db_connect(paths) as conn:
        seed_candidates(conn,135)
        bundle=ca.build_analysis_bundle(conn,mode='full')
        assert bundle['stats']['selected_candidates']==135
        assert bundle['stats']['candidate_cap_applied'] is False
        assert len(bundle['batch_plan'])==3
        flattened=[cid for batch in bundle['batch_plan'] for cid in batch]
        assert len(flattened)==135
        assert len(set(flattened))==135


def test_context_agent_estimate_is_cop_first_and_auto_output(tmp_path: Path, monkeypatch):
    paths=core.ensure_workspace(tmp_path,'example.test',scopes=['example.test'],project_name='Example')
    monkeypatch.setattr(ca.intel,'load_settings',lambda:{'usd_cop_rate':3160.05})
    with core.db_connect(paths) as conn:
        seed_candidates(conn,60)
        data=ca.estimate(conn,mode='full',model='gpt-6.1-sol')
        est=data['estimate']
        assert est['batch_count']==2
        assert est['candidate_count']==60
        assert est['candidate_cap_applied'] is False
        assert est['output_tokens_budget']>0
        assert est['max_total_cop_est']>0
        assert est['max_total_cop_est']==est['max_total_usd_est']*3160.05


def test_context_agent_executes_every_batch_and_reports_100_percent(tmp_path: Path, monkeypatch):
    paths=core.ensure_workspace(tmp_path,'example.test',scopes=['example.test'],project_name='Example')
    monkeypatch.setattr(ca.intel,'load_settings',lambda:{'usd_cop_rate':3160.05})
    calls=[]
    def fake_run(bundle, **kwargs):
        calls.append([c['candidate_id'] for c in bundle['candidates']])
        return {
            'summary':f"batch {bundle['batch']['number']}",
            'inferences':[],
            'relationships':[],
        }, {'input_tokens':1000,'output_tokens':100,'total_tokens':1100}
    monkeypatch.setattr(ca,'run_model',fake_run)
    with core.db_connect(paths) as conn:
        seed_candidates(conn,135)
        result=ca.execute(conn,mode='full',model='gpt-6.1-sol',budget_cop=100000)
        assert len(calls)==3
        assert sum(len(x) for x in calls)==135
        assert len({cid for batch in calls for cid in batch})==135
        assert result['completeness']['coverage_pct']==100.0
        assert result['completeness']['truncated'] is False
        assert result['completeness']['candidates_analyzed']==135
        assert result['cost_cop']>0
