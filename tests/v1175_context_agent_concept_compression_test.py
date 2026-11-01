from pathlib import Path

import negro_core as core
import negro_context_agent as ca


def seed_instances(conn, key: str, prefix: str, count: int):
    ca.init_schema(conn)
    now=ca.now_iso()
    norm=ca._norm_key(key)
    for i in range(count):
        value=f"{prefix}-{i:04d}"
        vh=ca.http_inspector.sha(value)
        cid=ca._candidate_id(norm,vh,value=value,kind='scalar',location=f'request_json:$.{key}')
        conn.execute(
            """INSERT INTO semantic_observations(
                exchange_id,side,location,key_name,normalized_key,candidate_id,value_hash,value_preview,value_raw,value_kind,
                method,hostname,path,flow_ids_json,first_seen_at,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (i+1,'request',f'request_json:$.{key}',key,norm,cid,vh,value,value,'scalar','POST','example.test','/business/action','[]',now,now),
        )


def test_many_instances_are_compressed_into_semantic_concepts_without_dropping_members(tmp_path: Path):
    paths=core.ensure_workspace(tmp_path,'example.test',scopes=['example.test'],project_name='Example')
    with core.db_connect(paths) as conn:
        seed_instances(conn,'accountId','ACC',240)
        seed_instances(conn,'orderId','ORD',80)
        bundle=ca.build_analysis_bundle(conn,mode='full')
        assert bundle['stats']['selected_candidates']==320
        assert bundle['stats']['instance_candidates']==320
        assert bundle['stats']['model_concepts']==2
        assert bundle['stats']['semantic_compression_ratio']==160.0
        assert len(bundle['batch_plan'])==1
        members={m for u in bundle['model_units'] for m in u['member_candidate_ids']}
        assert len(members)==320
        assert members=={c['candidate_id'] for c in bundle['candidates']}


def test_concept_inference_projects_back_to_every_concrete_instance(tmp_path: Path):
    paths=core.ensure_workspace(tmp_path,'example.test',scopes=['example.test'],project_name='Example')
    with core.db_connect(paths) as conn:
        seed_instances(conn,'accountId','ACC',25)
        bundle=ca.build_analysis_bundle(conn,mode='full')
        concept=bundle['model_units'][0]
        rid=conn.execute(
            "INSERT INTO semantic_agent_runs(agent_version,mode,model,status,created_at) VALUES(?,?,?,?,?)",
            (ca.AGENT_VERSION,'full','gpt-6.1-sol','running',ca.now_iso()),
        ).lastrowid
        result={
            'summary':'account concept',
            'inferences':[{
                'candidate_id':concept['candidate_id'],'category':'business_object','semantic_type':'Account',
                'role':'identifier','confidence':0.97,'explanation':'same field/context across instances',
                'evidence_observation_ids':concept['observation_ids'],
            }],
            'relationships':[],
        }
        persisted=ca._persist_result(conn,rid,bundle,result)
        assert persisted['concepts']==1
        assert persisted['inferences']==25
        rows=conn.execute("SELECT DISTINCT semantic_type FROM semantic_inferences WHERE run_id=?",(rid,)).fetchall()
        assert [r['semantic_type'] for r in rows]==['Account']
        assert conn.execute("SELECT COUNT(*) c FROM semantic_inferences WHERE run_id=?",(rid,)).fetchone()['c']==25


def test_estimate_is_based_on_concepts_not_instance_count(tmp_path: Path, monkeypatch):
    paths=core.ensure_workspace(tmp_path,'example.test',scopes=['example.test'],project_name='Example')
    monkeypatch.setattr(ca.intel,'load_settings',lambda:{'usd_cop_rate':3160.05})
    with core.db_connect(paths) as conn:
        seed_instances(conn,'accountId','ACC',500)
        bundle=ca.build_analysis_bundle(conn,mode='full')
        est=ca.estimate_bundle(bundle,model='gpt-6.1-sol')
        assert est['instance_candidates']==500
        assert est['concept_count']==1
        assert est['batch_count']==1
        assert est['input_tokens_est'] < 10000
        assert est['expected_total_cop_est'] < 1000
