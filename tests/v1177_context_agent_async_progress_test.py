from pathlib import Path
import negro_core as core
import negro_context_agent as ca


def test_execute_emits_progress_and_completes(tmp_path: Path, monkeypatch):
    paths=core.ensure_workspace(tmp_path,'example.test',scopes=['example.test'],project_name='Example')
    with core.db_connect(paths) as conn:
        ca.init_schema(conn); now=ca.now_iso()
        for i,key in enumerate(('memberId','accountId','orderId')):
            value=f'V-{i}'; norm=ca._norm_key(key); vh=ca.http_inspector.sha(value)
            cid=ca._candidate_id(norm,vh,value=value,kind='scalar',location=f'request_json:$.{key}')
            conn.execute('''INSERT INTO semantic_observations(exchange_id,side,location,key_name,normalized_key,candidate_id,value_hash,value_preview,value_raw,value_kind,method,hostname,path,flow_ids_json,first_seen_at,created_at)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                         (i+1,'request',f'request_json:$.{key}',key,norm,cid,vh,value,value,'scalar','POST','example.test','/login','[1]',now,now))
        monkeypatch.setattr(ca.intel,'load_settings',lambda:{'usd_cop_rate':3160.05})
        def fake_run(bundle, *, model, output_tokens, reasoning_effort):
            inf=[]
            for c in bundle.get('candidates') or []:
                inf.append({'candidate_id':c['candidate_id'],'category':'business_object','semantic_type':'Thing','role':'identifier','confidence':0.95,'explanation':'test','evidence_observation_ids':list(c.get('observation_ids') or [])[:2]})
            return {'summary':'ok','inferences':inf,'relationships':[]},{'input_tokens':100,'output_tokens':20,'total_tokens':120}
        monkeypatch.setattr(ca,'run_model',fake_run)
        progress=[]
        result=ca.execute(conn,mode='full',model=ca.HYBRID_MODEL,budget_cop=100000,progress_callback=progress.append)
        assert result['ok'] is True
        stages=[p.get('stage') for p in progress]
        assert 'preparing' in stages
        assert 'luna' in stages
        assert 'persisting' in stages
        assert stages[-1]=='completed'
        assert any(p.get('run_id') for p in progress)
        assert result['completeness']['coverage_pct']==100.0


def test_context_agent_async_ui_and_timeout_contract():
    root=Path(__file__).resolve().parents[1]
    page=(root/'web/templates/context_agent.html').read_text(encoding='utf-8')
    web=(root/'negro_web.py').read_text(encoding='utf-8')
    agent=(root/'negro_context_agent.py').read_text(encoding='utf-8')
    assert 'Context Agent v1.7' in page
    assert 'data-status-url' in page
    assert 'reconnectStatus' in page
    assert 'pollJob' in page
    assert '/context-agent/status' in web
    assert '_start_context_agent_job' in web
    assert 'already_running' in web
    assert 'MODEL_TIMEOUT_SECONDS' in agent
    assert 'max_retries=MODEL_MAX_RETRIES' in agent
