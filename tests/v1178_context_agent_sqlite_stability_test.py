from pathlib import Path
import inspect
import negro_context_agent as ca
import negro_core as core


def test_luna_has_exactly_one_model_call_per_loop_body():
    src=inspect.getsource(ca.execute)
    call='r,u=run_model(b,model=LUNA_MODEL,output_tokens=out_budget,reasoning_effort="low")'
    assert src.count(call)==1


def test_run_creation_commits_before_remote_models():
    src=inspect.getsource(ca.execute)
    assert src.index('conn.commit()') < src.index('run_model(')


def test_sqlite_busy_timeout_is_30_seconds(tmp_path: Path):
    paths=core.ensure_workspace(tmp_path,'example.test',scopes=['example.test'])
    with core.db_connect(paths) as conn:
        assert int(conn.execute('PRAGMA busy_timeout').fetchone()[0])==30000


def test_read_only_polling_routes_use_fast_target_context():
    root=Path(__file__).resolve().parents[1]
    web=(root/'negro_web.py').read_text(encoding='utf-8')
    assert 'def _target_context(target_key: str, *, ensure: bool = True)' in web
    assert 'def notifications_api' in web
    assert web.count('_target_context(target_key, ensure=False)') >= 3


def test_progress_feedback_is_above_estimate_and_v18():
    root=Path(__file__).resolve().parents[1]
    page=(root/'web/templates/context_agent.html').read_text(encoding='utf-8')
    assert 'Context Agent v1.8' in page
    assert page.index('data-ca-feedback') < page.index('data-ca-estimate-box')
