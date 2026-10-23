from pathlib import Path
import tempfile
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

import negro_core as core


def test_project_scopes_automatically_become_surface_roots():
    with tempfile.TemporaryDirectory(prefix='negro-v091-sync-') as td:
        old=core.TARGETS_PATH
        try:
            core.TARGETS_PATH=Path(td)/'targets.json'
            key=core.register_target(
                'alpha.test', Path(td)/'ws',
                name='Program',
                scopes=['alpha.test','beta.test','api.gamma.test'],
            )
            target=core.get_target(key)
            assert target['scopes']==['alpha.test','beta.test','api.gamma.test']
            assert target['recon_roots']==['alpha.test','beta.test','api.gamma.test']
        finally:
            core.TARGETS_PATH=old


def test_project_scope_edit_adds_and_removes_surface_roots():
    with tempfile.TemporaryDirectory(prefix='negro-v091-edit-') as td:
        old=core.TARGETS_PATH
        try:
            core.TARGETS_PATH=Path(td)/'targets.json'
            key=core.register_target('alpha.test',Path(td)/'ws',scopes=['alpha.test','beta.test'])
            updated=core.update_target_project(key,scopes=['alpha.test','gamma.test'])
            assert updated['recon_roots']==['alpha.test','gamma.test']
            assert 'beta.test' not in updated['recon_roots']
        finally:
            core.TARGETS_PATH=old


def test_existing_v090_project_is_healed_from_scopes():
    with tempfile.TemporaryDirectory(prefix='negro-v091-migrate-') as td:
        old=core.TARGETS_PATH
        try:
            core.TARGETS_PATH=Path(td)/'targets.json'
            core.TARGETS_PATH.write_text('''{
              "last_target": "program",
              "targets": {
                "program": {
                  "domain": "alpha.test",
                  "workspace": "/tmp/example",
                  "name": "Program",
                  "scopes": ["alpha.test", "beta.test", "gamma.test"],
                  "recon_roots": ["alpha.test"]
                }
              }
            }''', encoding='utf-8')
            target=core.get_target('program')
            assert target['recon_roots']==['alpha.test','beta.test','gamma.test']
            raw=core.targets_load()['targets']['program']
            assert raw['recon_roots']==['alpha.test','beta.test','gamma.test']
        finally:
            core.TARGETS_PATH=old
