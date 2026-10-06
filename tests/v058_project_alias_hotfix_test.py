from pathlib import Path
import json, tempfile
import negro_core as core

root=Path(tempfile.mkdtemp())
core.TARGETS_PATH=root/'targets.json'
core.CONFIG_PATH=root/'config.json'
ws=root/'terpel'

# Reproduce the user's real state: named project + legacy domain alias, same workspace.
core.TARGETS_PATH.write_text(json.dumps({
    'last_target':'terpel',
    'targets':{
        'terpel':{
            'domain':'terpel.com','name':'TERPEL',
            'scopes':['terpel.com','www.viveterpel.com'],
            'workspace':str(ws),
        },
        'terpel.com':{'domain':'terpel.com','workspace':str(ws)},
    }
}), encoding='utf-8')
# config.json mirrors current project and must NOT be re-migrated.
core.CONFIG_PATH.write_text(json.dumps({
    'domain':'terpel.com','name':'TERPEL','scopes':['terpel.com','www.viveterpel.com'],
    'workspace':str(ws),
}), encoding='utf-8')

data=core.targets_load()
assert list(data['targets']) == ['terpel'], data
assert data['last_target']=='terpel'
assert data['targets']['terpel']['scopes']==['terpel.com','www.viveterpel.com']

# Loading repeatedly must not recreate terpel.com.
for _ in range(5):
    data=core.targets_load()
    assert 'terpel.com' not in data['targets'], data
    assert 'terpel' in data['targets']

saved=json.loads(core.TARGETS_PATH.read_text())
assert list(saved['targets']) == ['terpel'], saved
print('[OK] named project survives and legacy domain alias is healed permanently')

# Pure legacy install still migrates once.
root2=Path(tempfile.mkdtemp())
core.TARGETS_PATH=root2/'targets.json'; core.CONFIG_PATH=root2/'config.json'
ws2=root2/'legacy'
core.CONFIG_PATH.write_text(json.dumps({'domain':'legacy.example','workspace':str(ws2)}),encoding='utf-8')
data=core.targets_load()
assert 'legacy.example' in data['targets']
assert core.TARGETS_PATH.exists()
print('[OK] empty registry still migrates legacy config once')
