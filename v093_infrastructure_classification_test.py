from pathlib import Path
import sqlite3, tempfile, threading
import negro_core as core
import negro_runners

root=Path(tempfile.mkdtemp())
core.TARGETS_PATH=root/'targets.json'; core.CONFIG_PATH=root/'config.json'
ws=root/'ws'
core.ensure_workspace(ws,'example.com',scopes=['example.com'],project_name='Example')
key=core.register_target('example.com',ws,name='Example',scopes=['example.com'])
t=core.get_target(key)
roots=core.normalize_scopes([*(t.get('scopes') or []),'api.qa.example.net'], t.get('domain'))
core.update_target_project(key,name=t.get('name'),scopes=roots)
roots2=core.normalize_scopes([*(core.get_target(key).get('scopes') or []),'api.qa.example.net'], 'example.com')
assert roots2.count('api.qa.example.net') == 1
assert 'api.qa.example.net' in core.get_target(key)['scopes']
print('[OK] Burp-assigned scope persists once in the selected Negro project')

p=root/'race.db'
c=sqlite3.connect(p); c.row_factory=sqlite3.Row
c.executescript('''CREATE TABLE hypotheses(id INTEGER PRIMARY KEY); CREATE TABLE flows(id INTEGER PRIMARY KEY); CREATE TABLE flow_steps(id INTEGER PRIMARY KEY); CREATE TABLE identities(id INTEGER PRIMARY KEY); CREATE TABLE http_exchanges(id INTEGER PRIMARY KEY);'''); c.commit(); c.close()
errors=[]
def worker():
    try:
        conn=sqlite3.connect(p, timeout=5); conn.row_factory=sqlite3.Row
        negro_runners.init_schema(conn); conn.commit(); conn.close()
    except Exception as exc: errors.append(exc)
threads=[threading.Thread(target=worker) for _ in range(8)]
for t in threads:t.start()
for t in threads:t.join()
assert not errors, errors
cols=[r[1] for r in sqlite3.connect(p).execute('PRAGMA table_info(runner_run_requests)')]
assert cols.count('url') == 1
print('[OK] concurrent Runner schema initialization no longer races on duplicate url column')
