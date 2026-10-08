from __future__ import annotations

import base64
import json
import re
import time
import urllib.parse
import os
import socket
import ssl
import sqlite3
from datetime import datetime, timezone
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_schema(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS runners (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER NOT NULL,
            alias TEXT NOT NULL,
            description TEXT,
            hypothesis_id INTEGER,
            identity_id INTEGER,
            status TEXT NOT NULL DEFAULT 'draft',
            origin TEXT NOT NULL DEFAULT 'manual',
            ai_idea_json TEXT,
            max_requests INTEGER NOT NULL DEFAULT 30,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(flow_id) REFERENCES flows(id) ON DELETE CASCADE,
            FOREIGN KEY(hypothesis_id) REFERENCES leads_v2(id) ON DELETE SET NULL,
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_runners_flow ON runners(flow_id, updated_at);
        CREATE INDEX IF NOT EXISTS idx_runners_hypothesis ON runners(hypothesis_id, updated_at);

        CREATE TABLE IF NOT EXISTS runner_hypotheses (
            runner_id INTEGER NOT NULL,
            hypothesis_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(runner_id,hypothesis_id),
            FOREIGN KEY(runner_id) REFERENCES runners(id) ON DELETE CASCADE,
            FOREIGN KEY(hypothesis_id) REFERENCES leads_v2(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_runner_hypotheses_hypothesis ON runner_hypotheses(hypothesis_id,runner_id);

        CREATE TABLE IF NOT EXISTS runner_steps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            runner_id INTEGER NOT NULL,
            flow_step_id INTEGER NOT NULL,
            position INTEGER NOT NULL,
            action TEXT NOT NULL DEFAULT 'keep',
            repeat_count INTEGER NOT NULL DEFAULT 1,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(runner_id, flow_step_id),
            FOREIGN KEY(runner_id) REFERENCES runners(id) ON DELETE CASCADE,
            FOREIGN KEY(flow_step_id) REFERENCES flow_steps(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_runner_steps_runner ON runner_steps(runner_id, position);

        CREATE TABLE IF NOT EXISTS runner_variables (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            runner_id INTEGER NOT NULL,
            target_runner_step_id INTEGER NOT NULL,
            target_name TEXT NOT NULL,
            target_value TEXT,
            mode TEXT NOT NULL DEFAULT 'values',
            values_json TEXT,
            source_runner_step_id INTEGER,
            source_name TEXT,
            regex_pattern TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(runner_id) REFERENCES runners(id) ON DELETE CASCADE,
            FOREIGN KEY(target_runner_step_id) REFERENCES runner_steps(id) ON DELETE CASCADE,
            FOREIGN KEY(source_runner_step_id) REFERENCES runner_steps(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_runner_variables_runner ON runner_variables(runner_id, target_runner_step_id);

        CREATE TABLE IF NOT EXISTS runner_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            runner_id INTEGER NOT NULL,
            result_flow_id INTEGER,
            identity_id INTEGER,
            status TEXT NOT NULL DEFAULT 'queued',
            outcome TEXT NOT NULL DEFAULT 'unreviewed',
            summary_json TEXT,
            error TEXT,
            started_at TEXT,
            finished_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(runner_id) REFERENCES runners(id) ON DELETE CASCADE,
            FOREIGN KEY(result_flow_id) REFERENCES flows(id) ON DELETE SET NULL,
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_runner_runs_runner ON runner_runs(runner_id, created_at);

        CREATE TABLE IF NOT EXISTS runner_run_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            runner_step_id INTEGER NOT NULL,
            repeat_index INTEGER NOT NULL DEFAULT 1,
            exchange_id INTEGER,
            status_code INTEGER,
            elapsed_ms INTEGER,
            error TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(run_id) REFERENCES runner_runs(id) ON DELETE CASCADE,
            FOREIGN KEY(runner_step_id) REFERENCES runner_steps(id) ON DELETE CASCADE,
            FOREIGN KEY(exchange_id) REFERENCES http_exchanges(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_runner_run_requests_run ON runner_run_requests(run_id, id);
        """
    )
    def _safe_add_column(table: str, name: str, ddl: str) -> None:
        cols={row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if name in cols:
            return
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                raise

    _safe_add_column("runners", "investigation_id", "INTEGER")
    _safe_add_column("runners", "target_flow_step_id", "INTEGER")
    for name,ddl in {
        "experiment_goal":"TEXT",
        "expected_support":"TEXT",
        "expected_refute":"TEXT"
    }.items():
        _safe_add_column("runners", name, ddl)
    _safe_add_column("runner_runs", "execution_class", "TEXT NOT NULL DEFAULT 'pending'")
    _safe_add_column("runner_runs", "counts_as_test", "INTEGER NOT NULL DEFAULT 0")
    _safe_add_column("runner_runs", "context_snapshot_json", "TEXT")
    _safe_add_column("runner_runs", "hypothesis_id", "INTEGER")
    _safe_add_column("runner_runs", "target_flow_step_id", "INTEGER")
    # FastAPI can initialize Runner schema from more than one request/thread at
    # the same time.  SQLite has no ALTER TABLE ... ADD COLUMN IF NOT EXISTS,
    # so two initializers can both observe a missing column and race.  Re-read
    # the schema for every column and tolerate only the benign duplicate-column
    # race; any other OperationalError must still surface.
    for name,ddl in {
        "execution_class":"TEXT NOT NULL DEFAULT 'pending'",
        "method":"TEXT",
        "url":"TEXT",
        "request_b64":"TEXT",
        "response_b64":"TEXT",
        "transport_detail_json":"TEXT",
        "resolved_variables_json":"TEXT",
        "extracted_values_json":"TEXT",
        "identity_id":"INTEGER"
    }.items():
        req_cols={row["name"] for row in conn.execute("PRAGMA table_info(runner_run_requests)")}
        if name in req_cols:
            continue
        try:
            conn.execute(f"ALTER TABLE runner_run_requests ADD COLUMN {name} {ddl}")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                raise

    # Contexto compuesto · Fase 1: older v0.40 workspaces may already have
    # runners.investigation_id values. Mirror them once into investigation_links
    # so the generic many-to-many graph becomes authoritative without dropping
    # the legacy/origin pointer.
    try:
        import negro_hunter as hunter
        hunter.backfill_investigation_links(conn)
    except Exception:
        pass
    # Legacy compatibility: a Runner used to have a single hypothesis_id. Keep
    # it as the default/origin pointer, but mirror it into the reusable M:N link.
    try:
        conn.execute(
            """INSERT OR IGNORE INTO runner_hypotheses(runner_id,hypothesis_id,created_at)
               SELECT id,hypothesis_id,COALESCE(created_at,?) FROM runners WHERE hypothesis_id IS NOT NULL""",
            (now_iso(),),
        )
    except Exception:
        pass


def _load_json(value: Any, default: Any) -> Any:
    try:
        parsed = json.loads(value or "")
        return parsed
    except Exception:
        return default


def _request_params(conn, exchange_id: int) -> list[dict[str, Any]]:
    try:
        rows = conn.execute(
            """SELECT id,name,normalized_name,location,COALESCE(value_raw,value_preview,'') value
               FROM parameter_observations WHERE exchange_id=?
               AND (lower(location) LIKE 'request%' OR lower(location) LIKE 'query%' OR lower(location) LIKE 'header%' OR lower(location) LIKE 'cookie%')
               ORDER BY id LIMIT 80""",
            (int(exchange_id),),
        ).fetchall()
    except Exception:
        return []
    out=[]
    seen=set()
    for row in rows:
        item=dict(row)
        key=(str(item.get("normalized_name") or item.get("name") or "").lower(), str(item.get("value") or ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _flow_steps(conn, flow_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT fs.id flow_step_id,fs.position,fs.exchange_id,fs.label,fs.notes,fs.role_label,fs.checkpoint_label,e.status_code,
                  o.method,r.id resource_id,r.url,r.path,h.hostname
           FROM flow_steps fs JOIN http_exchanges e ON e.id=fs.exchange_id
           JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id
           JOIN hosts h ON h.id=r.host_id
           WHERE fs.flow_id=? AND fs.included=1 ORDER BY fs.position,fs.id""",
        (int(flow_id),),
    ).fetchall()
    out=[]
    for row in rows:
        item=dict(row)
        item["request_params"]=_request_params(conn,int(item["exchange_id"]))
        out.append(item)
    return out


def create_runner_from_flow(conn, flow_id: int, *, alias: str, description: str = "", hypothesis_id: int | None = None,
                            identity_id: int | None = None, investigation_id: int | None = None, origin: str = "manual", ai_idea: dict[str, Any] | None = None,
                            step_actions: list[dict[str, Any]] | None = None, variables: list[dict[str, Any]] | None = None,
                            experiment_goal: str = "", expected_support: str = "", expected_refute: str = "") -> int:
    init_schema(conn)
    flow = conn.execute("SELECT id,name,identity_id FROM flows WHERE id=?", (int(flow_id),)).fetchone()
    if not flow:
        raise ValueError("Flujo no encontrado")
    alias = str(alias or "").strip()[:180]
    if not alias:
        raise ValueError("Alias del Runner requerido")
    if identity_id is None and flow["identity_id"]:
        identity_id = int(flow["identity_id"])
    now=now_iso()
    cur=conn.execute(
        """INSERT INTO runners(flow_id,alias,description,hypothesis_id,identity_id,status,origin,ai_idea_json,max_requests,created_at,updated_at)
           VALUES(?,?,?,?,?,'draft',?,?,30,?,?)""",
        (int(flow_id),alias,str(description or "")[:5000],hypothesis_id,identity_id,str(origin or "manual")[:40],
         json.dumps(ai_idea,ensure_ascii=False) if ai_idea else None,now,now),
    )
    runner_id=int(cur.lastrowid)
    if hypothesis_id is not None:
        conn.execute(
            "INSERT OR IGNORE INTO runner_hypotheses(runner_id,hypothesis_id,created_at) VALUES(?,?,?)",
            (runner_id,int(hypothesis_id),now),
        )
    if experiment_goal or expected_support or expected_refute:
        conn.execute(
            "UPDATE runners SET experiment_goal=?,expected_support=?,expected_refute=?,updated_at=? WHERE id=?",
            (str(experiment_goal or "")[:5000],str(expected_support or "")[:5000],str(expected_refute or "")[:5000],now,runner_id),
        )
    if investigation_id is not None:
        conn.execute("UPDATE runners SET investigation_id=? WHERE id=?", (int(investigation_id), runner_id))
        try:
            import negro_hunter as hunter
            hunter.link_investigation_entity(conn, int(investigation_id), "runner", runner_id, "test")
        except Exception:
            pass
    actions_by_position={}
    actions_by_step={}
    for action in step_actions or []:
        if not isinstance(action,dict):
            continue
        if action.get("flow_step_id") is not None:
            try: actions_by_step[int(action["flow_step_id"])]=action
            except Exception: pass
        if action.get("position") is not None:
            try: actions_by_position[int(action["position"])]=action
            except Exception: pass
    step_map: dict[int,int]={}
    position_map: dict[int,int]={}
    for step in _flow_steps(conn,int(flow_id)):
        action=actions_by_step.get(int(step["flow_step_id"])) or actions_by_position.get(int(step["position"])) or {}
        mode=str(action.get("action") or "keep").lower()
        if mode not in {"keep","omit","repeat"}: mode="keep"
        repeat=max(1,min(20,int(action.get("repeat_count") or 1)))
        c=conn.execute(
            """INSERT INTO runner_steps(runner_id,flow_step_id,position,action,repeat_count,notes,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (runner_id,int(step["flow_step_id"]),int(step["position"]),mode,repeat,str(action.get("notes") or "")[:1000],now,now),
        )
        rsid=int(c.lastrowid)
        step_map[int(step["flow_step_id"])]=rsid
        position_map[int(step["position"])]=rsid
    for var in variables or []:
        if not isinstance(var,dict):
            continue
        target_rsid=None
        if var.get("target_flow_step_id") is not None:
            try: target_rsid=step_map.get(int(var["target_flow_step_id"]))
            except Exception: pass
        if target_rsid is None and var.get("target_position") is not None:
            try: target_rsid=position_map.get(int(var["target_position"]))
            except Exception: pass
        if not target_rsid:
            continue
        source_rsid=None
        if var.get("source_position") is not None:
            try: source_rsid=position_map.get(int(var["source_position"]))
            except Exception: pass
        mode=str(var.get("mode") or "values")
        if mode not in {"values","response_key","response_regex"}: mode="values"
        vals=var.get("values") or []
        if isinstance(vals,str): vals=[x.strip() for x in vals.splitlines() if x.strip()]
        conn.execute(
            """INSERT INTO runner_variables(runner_id,target_runner_step_id,target_name,target_value,mode,values_json,source_runner_step_id,source_name,regex_pattern,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (runner_id,target_rsid,str(var.get("target_name") or "").strip()[:160],str(var.get("target_value") or "")[:2000],mode,
             json.dumps(list(vals)[:100],ensure_ascii=False),source_rsid,str(var.get("source_name") or "")[:160],str(var.get("regex_pattern") or "")[:1000],now,now),
        )
    return runner_id


def list_runners(conn, *, flow_id: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
    init_schema(conn)
    params=[]
    where=""
    if flow_id is not None:
        where="WHERE ru.flow_id=?"; params.append(int(flow_id))
    rows=conn.execute(
        f"""SELECT ru.*,f.name flow_name,i.name identity_name,h.title hypothesis_title,
                    (SELECT COUNT(*) FROM runner_runs rr WHERE rr.runner_id=ru.id) run_count,
                    (SELECT COUNT(*) FROM runner_hypotheses rh WHERE rh.runner_id=ru.id) hypothesis_count,
                    (SELECT COUNT(*) FROM runner_runs rr WHERE rr.runner_id=ru.id AND rr.outcome='interesting' AND COALESCE(rr.counts_as_test,0)=1) interesting_runs,
                    (SELECT COUNT(*) FROM runner_runs rr WHERE rr.runner_id=ru.id AND rr.outcome='negative' AND COALESCE(rr.counts_as_test,0)=1) negative_runs
             FROM runners ru JOIN flows f ON f.id=ru.flow_id
             LEFT JOIN identities i ON i.id=ru.identity_id LEFT JOIN leads_v2 h ON h.id=ru.hypothesis_id
             {where} ORDER BY ru.updated_at DESC,ru.id DESC LIMIT ?""",
        tuple(params+[max(1,min(int(limit),500))]),
    ).fetchall()
    return [dict(r) for r in rows]


def get_runner(conn, runner_id: int) -> dict[str, Any] | None:
    init_schema(conn)
    row=conn.execute(
        """SELECT ru.*,f.name flow_name,f.description flow_description,f.identity_id flow_identity_id,i.name identity_name,h.title hypothesis_title,inv.title investigation_title
           FROM runners ru JOIN flows f ON f.id=ru.flow_id LEFT JOIN identities i ON i.id=ru.identity_id
           LEFT JOIN leads_v2 h ON h.id=ru.hypothesis_id LEFT JOIN investigations inv ON inv.id=ru.investigation_id WHERE ru.id=?""",
        (int(runner_id),),
    ).fetchone()
    if not row:
        return None
    runner=dict(row)
    steps=[]
    for s in conn.execute(
        """SELECT rs.*,fs.exchange_id,fs.label flow_label,fs.notes flow_notes,fs.role_label,fs.checkpoint_label,e.status_code,o.method,r.id resource_id,r.url,r.path,h.hostname
           FROM runner_steps rs JOIN flow_steps fs ON fs.id=rs.flow_step_id JOIN http_exchanges e ON e.id=fs.exchange_id
           JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id
           WHERE rs.runner_id=? ORDER BY rs.position,rs.id""",
        (int(runner_id),),
    ).fetchall():
        item=dict(s)
        item["request_params"]=_request_params(conn,int(item["exchange_id"]))
        item["variables"]=[]
        steps.append(item)
    by_id={int(s["id"]):s for s in steps}
    for v in conn.execute("SELECT * FROM runner_variables WHERE runner_id=? ORDER BY id",(int(runner_id),)).fetchall():
        item=dict(v); item["values"]=_load_json(item.get("values_json"),[])
        if int(item["target_runner_step_id"]) in by_id:
            by_id[int(item["target_runner_step_id"])]["variables"].append(item)
    # Reuse Flow runtime definitions for readable dependencies. Runner does not
    # create a parallel variable model: these are the same Flow bindings.
    try:
        import negro_flow_runtime as flow_runtime
        runtime=flow_runtime.flow_runtime_data(conn,int(runner["flow_id"]))
        for s in steps:
            fid=int(s["flow_step_id"])
            s["flow_inputs"]=runtime.get("step_inputs",{}).get(fid,[])
            s["flow_outputs"]=runtime.get("step_outputs",{}).get(fid,[])
    except Exception:
        for s in steps:
            s["flow_inputs"]=[]; s["flow_outputs"]=[]
    linked_hypotheses=[dict(x) for x in conn.execute(
        """SELECT h.id,h.title,h.status,h.review_priority
           FROM runner_hypotheses rh JOIN leads_v2 h ON h.id=rh.hypothesis_id
           WHERE rh.runner_id=? ORDER BY h.updated_at DESC,h.id DESC""",
        (int(runner_id),),
    ).fetchall()]
    runs=[]
    for rr in conn.execute(
        """SELECT rr.*,f.name result_flow_name,
                  (SELECT COUNT(*) FROM runner_run_requests rrr WHERE rrr.run_id=rr.id) request_count,
                  (SELECT COUNT(*) FROM signal_occurrences s JOIN runner_run_requests rrr ON rrr.exchange_id=s.exchange_id WHERE rrr.run_id=rr.id AND s.dismissed_at IS NULL) signal_count
           FROM runner_runs rr LEFT JOIN flows f ON f.id=rr.result_flow_id WHERE rr.runner_id=? ORDER BY rr.id DESC LIMIT 30""",
        (int(runner_id),),
    ).fetchall():
        item=dict(rr); item["summary"]=_load_json(item.get("summary_json"),{})
        item["context"]=_load_json(item.get("context_snapshot_json"),{})
        attempts=[]
        for ar in conn.execute(
            """SELECT rrr.*,rs.position flow_position
               FROM runner_run_requests rrr LEFT JOIN runner_steps rs ON rs.id=rrr.runner_step_id
               WHERE rrr.run_id=? ORDER BY rrr.id""",
            (int(item["id"]),),
        ).fetchall():
            attempt=dict(ar)
            attempt["transport_detail"]=_load_json(attempt.get("transport_detail_json"),{})
            attempts.append(attempt)
        item["attempts"]=attempts
        runs.append(item)
    return {"runner":runner,"steps":steps,"runs":runs,"linked_hypotheses":linked_hypotheses,
            "ai_idea":_load_json(runner.get("ai_idea_json"),{})}


def update_runner(conn, runner_id: int, *, alias: str, description: str, identity_id: int | None, max_requests: int = 30,
                  experiment_goal: str | None = None, expected_support: str | None = None, expected_refute: str | None = None,
                  hypothesis_id: int | None = None, target_flow_step_id: int | None = None) -> None:
    init_schema(conn)
    alias=str(alias or "").strip()[:180]
    if not alias: raise ValueError("Alias requerido")
    current=conn.execute("SELECT experiment_goal,expected_support,expected_refute FROM runners WHERE id=?",(int(runner_id),)).fetchone()
    if not current: raise ValueError("Runner no encontrado")
    goal=current["experiment_goal"] if experiment_goal is None else str(experiment_goal or "")[:5000]
    support=current["expected_support"] if expected_support is None else str(expected_support or "")[:5000]
    refute=current["expected_refute"] if expected_refute is None else str(expected_refute or "")[:5000]
    if target_flow_step_id is not None:
        row=conn.execute("SELECT flow_id FROM runners WHERE id=?",(int(runner_id),)).fetchone()
        valid=conn.execute("SELECT 1 FROM flow_steps WHERE id=? AND flow_id=?",(int(target_flow_step_id),int(row["flow_id"]))).fetchone() if row else None
        if not valid:
            raise ValueError("Step objetivo no pertenece al Flow del Runner")
    if hypothesis_id is not None:
        if not conn.execute("SELECT 1 FROM leads_v2 WHERE id=?",(int(hypothesis_id),)).fetchone():
            raise ValueError("Hipótesis no encontrada")
        conn.execute("INSERT OR IGNORE INTO runner_hypotheses(runner_id,hypothesis_id,created_at) VALUES(?,?,?)",
                     (int(runner_id),int(hypothesis_id),now_iso()))
    conn.execute("""UPDATE runners SET alias=?,description=?,identity_id=?,max_requests=?,experiment_goal=?,expected_support=?,expected_refute=?,
                    hypothesis_id=?,target_flow_step_id=?,updated_at=? WHERE id=?""",
                 (alias,str(description or "")[:5000],identity_id,max(1,min(int(max_requests),100)),goal,support,refute,
                  hypothesis_id,target_flow_step_id,now_iso(),int(runner_id)))


def link_hypothesis(conn, runner_id: int, hypothesis_id: int) -> None:
    init_schema(conn)
    if not conn.execute("SELECT 1 FROM runners WHERE id=?",(int(runner_id),)).fetchone():
        raise ValueError("Runner no encontrado")
    if not conn.execute("SELECT 1 FROM leads_v2 WHERE id=?",(int(hypothesis_id),)).fetchone():
        raise ValueError("Hipótesis no encontrada")
    conn.execute("INSERT OR IGNORE INTO runner_hypotheses(runner_id,hypothesis_id,created_at) VALUES(?,?,?)",
                 (int(runner_id),int(hypothesis_id),now_iso()))


def unlink_hypothesis(conn, runner_id: int, hypothesis_id: int) -> None:
    init_schema(conn)
    conn.execute("DELETE FROM runner_hypotheses WHERE runner_id=? AND hypothesis_id=?",(int(runner_id),int(hypothesis_id)))
    conn.execute("UPDATE runners SET hypothesis_id=NULL WHERE id=? AND hypothesis_id=?",(int(runner_id),int(hypothesis_id)))


def update_runner_step(conn, runner_id: int, runner_step_id: int, *, action: str, repeat_count: int = 1, notes: str = "") -> None:
    init_schema(conn)
    action=str(action or "keep").lower()
    if action not in {"keep","omit","repeat"}: raise ValueError("Acción inválida")
    repeat=max(1,min(20,int(repeat_count)))
    cur=conn.execute("UPDATE runner_steps SET action=?,repeat_count=?,notes=?,updated_at=? WHERE id=? AND runner_id=?",
                     (action,repeat,str(notes or "")[:1000],now_iso(),int(runner_step_id),int(runner_id)))
    if cur.rowcount != 1: raise ValueError("Paso del Runner no encontrado")
    conn.execute("UPDATE runners SET updated_at=? WHERE id=?",(now_iso(),int(runner_id)))


def add_variable(conn, runner_id: int, *, target_runner_step_id: int, target_name: str, target_value: str = "",
                 mode: str = "values", values: list[str] | None = None, source_runner_step_id: int | None = None,
                 source_name: str = "", regex_pattern: str = "") -> int:
    init_schema(conn)
    if not conn.execute("SELECT id FROM runner_steps WHERE id=? AND runner_id=?",(int(target_runner_step_id),int(runner_id))).fetchone():
        raise ValueError("Paso destino inválido")
    mode=str(mode or "values")
    if mode not in {"values","response_key","response_regex"}: raise ValueError("Modo de variable inválido")
    if mode in {"response_key","response_regex"} and source_runner_step_id and not conn.execute("SELECT id FROM runner_steps WHERE id=? AND runner_id=?",(int(source_runner_step_id),int(runner_id))).fetchone():
        raise ValueError("Paso fuente inválido")
    now=now_iso()
    cur=conn.execute(
        """INSERT INTO runner_variables(runner_id,target_runner_step_id,target_name,target_value,mode,values_json,source_runner_step_id,source_name,regex_pattern,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (int(runner_id),int(target_runner_step_id),str(target_name or "").strip()[:160],str(target_value or "")[:2000],mode,
         json.dumps(list(values or [])[:100],ensure_ascii=False),source_runner_step_id,str(source_name or "")[:160],str(regex_pattern or "")[:1000],now,now),
    )
    conn.execute("UPDATE runners SET updated_at=? WHERE id=?",(now,int(runner_id)))
    return int(cur.lastrowid)


def delete_variable(conn, runner_id: int, variable_id: int) -> None:
    init_schema(conn)
    conn.execute("DELETE FROM runner_variables WHERE id=? AND runner_id=?",(int(variable_id),int(runner_id)))
    conn.execute("UPDATE runners SET updated_at=? WHERE id=?",(now_iso(),int(runner_id)))


def _value_preview(name: str, value: Any) -> str:
    raw=str(value or "")
    low=str(name or "").lower()
    sensitive=any(x in low for x in ("authorization","token","jwt","session","cookie","secret","password","otp"))
    if sensitive:
        if len(raw) <= 8:
            return "•" * max(4,len(raw))
        return raw[:6] + "…" + "•" * 6
    return raw if len(raw) <= 120 else raw[:117] + "…"


def _run_context_snapshot(conn, runner: dict[str,Any], steps: list[dict[str,Any]], *, hypothesis_id: int | None,
                          target_flow_step_id: int | None) -> dict[str,Any]:
    hypothesis=None
    if hypothesis_id is not None:
        row=conn.execute("SELECT id,title,why_interesting,next_test FROM leads_v2 WHERE id=?",(int(hypothesis_id),)).fetchone()
        if row:
            hypothesis=dict(row)
    identity=None
    if runner.get("identity_id"):
        row=conn.execute("SELECT id,name FROM identities WHERE id=?",(int(runner["identity_id"]),)).fetchone()
        identity=dict(row) if row else None
    target=None
    if target_flow_step_id is not None:
        for s in steps:
            if int(s.get("flow_step_id") or 0)==int(target_flow_step_id):
                target={"flow_step_id":int(target_flow_step_id),"position":int(s.get("position") or 0),
                        "name":str(s.get("flow_label") or s.get("method") or "Step"),"method":s.get("method"),"path":s.get("path")}
                break
    variable_rows=[]
    for v in conn.execute("SELECT * FROM runner_variables WHERE runner_id=? ORDER BY id",(int(runner["id"]),)).fetchall():
        item=dict(v)
        vals=_load_json(item.get("values_json"),[])
        variable_rows.append({"target_name":item.get("target_name"),"mode":item.get("mode"),
                              "values":[_value_preview(str(item.get("target_name") or ""),x) for x in vals[:5]],
                              "source_name":item.get("source_name"),"source_runner_step_id":item.get("source_runner_step_id")})
    return {
        "runner":{"id":int(runner["id"]),"alias":runner.get("alias"),"description":runner.get("description")},
        "flow":{"id":int(runner["flow_id"]),"name":runner.get("flow_name")},
        "investigation":{"id":int(runner["investigation_id"]),"title":runner.get("investigation_title")} if runner.get("investigation_id") else None,
        "hypothesis":hypothesis,
        "identity":identity,
        "target_step":target,
        "experiment_goal":runner.get("experiment_goal") or "",
        "expected_support":runner.get("expected_support") or "",
        "expected_refute":runner.get("expected_refute") or "",
        "step_plan":[{"position":int(s.get("position") or 0),"flow_step_id":int(s.get("flow_step_id") or 0),
                      "name":s.get("flow_label") or "","role":s.get("role_label") or "","action":s.get("action"),
                      "repeat_count":int(s.get("repeat_count") or 1)} for s in steps],
        "runner_variables":variable_rows,
        "captured_at":now_iso(),
    }


def get_runner_run(conn, run_id: int) -> dict[str,Any] | None:
    init_schema(conn)
    row=conn.execute(
        """SELECT rr.*,ru.alias runner_alias,ru.flow_id,f.name flow_name,i.name identity_name
           FROM runner_runs rr JOIN runners ru ON ru.id=rr.runner_id JOIN flows f ON f.id=ru.flow_id
           LEFT JOIN identities i ON i.id=rr.identity_id WHERE rr.id=?""",(int(run_id),)
    ).fetchone()
    if not row:
        return None
    run=dict(row)
    run["summary"]=_load_json(run.get("summary_json"),{})
    run["context"]=_load_json(run.get("context_snapshot_json"),{})
    attempts=[]
    for ar in conn.execute(
        """SELECT rrr.*,rs.position,rs.flow_step_id,fs.label flow_label,fs.role_label,fs.checkpoint_label,o.method flow_method,r.path flow_path
           FROM runner_run_requests rrr JOIN runner_steps rs ON rs.id=rrr.runner_step_id
           JOIN flow_steps fs ON fs.id=rs.flow_step_id JOIN http_exchanges e ON e.id=fs.exchange_id
           JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id
           WHERE rrr.run_id=? ORDER BY rrr.id""",(int(run_id),)
    ).fetchall():
        item=dict(ar)
        item["transport_detail"]=_load_json(item.get("transport_detail_json"),{})
        item["resolved_variables"]=_load_json(item.get("resolved_variables_json"),[])
        item["extracted_values"]=_load_json(item.get("extracted_values_json"),[])
        try:
            item["request_raw"]=base64.b64decode(item.get("request_b64") or "",validate=False).decode("iso-8859-1",errors="replace")
        except Exception:
            item["request_raw"]=""
        try:
            item["response_raw"]=base64.b64decode(item.get("response_b64") or "",validate=False).decode("iso-8859-1",errors="replace")
        except Exception:
            item["response_raw"]=""
        attempts.append(item)
    return {"run":run,"attempts":attempts}


def create_hypothesis_from_idea(conn, *, flow_id: int, idea: dict[str, Any]) -> int:
    """Persist one human-selected AI flow question as a hypothesis. Never automatic."""
    import hashlib
    import negro_hunter as hunter
    hunter.init_schema(conn)
    title=str(idea.get("question") or idea.get("title") or "Pregunta de lógica").strip()[:240]
    why=str(idea.get("rationale") or idea.get("why_interesting") or "").strip()
    suggested=str(idea.get("test_goal") or idea.get("runner_description") or "").strip()
    fingerprint=hashlib.sha256(f"flow:{flow_id}|{title.lower()}".encode()).hexdigest()[:20]
    evidence=[{"source":"ai_flow_logic","human_selected":True,"node_ids":[f"flow:{int(flow_id)}"],"facts":idea.get("facts") or [],"unknowns":idea.get("unknowns") or [],"runner_draft":idea.get("runner") or {}}]
    hunter.upsert_lead(conn, lead_key=f"ai_flow:{fingerprint}", host_id=None, resource_id=None,
                       lead_type="business_logic", title=title, confidence="medium", review_priority="medium",
                       evidence=evidence, why=why, next_test=suggested,
                       confirm_if=str(idea.get("confirm_if") or ""), discard_if=str(idea.get("discard_if") or ""), source="AI_IDEA")
    row=conn.execute("SELECT id FROM leads_v2 WHERE lead_key=?",(f"ai_flow:{fingerprint}",)).fetchone()
    return int(row["id"])


def _decode_raw_request(conn, exchange_id: int, identity_id: int | None) -> tuple[str,str]:
    import negro_identity as identity_tools
    if identity_id is not None:
        rewritten=identity_tools.rewrite_exchange_as_identity(conn,int(exchange_id),int(identity_id))
        raw=base64.b64decode(str(rewritten["request_b64"]),validate=False).decode("iso-8859-1",errors="replace")
        return raw,str(rewritten["url"])
    row=conn.execute(
        """SELECT e.request_b64,r.url FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id WHERE e.id=?""",(int(exchange_id),)
    ).fetchone()
    if not row or not row["request_b64"]: raise ValueError("Request base sin raw HTTP")
    return base64.b64decode(str(row["request_b64"]),validate=False).decode("iso-8859-1",errors="replace"),str(row["url"])


def _split_raw_request(raw: str, base_url: str) -> tuple[str,str,dict[str,str],str]:
    head,sep,body=raw.replace("\r\n","\n").partition("\n\n")
    lines=head.split("\n")
    if not lines: raise ValueError("Request raw inválida")
    parts=lines[0].split()
    if len(parts)<2: raise ValueError("Request line inválida")
    method=parts[0].upper(); target=parts[1]
    parsed=urllib.parse.urlsplit(base_url)
    if target.startswith("http://") or target.startswith("https://"):
        url=target
    else:
        path=target if target.startswith("/") else "/"+target
        url=urllib.parse.urljoin(f"{parsed.scheme}://{parsed.netloc}/", path)
    headers={}
    for line in lines[1:]:
        if ":" not in line: continue
        name,value=line.split(":",1)
        headers[name.strip()]=value.strip()
    return method,url,headers,body if sep else ""


def _replace_value(raw: str, old: str, new: str) -> str:
    if not old: return raw
    candidates=[(old,new)]
    try:
        candidates.append((urllib.parse.quote_plus(old),urllib.parse.quote_plus(new)))
        candidates.append((urllib.parse.quote(old,safe=""),urllib.parse.quote(new,safe="")))
    except Exception:
        pass
    out=raw
    for before,after in candidates:
        if before and before in out:
            return out.replace(before,after,1)
    return out


def _extract_json_key(body: str, key: str) -> str | None:
    try: data=json.loads(body)
    except Exception: return None
    wanted=str(key or "").lower()
    def walk(v):
        if isinstance(v,dict):
            for k,val in v.items():
                if str(k).lower()==wanted and not isinstance(val,(dict,list)):
                    return str(val)
            for val in v.values():
                found=walk(val)
                if found is not None: return found
        elif isinstance(v,list):
            for val in v:
                found=walk(val)
                if found is not None: return found
        return None
    return walk(data)


def _response_raw(resp) -> str:
    reason=getattr(resp,"reason","") or ""
    line=f"HTTP/1.1 {int(resp.status_code)} {reason}".rstrip()
    headers="\r\n".join(f"{k}: {v}" for k,v in resp.headers.items())
    try: body=resp.content.decode("iso-8859-1",errors="replace")
    except Exception: body=str(resp.text or "")
    return line+"\r\n"+headers+"\r\n\r\n"+body


def _headers_list(headers: dict[str,str]) -> list[dict[str,str]]:
    return [{"name":str(k),"value":str(v)} for k,v in headers.items()]



EXECUTION_CLASSES = {"application_response","transport_error","timeout","dns_error","tls_error","proxy_error","runner_error"}


def transport_settings() -> dict[str, Any]:
    import negro_intel as intel
    settings=intel.load_settings()
    mode=str(settings.get("runner_transport_mode") or "burp_bridge").lower()
    if mode not in {"burp_bridge","direct","environment","proxy"}: mode="burp_bridge"
    return {
        "mode":mode,
        "proxy_url":str(settings.get("runner_proxy_url") or "").strip(),
        "verify_tls":bool(settings.get("runner_verify_tls", True)),
        "ca_bundle":str(settings.get("runner_ca_bundle") or "").strip(),
        "timeout_seconds":max(2,min(int(settings.get("runner_timeout_seconds") or 20),120)),
    }


def _build_session(cfg: dict[str, Any]):
    import requests
    session=requests.Session()
    mode=str(cfg.get("mode") or "direct")
    session.trust_env = mode == "environment"
    if mode == "proxy":
        proxy=str(cfg.get("proxy_url") or "").strip()
        if not proxy:
            raise ValueError("Transporte proxy seleccionado pero no hay URL de proxy configurada")
        session.proxies.update({"http":proxy,"https":proxy})
    return session


def _verify_value(cfg: dict[str, Any]):
    if not bool(cfg.get("verify_tls",True)):
        return False
    ca=str(cfg.get("ca_bundle") or "").strip()
    return ca or True


def _effective_proxy_for_url(session, url: str, cfg: dict[str, Any]) -> str | None:
    mode=str(cfg.get("mode") or "direct")
    if mode == "proxy":
        return str(cfg.get("proxy_url") or "") or None
    if mode == "environment":
        try:
            import requests
            proxies=requests.utils.get_environ_proxies(url)
            return proxies.get(urllib.parse.urlsplit(url).scheme) or proxies.get("https") or proxies.get("http")
        except Exception:
            return None
    return None


def _classify_exception(exc: Exception) -> str:
    try:
        import requests
        if isinstance(exc, requests.exceptions.ProxyError): return "proxy_error"
        if isinstance(exc, requests.exceptions.Timeout): return "timeout"
        if isinstance(exc, requests.exceptions.SSLError): return "tls_error"
        if isinstance(exc, requests.exceptions.ConnectionError):
            msg=str(exc).lower()
            if any(x in msg for x in ("name resolution","failed to resolve","getaddrinfo","nodename nor servname","temporary failure in name resolution")):
                return "dns_error"
            return "transport_error"
        if isinstance(exc, requests.exceptions.RequestException): return "transport_error"
    except Exception:
        pass
    msg=str(exc).lower()
    if any(x in msg for x in ("getaddrinfo","name resolution","failed to resolve")): return "dns_error"
    if "ssl" in msg or "certificate" in msg or "tls" in msg: return "tls_error"
    if "proxy" in msg: return "proxy_error"
    if "timed out" in msg or "timeout" in msg: return "timeout"
    return "runner_error"


def _classify_response(resp, *, proxy_url: str | None) -> tuple[str, dict[str, Any]]:
    """Separate a target HTTP response from a gateway/proxy transport failure.

    5xx remains application evidence unless the request actually used a proxy and
    the response contains generic proxy/gateway failure indicators. This avoids
    treating a real application 504 as a transport error.
    """
    detail={"proxy_used":bool(proxy_url),"proxy":proxy_url or "","status":int(resp.status_code)}
    if int(resp.status_code) not in {502,503,504}:
        return "application_response",detail
    head=" ".join(f"{k}:{v}" for k,v in resp.headers.items()).lower()
    body=(resp.text or "")[:5000].lower()
    # Generic gateway/connectivity pages are transport evidence even when the proxy is
    # transparent to requests (container gateway, corporate egress, service mesh, etc.).
    # A plain application 5xx without these transport indicators remains app evidence.
    indicators=("proxy error","gateway timeout","bad gateway","upstream connect","upstream request timeout",
                "connect error","connection refused","connecting to","tunnel connection failed",
                "connection timed out","name resolution failed","dns resolution failed")
    header_indicators=("via:","x-squid-error","proxy-agent:","x-envoy", "x-cache:","x-served-by:")
    if any(x in body for x in indicators) or any(x in head for x in header_indicators):
        detail["reason"]="Respuesta genérica de gateway/conectividad durante el transporte; no se usa como evidencia del aplicativo."
        return ("proxy_error" if proxy_url else "transport_error"),detail
    return "application_response",detail


class BurpBridgeTransportError(RuntimeError):
    def __init__(self, message: str, execution_class: str = "transport_error", detail: dict[str, Any] | None = None):
        super().__init__(message)
        self.execution_class = execution_class if execution_class in EXECUTION_CLASSES else "transport_error"
        self.detail = detail or {}


def _queue_bridge_execute(paths: dict[str, Any], *, resource_id: int, method: str, url: str, request_b64: str, timeout_seconds: int) -> dict[str, Any]:
    """Execute one exact Request through the already connected Burp Bridge.

    This deliberately reuses `burp_repeater_queue` with job_kind=execute instead
    of creating a second bridge protocol. Burp therefore owns DNS, TCP, TLS/SNI,
    upstream proxy behavior and the actual HTTP send path -- the same networking
    stack that captured the baseline traffic.
    """
    import negro_core as core
    created = now_iso()
    with core.db_connect(paths) as conn:
        cur = conn.execute(
            """INSERT INTO burp_repeater_queue(resource_id,method,url,request_b64,caption,status,job_kind,created_at)
               VALUES(?,?,?,?,?,'pending','execute',?)""",
            (int(resource_id), str(method or "GET").upper(), str(url), str(request_b64 or ""), "Negro Runner", created),
        )
        queue_id = int(cur.lastrowid)
    print(f"[runner-transport] queued bridge execute id={queue_id} {method} {url}", flush=True)

    # Fail fast when no current extension claims the request, but once Burp has
    # claimed it allow the configured network timeout plus a small bridge margin.
    claim_deadline = time.monotonic() + min(6.0, max(3.0, float(timeout_seconds) / 3.0))
    finish_deadline = time.monotonic() + float(timeout_seconds) + 15.0
    seen_claim = False
    last_status = "pending"
    while time.monotonic() < finish_deadline:
        with core.db_connect(paths) as conn:
            row = conn.execute("SELECT * FROM burp_repeater_queue WHERE id=?", (queue_id,)).fetchone()
            item = dict(row) if row else None
        if not item:
            raise BurpBridgeTransportError("El trabajo de transporte desapareció de la cola de Burp.", "runner_error", {"queue_id": queue_id})
        last_status = str(item.get("status") or "pending")
        if last_status == "claimed":
            seen_claim = True
        if last_status == "done":
            if not item.get("response_b64") or item.get("response_status") is None:
                raise BurpBridgeTransportError(
                    "Burp recibió el trabajo pero no devolvió una Response. Actualiza/reinstala la extensión Negro Burp Bridge incluida en esta versión.",
                    "transport_error", {"queue_id": queue_id, "bridge_instance_id": item.get("bridge_instance_id")},
                )
            print(f"[runner-transport] bridge execute done id={queue_id} status={item.get('response_status')} elapsed={item.get('elapsed_ms')}ms", flush=True)
            return item
        if last_status == "error":
            msg = str(item.get("error") or "Burp no pudo enviar la Request")
            klass = "timeout" if "timeout" in msg.lower() or "timed out" in msg.lower() else "transport_error"
            if "dns" in msg.lower() or "resolve" in msg.lower(): klass = "dns_error"
            if "tls" in msg.lower() or "certificate" in msg.lower() or "ssl" in msg.lower(): klass = "tls_error"
            raise BurpBridgeTransportError(msg, klass, {"queue_id": queue_id, "bridge_instance_id": item.get("bridge_instance_id")})
        if not seen_claim and time.monotonic() >= claim_deadline:
            with core.db_connect(paths) as conn:
                conn.execute(
                    "UPDATE burp_repeater_queue SET status='error',finished_at=?,error=? WHERE id=? AND status='pending'",
                    (now_iso(), "burp_bridge_not_connected_or_outdated", queue_id),
                )
            raise BurpBridgeTransportError(
                "Negro no detectó una extensión Burp Bridge compatible consumiendo el Runner. Reemplaza el JAR por el incluido en v0.41 y confirma que el panel Negro de Burp aparece conectado.",
                "proxy_error", {"queue_id": queue_id},
            )
        time.sleep(0.12)

    with core.db_connect(paths) as conn:
        conn.execute(
            "UPDATE burp_repeater_queue SET status='error',finished_at=?,error=? WHERE id=? AND status IN ('pending','claimed')",
            (now_iso(), "burp_bridge_timeout_waiting_response", queue_id),
        )
    raise BurpBridgeTransportError(
        f"Burp no devolvió una Response en {timeout_seconds}s.", "timeout", {"queue_id": queue_id, "last_status": last_status},
    )


def _headers_from_json(value: Any) -> list[dict[str, str]]:
    try:
        data = json.loads(value or "[]") if not isinstance(value, list) else value
    except Exception:
        data = []
    out=[]
    for item in data if isinstance(data,list) else []:
        if isinstance(item,dict) and item.get("name"):
            out.append({"name":str(item.get("name")),"value":str(item.get("value") or "")})
    return out


def _header_value(headers: list[dict[str,str]], name: str) -> str | None:
    low=str(name).lower()
    for h in headers:
        if str(h.get("name") or "").lower()==low:
            return str(h.get("value") or "")
    return None


def _apply_response_cookies(session, headers: list[dict[str,str]]) -> None:
    # Runner needs cookie rotation between Flow steps even when Burp performs the
    # network send. We only persist the cookie name/value from Set-Cookie; scope
    # attributes are not needed because the Runner explicitly builds Cookie for
    # the next step from this isolated session jar.
    for h in headers:
        if str(h.get("name") or "").lower() != "set-cookie":
            continue
        first = str(h.get("value") or "").split(";",1)[0]
        if "=" not in first:
            continue
        name,value=first.split("=",1)
        name=name.strip(); value=value.strip()
        if name:
            session.cookies.set(name,value)


def diagnose_transport(url: str) -> dict[str, Any]:
    """Local diagnostic for the Runner process. It does not mutate project evidence."""
    import requests
    cfg=transport_settings(); parsed=urllib.parse.urlsplit(str(url))
    host=parsed.hostname or ""; port=parsed.port or (443 if parsed.scheme=="https" else 80)
    result={"url":url,"mode":cfg["mode"],"target_host":host,"target_port":port,"proxy_url":cfg.get("proxy_url") or "",
            "verify_tls":cfg.get("verify_tls"),"dns":None,"tcp":None,"tls":None,"http":None,"execution_class":None,"notes":[]}
    if cfg["mode"] == "burp_bridge":
        result["execution_class"]="pending"
        result["notes"].append("El modo Burp Bridge se diagnostica durante el Run con la Request real para reutilizar exactamente la misma pila de red de Burp.")
        result["bridge"]={"recommended":True,"requires_extension":"0.27.0+"}
        return result
    if not host:
        result["execution_class"]="runner_error"; result["notes"].append("URL sin hostname"); return result
    proxy_host=None; proxy_port=None; effective_proxy=None
    try:
        probe_session=_build_session(cfg)
        effective_proxy=_effective_proxy_for_url(probe_session,str(url),cfg)
    except Exception as exc:
        result["execution_class"]="proxy_error"; result["notes"].append(str(exc)[:500]); return result
    if effective_proxy:
        pp=urllib.parse.urlsplit(str(effective_proxy)); proxy_host=pp.hostname; proxy_port=pp.port or (443 if pp.scheme=="https" else 80)
        result["effective_proxy"]=effective_proxy
    dns_host=proxy_host or host
    try:
        infos=socket.getaddrinfo(dns_host, proxy_port or port, type=socket.SOCK_STREAM)
        ips=sorted({x[4][0] for x in infos})
        result["dns"]={"ok":True,"host":dns_host,"ips":ips[:8]}
    except Exception as exc:
        result["dns"]={"ok":False,"host":dns_host,"error":str(exc)[:500]}; result["execution_class"]="dns_error"; return result
    try:
        with socket.create_connection((dns_host,proxy_port or port),timeout=min(8,cfg["timeout_seconds"])):
            result["tcp"]={"ok":True,"host":dns_host,"port":proxy_port or port}
    except Exception as exc:
        result["tcp"]={"ok":False,"host":dns_host,"port":proxy_port or port,"error":str(exc)[:500]}; result["execution_class"]="transport_error"; return result
    # Direct TLS probe is meaningful only when the Runner itself terminates TLS.
    if parsed.scheme=="https" and not effective_proxy:
        try:
            ctx=ssl.create_default_context()
            if not cfg.get("verify_tls"):
                ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            elif cfg.get("ca_bundle"):
                ctx.load_verify_locations(cafile=str(cfg["ca_bundle"]))
            with socket.create_connection((host,port),timeout=min(8,cfg["timeout_seconds"])) as raw:
                with ctx.wrap_socket(raw,server_hostname=host) as tls_sock:
                    result["tls"]={"ok":True,"sni":host,"version":tls_sock.version()}
        except Exception as exc:
            result["tls"]={"ok":False,"sni":host,"error":str(exc)[:500]}; result["execution_class"]="tls_error"; return result
    try:
        session=_build_session(cfg); proxy=_effective_proxy_for_url(session,url,cfg)
        resp=session.request("HEAD",url,allow_redirects=False,timeout=cfg["timeout_seconds"],verify=_verify_value(cfg))
        klass,detail=_classify_response(resp,proxy_url=proxy)
        result["http"]={"ok":klass=="application_response","status":int(resp.status_code),"class":klass,"proxy_used":bool(proxy)}
        result["execution_class"]=klass
        if klass!="application_response": result["notes"].append(detail.get("reason") or "Fallo de transporte")
    except Exception as exc:
        result["execution_class"]=_classify_exception(exc); result["http"]={"ok":False,"error":f"{type(exc).__name__}: {str(exc)[:500]}"}
    return result


def _postprocess_exchange(conn, exchange_id: int, resource_id: int, host_id: int, domain: str, identity_id: int | None) -> None:
    import negro_hunter as hunter
    import negro_identity as identity_tools
    import negro_objects as object_tools
    import negro_custom_signals as custom_signals
    import negro_search as search_index
    hunter.init_schema(conn)
    try: hunter.analyze_http_exchange(conn,int(exchange_id),domain,emit_notifications=True)
    except Exception: pass
    try:
        if identity_id is not None:
            identity_tools.assign_exchange(conn,int(exchange_id),int(identity_id),learn_auth=False,source="runner")
        else:
            identity_tools.resolve_exchange(conn,int(exchange_id))
    except Exception: pass
    try: object_tools.refresh_exchange(conn,int(exchange_id))
    except Exception: pass
    try: custom_signals.evaluate_exchange(conn,int(exchange_id))
    except Exception: pass
    try: hunter.evaluate_correlation_memory(conn,int(exchange_id))
    except Exception: pass
    try:
        search_index.index_exchange(conn,int(exchange_id)); search_index.index_resource(conn,int(resource_id)); search_index.index_host(conn,int(host_id))
    except Exception: pass


def execute_runner(paths: dict[str,Any], domain: str, runner_id: int, hypothesis_id: int | None = None,
                   target_flow_step_id: int | None = None) -> dict[str,Any]:
    """Execute a bounded investigation Runner.

    v0.41 prefers the existing Negro Burp Bridge as transport. This makes replay
    use Burp's own DNS/TCP/TLS/upstream-proxy stack instead of asking Python to
    rediscover a different network path. Direct/environment/explicit-proxy modes
    remain available for users who intentionally do not want Burp in the path.

    Only valid application responses enter canonical evidence. A transport failure
    breaks the sequential Run immediately: later Flow steps would no longer have a
    trustworthy application state and therefore must not count as coverage.
    """
    import requests
    import types
    import negro_core as core
    import negro_flows as flow_tools

    cfg=transport_settings()
    with core.db_connect(paths) as conn:
        data=get_runner(conn,int(runner_id))
        if not data: raise ValueError("Runner no encontrado")
        runner=data["runner"]; steps=data["steps"]
        if hypothesis_id is None and runner.get("hypothesis_id"):
            hypothesis_id=int(runner["hypothesis_id"])
        if target_flow_step_id is None and runner.get("target_flow_step_id"):
            target_flow_step_id=int(runner["target_flow_step_id"])
        if hypothesis_id is not None:
            linked=conn.execute("SELECT 1 FROM runner_hypotheses WHERE runner_id=? AND hypothesis_id=?",
                                (int(runner_id),int(hypothesis_id))).fetchone()
            if not linked:
                raise ValueError("La Hipótesis seleccionada no está asociada a este Runner")
        if target_flow_step_id is not None and not any(int(s.get("flow_step_id") or 0)==int(target_flow_step_id) for s in steps):
            raise ValueError("El Step objetivo no pertenece al Runner")
        planned=sum(0 if st["action"]=="omit" else (int(st["repeat_count"]) if st["action"]=="repeat" else 1) for st in steps)
        cap=min(100,int(runner.get("max_requests") or 30))
        if planned>cap:
            raise ValueError(f"El Runner intentaría {planned} Requests y su límite es {cap}. Ajusta repeticiones o el límite antes de ejecutar.")
        now=now_iso()
        context_snapshot=_run_context_snapshot(conn,runner,steps,hypothesis_id=hypothesis_id,target_flow_step_id=target_flow_step_id)
        cur=conn.execute("""INSERT INTO runner_runs(runner_id,identity_id,hypothesis_id,target_flow_step_id,context_snapshot_json,
                            status,execution_class,counts_as_test,started_at,created_at,updated_at)
                            VALUES(?,?,?,?,?,'running','pending',0,?,?,?)""",
                         (int(runner_id),runner.get("identity_id"),hypothesis_id,target_flow_step_id,
                          json.dumps(context_snapshot,ensure_ascii=False),now,now,now))
        run_id=int(cur.lastrowid)

    # Even Burp-transport Runs use an isolated cookie jar so Set-Cookie rotations
    # can be carried into later Flow steps without mutating browser/Burp state.
    session=requests.Session()
    session.trust_env=False
    if cfg["mode"] != "burp_bridge":
        session=_build_session(cfg)
    extracted: dict[int,dict[str,str]]={}
    request_count=0; statuses=[]; errors=[]; exchange_ids=[]; execution_classes=[]
    first_cookie_seed=True; result_flow_id=None; stop_after_transport_error=False
    try:
        for step in steps:
            if stop_after_transport_error:
                break
            if step["action"]=="omit":
                continue
            repeats=int(step["repeat_count"] or 1) if step["action"]=="repeat" else 1
            repeats=max(1,min(20,repeats))
            for rep_idx in range(1,repeats+1):
                if stop_after_transport_error:
                    break
                with core.db_connect(paths) as conn:
                    raw,base_url=_decode_raw_request(conn,int(step["exchange_id"]),runner.get("identity_id"))
                    vars_for_step=[dict(v) for v in conn.execute("SELECT * FROM runner_variables WHERE target_runner_step_id=? ORDER BY id",(int(step["id"]),)).fetchall()]
                    resolved_for_request=[]
                    for var in vars_for_step:
                        mode=str(var["mode"]); new_value=None
                        if mode=="values":
                            vals=_load_json(var["values_json"],[])
                            if vals: new_value=str(vals[(rep_idx-1)%len(vals)])
                        elif mode=="response_key" and var["source_runner_step_id"]:
                            new_value=(extracted.get(int(var["source_runner_step_id"])) or {}).get(str(var["source_name"] or ""))
                        elif mode=="response_regex" and var["source_runner_step_id"]:
                            new_value=(extracted.get(int(var["source_runner_step_id"])) or {}).get(f"regex:{int(var['id'])}")
                        if new_value is not None:
                            raw=_replace_value(raw,str(var["target_value"] or ""),str(new_value))
                            resolved_for_request.append({"name":str(var.get("target_name") or ""),"mode":mode,
                                                         "value_preview":_value_preview(str(var.get("target_name") or ""),new_value),
                                                         "source_runner_step_id":var.get("source_runner_step_id")})
                    method,url,headers,body=_split_raw_request(raw,base_url)

                # Cookies are state, not a static copy of the baseline. Seed them
                # from the first captured Request and then carry server rotations.
                cookie_header=None
                for key in list(headers):
                    if key.lower()=="cookie": cookie_header=headers.pop(key)
                    elif key.lower() in {"content-length","connection","proxy-connection"}: headers.pop(key,None)
                if cookie_header:
                    for piece in cookie_header.split(";"):
                        if "=" not in piece: continue
                        ck,cv=piece.split("=",1); ck=ck.strip(); cv=cv.strip()
                        if ck and (first_cookie_seed or ck not in session.cookies): session.cookies.set(ck,cv)
                    first_cookie_seed=False

                request_line=urllib.parse.urlsplit(url)
                target=(request_line.path or "/")+("?"+request_line.query if request_line.query else "")
                raw_headers=dict(headers)
                if session.cookies:
                    raw_headers["Cookie"]="; ".join(f"{c.name}={c.value}" for c in session.cookies)
                actual_raw=f"{method} {target} HTTP/1.1\r\n"+"\r\n".join(f"{k}: {v}" for k,v in raw_headers.items())+"\r\n\r\n"+body
                req_b64=base64.b64encode(actual_raw.encode("iso-8859-1",errors="replace")).decode("ascii")
                proxy_url=_effective_proxy_for_url(session,url,cfg) if cfg["mode"] != "burp_bridge" else None
                transport_detail={
                    "mode":cfg["mode"],"proxy_used":bool(proxy_url),"proxy":proxy_url or "",
                    "url_host":request_line.hostname or "","host_header":raw_headers.get("Host") or raw_headers.get("host") or "",
                    "sni":request_line.hostname or "","verify_tls":cfg.get("verify_tls",True),
                    "runner_step_id":int(step["id"]),"flow_step_position":int(step.get("position") or 0),
                }
                start=time.perf_counter(); error=None; response_b64=None; status=None
                response_headers: list[dict[str,str]]=[]; response_body_b64=None; response_text=""; canonical_request_b64=req_b64
                exec_class="runner_error"
                try:
                    if cfg["mode"] == "burp_bridge":
                        item=_queue_bridge_execute(paths,resource_id=int(step["resource_id"]),method=method,url=url,request_b64=req_b64,timeout_seconds=int(cfg["timeout_seconds"]))
                        elapsed=int(item.get("elapsed_ms") or ((time.perf_counter()-start)*1000))
                        status=int(item["response_status"])
                        response_b64=str(item.get("response_b64") or "") or None
                        response_body_b64=str(item.get("response_body_b64") or "") or None
                        response_headers=_headers_from_json(item.get("response_headers_json"))
                        canonical_request_b64=str(item.get("result_request_b64") or req_b64)
                        try:
                            response_text=base64.b64decode(response_body_b64 or "",validate=False).decode("iso-8859-1",errors="replace")
                        except Exception:
                            response_text=""
                        pseudo=types.SimpleNamespace(status_code=status,headers={h["name"]:h["value"] for h in response_headers},text=response_text)
                        exec_class,detail=_classify_response(pseudo,proxy_url=None)
                        transport_detail.update(detail)
                        transport_detail.update({"bridge_queue_id":int(item["id"]),"bridge_instance_id":item.get("bridge_instance_id") or "","burp_transport":True})
                        _apply_response_cookies(session,response_headers)
                    else:
                        resp=session.request(method,url,headers=headers,data=body.encode("iso-8859-1",errors="replace"),
                                             allow_redirects=False,timeout=cfg["timeout_seconds"],verify=_verify_value(cfg))
                        elapsed=int((time.perf_counter()-start)*1000)
                        status=int(resp.status_code)
                        exec_class,detail=_classify_response(resp,proxy_url=proxy_url)
                        transport_detail.update(detail)
                        response_raw=_response_raw(resp)
                        response_b64=base64.b64encode(response_raw.encode("iso-8859-1",errors="replace")).decode("ascii")
                        response_headers=_headers_list(dict(resp.headers))
                        response_body_b64=base64.b64encode(resp.content).decode("ascii")
                        response_text=resp.text or ""
                except BurpBridgeTransportError as exc:
                    elapsed=int((time.perf_counter()-start)*1000)
                    exec_class=exc.execution_class
                    error=f"{type(exc).__name__}: {str(exc)[:1000]}"; errors.append(error)
                    transport_detail.update(exc.detail); transport_detail["error"]=str(exc)[:1000]
                except Exception as exc:
                    elapsed=int((time.perf_counter()-start)*1000)
                    exec_class=_classify_exception(exc)
                    error=f"{type(exc).__name__}: {str(exc)[:1000]}"; errors.append(error)
                    transport_detail["exception_type"]=type(exc).__name__; transport_detail["error"]=str(exc)[:1000]

                request_count+=1; execution_classes.append(exec_class)
                exid=None
                extracted_for_request=[]
                if status is not None and exec_class=="application_response":
                    statuses.append(status)
                    actual_headers=dict(raw_headers)
                    result=core.upsert_http_observation(paths,domain,url=url,method=method,source="negro_runner",status_code=status,
                        authenticated=bool(runner.get("identity_id")),request_content_type=next((v for k,v in actual_headers.items() if k.lower()=="content-type"),None),
                        response_content_type=_header_value(response_headers,"Content-Type"),tool="RUNNER",request_b64=canonical_request_b64,response_b64=response_b64,
                        request_headers=_headers_list(actual_headers),response_headers=response_headers,query=dict(urllib.parse.parse_qsl(request_line.query,keep_blank_values=True)),
                        response_body_b64=response_body_b64)
                    exid=int(result["exchange_id"]); exchange_ids.append(exid)
                    with core.db_connect(paths) as conn:
                        if result_flow_id is None:
                            result_flow_id=flow_tools.create_flow(conn,f"Run · {runner['alias']} · #{run_id}",description=f"Resultado del Runner #{runner_id}: {runner['description'] or ''}",identity_id=runner.get("identity_id"))
                            conn.execute("UPDATE runner_runs SET result_flow_id=? WHERE id=?",(result_flow_id,run_id))
                            if runner.get("investigation_id"):
                                try:
                                    import negro_hunter as hunter
                                    hunter.link_investigation_entity(conn,int(runner["investigation_id"]),"flow",int(result_flow_id),"run_result")
                                except Exception: pass
                        _postprocess_exchange(conn,exid,int(result["resource_id"]),int(result["host_id"]),domain,runner.get("identity_id"))
                        flow_tools.add_step(conn,result_flow_id,exid,allow_duplicate=True)
                        bucket=extracted.setdefault(int(step["id"]),{})
                        for v in conn.execute("SELECT * FROM runner_variables WHERE source_runner_step_id=? ORDER BY id",(int(step["id"]),)).fetchall():
                            if str(v["mode"])=="response_key":
                                val=_extract_json_key(response_text,str(v["source_name"] or ""))
                                if val is not None:
                                    bucket[str(v["source_name"] or "")]=val
                                    extracted_for_request.append({"name":str(v["source_name"] or ""),"mode":"response_key",
                                                                  "value_preview":_value_preview(str(v["source_name"] or ""),val)})
                            elif str(v["mode"])=="response_regex" and v["regex_pattern"]:
                                try:
                                    m=re.search(str(v["regex_pattern"]),response_text,re.I|re.S)
                                    if m:
                                        val=m.group(1) if m.groups() else m.group(0)
                                        bucket[f"regex:{int(v['id'])}"]=val
                                        extracted_for_request.append({"name":str(v.get("source_name") or f"regex:{int(v['id'])}"),"mode":"response_regex",
                                                                      "value_preview":_value_preview(str(v.get("source_name") or "regex"),val)})
                                except re.error: pass
                else:
                    if status is not None and not error:
                        error=transport_detail.get("reason") or f"HTTP {status} clasificado como {exec_class}"
                        errors.append(str(error))
                    # A multi-step business Flow cannot remain trustworthy after a
                    # transport failure. Stop instead of producing seven copies of
                    # the same infrastructure error and pretending later steps ran.
                    stop_after_transport_error=True

                print(f"[runner-transport] run={run_id} step={step.get('position')} repeat={rep_idx} mode={cfg['mode']} class={exec_class} status={status} elapsed_ms={elapsed} url={url}", flush=True)
                with core.db_connect(paths) as conn:
                    conn.execute("""INSERT INTO runner_run_requests(
                        run_id,runner_step_id,repeat_index,exchange_id,status_code,elapsed_ms,error,execution_class,
                        method,url,request_b64,response_b64,transport_detail_json,resolved_variables_json,extracted_values_json,identity_id,created_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (run_id,int(step["id"]),rep_idx,exid,status,elapsed,error,exec_class,method,url,canonical_request_b64,response_b64,
                         json.dumps(transport_detail,ensure_ascii=False),json.dumps(resolved_for_request,ensure_ascii=False),
                         json.dumps(extracted_for_request,ensure_ascii=False),runner.get("identity_id"),now_iso()))

        app_count=sum(1 for c in execution_classes if c=="application_response")
        failure_classes=[c for c in execution_classes if c!="application_response"]
        if request_count and not failure_classes and app_count==request_count and request_count==planned:
            run_class="application_response"; counts_as_test=1
        elif failure_classes:
            counts_as_test=0
            if app_count:
                run_class="transport_error"
            else:
                priority=("proxy_error","timeout","dns_error","tls_error","runner_error","transport_error")
                run_class=next((c for c in priority if c in failure_classes),failure_classes[0])
        else:
            run_class="runner_error"; counts_as_test=0
        with core.db_connect(paths) as conn:
            sig_count=0
            if exchange_ids:
                marks=",".join("?" for _ in exchange_ids)
                sig_count=int(conn.execute(f"SELECT COUNT(*) c FROM signal_occurrences WHERE exchange_id IN ({marks}) AND COALESCE(human_decision,'new')!='dismissed'",tuple(exchange_ids)).fetchone()["c"] or 0)
            summary={"requests":request_count,"planned_requests":planned,"application_responses":app_count,"transport_failures":len(failure_classes),
                     "statuses":statuses,"errors":len(errors),"signals":sig_count,"exchange_ids":exchange_ids[:100],
                     "execution_class":run_class,"counts_as_test":bool(counts_as_test),"transport":cfg,
                     "stopped_early":bool(stop_after_transport_error and request_count < planned)}
            conn.execute("""UPDATE runner_runs SET status='completed',execution_class=?,counts_as_test=?,summary_json=?,finished_at=?,updated_at=? WHERE id=?""",
                         (run_class,counts_as_test,json.dumps(summary,ensure_ascii=False),now_iso(),now_iso(),run_id))
            conn.execute("UPDATE runners SET status='ready',updated_at=? WHERE id=?",(now_iso(),int(runner_id)))
        return {"run_id":run_id,"runner_id":int(runner_id),"result_flow_id":result_flow_id,**summary}
    except Exception as exc:
        with core.db_connect(paths) as conn:
            conn.execute("UPDATE runner_runs SET status='failed',execution_class='runner_error',counts_as_test=0,error=?,finished_at=?,updated_at=? WHERE id=?",
                         (f"{type(exc).__name__}: {str(exc)[:1000]}",now_iso(),now_iso(),run_id))
        raise


def update_run_outcome(conn, run_id: int, outcome: str) -> None:
    init_schema(conn)
    if outcome not in {"unreviewed","negative","interesting","confirmed","needs_retest"}:
        raise ValueError("Resultado inválido")
    row=conn.execute("SELECT counts_as_test,execution_class FROM runner_runs WHERE id=?",(int(run_id),)).fetchone()
    if not row:
        raise ValueError("Run no encontrado")
    if outcome in {"negative","interesting","confirmed"} and not bool(row["counts_as_test"]):
        raise ValueError("Este Run no alcanzó válidamente al aplicativo y no puede usarse como resultado de seguridad. Reinténtalo primero.")
    conn.execute("UPDATE runner_runs SET outcome=?,updated_at=? WHERE id=?",(outcome,now_iso(),int(run_id)))

