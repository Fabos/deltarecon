from __future__ import annotations

import base64
import json
import re
import time
import urllib.parse
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
        """SELECT fs.id flow_step_id,fs.position,fs.exchange_id,fs.label,fs.notes,e.status_code,
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
                            identity_id: int | None = None, origin: str = "manual", ai_idea: dict[str, Any] | None = None,
                            step_actions: list[dict[str, Any]] | None = None, variables: list[dict[str, Any]] | None = None) -> int:
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
                    (SELECT COUNT(*) FROM runner_runs rr WHERE rr.runner_id=ru.id AND rr.outcome='interesting') interesting_runs,
                    (SELECT COUNT(*) FROM runner_runs rr WHERE rr.runner_id=ru.id AND rr.outcome='negative') negative_runs
             FROM runners ru JOIN flows f ON f.id=ru.flow_id
             LEFT JOIN identities i ON i.id=ru.identity_id LEFT JOIN leads_v2 h ON h.id=ru.hypothesis_id
             {where} ORDER BY ru.updated_at DESC,ru.id DESC LIMIT ?""",
        tuple(params+[max(1,min(int(limit),500))]),
    ).fetchall()
    return [dict(r) for r in rows]


def get_runner(conn, runner_id: int) -> dict[str, Any] | None:
    init_schema(conn)
    row=conn.execute(
        """SELECT ru.*,f.name flow_name,f.description flow_description,i.name identity_name,h.title hypothesis_title
           FROM runners ru JOIN flows f ON f.id=ru.flow_id LEFT JOIN identities i ON i.id=ru.identity_id
           LEFT JOIN leads_v2 h ON h.id=ru.hypothesis_id WHERE ru.id=?""",
        (int(runner_id),),
    ).fetchone()
    if not row:
        return None
    runner=dict(row)
    steps=[]
    for s in conn.execute(
        """SELECT rs.*,fs.exchange_id,fs.label flow_label,e.status_code,o.method,r.id resource_id,r.url,r.path,h.hostname
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
    runs=[]
    for rr in conn.execute(
        """SELECT rr.*,f.name result_flow_name,
                  (SELECT COUNT(*) FROM runner_run_requests rrr WHERE rrr.run_id=rr.id) request_count,
                  (SELECT COUNT(*) FROM signal_occurrences s JOIN runner_run_requests rrr ON rrr.exchange_id=s.exchange_id WHERE rrr.run_id=rr.id AND s.dismissed_at IS NULL) signal_count
           FROM runner_runs rr LEFT JOIN flows f ON f.id=rr.result_flow_id WHERE rr.runner_id=? ORDER BY rr.id DESC LIMIT 30""",
        (int(runner_id),),
    ).fetchall():
        item=dict(rr); item["summary"]=_load_json(item.get("summary_json"),{})
        runs.append(item)
    return {"runner":runner,"steps":steps,"runs":runs,"ai_idea":_load_json(runner.get("ai_idea_json"),{})}


def update_runner(conn, runner_id: int, *, alias: str, description: str, identity_id: int | None, max_requests: int = 30) -> None:
    init_schema(conn)
    alias=str(alias or "").strip()[:180]
    if not alias: raise ValueError("Alias requerido")
    conn.execute("UPDATE runners SET alias=?,description=?,identity_id=?,max_requests=?,updated_at=? WHERE id=?",
                 (alias,str(description or "")[:5000],identity_id,max(1,min(int(max_requests),100)),now_iso(),int(runner_id)))


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


def create_hypothesis_from_idea(conn, *, flow_id: int, idea: dict[str, Any]) -> int:
    """Persist one human-selected AI flow question as a hypothesis. Never automatic."""
    import hashlib
    import negro_hunter as hunter
    hunter.init_schema(conn)
    title=str(idea.get("question") or idea.get("title") or "Pregunta de lógica").strip()[:240]
    why=str(idea.get("rationale") or idea.get("why_interesting") or "").strip()
    suggested=str(idea.get("test_goal") or idea.get("runner_description") or "").strip()
    fingerprint=hashlib.sha256(f"flow:{flow_id}|{title.lower()}".encode()).hexdigest()[:20]
    evidence=[{"source":"ai_flow_logic","node_ids":[f"flow:{int(flow_id)}"],"facts":idea.get("facts") or [],"unknowns":idea.get("unknowns") or [],"runner_draft":idea.get("runner") or {}}]
    hunter.upsert_lead(conn, lead_key=f"ai_flow:{fingerprint}", host_id=None, resource_id=None,
                       lead_type="business_logic", title=title, confidence="medium", review_priority="medium",
                       evidence=evidence, why=why, next_test=suggested,
                       confirm_if=str(idea.get("confirm_if") or ""), discard_if=str(idea.get("discard_if") or ""), source="AI")
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


def execute_runner(paths: dict[str,Any], domain: str, runner_id: int) -> dict[str,Any]:
    """Execute one explicit Runner sequentially. Never runs automatically.

    Hard caps keep this an investigation helper rather than a fuzzer: max 100 total
    HTTP requests, max 20 repetitions per step, no concurrency.
    """
    import requests
    import negro_core as core
    import negro_flows as flow_tools
    import negro_identity as identity_tools

    with core.db_connect(paths) as conn:
        data=get_runner(conn,int(runner_id))
        if not data: raise ValueError("Runner no encontrado")
        runner=data["runner"]; steps=data["steps"]
        planned=sum(0 if s["action"]=="omit" else (int(s["repeat_count"]) if s["action"]=="repeat" else 1) for s in steps)
        cap=min(100,int(runner.get("max_requests") or 30))
        if planned>cap:
            raise ValueError(f"El Runner intentaría {planned} Requests y su límite es {cap}. Ajusta repeticiones o el límite antes de ejecutar.")
        now=now_iso()
        cur=conn.execute("INSERT INTO runner_runs(runner_id,identity_id,status,started_at,created_at,updated_at) VALUES(?,?,'running',?,?,?)",
                         (int(runner_id),runner.get("identity_id"),now,now,now))
        run_id=int(cur.lastrowid)
        result_flow_id=flow_tools.create_flow(conn,f"Run · {runner['alias']} · #{run_id}",description=f"Resultado del Runner #{runner_id}: {runner['description'] or ''}",identity_id=runner.get("identity_id"))
        conn.execute("UPDATE runner_runs SET result_flow_id=? WHERE id=?",(result_flow_id,run_id))

    session=requests.Session()
    extracted: dict[int,dict[str,str]]={}
    request_count=0; statuses=[]; errors=[]; exchange_ids=[]
    first_cookie_seed=True
    try:
        for step in steps:
            if step["action"]=="omit":
                continue
            repeats=int(step["repeat_count"] or 1) if step["action"]=="repeat" else 1
            repeats=max(1,min(20,repeats))
            for rep_idx in range(1,repeats+1):
                with core.db_connect(paths) as conn:
                    raw,base_url=_decode_raw_request(conn,int(step["exchange_id"]),runner.get("identity_id"))
                    vars_for_step=[dict(v) for v in conn.execute("SELECT * FROM runner_variables WHERE target_runner_step_id=? ORDER BY id",(int(step["id"]),)).fetchall()]
                    for var in vars_for_step:
                        mode=str(var["mode"])
                        new_value=None
                        if mode=="values":
                            vals=_load_json(var["values_json"],[])
                            if vals:
                                new_value=str(vals[(rep_idx-1)%len(vals)])
                        elif mode=="response_key" and var["source_runner_step_id"]:
                            new_value=(extracted.get(int(var["source_runner_step_id"])) or {}).get(str(var["source_name"] or ""))
                        elif mode=="response_regex" and var["source_runner_step_id"]:
                            new_value=(extracted.get(int(var["source_runner_step_id"])) or {}).get(f"regex:{int(var['id'])}")
                        if new_value is not None:
                            raw=_replace_value(raw,str(var["target_value"] or ""),str(new_value))
                    method,url,headers,body=_split_raw_request(raw,base_url)
                # Let requests maintain session cookies across steps. Seed cookies from
                # the captured request only when they are not already present.
                cookie_header=None
                for key in list(headers):
                    if key.lower()=="cookie": cookie_header=headers.pop(key)
                    elif key.lower() in {"content-length","connection","proxy-connection","host"}: headers.pop(key,None)
                if cookie_header:
                    for piece in cookie_header.split(";"):
                        if "=" not in piece: continue
                        ck,cv=piece.split("=",1); ck=ck.strip(); cv=cv.strip()
                        if ck and (first_cookie_seed or ck not in session.cookies):
                            session.cookies.set(ck,cv)
                    first_cookie_seed=False
                start=time.perf_counter()
                error=None; resp=None
                try:
                    resp=session.request(method,url,headers=headers,data=body.encode("iso-8859-1",errors="replace"),allow_redirects=False,timeout=20)
                    elapsed=int((time.perf_counter()-start)*1000)
                    status=int(resp.status_code); statuses.append(status)
                except Exception as exc:
                    elapsed=int((time.perf_counter()-start)*1000); status=None; error=f"{type(exc).__name__}: {str(exc)[:500]}"; errors.append(error)
                if resp is not None:
                    actual_headers=dict(headers)
                    # Record actual Cookie header from the live session without exposing
                    # it elsewhere in runner metadata.
                    if session.cookies:
                        actual_headers["Cookie"]="; ".join(f"{c.name}={c.value}" for c in session.cookies)
                    request_line=urllib.parse.urlsplit(url)
                    target=(request_line.path or "/")+("?"+request_line.query if request_line.query else "")
                    actual_raw=f"{method} {target} HTTP/1.1\r\n"+"\r\n".join(f"{k}: {v}" for k,v in actual_headers.items())+"\r\n\r\n"+body
                    response_raw=_response_raw(resp)
                    req_b64=base64.b64encode(actual_raw.encode("iso-8859-1",errors="replace")).decode("ascii")
                    resp_b64=base64.b64encode(response_raw.encode("iso-8859-1",errors="replace")).decode("ascii")
                    result=core.upsert_http_observation(paths,domain,url=url,method=method,source="negro_runner",status_code=status,
                        authenticated=bool(runner.get("identity_id")),request_content_type=resp.request.headers.get("Content-Type"),
                        response_content_type=resp.headers.get("Content-Type"),tool="RUNNER",request_b64=req_b64,response_b64=resp_b64,
                        request_headers=_headers_list(actual_headers),response_headers=_headers_list(dict(resp.headers)),query=dict(urllib.parse.parse_qsl(request_line.query,keep_blank_values=True)),
                        response_body_b64=base64.b64encode(resp.content).decode("ascii"))
                    exid=int(result["exchange_id"]); exchange_ids.append(exid); request_count+=1
                    with core.db_connect(paths) as conn:
                        _postprocess_exchange(conn,exid,int(result["resource_id"]),int(result["host_id"]),domain,runner.get("identity_id"))
                        flow_tools.add_step(conn,result_flow_id,exid,allow_duplicate=True)
                        conn.execute("INSERT INTO runner_run_requests(run_id,runner_step_id,repeat_index,exchange_id,status_code,elapsed_ms,error,created_at) VALUES(?,?,?,?,?,?,?,?)",
                                     (run_id,int(step["id"]),rep_idx,exid,status,elapsed,None,now_iso()))
                        # Extract values that later steps may reference. JSON keys are
                        # indexed by normalized key name; regex extractors are stored by variable id.
                        body_text=resp.text or ""
                        bucket=extracted.setdefault(int(step["id"]),{})
                        for v in conn.execute("SELECT * FROM runner_variables WHERE source_runner_step_id=? ORDER BY id",(int(step["id"]),)).fetchall():
                            if str(v["mode"])=="response_key":
                                val=_extract_json_key(body_text,str(v["source_name"] or ""))
                                if val is not None: bucket[str(v["source_name"] or "")]=val
                            elif str(v["mode"])=="response_regex" and v["regex_pattern"]:
                                try:
                                    m=re.search(str(v["regex_pattern"]),body_text,re.I|re.S)
                                    if m: bucket[f"regex:{int(v['id'])}"]=m.group(1) if m.groups() else m.group(0)
                                except re.error: pass
                else:
                    request_count+=1
                    with core.db_connect(paths) as conn:
                        conn.execute("INSERT INTO runner_run_requests(run_id,runner_step_id,repeat_index,status_code,elapsed_ms,error,created_at) VALUES(?,?,?,?,?,?,?)",
                                     (run_id,int(step["id"]),rep_idx,None,elapsed,error,now_iso()))
        with core.db_connect(paths) as conn:
            sig_count=0
            if exchange_ids:
                marks=",".join("?" for _ in exchange_ids)
                sig_count=int(conn.execute(f"SELECT COUNT(*) c FROM signal_occurrences WHERE dismissed_at IS NULL AND exchange_id IN ({marks})",tuple(exchange_ids)).fetchone()["c"] or 0)
            summary={"requests":request_count,"statuses":statuses,"errors":len(errors),"signals":sig_count,"exchange_ids":exchange_ids[:100]}
            conn.execute("UPDATE runner_runs SET status='completed',summary_json=?,finished_at=?,updated_at=? WHERE id=?",
                         (json.dumps(summary,ensure_ascii=False),now_iso(),now_iso(),run_id))
            conn.execute("UPDATE runners SET status='ready',updated_at=? WHERE id=?",(now_iso(),int(runner_id)))
        return {"run_id":run_id,"runner_id":int(runner_id),"result_flow_id":result_flow_id,**summary}
    except Exception as exc:
        with core.db_connect(paths) as conn:
            conn.execute("UPDATE runner_runs SET status='failed',error=?,finished_at=?,updated_at=? WHERE id=?",(f"{type(exc).__name__}: {str(exc)[:1000]}",now_iso(),now_iso(),run_id))
        raise


def update_run_outcome(conn, run_id: int, outcome: str) -> None:
    init_schema(conn)
    if outcome not in {"unreviewed","negative","interesting","confirmed","needs_retest"}:
        raise ValueError("Resultado inválido")
    conn.execute("UPDATE runner_runs SET outcome=?,updated_at=? WHERE id=?",(outcome,now_iso(),int(run_id)))
