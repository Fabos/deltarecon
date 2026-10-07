from __future__ import annotations

import base64
import json
import re
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any

SOURCE_TYPES = {"CONSTANT", "MANUAL_INPUT", "PREVIOUS_RESPONSE", "IDENTITY", "OBJECT", "GENERATED"}
EXTRACT_TYPES = {"json", "header", "cookie", "regex", "location"}
RUN_STATES = {"queued", "running", "waiting_input", "waiting_prerequisite", "completed", "failed", "aborted"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _loads(value: Any, default: Any) -> Any:
    try:
        return json.loads(value or "")
    except Exception:
        return default


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def init_schema(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS flow_variables (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            source_type TEXT NOT NULL DEFAULT 'CONSTANT',
            default_value TEXT,
            prompt TEXT,
            required INTEGER NOT NULL DEFAULT 1,
            sensitive INTEGER NOT NULL DEFAULT 0,
            exported INTEGER NOT NULL DEFAULT 0,
            producer_step_id INTEGER,
            extraction_type TEXT,
            extraction_expr TEXT,
            identity_id INTEGER,
            identity_field TEXT,
            object_id INTEGER,
            generated_type TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(flow_id, name),
            FOREIGN KEY(flow_id) REFERENCES flows(id) ON DELETE CASCADE,
            FOREIGN KEY(producer_step_id) REFERENCES flow_steps(id) ON DELETE SET NULL,
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE SET NULL,
            FOREIGN KEY(object_id) REFERENCES business_objects(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_flow_variables_flow ON flow_variables(flow_id,id);
        CREATE INDEX IF NOT EXISTS idx_flow_variables_producer ON flow_variables(producer_step_id);

        CREATE TABLE IF NOT EXISTS flow_step_variable_bindings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER NOT NULL,
            flow_step_id INTEGER NOT NULL,
            variable_id INTEGER NOT NULL,
            target_value TEXT NOT NULL,
            target_name TEXT,
            target_location TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(flow_step_id, variable_id, target_value),
            FOREIGN KEY(flow_id) REFERENCES flows(id) ON DELETE CASCADE,
            FOREIGN KEY(flow_step_id) REFERENCES flow_steps(id) ON DELETE CASCADE,
            FOREIGN KEY(variable_id) REFERENCES flow_variables(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_flow_bindings_step ON flow_step_variable_bindings(flow_step_id,id);
        CREATE INDEX IF NOT EXISTS idx_flow_bindings_var ON flow_step_variable_bindings(variable_id,flow_step_id);

        CREATE TABLE IF NOT EXISTS flow_prerequisites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER NOT NULL,
            prerequisite_flow_id INTEGER NOT NULL,
            position INTEGER NOT NULL DEFAULT 1,
            required INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            UNIQUE(flow_id, prerequisite_flow_id),
            FOREIGN KEY(flow_id) REFERENCES flows(id) ON DELETE CASCADE,
            FOREIGN KEY(prerequisite_flow_id) REFERENCES flows(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_flow_prereq_flow ON flow_prerequisites(flow_id,position,id);

        CREATE TABLE IF NOT EXISTS flow_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER NOT NULL,
            parent_run_id INTEGER,
            prerequisite_for_run_id INTEGER,
            status TEXT NOT NULL DEFAULT 'queued',
            cursor_position INTEGER NOT NULL DEFAULT 0,
            prerequisite_cursor INTEGER NOT NULL DEFAULT 0,
            waiting_variable_id INTEGER,
            context_json TEXT NOT NULL DEFAULT '{}',
            exported_context_json TEXT NOT NULL DEFAULT '{}',
            error TEXT,
            started_at TEXT,
            finished_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(flow_id) REFERENCES flows(id) ON DELETE CASCADE,
            FOREIGN KEY(parent_run_id) REFERENCES flow_runs(id) ON DELETE CASCADE,
            FOREIGN KEY(prerequisite_for_run_id) REFERENCES flow_runs(id) ON DELETE CASCADE,
            FOREIGN KEY(waiting_variable_id) REFERENCES flow_variables(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_flow_runs_flow ON flow_runs(flow_id,id DESC);
        CREATE INDEX IF NOT EXISTS idx_flow_runs_parent ON flow_runs(parent_run_id,id);

        CREATE TABLE IF NOT EXISTS flow_run_steps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            flow_step_id INTEGER NOT NULL,
            position INTEGER NOT NULL,
            exchange_id INTEGER,
            status TEXT NOT NULL,
            status_code INTEGER,
            elapsed_ms INTEGER,
            request_b64 TEXT,
            response_b64 TEXT,
            used_context_json TEXT,
            produced_context_json TEXT,
            error TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(run_id, flow_step_id),
            FOREIGN KEY(run_id) REFERENCES flow_runs(id) ON DELETE CASCADE,
            FOREIGN KEY(flow_step_id) REFERENCES flow_steps(id) ON DELETE CASCADE,
            FOREIGN KEY(exchange_id) REFERENCES http_exchanges(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_flow_run_steps_run ON flow_run_steps(run_id,position,id);

        CREATE TABLE IF NOT EXISTS flow_run_overrides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            flow_step_id INTEGER NOT NULL,
            variable_id INTEGER NOT NULL,
            source_type TEXT NOT NULL DEFAULT 'CONSTANT',
            value TEXT,
            identity_id INTEGER,
            identity_field TEXT,
            object_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(run_id, flow_step_id, variable_id),
            FOREIGN KEY(run_id) REFERENCES flow_runs(id) ON DELETE CASCADE,
            FOREIGN KEY(flow_step_id) REFERENCES flow_steps(id) ON DELETE CASCADE,
            FOREIGN KEY(variable_id) REFERENCES flow_variables(id) ON DELETE CASCADE,
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE SET NULL,
            FOREIGN KEY(object_id) REFERENCES business_objects(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_flow_overrides_run ON flow_run_overrides(run_id,flow_step_id);
        """
    )
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(flow_run_steps)")}
    if "exchange_id" not in cols:
        try:
            conn.execute("ALTER TABLE flow_run_steps ADD COLUMN exchange_id INTEGER")
        except Exception:
            pass


def create_variable(conn, flow_id: int, *, name: str, source_type: str, description: str = "", default_value: str = "",
                    prompt: str = "", required: bool = True, sensitive: bool = False, exported: bool = False,
                    producer_step_id: int | None = None, extraction_type: str = "", extraction_expr: str = "",
                    identity_id: int | None = None, identity_field: str = "", object_id: int | None = None,
                    generated_type: str = "") -> int:
    init_schema(conn)
    name = re.sub(r"[^A-Za-z0-9_]+", "_", str(name or "").strip()).strip("_")[:80]
    if not name:
        raise ValueError("Nombre de variable requerido")
    source_type = str(source_type or "CONSTANT").upper()
    if source_type not in SOURCE_TYPES:
        raise ValueError("Source inválido")
    if producer_step_id is not None:
        row = conn.execute("SELECT flow_id FROM flow_steps WHERE id=?", (int(producer_step_id),)).fetchone()
        if not row or int(row["flow_id"]) != int(flow_id):
            raise ValueError("Producer Step no pertenece al Flow")
    if source_type == "PREVIOUS_RESPONSE":
        extraction_type = str(extraction_type or "json").lower()
        if extraction_type not in EXTRACT_TYPES:
            raise ValueError("Extractor inválido")
        if not producer_step_id:
            raise ValueError("PREVIOUS_RESPONSE necesita Producer Step")
        if not str(extraction_expr or "").strip():
            raise ValueError("PREVIOUS_RESPONSE necesita expresión de extracción")
    if source_type == "MANUAL_INPUT" and not prompt:
        prompt = name
    now = now_iso()
    cur = conn.execute(
        """INSERT INTO flow_variables(flow_id,name,description,source_type,default_value,prompt,required,sensitive,exported,
           producer_step_id,extraction_type,extraction_expr,identity_id,identity_field,object_id,generated_type,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (int(flow_id), name, str(description or "")[:1000], source_type, str(default_value or "")[:10000], str(prompt or "")[:500],
         1 if required else 0, 1 if sensitive else 0, 1 if exported else 0, producer_step_id, str(extraction_type or "")[:40],
         str(extraction_expr or "")[:1000], identity_id, str(identity_field or "")[:300], object_id, str(generated_type or "")[:100], now, now),
    )
    conn.execute("UPDATE flows SET updated_at=? WHERE id=?", (now, int(flow_id)))
    return int(cur.lastrowid)


def delete_variable(conn, flow_id: int, variable_id: int) -> None:
    init_schema(conn)
    conn.execute("DELETE FROM flow_variables WHERE id=? AND flow_id=?", (int(variable_id), int(flow_id)))


def update_variable(conn, flow_id: int, variable_id: int, *, description: str = "", prompt: str = "",
                    required: bool = True, sensitive: bool = False, exported: bool = False) -> None:
    init_schema(conn)
    row = conn.execute("SELECT id,source_type,name FROM flow_variables WHERE id=? AND flow_id=?", (int(variable_id), int(flow_id))).fetchone()
    if not row:
        raise ValueError("Variable no encontrada")
    if str(row["source_type"]).upper() == "MANUAL_INPUT" and not str(prompt or "").strip():
        prompt = str(row["name"] or "")
    conn.execute(
        """UPDATE flow_variables SET description=?,prompt=?,required=?,sensitive=?,exported=?,updated_at=? WHERE id=? AND flow_id=?""",
        (str(description or "")[:1000], str(prompt or "")[:500], 1 if required else 0, 1 if sensitive else 0,
         1 if exported else 0, now_iso(), int(variable_id), int(flow_id)),
    )


def add_binding(conn, flow_id: int, step_id: int, variable_id: int, *, target_value: str, target_name: str = "", target_location: str = "") -> int:
    init_schema(conn)
    s = conn.execute("SELECT flow_id FROM flow_steps WHERE id=?", (int(step_id),)).fetchone()
    v = conn.execute("SELECT flow_id FROM flow_variables WHERE id=?", (int(variable_id),)).fetchone()
    if not s or not v or int(s["flow_id"]) != int(flow_id) or int(v["flow_id"]) != int(flow_id):
        raise ValueError("Step/Variable no pertenecen al Flow")
    if not str(target_value or ""):
        raise ValueError("Valor original requerido")
    now = now_iso()
    cur = conn.execute(
        """INSERT INTO flow_step_variable_bindings(flow_id,flow_step_id,variable_id,target_value,target_name,target_location,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(flow_step_id,variable_id,target_value) DO UPDATE SET target_name=excluded.target_name,target_location=excluded.target_location,updated_at=excluded.updated_at""",
        (int(flow_id), int(step_id), int(variable_id), str(target_value)[:10000], str(target_name or "")[:200], str(target_location or "")[:200], now, now),
    )
    return int(cur.lastrowid or 0)


def add_prerequisite(conn, flow_id: int, prerequisite_flow_id: int) -> int:
    init_schema(conn)
    if int(flow_id) == int(prerequisite_flow_id):
        raise ValueError("Un Flow no puede requerirse a sí mismo")
    if not conn.execute("SELECT id FROM flows WHERE id=?", (int(prerequisite_flow_id),)).fetchone():
        raise ValueError("Flow requisito no encontrado")
    # conservative cycle check
    todo = [int(prerequisite_flow_id)]
    seen: set[int] = set()
    while todo:
        cur = todo.pop()
        if cur == int(flow_id):
            raise ValueError("Ese requisito crearía un ciclo de Flows")
        if cur in seen:
            continue
        seen.add(cur)
        todo.extend(int(r["prerequisite_flow_id"]) for r in conn.execute("SELECT prerequisite_flow_id FROM flow_prerequisites WHERE flow_id=?", (cur,)).fetchall())
    pos = int(conn.execute("SELECT COALESCE(MAX(position),0)+1 n FROM flow_prerequisites WHERE flow_id=?", (int(flow_id),)).fetchone()["n"])
    now = now_iso()
    cur = conn.execute("INSERT OR IGNORE INTO flow_prerequisites(flow_id,prerequisite_flow_id,position,required,created_at) VALUES(?,?,?,?,?)",
                       (int(flow_id), int(prerequisite_flow_id), pos, 1, now))
    return int(cur.lastrowid or 0)


def remove_prerequisite(conn, flow_id: int, prerequisite_flow_id: int) -> None:
    init_schema(conn)
    conn.execute("DELETE FROM flow_prerequisites WHERE flow_id=? AND prerequisite_flow_id=?", (int(flow_id), int(prerequisite_flow_id)))


def flow_runtime_data(conn, flow_id: int) -> dict[str, Any]:
    init_schema(conn)
    variables = [dict(r) for r in conn.execute(
        """SELECT v.*,fs.position producer_position,i.name identity_name,bot.name object_type,bo.identifier_preview object_preview
           FROM flow_variables v
           LEFT JOIN flow_steps fs ON fs.id=v.producer_step_id
           LEFT JOIN identities i ON i.id=v.identity_id
           LEFT JOIN business_objects bo ON bo.id=v.object_id
           LEFT JOIN business_object_types bot ON bot.id=bo.object_type_id
           WHERE v.flow_id=? ORDER BY v.id""", (int(flow_id),)).fetchall()]
    bindings = [dict(r) for r in conn.execute(
        """SELECT b.*,v.name variable_name,fs.position step_position FROM flow_step_variable_bindings b
           JOIN flow_variables v ON v.id=b.variable_id JOIN flow_steps fs ON fs.id=b.flow_step_id
           WHERE b.flow_id=? ORDER BY fs.position,b.id""", (int(flow_id),)).fetchall()]
    prereqs = [dict(r) for r in conn.execute(
        """SELECT p.*,f.name prerequisite_name FROM flow_prerequisites p JOIN flows f ON f.id=p.prerequisite_flow_id
           WHERE p.flow_id=? ORDER BY p.position,p.id""", (int(flow_id),)).fetchall()]
    runs = [dict(r) for r in conn.execute("SELECT * FROM flow_runs WHERE flow_id=? AND parent_run_id IS NULL ORDER BY id DESC LIMIT 20", (int(flow_id),)).fetchall()]
    consumers: dict[int, list[int]] = {}
    for b in bindings:
        consumers.setdefault(int(b["variable_id"]), []).append(int(b["step_position"]))

    source_labels = {
        "MANUAL_INPUT": "Te lo pide Negro al ejecutar",
        "PREVIOUS_RESPONSE": "Sale automáticamente de una respuesta anterior",
        "IDENTITY": "Lo toma de una Identity",
        "OBJECT": "Lo toma de un Object",
        "CONSTANT": "Valor fijo",
        "GENERATED": "Lo genera Negro",
    }
    step_inputs: dict[int, list[dict[str, Any]]] = {}
    step_outputs: dict[int, list[dict[str, Any]]] = {}
    by_var = {int(v["id"]): v for v in variables}
    for b in bindings:
        v = by_var.get(int(b["variable_id"]))
        if not v:
            continue
        item = {
            "id": int(v["id"]), "name": v["name"], "source_type": v["source_type"],
            "source_label": source_labels.get(str(v["source_type"]), str(v["source_type"])),
            "sensitive": bool(v.get("sensitive")), "target_name": b.get("target_name") or "",
            "target_location": b.get("target_location") or "",
        }
        step_inputs.setdefault(int(b["flow_step_id"]), []).append(item)
    for v in variables:
        v["consumers"] = consumers.get(int(v["id"]), [])
        v["source_label"] = source_labels.get(str(v["source_type"]), str(v["source_type"]))
        if v.get("producer_step_id"):
            step_outputs.setdefault(int(v["producer_step_id"]), []).append({
                "id": int(v["id"]), "name": v["name"], "source_type": v["source_type"],
                "source_label": v["source_label"], "sensitive": bool(v.get("sensitive")),
                "extraction_type": v.get("extraction_type") or "", "extraction_expr": v.get("extraction_expr") or "",
            })
    return {"variables": variables, "bindings": bindings, "prerequisites": prereqs, "runs": runs,
            "step_inputs": step_inputs, "step_outputs": step_outputs, "source_labels": source_labels}


def _mask(value: str) -> str:
    value = str(value or "")
    if len(value) <= 8:
        return "•" * max(4, len(value))
    return value[:6] + "…" + "•" * 6


def _resolve_identity_value(conn, identity_id: int | None, field: str) -> str | None:
    if not identity_id:
        return None
    field = str(field or "").strip()
    low = field.lower()
    if low.startswith("resolver:"):
        selector = field.split(":", 1)[1]
        row = conn.execute("""SELECT value_raw FROM identity_resolvers WHERE identity_id=? AND enabled=1 AND lower(selector)=lower(?)
                            ORDER BY updated_at DESC,id DESC LIMIT 1""", (int(identity_id), selector)).fetchone()
        return str(row["value_raw"]) if row and row["value_raw"] is not None else None
    material = field.split(":", 1)[1] if low.startswith("auth:") else field
    if material:
        row = conn.execute("""SELECT raw_value FROM auth_materials WHERE identity_id=? AND active=1 AND classification='auth'
                            AND lower(material_name)=lower(?) ORDER BY last_seen_at DESC,id DESC LIMIT 1""", (int(identity_id), material)).fetchone()
        if row and row["raw_value"] is not None:
            return str(row["raw_value"])
    row = conn.execute("""SELECT raw_value FROM auth_materials WHERE identity_id=? AND active=1 AND classification='auth'
                        ORDER BY CASE WHEN lower(material_name)='authorization' THEN 0 ELSE 1 END,last_seen_at DESC,id DESC LIMIT 1""", (int(identity_id),)).fetchone()
    return str(row["raw_value"]) if row and row["raw_value"] is not None else None


def _resolve_object_value(conn, object_id: int | None) -> str | None:
    if not object_id:
        return None
    row = conn.execute("SELECT identifier_raw,identifier_preview FROM business_objects WHERE id=?", (int(object_id),)).fetchone()
    if not row:
        return None
    return str(row["identifier_raw"] or row["identifier_preview"] or "") or None


def _generated_value(kind: str) -> str:
    import secrets
    kind = str(kind or "token").lower()
    if kind == "email":
        return f"negro-{secrets.token_hex(6)}@example.invalid"
    if kind in {"uuid", "uuid4"}:
        import uuid
        return str(uuid.uuid4())
    return secrets.token_urlsafe(18)


def _extract_json_path(text: str, expr: str) -> str | None:
    try:
        obj = json.loads(text)
    except Exception:
        return None
    path = str(expr or "").strip()
    if path.startswith("$."):
        path = path[2:]
    elif path == "$":
        return json.dumps(obj, ensure_ascii=False) if isinstance(obj, (dict, list)) else str(obj)
    tokens = [x for x in re.split(r"\.|\[|\]", path) if x != ""]
    cur: Any = obj
    try:
        for tok in tokens:
            if isinstance(cur, list):
                cur = cur[int(tok)]
            elif isinstance(cur, dict):
                cur = cur[tok]
            else:
                return None
    except Exception:
        return None
    if isinstance(cur, (dict, list)):
        return json.dumps(cur, ensure_ascii=False)
    return "" if cur is None else str(cur)


def _extract_value(extraction_type: str, expr: str, response_text: str, response_headers: list[dict[str, str]]) -> str | None:
    kind = str(extraction_type or "json").lower()
    expr = str(expr or "").strip()
    if kind == "json":
        return _extract_json_path(response_text, expr)
    if kind in {"header", "location"}:
        wanted = "location" if kind == "location" and not expr else expr.lower()
        for h in response_headers:
            if str(h.get("name") or "").lower() == wanted:
                return str(h.get("value") or "")
        return None
    if kind == "cookie":
        wanted = expr.lower()
        for h in response_headers:
            if str(h.get("name") or "").lower() != "set-cookie":
                continue
            first = str(h.get("value") or "").split(";", 1)[0]
            if "=" in first:
                name, value = first.split("=", 1)
                if name.strip().lower() == wanted:
                    return value.strip()
        return None
    if kind == "regex":
        try:
            m = re.search(expr, response_text, re.I | re.S)
        except re.error:
            return None
        if not m:
            return None
        return m.group(1) if m.groups() else m.group(0)
    return None


def _variables_for_flow(conn, flow_id: int) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute("SELECT * FROM flow_variables WHERE flow_id=? ORDER BY id", (int(flow_id),)).fetchall()]


def _bindings_for_step(conn, step_id: int) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute("""SELECT b.*,v.name variable_name,v.source_type,v.required,v.sensitive,v.identity_id,v.identity_field,v.object_id,v.default_value,v.generated_type
                                            FROM flow_step_variable_bindings b JOIN flow_variables v ON v.id=b.variable_id
                                            WHERE b.flow_step_id=? ORDER BY b.id""", (int(step_id),)).fetchall()]


def _resolve_variable(conn, variable: dict[str, Any], context: dict[str, str], *, override: dict[str, Any] | None = None) -> str | None:
    if override:
        st = str(override.get("source_type") or "CONSTANT").upper()
        if st == "IDENTITY":
            return _resolve_identity_value(conn, override.get("identity_id"), str(override.get("identity_field") or ""))
        if st == "OBJECT":
            return _resolve_object_value(conn, override.get("object_id"))
        return str(override.get("value") or "")
    name = str(variable["name"])
    if name in context:
        return str(context[name])
    st = str(variable.get("source_type") or "CONSTANT").upper()
    if st == "CONSTANT":
        return str(variable.get("default_value") or "")
    if st == "IDENTITY":
        return _resolve_identity_value(conn, variable.get("identity_id"), str(variable.get("identity_field") or ""))
    if st == "OBJECT":
        return _resolve_object_value(conn, variable.get("object_id"))
    if st == "GENERATED":
        return _generated_value(str(variable.get("generated_type") or "token"))
    return None


def _replace_all(raw: str, old: str, new: str) -> str:
    import negro_runners as runner_tools
    return runner_tools._replace_value(raw, old, new)


def _step_rows(conn, flow_id: int) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute(
        """SELECT fs.id flow_step_id,fs.position,fs.exchange_id,fs.label,o.method,r.id resource_id,r.url,r.path,h.hostname
           FROM flow_steps fs JOIN http_exchanges e ON e.id=fs.exchange_id
           JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id
           WHERE fs.flow_id=? AND fs.included=1 ORDER BY fs.position,fs.id""", (int(flow_id),)).fetchall()]


def create_run(conn, flow_id: int, *, parent_run_id: int | None = None, prerequisite_for_run_id: int | None = None,
               inherited_context: dict[str, str] | None = None) -> int:
    init_schema(conn)
    if not conn.execute("SELECT id FROM flows WHERE id=?", (int(flow_id),)).fetchone():
        raise ValueError("Flow no encontrado")
    context = dict(inherited_context or {})
    for v in _variables_for_flow(conn, int(flow_id)):
        st = str(v["source_type"] or "CONSTANT").upper()
        if st == "CONSTANT" and v["name"] not in context:
            context[str(v["name"])] = str(v["default_value"] or "")
        elif st == "GENERATED" and v["name"] not in context:
            context[str(v["name"])] = _generated_value(str(v["generated_type"] or "token"))
    now = now_iso()
    cur = conn.execute("""INSERT INTO flow_runs(flow_id,parent_run_id,prerequisite_for_run_id,status,cursor_position,prerequisite_cursor,context_json,exported_context_json,started_at,created_at,updated_at)
                        VALUES(?,?,?,'queued',0,0,?,'{}',?,?,?)""",
                       (int(flow_id), parent_run_id, prerequisite_for_run_id, _dumps(context), now, now, now))
    return int(cur.lastrowid)


def provide_input(conn, run_id: int, variable_id: int, value: str) -> None:
    init_schema(conn)
    run = conn.execute("SELECT * FROM flow_runs WHERE id=?", (int(run_id),)).fetchone()
    var = conn.execute("SELECT * FROM flow_variables WHERE id=?", (int(variable_id),)).fetchone()
    if not run or not var or int(var["flow_id"]) != int(run["flow_id"]):
        raise ValueError("Input/Run inválido")
    context = _loads(run["context_json"], {})
    context[str(var["name"])] = str(value)
    conn.execute("UPDATE flow_runs SET context_json=?,waiting_variable_id=NULL,status='running',updated_at=? WHERE id=?", (_dumps(context), now_iso(), int(run_id)))


def set_override(conn, run_id: int, step_id: int, variable_id: int, *, source_type: str = "CONSTANT", value: str = "",
                 identity_id: int | None = None, identity_field: str = "", object_id: int | None = None) -> None:
    init_schema(conn)
    run = conn.execute("SELECT flow_id FROM flow_runs WHERE id=?", (int(run_id),)).fetchone()
    if not run:
        raise ValueError("Run no encontrado")
    flow_id = int(run["flow_id"])
    if not conn.execute("SELECT 1 FROM flow_steps WHERE id=? AND flow_id=?", (int(step_id), flow_id)).fetchone():
        raise ValueError("Step inválido")
    if not conn.execute("SELECT 1 FROM flow_variables WHERE id=? AND flow_id=?", (int(variable_id), flow_id)).fetchone():
        raise ValueError("Variable inválida")
    st = str(source_type or "CONSTANT").upper()
    if st not in {"CONSTANT", "IDENTITY", "OBJECT"}:
        raise ValueError("Override MVP soporta CONSTANT, IDENTITY u OBJECT")
    now = now_iso()
    conn.execute("""INSERT INTO flow_run_overrides(run_id,flow_step_id,variable_id,source_type,value,identity_id,identity_field,object_id,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(run_id,flow_step_id,variable_id) DO UPDATE SET source_type=excluded.source_type,value=excluded.value,
                    identity_id=excluded.identity_id,identity_field=excluded.identity_field,object_id=excluded.object_id,updated_at=excluded.updated_at""",
                 (int(run_id), int(step_id), int(variable_id), st, str(value or "")[:10000], identity_id, str(identity_field or "")[:300], object_id, now, now))


def _run_one_step(paths: dict[str, Any], domain: str, run: dict[str, Any], step: dict[str, Any], context: dict[str, str]) -> tuple[dict[str, Any], dict[str, str]]:
    import requests
    import types
    import negro_core as core
    import negro_runners as rt

    cfg = rt.transport_settings()
    with core.db_connect(paths) as conn:
        raw, base_url = rt._decode_raw_request(conn, int(step["exchange_id"]), None)
        bindings = _bindings_for_step(conn, int(step["flow_step_id"]))
        used: dict[str, str] = {}
        flow_row = conn.execute("SELECT identity_id FROM flows WHERE id=?", (int(run["flow_id"]),)).fetchone()
        step_identity_id = int(flow_row["identity_id"]) if flow_row and flow_row["identity_id"] else None
        for binding in bindings:
            variable = conn.execute("SELECT * FROM flow_variables WHERE id=?", (int(binding["variable_id"]),)).fetchone()
            variable = dict(variable) if variable else None
            if not variable:
                continue
            override_row = conn.execute("SELECT * FROM flow_run_overrides WHERE run_id=? AND flow_step_id=? AND variable_id=?",
                                        (int(run["id"]), int(step["flow_step_id"]), int(variable["id"]))).fetchone()
            override = dict(override_row) if override_row else None
            if override and str(override.get("source_type") or "").upper() == "IDENTITY" and override.get("identity_id"):
                step_identity_id = int(override["identity_id"])
            value = _resolve_variable(conn, variable, context, override=override)
            if value is None and int(variable.get("required") or 0):
                if str(variable.get("source_type") or "").upper() == "MANUAL_INPUT" and not override:
                    return {"waiting_variable": variable, "used": used}, context
                return {"error": f"Missing variable {{{{{variable['name']}}}}}; source={variable.get('source_type')}", "used": used}, context
            if value is None:
                value = ""
            used[str(variable["name"])] = _mask(value) if int(variable.get("sensitive") or 0) else value
            replacement = str(value)
            # Identity auth materials normally preserve the full header value
            # (e.g. "Bearer eyJ..."). If the researcher marked only the token
            # portion inside Authorization, avoid producing "Bearer Bearer ...".
            if str(binding.get("target_name") or "").lower() == "authorization":
                old = str(binding.get("target_value") or "")
                if replacement.lower().startswith("bearer ") and not old.lower().startswith("bearer "):
                    replacement = replacement.split(" ", 1)[1]
            raw = _replace_all(raw, str(binding["target_value"] or ""), replacement)
        method, url, headers, body = rt._split_raw_request(raw, base_url)

    session = requests.Session(); session.trust_env = False
    if cfg["mode"] != "burp_bridge":
        session = rt._build_session(cfg)
    cookiejar = context.get("__cookiejar") if isinstance(context.get("__cookiejar"), dict) else {}
    # Seed from the captured request, then let prior Set-Cookie values win. This
    # preserves session rotation across incremental Flow execution without mutating
    # the user's browser or global Burp state.
    baseline_cookie_key = next((k for k in headers if k.lower() == "cookie"), None)
    if baseline_cookie_key:
        baseline_cookie = headers.pop(baseline_cookie_key)
        for piece in str(baseline_cookie).split(";"):
            if "=" not in piece:
                continue
            ck, cv = piece.split("=", 1); ck = ck.strip(); cv = cv.strip()
            if ck and ck not in cookiejar:
                cookiejar[ck] = cv
    for ck, cv in cookiejar.items():
        session.cookies.set(str(ck), str(cv))
    for key in list(headers):
        if key.lower() in {"content-length", "connection", "proxy-connection"}:
            headers.pop(key, None)
    if session.cookies:
        headers["Cookie"] = "; ".join(f"{c.name}={c.value}" for c in session.cookies)
    request_line = urllib.parse.urlsplit(url)
    target = (request_line.path or "/") + ("?" + request_line.query if request_line.query else "")
    actual_raw = f"{method} {target} HTTP/1.1\r\n" + "\r\n".join(f"{k}: {v}" for k, v in headers.items()) + "\r\n\r\n" + body
    req_b64 = base64.b64encode(actual_raw.encode("iso-8859-1", errors="replace")).decode("ascii")
    start = time.perf_counter()
    response_headers: list[dict[str, str]] = []
    response_b64 = None; response_body_b64 = None; response_text = ""; status = None
    exec_class = "runner_error"; error = None; canonical_request_b64 = req_b64
    try:
        if cfg["mode"] == "burp_bridge":
            item = rt._queue_bridge_execute(paths, resource_id=int(step["resource_id"]), method=method, url=url, request_b64=req_b64, timeout_seconds=int(cfg["timeout_seconds"]))
            status = int(item["response_status"]); response_b64 = str(item.get("response_b64") or "") or None
            response_body_b64 = str(item.get("response_body_b64") or "") or None
            response_headers = rt._headers_from_json(item.get("response_headers_json"))
            canonical_request_b64 = str(item.get("result_request_b64") or req_b64)
            try:
                response_text = base64.b64decode(response_body_b64 or "", validate=False).decode("iso-8859-1", errors="replace")
            except Exception:
                response_text = ""
            pseudo = types.SimpleNamespace(status_code=status, headers={h["name"]: h["value"] for h in response_headers}, text=response_text)
            exec_class, _ = rt._classify_response(pseudo, proxy_url=None)
            rt._apply_response_cookies(session, response_headers)
        else:
            resp = session.request(method, url, headers=headers, data=body.encode("iso-8859-1", errors="replace"), allow_redirects=False,
                                   timeout=cfg["timeout_seconds"], verify=rt._verify_value(cfg))
            status = int(resp.status_code); exec_class, _ = rt._classify_response(resp, proxy_url=rt._effective_proxy_for_url(session, url, cfg))
            response_raw = rt._response_raw(resp)
            response_b64 = base64.b64encode(response_raw.encode("iso-8859-1", errors="replace")).decode("ascii")
            response_headers = rt._headers_list(dict(resp.headers)); response_body_b64 = base64.b64encode(resp.content).decode("ascii"); response_text = resp.text or ""
            rt._apply_response_cookies(session, response_headers)
    except Exception as exc:
        error = f"{type(exc).__name__}: {str(exc)[:1000]}"
    elapsed = int((time.perf_counter() - start) * 1000)
    if error or exec_class != "application_response":
        return {"error": error or f"HTTP/transport classified as {exec_class}", "status_code": status, "elapsed_ms": elapsed,
                "request_b64": canonical_request_b64, "response_b64": response_b64, "used": used}, context

    exchange_id = None
    try:
        result = core.upsert_http_observation(
            paths, domain, url=url, method=method, source="negro_flow_runtime", status_code=status,
            authenticated=bool(step_identity_id),
            request_content_type=next((v for k,v in headers.items() if k.lower()=="content-type"), None),
            response_content_type=rt._header_value(response_headers, "Content-Type"), tool="FLOW_RUNTIME",
            request_b64=canonical_request_b64, response_b64=response_b64, request_headers=rt._headers_list(headers),
            response_headers=response_headers, query=dict(urllib.parse.parse_qsl(request_line.query, keep_blank_values=True)),
            response_body_b64=response_body_b64)
        exchange_id = int(result["exchange_id"])
        with core.db_connect(paths) as post_conn:
            rt._postprocess_exchange(post_conn, exchange_id, int(result["resource_id"]), int(result["host_id"]), domain, step_identity_id)
    except Exception:
        exchange_id = None

    # Persist the isolated cookie jar in this Run context so the next Step sees
    # rotations produced by the server. Internal keys never become Flow exports.
    context["__cookiejar"] = {c.name: c.value for c in session.cookies}
    produced: dict[str, str] = {}
    with core.db_connect(paths) as conn:
        for variable in conn.execute("SELECT * FROM flow_variables WHERE producer_step_id=? ORDER BY id", (int(step["flow_step_id"]),)).fetchall():
            v = dict(variable)
            if str(v["source_type"]).upper() != "PREVIOUS_RESPONSE":
                continue
            val = _extract_value(str(v.get("extraction_type") or "json"), str(v.get("extraction_expr") or ""), response_text, response_headers)
            if val is not None:
                context[str(v["name"])] = val
                produced[str(v["name"])] = _mask(val) if int(v.get("sensitive") or 0) else val
            elif int(v.get("required") or 0):
                return {"error": f"Extraction failed for {{{{{v['name']}}}}} from {v.get('extraction_type')}:{v.get('extraction_expr')}",
                        "status_code": status, "elapsed_ms": elapsed, "request_b64": canonical_request_b64, "response_b64": response_b64,
                        "used": used, "produced": produced}, context
    return {"status_code": status, "elapsed_ms": elapsed, "request_b64": canonical_request_b64, "response_b64": response_b64,
            "exchange_id": exchange_id, "used": used, "produced": produced}, context


def advance_run(paths: dict[str, Any], domain: str, run_id: int) -> dict[str, Any]:
    import negro_core as core
    init_error = None
    with core.db_connect(paths) as conn:
        init_schema(conn)
        run_row = conn.execute("SELECT * FROM flow_runs WHERE id=?", (int(run_id),)).fetchone()
        if not run_row:
            raise ValueError("Flow Run no encontrado")
        run = dict(run_row)
        if run["status"] in {"completed", "failed", "aborted"}:
            return get_run(conn, int(run_id)) or run
        flow_id = int(run["flow_id"]); context = _loads(run["context_json"], {})
        conn.execute("UPDATE flow_runs SET status='running',updated_at=? WHERE id=?", (now_iso(), int(run_id)))

    # Resolve reusable prerequisite Flows first. Each child Run keeps its own
    # context; only explicitly exported variables are copied into the parent.
    while True:
        with core.db_connect(paths) as conn:
            prereqs = [dict(r) for r in conn.execute("SELECT * FROM flow_prerequisites WHERE flow_id=? ORDER BY position,id", (flow_id,)).fetchall()]
            run = dict(conn.execute("SELECT * FROM flow_runs WHERE id=?", (int(run_id),)).fetchone())
            idx = int(run.get("prerequisite_cursor") or 0)
            context = _loads(run.get("context_json"), {})
            if idx >= len(prereqs):
                break
            pre = prereqs[idx]
            child = conn.execute("SELECT * FROM flow_runs WHERE parent_run_id=? AND prerequisite_for_run_id=? AND flow_id=? ORDER BY id DESC LIMIT 1",
                                 (int(run_id), int(run_id), int(pre["prerequisite_flow_id"]))).fetchone()
            if not child:
                child_id = create_run(conn, int(pre["prerequisite_flow_id"]), parent_run_id=int(run_id), prerequisite_for_run_id=int(run_id), inherited_context={})
            else:
                child_id = int(child["id"])
        child_result = advance_run(paths, domain, child_id)
        child_status = str(child_result.get("run", child_result).get("status") if isinstance(child_result.get("run"), dict) else child_result.get("status") or "")
        if child_status == "waiting_input":
            with core.db_connect(paths) as conn:
                conn.execute("UPDATE flow_runs SET status='waiting_prerequisite',updated_at=? WHERE id=?", (now_iso(), int(run_id)))
            return get_run_by_paths(paths, int(run_id))
        if child_status != "completed":
            with core.db_connect(paths) as conn:
                conn.execute("UPDATE flow_runs SET status='failed',error=?,updated_at=?,finished_at=? WHERE id=?",
                             (f"Prerequisite Flow #{pre['prerequisite_flow_id']} failed", now_iso(), now_iso(), int(run_id)))
            return get_run_by_paths(paths, int(run_id))
        child_exported = child_result.get("run", child_result).get("exported_context", {}) if isinstance(child_result.get("run"), dict) else child_result.get("exported_context", {})
        with core.db_connect(paths) as conn:
            run = dict(conn.execute("SELECT * FROM flow_runs WHERE id=?", (int(run_id),)).fetchone())
            context = _loads(run["context_json"], {})
            context.update(child_exported or {})
            conn.execute("UPDATE flow_runs SET context_json=?,prerequisite_cursor=?,status='running',updated_at=? WHERE id=?",
                         (_dumps(context), idx + 1, now_iso(), int(run_id)))

    with core.db_connect(paths) as conn:
        run = dict(conn.execute("SELECT * FROM flow_runs WHERE id=?", (int(run_id),)).fetchone())
        steps = _step_rows(conn, flow_id)
        cursor = int(run.get("cursor_position") or 0)
        context = _loads(run["context_json"], {})

    for step in steps:
        if int(step["position"]) <= cursor:
            continue
        result, context = _run_one_step(paths, domain, run, step, context)
        if result.get("waiting_variable"):
            variable = result["waiting_variable"]
            with core.db_connect(paths) as conn:
                conn.execute("UPDATE flow_runs SET status='waiting_input',waiting_variable_id=?,context_json=?,updated_at=? WHERE id=?",
                             (int(variable["id"]), _dumps(context), now_iso(), int(run_id)))
            return get_run_by_paths(paths, int(run_id))
        status = "failed" if result.get("error") else "completed"
        with core.db_connect(paths) as conn:
            now = now_iso()
            conn.execute("""INSERT INTO flow_run_steps(run_id,flow_step_id,position,exchange_id,status,status_code,elapsed_ms,request_b64,response_b64,used_context_json,produced_context_json,error,created_at,updated_at)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                            ON CONFLICT(run_id,flow_step_id) DO UPDATE SET exchange_id=excluded.exchange_id,status=excluded.status,status_code=excluded.status_code,elapsed_ms=excluded.elapsed_ms,
                            request_b64=excluded.request_b64,response_b64=excluded.response_b64,used_context_json=excluded.used_context_json,produced_context_json=excluded.produced_context_json,error=excluded.error,updated_at=excluded.updated_at""",
                         (int(run_id), int(step["flow_step_id"]), int(step["position"]), result.get("exchange_id"), status, result.get("status_code"), result.get("elapsed_ms"), result.get("request_b64"), result.get("response_b64"),
                          _dumps(result.get("used") or {}), _dumps(result.get("produced") or {}), result.get("error"), now, now))
            conn.execute("UPDATE flow_runs SET cursor_position=?,context_json=?,status=?,error=?,updated_at=? WHERE id=?",
                         (int(step["position"]), _dumps(context), "failed" if result.get("error") else "running", result.get("error"), now, int(run_id)))
        if result.get("error"):
            with core.db_connect(paths) as conn:
                conn.execute("UPDATE flow_runs SET finished_at=?,updated_at=? WHERE id=?", (now_iso(), now_iso(), int(run_id)))
            return get_run_by_paths(paths, int(run_id))

    with core.db_connect(paths) as conn:
        vars_ = _variables_for_flow(conn, flow_id); run = dict(conn.execute("SELECT * FROM flow_runs WHERE id=?", (int(run_id),)).fetchone())
        context = _loads(run["context_json"], {})
        exported = {str(v["name"]): context[str(v["name"])] for v in vars_ if int(v.get("exported") or 0) and str(v["name"]) in context}
        conn.execute("UPDATE flow_runs SET status='completed',waiting_variable_id=NULL,exported_context_json=?,finished_at=?,updated_at=? WHERE id=?",
                     (_dumps(exported), now_iso(), now_iso(), int(run_id)))
    return get_run_by_paths(paths, int(run_id))


def get_run(conn, run_id: int) -> dict[str, Any] | None:
    init_schema(conn)
    row = conn.execute("""SELECT fr.*,f.name flow_name,v.name waiting_variable_name,v.prompt waiting_prompt,v.sensitive waiting_sensitive
                          FROM flow_runs fr JOIN flows f ON f.id=fr.flow_id LEFT JOIN flow_variables v ON v.id=fr.waiting_variable_id WHERE fr.id=?""", (int(run_id),)).fetchone()
    if not row:
        return None
    run = dict(row); run["context"] = _loads(run.get("context_json"), {}); run["exported_context"] = _loads(run.get("exported_context_json"), {})
    variable_meta = {str(v["name"]): dict(v) for v in conn.execute("SELECT name,sensitive FROM flow_variables WHERE flow_id=?", (int(run["flow_id"]),)).fetchall()}
    run["context_display"] = {}
    for key, value in run["context"].items():
        if str(key).startswith("__"):
            continue
        meta = variable_meta.get(str(key), {})
        run["context_display"][str(key)] = _mask(str(value)) if int(meta.get("sensitive") or 0) else str(value)
    run["exported_context_display"] = {}
    for key, value in run["exported_context"].items():
        meta = variable_meta.get(str(key), {})
        run["exported_context_display"][str(key)] = _mask(str(value)) if int(meta.get("sensitive") or 0) else str(value)
    steps = [dict(r) for r in conn.execute("""SELECT rs.*,fs.label,o.method,r.path FROM flow_run_steps rs JOIN flow_steps fs ON fs.id=rs.flow_step_id
                                              JOIN http_exchanges e ON e.id=fs.exchange_id JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id
                                              WHERE rs.run_id=? ORDER BY rs.position,rs.id""", (int(run_id),)).fetchall()]
    for s in steps:
        s["used_context"] = _loads(s.get("used_context_json"), {}); s["produced_context"] = _loads(s.get("produced_context_json"), {})
    overrides = [dict(r) for r in conn.execute("""SELECT o.*,v.name variable_name,i.name identity_name,bot.name object_type,bo.identifier_preview object_preview,fs.position step_position
                                                  FROM flow_run_overrides o JOIN flow_variables v ON v.id=o.variable_id JOIN flow_steps fs ON fs.id=o.flow_step_id
                                                  LEFT JOIN identities i ON i.id=o.identity_id LEFT JOIN business_objects bo ON bo.id=o.object_id LEFT JOIN business_object_types bot ON bot.id=bo.object_type_id
                                                  WHERE o.run_id=? ORDER BY fs.position,o.id""", (int(run_id),)).fetchall()]
    children = [dict(r) for r in conn.execute("SELECT fr.id,fr.flow_id,fr.status,f.name flow_name FROM flow_runs fr JOIN flows f ON f.id=fr.flow_id WHERE fr.parent_run_id=? ORDER BY fr.id", (int(run_id),)).fetchall()]
    return {"run": run, "steps": steps, "overrides": overrides, "children": children}


def get_run_by_paths(paths: dict[str, Any], run_id: int) -> dict[str, Any]:
    import negro_core as core
    with core.db_connect(paths) as conn:
        return get_run(conn, int(run_id)) or {"run": {"id": int(run_id), "status": "missing"}, "steps": [], "overrides": [], "children": []}
