from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any

import negro_parameters as parameter_tools


STATE_HINTS = (
    "status", "state", "phase", "stage", "step", "paymentstatus", "payment_status",
    "orderstatus", "order_status", "shipmentstatus", "shipment_status", "deliverystatus", "delivery_status",
)
BUSINESS_VALUE_HINTS = (
    "id", "owner", "user", "account", "tenant", "seller", "buyer", "customer", "order", "invoice",
    "payment", "shipment", "price", "amount", "total", "discount", "coupon", "quantity", "status", "state",
)
BACKGROUND_TOKENS = (
    "notification", "notifications", "feature-flag", "feature_flag", "analytics", "telemetry", "tracking",
    "heartbeat", "metrics", "events", "beacon", "poll", "presence",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", errors="ignore")).hexdigest()


def init_schema(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            identity_id INTEGER,
            context_id INTEGER,
            capture_status TEXT NOT NULL DEFAULT 'stopped',
            capture_source TEXT,
            capture_start_exchange_id INTEGER,
            capture_started_after_exchange_id INTEGER,
            capture_end_exchange_id INTEGER,
            capture_started_at TEXT,
            capture_stopped_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE SET NULL,
            FOREIGN KEY(context_id) REFERENCES identity_contexts(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS flow_steps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER NOT NULL,
            position INTEGER NOT NULL,
            exchange_id INTEGER NOT NULL,
            label TEXT,
            state_label TEXT,
            notes TEXT,
            included INTEGER NOT NULL DEFAULT 1,
            candidate INTEGER NOT NULL DEFAULT 0,
            noise_suggested INTEGER NOT NULL DEFAULT 0,
            noise_reason TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(flow_id) REFERENCES flows(id) ON DELETE CASCADE,
            FOREIGN KEY(exchange_id) REFERENCES http_exchanges(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_flow_steps_flow ON flow_steps(flow_id, position);
        CREATE INDEX IF NOT EXISTS idx_flow_steps_exchange ON flow_steps(exchange_id);

        CREATE TABLE IF NOT EXISTS business_state_tracks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            object_type TEXT NOT NULL DEFAULT '',
            object_identifier_name TEXT NOT NULL,
            state_field TEXT NOT NULL,
            source_observation_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(object_type, object_identifier_name, state_field),
            FOREIGN KEY(source_observation_id) REFERENCES parameter_observations(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS business_state_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            track_id INTEGER NOT NULL,
            exchange_id INTEGER NOT NULL,
            object_observation_id INTEGER,
            state_observation_id INTEGER,
            object_identifier_value_hash TEXT NOT NULL,
            object_identifier_value_preview TEXT,
            object_identifier_value_raw TEXT,
            state_value_hash TEXT NOT NULL,
            state_value_preview TEXT,
            state_value_raw TEXT,
            source_location TEXT,
            identity_id INTEGER,
            context_id INTEGER,
            observed_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(track_id, exchange_id, object_identifier_value_hash, state_value_hash, source_location),
            FOREIGN KEY(track_id) REFERENCES business_state_tracks(id) ON DELETE CASCADE,
            FOREIGN KEY(exchange_id) REFERENCES http_exchanges(id) ON DELETE CASCADE,
            FOREIGN KEY(object_observation_id) REFERENCES parameter_observations(id) ON DELETE SET NULL,
            FOREIGN KEY(state_observation_id) REFERENCES parameter_observations(id) ON DELETE SET NULL,
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE SET NULL,
            FOREIGN KEY(context_id) REFERENCES identity_contexts(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_business_state_obs_track ON business_state_observations(track_id, observed_at, id);
        CREATE INDEX IF NOT EXISTS idx_business_state_obs_exchange ON business_state_observations(exchange_id, track_id);
        CREATE INDEX IF NOT EXISTS idx_business_state_obs_object ON business_state_observations(track_id, object_identifier_value_hash, observed_at);
        """
    )
    flow_cols = {row["name"] for row in conn.execute("PRAGMA table_info(flows)")}
    migrations = {
        "capture_status": "TEXT NOT NULL DEFAULT 'stopped'",
        "capture_source": "TEXT",
        "capture_start_exchange_id": "INTEGER",
        "capture_started_after_exchange_id": "INTEGER",
        "capture_end_exchange_id": "INTEGER",
        "capture_started_at": "TEXT",
        "capture_stopped_at": "TEXT",
    }
    for name, ddl in migrations.items():
        if name not in flow_cols:
            conn.execute(f"ALTER TABLE flows ADD COLUMN {name} {ddl}")
    step_cols = {row["name"] for row in conn.execute("PRAGMA table_info(flow_steps)")}
    step_migrations = {
        "included": "INTEGER NOT NULL DEFAULT 1",
        "candidate": "INTEGER NOT NULL DEFAULT 0",
        "noise_suggested": "INTEGER NOT NULL DEFAULT 0",
        "noise_reason": "TEXT",
    }
    for name, ddl in step_migrations.items():
        if name not in step_cols:
            conn.execute(f"ALTER TABLE flow_steps ADD COLUMN {name} {ddl}")

    # v0.26: a Flow is an ordered observation sequence, not a set. The same
    # persisted exchange can legitimately occur more than once during one
    # capture (http_exchanges is content-deduplicated), so remove the legacy
    # UNIQUE(flow_id, exchange_id) constraint while preserving existing rows.
    table_sql_row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='flow_steps'"
    ).fetchone()
    table_sql = str(table_sql_row["sql"] or "") if table_sql_row else ""
    compact_sql = re.sub(r"\s+", "", table_sql).lower()
    if "unique(flow_id,exchange_id)" in compact_sql:
        conn.executescript(
            """
            CREATE TABLE flow_steps_v026 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id INTEGER NOT NULL,
                position INTEGER NOT NULL,
                exchange_id INTEGER NOT NULL,
                label TEXT,
                state_label TEXT,
                notes TEXT,
                included INTEGER NOT NULL DEFAULT 1,
                candidate INTEGER NOT NULL DEFAULT 0,
                noise_suggested INTEGER NOT NULL DEFAULT 0,
                noise_reason TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(flow_id) REFERENCES flows(id) ON DELETE CASCADE,
                FOREIGN KEY(exchange_id) REFERENCES http_exchanges(id) ON DELETE CASCADE
            );
            INSERT INTO flow_steps_v026(
                id,flow_id,position,exchange_id,label,state_label,notes,included,candidate,noise_suggested,noise_reason,created_at,updated_at
            )
            SELECT id,flow_id,position,exchange_id,label,state_label,notes,included,candidate,noise_suggested,noise_reason,created_at,updated_at
            FROM flow_steps;
            DROP TABLE flow_steps;
            ALTER TABLE flow_steps_v026 RENAME TO flow_steps;
            CREATE INDEX IF NOT EXISTS idx_flow_steps_flow ON flow_steps(flow_id, position);
            CREATE INDEX IF NOT EXISTS idx_flow_steps_exchange ON flow_steps(exchange_id);
            """
        )


def _normalize_path(path: str) -> str:
    parts = []
    for seg in str(path or "").split("/"):
        if not seg:
            continue
        if re.fullmatch(r"\d{2,}", seg) or re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", seg) or (len(seg) >= 8 and any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg)):
            parts.append("{id}")
        else:
            parts.append(seg)
    return "/" + "/".join(parts)


def _signature(step: dict[str, Any]) -> str:
    return f"{str(step.get('method') or '').upper()} {_normalize_path(str(step.get('path') or ''))}"


def create_flow(conn, name: str, *, description: str = "", identity_id: int | None = None, context_id: int | None = None) -> int:
    init_schema(conn)
    name = str(name or "").strip()[:160]
    if not name:
        raise ValueError("Nombre del flow requerido")
    now = now_iso()
    cur = conn.execute(
        "INSERT INTO flows(name,description,identity_id,context_id,created_at,updated_at) VALUES(?,?,?,?,?,?)",
        (name, str(description or "")[:4000], identity_id, context_id, now, now),
    )
    return int(cur.lastrowid)


def start_capture(conn, name: str, *, description: str = "", identity_id: int | None = None, context_id: int | None = None,
                  start_exchange_id: int | None = None, source: str = "web") -> int:
    """Open a capture window. Traffic is only a candidate until the researcher edits it."""
    init_schema(conn)
    flow_id = create_flow(conn, name, description=description, identity_id=identity_id, context_id=context_id)
    current_max = int(conn.execute("SELECT COALESCE(MAX(id),0) n FROM http_exchanges").fetchone()["n"] or 0)
    if start_exchange_id is not None:
        if not conn.execute("SELECT id FROM http_exchanges WHERE id=?", (int(start_exchange_id),)).fetchone():
            raise ValueError("Exchange inicial no encontrado")
        started_after = max(0, int(start_exchange_id) - 1)
    else:
        started_after = current_max
    now = now_iso()
    conn.execute(
        """UPDATE flows SET capture_status='capturing',capture_source=?,capture_start_exchange_id=?,
               capture_started_after_exchange_id=?,capture_started_at=?,capture_stopped_at=NULL,updated_at=? WHERE id=?""",
        (str(source or "web")[:40], int(start_exchange_id) if start_exchange_id else None, started_after, now, now, flow_id),
    )
    if start_exchange_id:
        add_step(conn, flow_id, int(start_exchange_id), candidate=True, allow_duplicate=True)
    return flow_id


def active_captures(conn) -> list[dict[str, Any]]:
    init_schema(conn)
    return [dict(r) for r in conn.execute(
        "SELECT * FROM flows WHERE capture_status='capturing' ORDER BY capture_started_at DESC,id DESC"
    ).fetchall()]


def capture_observed_exchange(conn, exchange_id: int) -> dict[str, int]:
    """Append one *observed occurrence* to every active capture window.

    This is called for every live Burp ingest, so the no-capture path is kept
    intentionally cheap: no schema migration/DDL unless a Flow table already
    exists and actually has an active capture.
    """
    if not conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='flows' LIMIT 1"
    ).fetchone():
        return {"flows": 0, "added": 0}
    try:
        flows = conn.execute(
            "SELECT id FROM flows WHERE capture_status='capturing' ORDER BY id"
        ).fetchall()
    except Exception:
        # A pre-v0.26 Flow schema may exist but not yet have capture_status. No
        # capture can be active in that schema, so defer migration until Flows UI.
        return {"flows": 0, "added": 0}
    if not flows:
        return {"flows": 0, "added": 0}
    init_schema(conn)
    added = 0
    for row in flows:
        add_step(conn, int(row["id"]), int(exchange_id), candidate=True, allow_duplicate=True, _schema_ready=True)
        added += 1
    return {"flows": len(flows), "added": added}


def stop_capture(conn, flow_id: int, *, end_exchange_id: int | None = None) -> dict[str, int]:
    init_schema(conn)
    flow = conn.execute("SELECT * FROM flows WHERE id=?", (int(flow_id),)).fetchone()
    if not flow:
        raise ValueError("Flow no encontrado")
    if str(flow["capture_status"] or "") != "capturing":
        raise ValueError("El flow no está capturando")

    # If Burp ends a capture from a selected request, ensure that exact request
    # is represented. Live traffic has normally already appended it; manual
    # context-sync traffic deliberately does not, so this is idempotent.
    if end_exchange_id is not None:
        if not conn.execute("SELECT id FROM http_exchanges WHERE id=?", (int(end_exchange_id),)).fetchone():
            raise ValueError("Exchange final no encontrado")
        add_step(conn, int(flow_id), int(end_exchange_id), candidate=True, allow_duplicate=False)

    end_id = int(end_exchange_id) if end_exchange_id is not None else None
    now = now_iso()
    conn.execute(
        "UPDATE flows SET capture_status='stopped',capture_end_exchange_id=?,capture_stopped_at=?,updated_at=? WHERE id=?",
        (end_id, now, now, int(flow_id)),
    )
    refresh_noise_suggestions(conn, int(flow_id))
    step_count = int(conn.execute("SELECT COUNT(*) n FROM flow_steps WHERE flow_id=?", (int(flow_id),)).fetchone()["n"] or 0)
    return {"added": 0, "skipped": 0, "steps": step_count}


def list_flows(conn) -> list[dict[str, Any]]:
    init_schema(conn)
    rows = conn.execute(
        """SELECT f.*,i.name identity_name,c.label context_label,
                  COUNT(fs.id) step_count,
                  SUM(CASE WHEN fs.included=1 THEN 1 ELSE 0 END) included_count,
                  SUM(CASE WHEN fs.included=0 THEN 1 ELSE 0 END) ignored_count,
                  MIN(fs.exchange_id) first_exchange,MAX(fs.exchange_id) last_exchange
           FROM flows f
           LEFT JOIN identities i ON i.id=f.identity_id
           LEFT JOIN identity_contexts c ON c.id=f.context_id
           LEFT JOIN flow_steps fs ON fs.flow_id=f.id
           GROUP BY f.id ORDER BY CASE WHEN f.capture_status='capturing' THEN 0 ELSE 1 END,f.updated_at DESC,f.id DESC"""
    ).fetchall()
    return [dict(r) for r in rows]


def add_step(conn, flow_id: int, exchange_id: int, *, label: str = "", state_label: str = "", notes: str = "",
             included: bool = True, candidate: bool = False, allow_duplicate: bool = False, _schema_ready: bool = False) -> int:
    if not _schema_ready:
        init_schema(conn)
    if not conn.execute("SELECT id FROM flows WHERE id=?", (int(flow_id),)).fetchone():
        raise ValueError("Flow no encontrado")
    if not conn.execute("SELECT id FROM http_exchanges WHERE id=?", (int(exchange_id),)).fetchone():
        raise ValueError("Exchange no encontrado")
    if not allow_duplicate:
        existing = conn.execute(
            "SELECT id FROM flow_steps WHERE flow_id=? AND exchange_id=? ORDER BY position,id LIMIT 1",
            (int(flow_id), int(exchange_id)),
        ).fetchone()
        if existing:
            if included:
                conn.execute("UPDATE flow_steps SET included=1,updated_at=? WHERE id=?", (now_iso(), int(existing["id"])))
            return int(existing["id"])
    pos = int(conn.execute("SELECT COALESCE(MAX(position),0)+1 n FROM flow_steps WHERE flow_id=?", (int(flow_id),)).fetchone()["n"])
    now = now_iso()
    cur = conn.execute(
        """INSERT INTO flow_steps(flow_id,position,exchange_id,label,state_label,notes,included,candidate,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (int(flow_id), pos, int(exchange_id), str(label or "")[:200], str(state_label or "")[:160], str(notes or "")[:3000], 1 if included else 0, 1 if candidate else 0, now, now),
    )
    conn.execute("UPDATE flows SET updated_at=? WHERE id=?", (now, int(flow_id)))
    return int(cur.lastrowid)


def add_range(conn, flow_id: int, start_exchange: int, end_exchange: int, *, exclude_options: bool = True, candidate: bool = False) -> dict[str, int]:
    init_schema(conn)
    lo, hi = sorted((int(start_exchange), int(end_exchange)))
    sql = """SELECT e.id,o.method FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
             WHERE e.id BETWEEN ? AND ? ORDER BY e.id"""
    rows = conn.execute(sql, (lo, hi)).fetchall()
    added = 0
    skipped = 0
    for row in rows:
        if exclude_options and str(row["method"]).upper() == "OPTIONS":
            skipped += 1
            continue
        before = conn.execute("SELECT id FROM flow_steps WHERE flow_id=? AND exchange_id=?", (int(flow_id), int(row["id"]))).fetchone()
        add_step(conn, int(flow_id), int(row["id"]), candidate=candidate)
        if before:
            skipped += 1
        else:
            added += 1
    if candidate:
        refresh_noise_suggestions(conn, int(flow_id))
    return {"added": added, "skipped": skipped}


def remove_step(conn, flow_id: int, step_id: int) -> None:
    init_schema(conn)
    conn.execute("DELETE FROM flow_steps WHERE id=? AND flow_id=?", (int(step_id), int(flow_id)))
    rows = conn.execute("SELECT id FROM flow_steps WHERE flow_id=? ORDER BY position,id", (int(flow_id),)).fetchall()
    for idx, row in enumerate(rows, 1):
        conn.execute("UPDATE flow_steps SET position=? WHERE id=?", (idx, int(row["id"])))
    conn.execute("UPDATE flows SET updated_at=? WHERE id=?", (now_iso(), int(flow_id)))


def update_step(conn, flow_id: int, step_id: int, *, label: str = "", state_label: str = "", notes: str = "") -> None:
    init_schema(conn)
    now = now_iso()
    conn.execute(
        "UPDATE flow_steps SET label=?,state_label=?,notes=?,updated_at=? WHERE id=? AND flow_id=?",
        (str(label or "")[:200], str(state_label or "")[:160], str(notes or "")[:3000], now, int(step_id), int(flow_id)),
    )
    conn.execute("UPDATE flows SET updated_at=? WHERE id=?", (now, int(flow_id)))


def set_step_included(conn, flow_id: int, step_id: int, included: bool) -> None:
    init_schema(conn)
    now = now_iso()
    cur = conn.execute("UPDATE flow_steps SET included=?,updated_at=? WHERE id=? AND flow_id=?", (1 if included else 0, now, int(step_id), int(flow_id)))
    if cur.rowcount != 1:
        raise ValueError("Paso no encontrado")
    conn.execute("UPDATE flows SET updated_at=? WHERE id=?", (now, int(flow_id)))


def set_boundary(conn, flow_id: int, step_id: int, boundary: str) -> None:
    init_schema(conn)
    step = conn.execute("SELECT position FROM flow_steps WHERE id=? AND flow_id=?", (int(step_id), int(flow_id))).fetchone()
    if not step:
        raise ValueError("Paso no encontrado")
    pos = int(step["position"])
    now = now_iso()
    if boundary == "start":
        conn.execute("UPDATE flow_steps SET included=CASE WHEN position<? THEN 0 ELSE included END,updated_at=? WHERE flow_id=?", (pos, now, int(flow_id)))
        conn.execute("UPDATE flow_steps SET included=1 WHERE flow_id=? AND id=?", (int(flow_id), int(step_id)))
    elif boundary == "end":
        conn.execute("UPDATE flow_steps SET included=CASE WHEN position>? THEN 0 ELSE included END,updated_at=? WHERE flow_id=?", (pos, now, int(flow_id)))
        conn.execute("UPDATE flow_steps SET included=1 WHERE flow_id=? AND id=?", (int(flow_id), int(step_id)))
    else:
        raise ValueError("Boundary inválido")
    conn.execute("UPDATE flows SET updated_at=? WHERE id=?", (now, int(flow_id)))


def refresh_noise_suggestions(conn, flow_id: int) -> None:
    """Suggest likely background traffic. Never excludes a step."""
    init_schema(conn)
    rows = [dict(r) for r in conn.execute(
        """SELECT fs.id,fs.exchange_id,o.method,r.path FROM flow_steps fs
           JOIN http_exchanges e ON e.id=fs.exchange_id JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id WHERE fs.flow_id=? ORDER BY fs.position""",
        (int(flow_id),),
    ).fetchall()]
    sig_counts = Counter(f"{str(r['method']).upper()} {_normalize_path(str(r['path']))}" for r in rows)
    for r in rows:
        method = str(r["method"] or "").upper()
        path = str(r["path"] or "").lower()
        sig = f"{method} {_normalize_path(str(r['path']))}"
        reason = ""
        if method == "OPTIONS":
            reason = "preflight OPTIONS"
        elif any(tok in path for tok in BACKGROUND_TOKENS):
            reason = "ruta con patrón típico de tráfico de fondo"
        elif method == "GET" and sig_counts[sig] >= 4:
            reason = f"GET repetido {sig_counts[sig]} veces en la ventana"
        conn.execute(
            "UPDATE flow_steps SET noise_suggested=?,noise_reason=? WHERE id=?",
            (1 if reason else 0, reason or None, int(r["id"])),
        )


def _is_identifier_name(name: str) -> bool:
    n = str(name or "").lower().replace("-", "_")
    return n == "id" or n.endswith("id") or n.endswith("_id") or any(tok in n for tok in ("order", "payment", "shipment", "invoice", "account", "user", "customer", "seller", "cart")) and "status" not in n and "state" not in n


def _business_observations(conn, exchange_id: int, *, limit: int = 30) -> list[dict[str, Any]]:
    rows = [dict(r) for r in conn.execute(
        """SELECT p.id,p.name,p.normalized_name,p.location,p.value_hash,COALESCE(p.value_raw,p.value_preview) value
           FROM parameter_observations p WHERE p.exchange_id=? ORDER BY p.id""", (int(exchange_id),)
    ).fetchall()]
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        name = str(row.get("normalized_name") or "").lower()
        if not any(h in name for h in BUSINESS_VALUE_HINTS):
            continue
        value = str(row.get("value") or "")
        key = (name, value, str(row.get("location") or ""))
        if key in seen:
            continue
        seen.add(key)
        row["is_state"] = any(h == name or h in name for h in STATE_HINTS)
        row["is_identifier"] = _is_identifier_name(name) and not row["is_state"]
        out.append(row)
        if len(out) >= limit:
            break
    return out


def _step_row(conn, step_row) -> dict[str, Any]:
    row = conn.execute(
        """SELECT fs.*,e.status_code,e.first_seen_at,o.method,o.resource_id,r.path,h.hostname,
                  ei.identity_id,i.name identity_name,ic.label context_label
           FROM flow_steps fs
           JOIN http_exchanges e ON e.id=fs.exchange_id
           JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id
           JOIN hosts h ON h.id=r.host_id
           LEFT JOIN exchange_identities ei ON ei.exchange_id=e.id
           LEFT JOIN identities i ON i.id=ei.identity_id
           LEFT JOIN identity_contexts ic ON ic.id=ei.context_id
           WHERE fs.id=?""", (int(step_row["id"]),)
    ).fetchone()
    item = dict(row)
    item["signature"] = _signature(item)
    item["business_values"] = _business_observations(conn, int(item["exchange_id"]))
    item["state_values"] = [x for x in item["business_values"] if x.get("is_state")]
    item["identifier_values"] = [x for x in item["business_values"] if x.get("is_identifier")]
    return item


def _location_parent(location: str) -> str:
    raw = str(location or "")
    if ":" not in raw:
        return ""
    prefix, path = raw.split(":", 1)
    # JSON paths in Negro commonly use dotted/bracket notation. Keeping only the
    # parent lets arrays with multiple business objects pair id/status sensibly.
    path = re.sub(r"\[[^\]]+\]$", "", path)
    if "." in path:
        path = path.rsplit(".", 1)[0]
    return f"{prefix}:{path}"


def _pair_state_values(objects: list[dict[str, Any]], states: list[dict[str, Any]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    if not objects or not states:
        return []
    if len(objects) == 1 and len(states) == 1:
        return [(objects[0], states[0])]
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    used_states: set[int] = set()
    for obj in objects:
        parent = _location_parent(str(obj.get("location") or ""))
        candidates = [(idx, st) for idx, st in enumerate(states) if idx not in used_states and _location_parent(str(st.get("location") or "")) == parent]
        if candidates:
            idx, st = candidates[0]
            used_states.add(idx)
            pairs.append((obj, st))
    if pairs:
        return pairs
    # Ambiguous multi-value payloads are intentionally not cross-product paired.
    return []


def _infer_object_type(identifier_name: str) -> str:
    n = str(identifier_name or "").lower().replace("_", "")
    for suffix in ("identifier", "uuid", "id"):
        if n.endswith(suffix):
            n = n[:-len(suffix)]
            break
    return n[:1].upper() + n[1:] if n else "Object"


def create_state_track(conn, state_observation_id: int, object_observation_id: int, *, object_type: str = "") -> int:
    """Teach Negro a state schema, e.g. Order: orderId + status.

    The track is a definition, not one object instance. Once defined, Negro observes
    every captured instance that exposes the same identifier field and state field.
    """
    init_schema(conn)
    state = conn.execute("SELECT * FROM parameter_observations WHERE id=?", (int(state_observation_id),)).fetchone()
    obj = conn.execute("SELECT * FROM parameter_observations WHERE id=?", (int(object_observation_id),)).fetchone()
    if not state or not obj:
        raise ValueError("Observación no encontrada")
    if int(state["exchange_id"]) != int(obj["exchange_id"]):
        raise ValueError("El identificador y el estado deben provenir del mismo exchange para crear el track")
    state_field = str(state["normalized_name"] or "").lower()
    identifier_name = str(obj["normalized_name"] or "").lower()
    if not any(h == state_field or h in state_field for h in STATE_HINTS):
        raise ValueError("El campo seleccionado no parece un estado")
    object_type = str(object_type or _infer_object_type(identifier_name)).strip()[:80]
    now = now_iso()
    conn.execute(
        """INSERT INTO business_state_tracks(object_type,object_identifier_name,state_field,source_observation_id,created_at,updated_at)
           VALUES(?,?,?,?,?,?)
           ON CONFLICT(object_type,object_identifier_name,state_field)
           DO UPDATE SET source_observation_id=COALESCE(business_state_tracks.source_observation_id,excluded.source_observation_id),updated_at=excluded.updated_at""",
        (object_type, identifier_name, state_field, int(state_observation_id), now, now),
    )
    row = conn.execute(
        "SELECT id FROM business_state_tracks WHERE object_type=? AND object_identifier_name=? AND state_field=?",
        (object_type, identifier_name, state_field),
    ).fetchone()
    track_id = int(row["id"])
    refresh_state_track(conn, track_id)
    # v0.27: a taught state schema also teaches the underlying Business Object
    # identifier. This reuses the same object type rather than creating a second
    # entity model for Flow states.
    try:
        import negro_objects as object_tools
        object_tools.ensure_identifier(conn, object_type, identifier_name, source_observation_id=int(object_observation_id))
    except Exception:
        # State tracking must remain usable even if an older workspace has a
        # partially migrated Business Object schema.
        pass
    return track_id


def _observe_track_exchange(conn, track: dict[str, Any], exchange_id: int) -> int:
    objects = [dict(r) for r in conn.execute(
        """SELECT * FROM parameter_observations WHERE exchange_id=? AND normalized_name=? ORDER BY id""",
        (int(exchange_id), str(track["object_identifier_name"])),
    ).fetchall()]
    states = [dict(r) for r in conn.execute(
        """SELECT * FROM parameter_observations WHERE exchange_id=? AND normalized_name=? ORDER BY id""",
        (int(exchange_id), str(track["state_field"])),
    ).fetchall()]
    pairs = _pair_state_values(objects, states)
    if not pairs:
        return 0
    actor = conn.execute("SELECT identity_id,context_id FROM exchange_identities WHERE exchange_id=?", (int(exchange_id),)).fetchone()
    ex = conn.execute("SELECT first_seen_at FROM http_exchanges WHERE id=?", (int(exchange_id),)).fetchone()
    observed_at = str(ex["first_seen_at"] if ex else now_iso())
    added = 0
    for obj, state in pairs:
        obj_raw = str(obj.get("value_raw") or obj.get("value_preview") or "")
        state_raw = str(state.get("value_raw") or state.get("value_preview") or "")
        if not obj_raw or not state_raw:
            continue
        cur = conn.execute(
            """INSERT OR IGNORE INTO business_state_observations(
                   track_id,exchange_id,object_observation_id,state_observation_id,
                   object_identifier_value_hash,object_identifier_value_preview,object_identifier_value_raw,
                   state_value_hash,state_value_preview,state_value_raw,source_location,identity_id,context_id,observed_at,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (int(track["id"]), int(exchange_id), int(obj["id"]), int(state["id"]), str(obj["value_hash"] or _sha(obj_raw)), str(obj.get("value_preview") or obj_raw)[:160], obj_raw,
             str(state["value_hash"] or _sha(state_raw)), str(state.get("value_preview") or state_raw)[:160], state_raw, str(state.get("location") or "")[:300],
             int(actor["identity_id"]) if actor and actor["identity_id"] else None, int(actor["context_id"]) if actor and actor["context_id"] else None, observed_at, now_iso()),
        )
        added += max(0, int(cur.rowcount or 0))
    return added


def refresh_state_track(conn, track_id: int) -> dict[str, int]:
    init_schema(conn)
    row = conn.execute("SELECT * FROM business_state_tracks WHERE id=?", (int(track_id),)).fetchone()
    if not row:
        raise ValueError("Track de estado no encontrado")
    track = dict(row)
    exchange_ids = [int(r["exchange_id"]) for r in conn.execute(
        """SELECT DISTINCT a.exchange_id FROM parameter_observations a
           JOIN parameter_observations b ON b.exchange_id=a.exchange_id
           WHERE a.normalized_name=? AND b.normalized_name=? ORDER BY a.exchange_id""",
        (str(track["object_identifier_name"]), str(track["state_field"])),
    ).fetchall()]
    added = 0
    for exchange_id in exchange_ids:
        added += _observe_track_exchange(conn, track, exchange_id)
    return {"exchanges": len(exchange_ids), "added": added}


def refresh_state_tracks_for_exchange(conn, exchange_id: int) -> int:
    init_schema(conn)
    tracks = [dict(r) for r in conn.execute("SELECT * FROM business_state_tracks ORDER BY id").fetchall()]
    return sum(_observe_track_exchange(conn, t, int(exchange_id)) for t in tracks)


def list_state_tracks(conn) -> list[dict[str, Any]]:
    init_schema(conn)
    return [dict(r) for r in conn.execute(
        """SELECT t.*,(SELECT COUNT(*) FROM business_state_observations o WHERE o.track_id=t.id) observation_count,
                  (SELECT COUNT(DISTINCT object_identifier_value_hash) FROM business_state_observations o WHERE o.track_id=t.id) object_count
           FROM business_state_tracks t ORDER BY lower(t.object_type),lower(t.object_identifier_name),lower(t.state_field)"""
    ).fetchall()]


def _state_timelines_for_flow(conn, flow_id: int) -> list[dict[str, Any]]:
    # Learn observations for each currently captured exchange using existing definitions.
    exchange_ids = [int(r["exchange_id"]) for r in conn.execute("SELECT exchange_id FROM flow_steps WHERE flow_id=? ORDER BY position", (int(flow_id),)).fetchall()]
    for exid in exchange_ids:
        refresh_state_tracks_for_exchange(conn, exid)
    rows = [dict(r) for r in conn.execute(
        """SELECT o.*,t.object_type,t.object_identifier_name,t.state_field,fs.position,fs.included,
                  i.name identity_name,c.label context_label
           ,ro.resource_id
           FROM business_state_observations o
           JOIN business_state_tracks t ON t.id=o.track_id
           JOIN flow_steps fs ON fs.exchange_id=o.exchange_id AND fs.flow_id=?
           JOIN http_exchanges he ON he.id=o.exchange_id
           JOIN resource_operations ro ON ro.id=he.operation_id
           LEFT JOIN identities i ON i.id=o.identity_id
           LEFT JOIN identity_contexts c ON c.id=o.context_id
           WHERE fs.included=1
           ORDER BY fs.position,o.id""", (int(flow_id),)
    ).fetchall()]
    grouped: dict[tuple[int, str], dict[str, Any]] = {}
    for row in rows:
        key = (int(row["track_id"]), str(row["object_identifier_value_hash"]))
        item = grouped.setdefault(key, {
            "track_id": int(row["track_id"]),
            "object_type": str(row["object_type"] or "Object"),
            "identifier_name": str(row["object_identifier_name"]),
            "identifier_value": str(row["object_identifier_value_raw"] or row["object_identifier_value_preview"] or ""),
            "state_field": str(row["state_field"]),
            "semantic_key": f"{row['object_type']}:{row['object_identifier_name']}:{row['state_field']}",
            "observations": [],
        })
        obs = {
            "id": int(row["id"]), "exchange_id": int(row["exchange_id"]), "resource_id": int(row["resource_id"]), "position": int(row["position"]),
            "state": str(row["state_value_raw"] or row["state_value_preview"] or ""), "source_location": str(row["source_location"] or ""),
            "identity_id": int(row["identity_id"]) if row["identity_id"] else None, "identity_name": row["identity_name"], "context_label": row["context_label"],
            "observed_at": str(row["observed_at"]),
        }
        # Avoid duplicate adjacent representations of the same state for one object.
        if not item["observations"] or item["observations"][-1]["state"] != obs["state"]:
            item["observations"].append(obs)
    out = list(grouped.values())
    for item in out:
        item["sequence"] = [o["state"] for o in item["observations"]]
    out.sort(key=lambda x: (x["object_type"].lower(), x["identifier_value"], x["state_field"]))
    return out


def _legacy_adjacent_transitions(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    transitions: list[dict[str, Any]] = []
    for prev, cur in zip(steps, steps[1:]):
        prev_states = {str(x["normalized_name"]): x for x in prev["state_values"]}
        cur_states = {str(x["normalized_name"]): x for x in cur["state_values"]}
        for name in sorted(set(prev_states) & set(cur_states)):
            av = str(prev_states[name].get("value") or "")
            bv = str(cur_states[name].get("value") or "")
            if av != bv:
                transitions.append({
                    "name": name, "from": av, "to": bv,
                    "from_step": prev["position"], "to_step": cur["position"],
                    "from_exchange": prev["exchange_id"], "to_exchange": cur["exchange_id"],
                })
    return transitions


def _repeated_sequence_anomalies(conn, flow_id: int, timelines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag only when another sequence has already been observed at least twice."""
    anomalies: list[dict[str, Any]] = []
    for tl in timelines:
        if len(tl["sequence"]) < 2:
            continue
        semantic = tl["semantic_key"]
        sequences: Counter[tuple[str, ...]] = Counter()
        for f in conn.execute("SELECT id FROM flows WHERE id<>? ORDER BY id", (int(flow_id),)).fetchall():
            other = _state_timelines_for_flow(conn, int(f["id"]))
            for otl in other:
                if otl["semantic_key"] == semantic and len(otl["sequence"]) >= 2:
                    sequences[tuple(otl["sequence"])] += 1
        if not sequences:
            continue
        baseline, count = sequences.most_common(1)[0]
        current = tuple(tl["sequence"])
        if count >= 2 and current != baseline:
            anomalies.append({
                "semantic_key": semantic, "object_type": tl["object_type"], "identifier_value": tl["identifier_value"],
                "state_field": tl["state_field"], "previous_sequence": list(baseline), "current_sequence": list(current), "previous_count": count,
            })
    return anomalies


def get_flow(conn, flow_id: int) -> dict[str, Any] | None:
    init_schema(conn)
    row = conn.execute(
        """SELECT f.*,i.name identity_name,c.label context_label FROM flows f
           LEFT JOIN identities i ON i.id=f.identity_id LEFT JOIN identity_contexts c ON c.id=f.context_id
           WHERE f.id=?""", (int(flow_id),)
    ).fetchone()
    if not row:
        return None
    steps = [_step_row(conn, s) for s in conn.execute("SELECT * FROM flow_steps WHERE flow_id=? ORDER BY position,id", (int(flow_id),)).fetchall()]
    included_steps = [s for s in steps if int(s.get("included", 1) or 0) == 1]
    transitions = _legacy_adjacent_transitions(included_steps)
    timelines = _state_timelines_for_flow(conn, int(flow_id))
    anomalies = _repeated_sequence_anomalies(conn, int(flow_id), timelines) if timelines else []
    business_objects = []
    try:
        import negro_objects as object_tools
        business_objects = object_tools.objects_for_flow(conn, int(flow_id))
    except Exception:
        business_objects = []
    return {"flow": dict(row), "steps": steps, "included_steps": included_steps, "transitions": transitions, "state_timelines": timelines, "state_anomalies": anomalies, "state_tracks": list_state_tracks(conn), "business_objects": business_objects}


def _align_steps(a_steps: list[dict[str, Any]], b_steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sig_a = [x["signature"] for x in a_steps]
    sig_b = [x["signature"] for x in b_steps]
    matcher = SequenceMatcher(a=sig_a, b=sig_b, autojunk=False)
    aligned: list[dict[str, Any]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for ai, bj in zip(range(i1, i2), range(j1, j2)):
                aligned.append({"kind": "same", "a": a_steps[ai], "b": b_steps[bj]})
        elif tag == "replace":
            span = max(i2 - i1, j2 - j1)
            for off in range(span):
                aa = a_steps[i1 + off] if i1 + off < i2 else None
                bb = b_steps[j1 + off] if j1 + off < j2 else None
                aligned.append({"kind": "changed", "a": aa, "b": bb})
        elif tag == "delete":
            for ai in range(i1, i2):
                aligned.append({"kind": "only_a", "a": a_steps[ai], "b": None})
        elif tag == "insert":
            for bj in range(j1, j2):
                aligned.append({"kind": "only_b", "a": None, "b": b_steps[bj]})
    return aligned


def _timeline_semantics(flow_data: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for tl in flow_data.get("state_timelines") or []:
        out[str(tl["semantic_key"])].append(tl)
    return out


def compare_flows(conn, flow_a: int, flow_b: int) -> dict[str, Any] | None:
    a = get_flow(conn, int(flow_a))
    b = get_flow(conn, int(flow_b))
    if not a or not b:
        return None
    a_steps = a.get("included_steps") or []
    b_steps = b.get("included_steps") or []
    aligned = _align_steps(a_steps, b_steps)
    for item in aligned:
        aa, bb = item.get("a"), item.get("b")
        if aa and bb:
            diff = parameter_tools.smart_diff(conn, int(aa["exchange_id"]), int(bb["exchange_id"]))
            if diff:
                item["correlations"] = (diff.get("strong_correlations") or [])[:5] + (diff.get("medium_correlations") or [])[:3]
                item["business_changes"] = [x for x in diff.get("changes", []) if x.get("business")][:8]
                item["other_change_count"] = int(diff.get("other_changes") or 0)
                item["identity_changed"] = (aa.get("identity_id") or None) != (bb.get("identity_id") or None)
                item["status_changed"] = aa.get("status_code") != bb.get("status_code")
    state_changes: list[dict[str, Any]] = []
    a_sem = _timeline_semantics(a)
    b_sem = _timeline_semantics(b)
    for key in sorted(set(a_sem) | set(b_sem)):
        a_items, b_items = a_sem.get(key, []), b_sem.get(key, [])
        count = max(len(a_items), len(b_items))
        for idx in range(count):
            aa = a_items[idx] if idx < len(a_items) else None
            bb = b_items[idx] if idx < len(b_items) else None
            a_seq = aa.get("sequence", []) if aa else []
            b_seq = bb.get("sequence", []) if bb else []
            if a_seq != b_seq:
                state_changes.append({
                    "semantic_key": key,
                    "object_type": (aa or bb or {}).get("object_type"),
                    "identifier_name": (aa or bb or {}).get("identifier_name"),
                    "state_field": (aa or bb or {}).get("state_field"),
                    "a": aa, "b": bb, "a_sequence": a_seq, "b_sequence": b_seq,
                })
    a_types = Counter(str(x.get("object_type") or "Object") for x in (a.get("business_objects") or []))
    b_types = Counter(str(x.get("object_type") or "Object") for x in (b.get("business_objects") or []))
    object_type_changes = []
    for name in sorted(set(a_types) | set(b_types), key=str.lower):
        if a_types.get(name, 0) != b_types.get(name, 0):
            object_type_changes.append({"object_type": name, "a_count": int(a_types.get(name, 0)), "b_count": int(b_types.get(name, 0))})
    return {"a": a, "b": b, "aligned": aligned, "state_changes": state_changes, "object_type_changes": object_type_changes}
