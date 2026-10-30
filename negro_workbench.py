from __future__ import annotations

"""Global HTTP Workbench helpers.

This module intentionally keeps the existing per-project databases as the source
of truth.  The Workbench only aggregates them for reading.  Burp traffic that
cannot be routed to a configured project is persisted in a small local inbox
workspace instead of being discarded.
"""

import json
import os
from pathlib import Path
from typing import Any

import negro_core as core
import negro_http_inspector as http_inspector

INBOX_KEY = "__inbox__"
INBOX_DOMAIN = "traffic.local"
INBOX_NAME = "Sin proyecto"


def inbox_workspace() -> Path:
    configured = str(os.environ.get("NEGRO_TRAFFIC_WORKSPACE") or "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".local" / "share" / "negro" / "traffic-inbox"


def _init_workbench_schema(conn) -> None:
    """Persistent, non-destructive UI memory for the global HTTP Workbench."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS workbench_checkpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL DEFAULT '',
            cutoff_at TEXT NOT NULL,
            target_hint TEXT NOT NULL DEFAULT 'all',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_workbench_checkpoints_created
            ON workbench_checkpoints(created_at DESC, id DESC);
        CREATE TABLE IF NOT EXISTS workbench_capture_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_key TEXT NOT NULL,
            exchange_id INTEGER NOT NULL,
            captured_at TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            tool TEXT NOT NULL DEFAULT '',
            method TEXT NOT NULL DEFAULT '',
            url TEXT NOT NULL DEFAULT '',
            hostname TEXT NOT NULL DEFAULT '',
            path TEXT NOT NULL DEFAULT '/',
            status_code INTEGER,
            request_size INTEGER NOT NULL DEFAULT 0,
            response_size INTEGER NOT NULL DEFAULT 0,
            request_content_type TEXT,
            response_content_type TEXT,
            authenticated_observed INTEGER NOT NULL DEFAULT 0,
            burp_scope_status TEXT NOT NULL DEFAULT 'UNKNOWN',
            is_inbox INTEGER NOT NULL DEFAULT 0,
            synthetic INTEGER NOT NULL DEFAULT 0,
            seen_at TEXT,
            provenance_source TEXT NOT NULL DEFAULT '',
            interaction_kind TEXT NOT NULL DEFAULT 'OBSERVED',
            parent_event_id INTEGER,
            parent_confidence REAL,
            mutation_diff_json TEXT,
            bridge_message_id TEXT,
            request_hash TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_workbench_capture_events_target_id
            ON workbench_capture_events(target_key, id);
        CREATE INDEX IF NOT EXISTS idx_workbench_capture_events_exchange
            ON workbench_capture_events(target_key, exchange_id, id);
        CREATE INDEX IF NOT EXISTS idx_workbench_capture_events_seen
            ON workbench_capture_events(seen_at, id);
        CREATE TABLE IF NOT EXISTS workbench_timeline_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS workbench_project_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_key TEXT NOT NULL,
            rule_type TEXT NOT NULL CHECK(rule_type IN ('host','endpoint')),
            hostname TEXT NOT NULL,
            method TEXT NOT NULL DEFAULT '',
            path TEXT NOT NULL DEFAULT '',
            source_event_id INTEGER,
            created_at TEXT NOT NULL,
            UNIQUE(target_key, rule_type, hostname, method, path)
        );
        CREATE INDEX IF NOT EXISTS idx_workbench_project_rules_match
            ON workbench_project_rules(rule_type, hostname, method, path);
        CREATE INDEX IF NOT EXISTS idx_workbench_project_rules_target
            ON workbench_project_rules(target_key, id);
        """
    )
    # Additive migration for v0.115 checkpoints created by older Workbench versions.
    cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(workbench_checkpoints)").fetchall()}
    if "cutoff_event_id" not in cols:
        conn.execute("ALTER TABLE workbench_checkpoints ADD COLUMN cutoff_event_id INTEGER")

    event_cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(workbench_capture_events)").fetchall()}
    additive = {
        "provenance_source": "TEXT NOT NULL DEFAULT ''",
        "interaction_kind": "TEXT NOT NULL DEFAULT 'OBSERVED'",
        "parent_event_id": "INTEGER",
        "parent_confidence": "REAL",
        "mutation_diff_json": "TEXT",
        "bridge_message_id": "TEXT",
        "request_hash": "TEXT",
    }
    for name, ddl in additive.items():
        if name not in event_cols:
            conn.execute(f"ALTER TABLE workbench_capture_events ADD COLUMN {name} {ddl}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_workbench_capture_events_parent ON workbench_capture_events(parent_event_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_workbench_capture_events_request_hash ON workbench_capture_events(request_hash,id)")


def _init_context_schema(conn) -> None:
    _init_workbench_schema(conn)
    # The inbox is not a registered project, so initialize the contextual tables
    # that normal project startup would have created before the Workbench reads it.
    try:
        import negro_identity as identity_tools
        identity_tools.init_schema(conn)
    except Exception:
        pass
    try:
        import negro_objects as object_tools
        object_tools.init_schema(conn)
    except Exception:
        pass
    try:
        import negro_flows as flow_tools
        flow_tools.init_schema(conn)
    except Exception:
        pass
    try:
        import negro_hunter as hunter
        hunter.init_schema(conn)
    except Exception:
        pass
    try:
        http_inspector.init_schema(conn)
    except Exception:
        pass


def ensure_inbox_paths() -> dict[str, Path]:
    paths = core.ensure_workspace(
        inbox_workspace(),
        INBOX_DOMAIN,
        scopes=[INBOX_DOMAIN],
        project_name="Traffic Inbox",
    )
    with core.db_connect(paths) as conn:
        _init_context_schema(conn)
    return paths



def _event_source_snapshot(source_key: str, exchange_id: int) -> dict[str, Any] | None:
    source = source_for_key(source_key)
    if not source:
        return None
    with core.db_connect(source["paths"]) as conn:
        _init_context_schema(conn)
        row = conn.execute(
            """
            SELECT e.id,e.source,e.tool,e.status_code,e.request_size,e.response_size,
                   e.burp_scope_status,e.first_seen_at,e.last_seen_at,e.request_hash,
                   o.method,o.authenticated_observed,o.request_content_type,o.response_content_type,
                   r.url,r.path,h.hostname
              FROM http_exchanges e
              JOIN resource_operations o ON o.id=e.operation_id
              JOIN resources r ON r.id=o.resource_id
              JOIN hosts h ON h.id=r.host_id
             WHERE e.id=?
            """,
            (int(exchange_id),),
        ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["target_key"] = str(source["key"])
        item["target_name"] = str(source["name"])
        item["is_inbox"] = bool(source["inbox"])
        return item


def _timeline_bootstrapped(conn) -> bool:
    row = conn.execute("SELECT value FROM workbench_timeline_state WHERE key='bootstrapped_v115'").fetchone()
    return bool(row and str(row["value"] or ""))


def ensure_timeline_bootstrap() -> None:
    """One-time migration: preserve pre-v0.115 history as synthetic, already-seen events.

    Exact occurrence order before v0.115 cannot be reconstructed after exchange
    deduplication, so we intentionally create one synthetic event per historical
    exchange ordered by first_seen_at. New Burp captures are exact events.
    """
    paths = ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        if _timeline_bootstrapped(conn):
            return

    historical: list[dict[str, Any]] = []
    for source in source_catalog(include_inbox=True):
        try:
            if source["inbox"]:
                spaths = ensure_inbox_paths()
            else:
                target_obj = core.get_target(str(source["key"]))
                if not target_obj:
                    continue
                spaths = core.ensure_workspace(Path(str(target_obj.get("workspace") or "")).expanduser(), str(target_obj.get("domain") or source["key"]), scopes=target_obj.get("scopes"), project_name=target_obj.get("name"))
            with core.db_connect(spaths) as sconn:
                rows = _safe_query(sconn, """
                    SELECT e.id exchange_id,e.source,e.tool,e.status_code,e.request_size,e.response_size,e.burp_scope_status,
                           e.last_seen_at captured_at,o.method,o.authenticated_observed,o.request_content_type,o.response_content_type,
                           r.url,r.path,h.hostname
                      FROM http_exchanges e
                      JOIN resource_operations o ON o.id=e.operation_id
                      JOIN resources r ON r.id=o.resource_id
                      JOIN hosts h ON h.id=r.host_id
                     ORDER BY e.first_seen_at,e.id
                """)
                for row in rows:
                    row["target_key"] = str(source["key"])
                    row["is_inbox"] = 1 if source["inbox"] else 0
                    historical.append(row)
        except Exception:
            continue

    historical.sort(key=lambda r: (str(r.get("captured_at") or ""), str(r.get("target_key") or ""), int(r.get("exchange_id") or 0)))
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        if _timeline_bootstrapped(conn):
            return
        for row in historical:
            ts = str(row.get("captured_at") or core.now_iso())
            conn.execute(
                """INSERT INTO workbench_capture_events(
                       target_key,exchange_id,captured_at,source,tool,method,url,hostname,path,status_code,
                       request_size,response_size,request_content_type,response_content_type,authenticated_observed,
                       burp_scope_status,is_inbox,synthetic,seen_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)""",
                (
                    str(row.get("target_key") or ""), int(row.get("exchange_id") or 0), ts,
                    str(row.get("source") or ""), str(row.get("tool") or ""), str(row.get("method") or ""),
                    str(row.get("url") or ""), str(row.get("hostname") or ""), str(row.get("path") or "/"),
                    row.get("status_code"), int(row.get("request_size") or 0), int(row.get("response_size") or 0),
                    row.get("request_content_type"), row.get("response_content_type"), int(row.get("authenticated_observed") or 0),
                    str(row.get("burp_scope_status") or "UNKNOWN"), int(row.get("is_inbox") or 0), ts,
                ),
            )
        conn.execute("INSERT OR REPLACE INTO workbench_timeline_state(key,value) VALUES('bootstrapped_v115',?)", (core.now_iso(),))
        conn.commit()



def sync_untracked_exchanges() -> int:
    """Compatibility safety net for observations created outside the Burp ingest route.

    v0.115 records exact Burp occurrences explicitly. Older code/tests and manual
    imports may still create an http_exchange directly; ensure such exchanges are
    visible at least once in the timeline without fabricating repeated occurrences.
    """
    ensure_timeline_bootstrap()
    paths = ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        tracked = {(str(r["target_key"]), int(r["exchange_id"])) for r in conn.execute("SELECT DISTINCT target_key,exchange_id FROM workbench_capture_events").fetchall()}
    pending: list[tuple[str,int,str]] = []
    for source in source_catalog(include_inbox=True):
        try:
            src = source_for_key(str(source["key"]))
            if not src:
                continue
            with core.db_connect(src["paths"]) as conn:
                rows = conn.execute("SELECT id,last_seen_at FROM http_exchanges ORDER BY last_seen_at,id").fetchall()
                for row in rows:
                    key=(str(source["key"]),int(row["id"]))
                    if key not in tracked:
                        pending.append((key[0],key[1],str(row["last_seen_at"] or core.now_iso())))
        except Exception:
            continue
    created=0
    for source_key, exchange_id, ts in sorted(pending,key=lambda x:(x[2],x[0],x[1])):
        snap=_event_source_snapshot(source_key,exchange_id)
        if not snap:
            continue
        with core.db_connect(paths) as conn:
            _init_workbench_schema(conn)
            cur=conn.execute(
                """INSERT INTO workbench_capture_events(target_key,exchange_id,captured_at,source,tool,method,url,hostname,path,status_code,request_size,response_size,request_content_type,response_content_type,authenticated_observed,burp_scope_status,is_inbox,synthetic,seen_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)""",
                (source_key,exchange_id,ts,str(snap.get('source') or ''),str(snap.get('tool') or ''),str(snap.get('method') or ''),str(snap.get('url') or ''),str(snap.get('hostname') or ''),str(snap.get('path') or '/'),snap.get('status_code'),int(snap.get('request_size') or 0),int(snap.get('response_size') or 0),snap.get('request_content_type'),snap.get('response_content_type'),int(snap.get('authenticated_observed') or 0),str(snap.get('burp_scope_status') or 'UNKNOWN'),1 if snap.get('is_inbox') else 0,ts),
            )
            conn.commit()
            created += int(cur.rowcount or 0)
    return created

def latest_event_id() -> int:
    ensure_timeline_bootstrap()
    paths = ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        row = conn.execute("SELECT COALESCE(MAX(id),0) id FROM workbench_capture_events").fetchone()
        return int(row["id"] or 0)


def _find_parent_event(conn, *, target_key: str, request_hash: str, before_id: int | None = None) -> tuple[int | None, float | None]:
    """Best-effort parent lookup for experiments without an explicit parent.

    Exact request-hash matches are high confidence. We intentionally do not
    fabricate fuzzy parents here; a later correlation layer can add probable
    parents with richer similarity evidence.
    """
    rh = str(request_hash or "").strip()
    if not rh:
        return None, None
    clauses = ["target_key=?", "request_hash=?", "upper(COALESCE(interaction_kind,'OBSERVED'))='OBSERVED'"]
    params: list[Any] = [str(target_key), rh]
    if before_id and int(before_id) > 0:
        clauses.append("id<?")
        params.append(int(before_id))
    row = conn.execute(
        "SELECT id FROM workbench_capture_events WHERE " + " AND ".join(clauses) + " ORDER BY id DESC LIMIT 1",
        tuple(params),
    ).fetchone()
    return (int(row["id"]), 1.0) if row else (None, None)


def record_capture_event(
    source_key: str, exchange_id: int, *, captured_at: str | None = None,
    provenance_source: str = "", interaction_kind: str = "",
    parent_event_id: int | None = None, parent_confidence: float | None = None,
    mutation_diff: Any = None, bridge_message_id: str = "",
) -> dict[str, Any] | None:
    """Append one exact occurrence to the global Workbench timeline.

    Provenance belongs to the occurrence (Capture Event), not the deduplicated
    HTTP Exchange. This prevents a normal browser request and a later Repeater
    experiment from being conflated simply because their bytes match.
    """
    ensure_timeline_bootstrap()
    snap = _event_source_snapshot(source_key, int(exchange_id))
    if not snap:
        return None
    ts = str(captured_at or core.now_iso())
    prov = str(provenance_source or "").strip().upper()
    tool = str(snap.get("tool") or "").strip().upper()
    if not prov:
        prov = "REPEATER" if tool == "REPEATER" else ("PROXY" if tool == "PROXY" else (tool or "OTHER"))
    kind = str(interaction_kind or "").strip().upper()
    if not kind:
        kind = "EXPERIMENT" if prov in {"REPEATER","PROXY_MANUAL_MUTATION","NEGRO_REPLAY","RUNNER"} else "OBSERVED"
    if kind not in {"OBSERVED", "EXPERIMENT"}:
        kind = "EXPERIMENT" if prov in {"REPEATER","PROXY_MANUAL_MUTATION","NEGRO_REPLAY","RUNNER"} else "OBSERVED"
    request_hash = str(snap.get("request_hash") or "")
    paths = ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        if kind == "EXPERIMENT" and parent_event_id is None and prov == "REPEATER":
            parent_event_id, parent_confidence = _find_parent_event(conn, target_key=str(source_key), request_hash=request_hash)
        cur = conn.execute(
            """INSERT INTO workbench_capture_events(
                   target_key,exchange_id,captured_at,source,tool,method,url,hostname,path,status_code,
                   request_size,response_size,request_content_type,response_content_type,authenticated_observed,
                   burp_scope_status,is_inbox,synthetic,seen_at,provenance_source,interaction_kind,parent_event_id,
                   parent_confidence,mutation_diff_json,bridge_message_id,request_hash)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,NULL,?,?,?,?,?,?,?)""",
            (
                str(source_key), int(exchange_id), ts, str(snap.get("source") or ""), str(snap.get("tool") or ""),
                str(snap.get("method") or ""), str(snap.get("url") or ""), str(snap.get("hostname") or ""), str(snap.get("path") or "/"),
                snap.get("status_code"), int(snap.get("request_size") or 0), int(snap.get("response_size") or 0),
                snap.get("request_content_type"), snap.get("response_content_type"), int(snap.get("authenticated_observed") or 0),
                str(snap.get("burp_scope_status") or "UNKNOWN"), 1 if snap.get("is_inbox") else 0,
                prov, kind, int(parent_event_id) if parent_event_id else None,
                float(parent_confidence) if parent_confidence is not None else None,
                json.dumps(mutation_diff, ensure_ascii=False, separators=(",",":")) if mutation_diff not in (None, "", [], {}) else None,
                str(bridge_message_id or "") or None, request_hash or None,
            ),
        )
        event_id = int(cur.lastrowid)
        conn.commit()
        row = conn.execute("SELECT * FROM workbench_capture_events WHERE id=?", (event_id,)).fetchone()
        return dict(row) if row else None


def get_capture_event(event_id: int) -> dict[str, Any] | None:
    ensure_timeline_bootstrap()
    paths = ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        row = conn.execute("SELECT * FROM workbench_capture_events WHERE id=?", (int(event_id),)).fetchone()
        return dict(row) if row else None


def mark_event_seen(event_id: int) -> bool:
    paths = ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        cur = conn.execute("UPDATE workbench_capture_events SET seen_at=COALESCE(seen_at,?) WHERE id=?", (core.now_iso(), int(event_id)))
        conn.commit()
        return bool(cur.rowcount)


def mark_all_events_seen(*, through_event_id: int | None = None) -> int:
    paths = ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        if through_event_id and int(through_event_id) > 0:
            cur = conn.execute("UPDATE workbench_capture_events SET seen_at=COALESCE(seen_at,?) WHERE id<=? AND seen_at IS NULL", (core.now_iso(), int(through_event_id)))
        else:
            cur = conn.execute("UPDATE workbench_capture_events SET seen_at=COALESCE(seen_at,?) WHERE seen_at IS NULL", (core.now_iso(),))
        conn.commit()
        return int(cur.rowcount or 0)


def event_unread_count() -> int:
    ensure_timeline_bootstrap()
    paths = ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        row = conn.execute("SELECT COUNT(*) c FROM workbench_capture_events WHERE seen_at IS NULL").fetchone()
        return int(row["c"] or 0)

def create_checkpoint(*, label: str = "", target_hint: str = "all") -> dict[str, Any]:
    """Create a visual cut in history without deleting any HTTP exchange."""
    paths = ensure_inbox_paths()
    cutoff = core.now_iso()
    clean_label = str(label or "").strip()[:120]
    if not clean_label:
        clean_label = f"Checkpoint {cutoff[11:16]}"
    cutoff_event_id = latest_event_id()
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        cur = conn.execute(
            "INSERT INTO workbench_checkpoints(label,cutoff_at,target_hint,created_at,cutoff_event_id) VALUES(?,?,?,?,?)",
            (clean_label, cutoff, str(target_hint or "all")[:120], cutoff, cutoff_event_id),
        )
        row = conn.execute("SELECT * FROM workbench_checkpoints WHERE id=?", (int(cur.lastrowid),)).fetchone()
        conn.commit()
        return dict(row)


def list_checkpoints(*, limit: int = 30) -> list[dict[str, Any]]:
    paths = ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        return [dict(r) for r in conn.execute(
            "SELECT * FROM workbench_checkpoints ORDER BY id DESC LIMIT ?",
            (max(1, min(int(limit), 100)),),
        ).fetchall()]


def get_checkpoint(checkpoint_id: int) -> dict[str, Any] | None:
    paths = ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        row = conn.execute("SELECT * FROM workbench_checkpoints WHERE id=?", (int(checkpoint_id),)).fetchone()
        return dict(row) if row else None


def latest_checkpoint() -> dict[str, Any] | None:
    rows = list_checkpoints(limit=1)
    return rows[0] if rows else None


def rename_checkpoint(checkpoint_id: int, label: str) -> dict[str, Any] | None:
    clean = str(label or "").strip()[:120]
    if not clean:
        return get_checkpoint(checkpoint_id)
    paths = ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        conn.execute("UPDATE workbench_checkpoints SET label=? WHERE id=?", (clean, int(checkpoint_id)))
        conn.commit()
    return get_checkpoint(checkpoint_id)


def delete_checkpoint(checkpoint_id: int) -> bool:
    paths = ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        cur = conn.execute("DELETE FROM workbench_checkpoints WHERE id=?", (int(checkpoint_id),))
        conn.commit()
        return bool(cur.rowcount)


def source_catalog(*, include_inbox: bool = True) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for target in core.list_targets():
        workspace = Path(str(target.get("workspace") or "")).expanduser()
        if not str(workspace):
            continue
        rows.append({
            "key": str(target["key"]),
            "name": str(target.get("name") or target.get("domain") or target["key"]),
            "domain": str(target.get("domain") or target["key"]),
            "workspace": workspace,
            "inbox": False,
        })
    if include_inbox:
        rows.append({
            "key": INBOX_KEY,
            "name": INBOX_NAME,
            "domain": INBOX_DOMAIN,
            "workspace": inbox_workspace(),
            "inbox": True,
        })
    return rows


def source_for_key(source_key: str) -> dict[str, Any] | None:
    key = str(source_key or "").strip()
    if key == INBOX_KEY:
        paths = ensure_inbox_paths()
        return {"key": INBOX_KEY, "name": INBOX_NAME, "domain": INBOX_DOMAIN, "workspace": paths["root"], "paths": paths, "inbox": True}
    target = core.get_target(key)
    if not target:
        return None
    workspace = Path(str(target.get("workspace") or "")).expanduser()
    paths = core.ensure_workspace(workspace, str(target.get("domain") or key), scopes=target.get("scopes"), project_name=target.get("name"))
    return {"key": key, "name": str(target.get("name") or target.get("domain") or key), "domain": str(target.get("domain") or key), "workspace": workspace, "paths": paths, "inbox": False}


def list_project_rules(target_key: str = "") -> list[dict[str, Any]]:
    """Analysis-routing rules for Traffic Inbox. These never widen active Recon scope."""
    paths = ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        if str(target_key or "").strip():
            rows = conn.execute(
                "SELECT * FROM workbench_project_rules WHERE target_key=? ORDER BY id DESC",
                (str(target_key).strip(),),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM workbench_project_rules ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]


def add_project_rule(target_key: str, *, rule_type: str, hostname: str, method: str = "", path: str = "", source_event_id: int | None = None) -> dict[str, Any]:
    """Teach the Workbench which passive traffic belongs to a project for analysis.

    This is deliberately separate from target.scopes. It changes routing/filtering in
    Negro only; it does not authorize active recon or modify Burp scope.
    """
    target_key = str(target_key or "").strip()
    if target_key == INBOX_KEY or not core.get_target(target_key):
        raise ValueError("Proyecto inválido")
    kind = str(rule_type or "").strip().lower()
    if kind not in {"host", "endpoint"}:
        raise ValueError("rule_type debe ser host o endpoint")
    host = str(hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError("Host requerido")
    meth = str(method or "").strip().upper() if kind == "endpoint" else ""
    pth = str(path or "/").strip() or "/" if kind == "endpoint" else ""
    if kind == "endpoint" and not meth:
        raise ValueError("Método requerido para endpoint")
    paths = ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        # One analysis owner per exact rule. Re-assigning a rule intentionally moves it.
        if kind == "host":
            conn.execute("DELETE FROM workbench_project_rules WHERE rule_type='host' AND hostname=? AND target_key<>?", (host, target_key))
        else:
            conn.execute("DELETE FROM workbench_project_rules WHERE rule_type='endpoint' AND hostname=? AND method=? AND path=? AND target_key<>?", (host, meth, pth, target_key))
        conn.execute(
            """INSERT INTO workbench_project_rules(target_key,rule_type,hostname,method,path,source_event_id,created_at)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(target_key,rule_type,hostname,method,path) DO UPDATE SET
                 source_event_id=excluded.source_event_id,created_at=excluded.created_at""",
            (target_key, kind, host, meth, pth, int(source_event_id) if source_event_id else None, core.now_iso()),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM workbench_project_rules WHERE target_key=? AND rule_type=? AND hostname=? AND method=? AND path=?",
            (target_key, kind, host, meth, pth),
        ).fetchone()
        return dict(row)


def match_project_rule(hostname: str, method: str = "", path: str = "") -> dict[str, Any] | None:
    """Return the passive analysis project for an observed request, most-specific first."""
    host = str(hostname or "").strip().lower().rstrip(".")
    meth = str(method or "").strip().upper()
    pth = str(path or "/").strip() or "/"
    if not host:
        return None
    paths = ensure_inbox_paths()
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        row = conn.execute(
            "SELECT * FROM workbench_project_rules WHERE rule_type='endpoint' AND hostname=? AND method=? AND path=? ORDER BY id DESC LIMIT 1",
            (host, meth, pth),
        ).fetchone()
        if not row:
            row = conn.execute(
                "SELECT * FROM workbench_project_rules WHERE rule_type='host' AND hostname=? ORDER BY id DESC LIMIT 1",
                (host,),
            ).fetchone()
        return dict(row) if row else None


def _transfer_exchange_payload(source_key: str, exchange_id: int) -> dict[str, Any] | None:
    source = source_for_key(source_key)
    if not source:
        return None
    with core.db_connect(source["paths"]) as conn:
        _init_context_schema(conn)
        row = conn.execute(
            """SELECT e.*,o.method,o.authenticated_observed,o.request_content_type,o.response_content_type,
                      r.url,r.path,h.hostname
                 FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
                 JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id
                WHERE e.id=?""",
            (int(exchange_id),),
        ).fetchone()
        if not row:
            return None
        item = dict(row)
        for field in ("request_headers_json", "response_headers_json", "query_json"):
            raw = item.get(field)
            try:
                item[field] = json.loads(str(raw)) if raw not in (None, "") else ([] if "headers" in field else None)
            except Exception:
                item[field] = [] if "headers" in field else raw
        return item


def _refresh_promoted_exchange(paths: dict[str, Path], domain: str, exchange_id: int) -> None:
    """Rebuild local-only context after copying passive Inbox evidence into a project."""
    try:
        import negro_hunter as hunter
        import negro_identity as identity_tools
        import negro_objects as object_tools
        import negro_search as search_index
        with core.db_connect(paths) as conn:
            try:
                hunter.analyze_http_exchange(conn, int(exchange_id), domain, emit_notifications=False)
            except Exception:
                pass
            try:
                identity_tools.resolve_exchange(conn, int(exchange_id))
                http_inspector.auto_learn_jwt_auth(conn, int(exchange_id))
            except Exception:
                pass
            try:
                object_tools.refresh_exchange(conn, int(exchange_id))
            except Exception:
                pass
            try:
                ex = conn.execute(
                    "SELECT o.resource_id,r.host_id FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id WHERE e.id=?",
                    (int(exchange_id),),
                ).fetchone()
                search_index.index_exchange(conn, int(exchange_id))
                if ex:
                    search_index.index_resource(conn, int(ex["resource_id"]))
                    search_index.index_host(conn, int(ex["host_id"]))
            except Exception:
                pass
            conn.commit()
    except Exception:
        pass


def assign_event_to_project(target_key: str, event_id: int, *, rule_type: str) -> dict[str, Any]:
    """Add a host/endpoint to project analysis scope and backfill matching Inbox events."""
    event = get_capture_event(int(event_id))
    if not event:
        raise ValueError("Evento no encontrado")
    target = core.get_target(str(target_key))
    if not target:
        raise ValueError("Proyecto no encontrado")
    host = str(event.get("hostname") or "").strip().lower().rstrip(".")
    method = str(event.get("method") or "").strip().upper()
    path = str(event.get("path") or "/").strip() or "/"
    rule = add_project_rule(str(target_key), rule_type=rule_type, hostname=host, method=method, path=path, source_event_id=int(event_id))

    global_paths = ensure_inbox_paths()
    with core.db_connect(global_paths) as conn:
        _init_workbench_schema(conn)
        if str(rule_type).lower() == "host":
            matched = [dict(r) for r in conn.execute(
                "SELECT * FROM workbench_capture_events WHERE target_key=? AND lower(hostname)=? ORDER BY id",
                (INBOX_KEY, host),
            ).fetchall()]
        else:
            matched = [dict(r) for r in conn.execute(
                "SELECT * FROM workbench_capture_events WHERE target_key=? AND lower(hostname)=? AND upper(method)=? AND path=? ORDER BY id",
                (INBOX_KEY, host, method, path),
            ).fetchall()]

    workspace = Path(str(target.get("workspace") or "")).expanduser()
    domain = str(target.get("domain") or target_key)
    target_paths = core.ensure_workspace(workspace, domain, scopes=target.get("scopes"), project_name=target.get("name"))
    exchange_map: dict[int, int] = {}
    for row in matched:
        old_id = int(row.get("exchange_id") or 0)
        if old_id in exchange_map:
            continue
        src = _transfer_exchange_payload(INBOX_KEY, old_id)
        if not src:
            continue
        scope_status = str(src.get("burp_scope_status") or "UNKNOWN").upper()
        burp_in_scope = True if scope_status == "IN_SCOPE" else (False if scope_status == "EXCLUDED" else None)
        result = core.upsert_http_observation(
            target_paths, domain,
            url=str(src.get("url") or ""), method=str(src.get("method") or "GET"), source=str(src.get("source") or "burp_proxy"),
            status_code=src.get("status_code"), authenticated=bool(src.get("authenticated_observed")),
            request_content_type=src.get("request_content_type"), response_content_type=src.get("response_content_type"), tool=src.get("tool"),
            request_b64=src.get("request_b64"), response_b64=src.get("response_b64"),
            request_headers=src.get("request_headers_json") if isinstance(src.get("request_headers_json"), list) else None,
            response_headers=src.get("response_headers_json") if isinstance(src.get("response_headers_json"), list) else None,
            query=src.get("query_json"), burp_in_scope=burp_in_scope, allow_out_of_scope=True,
        )
        new_id = int(result["exchange_id"])
        exchange_map[old_id] = new_id
        _refresh_promoted_exchange(target_paths, str(src.get("hostname") or domain), new_id)

    moved = 0
    with core.db_connect(global_paths) as conn:
        _init_workbench_schema(conn)
        for row in matched:
            old_id = int(row.get("exchange_id") or 0)
            new_id = exchange_map.get(old_id)
            if not new_id:
                continue
            cur = conn.execute(
                "UPDATE workbench_capture_events SET target_key=?,exchange_id=?,is_inbox=0 WHERE id=? AND target_key=?",
                (str(target_key), int(new_id), int(row["id"]), INBOX_KEY),
            )
            moved += int(cur.rowcount or 0)
        conn.commit()
    selected_new_exchange = exchange_map.get(int(event.get("exchange_id") or 0))
    return {
        "ok": True, "target_key": str(target_key), "rule": rule, "moved_events": moved,
        "matched_exchanges": len(exchange_map), "event_id": int(event_id), "exchange_id": selected_new_exchange,
        "active_recon_scope_changed": False,
    }


def _safe_query(conn, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    try:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]
    except Exception:
        return []


def _is_static(row: dict[str, Any]) -> bool:
    path = str(row.get("path") or "").lower().split("?", 1)[0]
    ctype = (str(row.get("response_content_type") or "") + " " + str(row.get("request_content_type") or "")).lower()
    return path.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".css", ".map")) or any(x in ctype for x in ("image/", "font/", "text/css"))


def _row_tags(row: dict[str, Any]) -> list[dict[str, str]]:
    tags: list[dict[str, str]] = []
    ctype = (str(row.get("request_content_type") or "") + " " + str(row.get("response_content_type") or "")).lower()
    if "json" in ctype:
        tags.append({"label": "JSON", "kind": "neutral"})
    if int(row.get("authenticated_observed") or 0):
        tags.append({"label": "Auth", "kind": "auth"})
    if row.get("identity_name"):
        tags.append({"label": str(row["identity_name"]), "kind": "identity"})
    if row.get("object_type"):
        tags.append({"label": str(row["object_type"]), "kind": "object"})
    if row.get("flow_name"):
        tags.append({"label": f"Flow: {row['flow_name']}", "kind": "flow"})
    if int(row.get("signal_count") or 0):
        tags.append({"label": f"Signals {int(row['signal_count'])}", "kind": "signal"})
    if str(row.get("burp_scope_status") or "").upper() == "IN_SCOPE":
        tags.append({"label": "In Scope", "kind": "scope"})
    return tags[:5]


def _enrich_event_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_source: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_source.setdefault(str(row.get("target_key") or ""), []).append(row)
    catalog = {str(x["key"]): x for x in source_catalog(include_inbox=True)}
    for source_key, source_rows in by_source.items():
        source = source_for_key(source_key)
        if not source:
            continue
        ids = sorted({int(r.get("exchange_id") or 0) for r in source_rows if int(r.get("exchange_id") or 0) > 0})
        meta: dict[int, dict[str, Any]] = {}
        if ids:
            with core.db_connect(source["paths"]) as conn:
                _init_context_schema(conn)
                marks = ",".join("?" for _ in ids)
                data = _safe_query(conn, f"""
                    SELECT e.id,
                           (SELECT i.name FROM exchange_identities xi JOIN identities i ON i.id=xi.identity_id WHERE xi.exchange_id=e.id LIMIT 1) identity_name,
                           (SELECT bot.name FROM business_object_observations boo JOIN business_objects bo ON bo.id=boo.business_object_id JOIN business_object_types bot ON bot.id=bo.object_type_id WHERE boo.exchange_id=e.id LIMIT 1) object_type,
                           (SELECT f.name FROM flow_steps fs JOIN flows f ON f.id=fs.flow_id WHERE fs.exchange_id=e.id AND fs.included=1 ORDER BY fs.position LIMIT 1) flow_name,
                           (SELECT COUNT(*) FROM signal_occurrences so WHERE so.exchange_id=e.id AND so.dismissed_at IS NULL) signal_count
                      FROM http_exchanges e WHERE e.id IN ({marks})
                """, tuple(ids))
                meta = {int(x["id"]): x for x in data}

                # Compact request parameters for the timeline. Use value_preview only:
                # it is already the privacy/sensitivity-safe projection used elsewhere
                # in Negro and lets the analyst distinguish repeated endpoint calls.
                param_rows = _safe_query(conn, f"""
                    SELECT exchange_id,name,normalized_name,location,value_preview,id
                      FROM parameter_observations
                     WHERE exchange_id IN ({marks})
                       AND (location='query' OR location='form' OR location='multipart' OR location LIKE 'json:%')
                     ORDER BY exchange_id,
                              CASE WHEN location='query' THEN 0
                                   WHEN location LIKE 'json:%' THEN 1
                                   WHEN location='form' THEN 2
                                   ELSE 3 END,
                              id
                """, tuple(ids))
                previews: dict[int, list[dict[str, str]]] = {}
                seen_params: dict[int, set[tuple[str, str]]] = {}
                for pr in param_rows:
                    exid = int(pr.get("exchange_id") or 0)
                    name = str(pr.get("name") or pr.get("normalized_name") or "").strip()
                    if not name:
                        continue
                    value = str(pr.get("value_preview") or "")
                    key = (name.lower(), value)
                    bucket_seen = seen_params.setdefault(exid, set())
                    if key in bucket_seen:
                        continue
                    bucket_seen.add(key)
                    bucket = previews.setdefault(exid, [])
                    if len(bucket) >= 4:
                        continue
                    bucket.append({
                        "name": name[:80],
                        "value": value[:120],
                        "location": str(pr.get("location") or "")[:80],
                    })
                for exid, items in previews.items():
                    meta.setdefault(exid, {"id": exid})["request_params"] = items
        cat = catalog.get(source_key) or {}
        for row in source_rows:
            enriched = dict(meta.get(int(row.get("exchange_id") or 0), {}))
            enriched.pop("id", None)
            row.update(enriched)
            row["target_name"] = str(cat.get("name") or source.get("name") or source_key)
            row["is_inbox"] = bool(row.get("is_inbox"))
            row["compound_id"] = f"event:{int(row.get('id') or 0)}"
            row["last_seen_at"] = str(row.get("captured_at") or "")
            row["first_seen_at"] = str(row.get("captured_at") or "")
            row["tags"] = _row_tags(row)
    return rows


def list_traffic(*, q: str = "", target: str = "all", host: str = "", method: str = "", status: str = "", scope: str = "", tool: str = "", hide_static: bool = True, since: str = "", since_event_id: int = 0, after_event_id: int = 0, limit: int = 300, sync_legacy: bool = True) -> dict[str, Any]:
    """Return the exact capture timeline, oldest -> newest inside the selected window."""
    ensure_timeline_bootstrap()
    if sync_legacy:
        sync_untracked_exchanges()
    qn = str(q or "").strip().lower()
    hn = str(host or "").strip().lower()
    mn = str(method or "").strip().upper()
    sn = str(status or "").strip()
    scn = str(scope or "").strip().upper()
    tn = str(tool or "").strip().upper()
    requested_target = str(target or "all")
    cutoff = str(since or "").strip()
    cutoff_event = max(0, int(since_event_id or 0), int(after_event_id or 0))
    paths = ensure_inbox_paths()
    clauses = ["id>?" ]
    params: list[Any] = [cutoff_event]
    if requested_target not in {"", "all"}:
        clauses.append("target_key=?"); params.append(requested_target)
    if hn:
        clauses.append("lower(hostname) LIKE ?"); params.append(f"%{hn}%")
    if mn:
        clauses.append("upper(method)=?"); params.append(mn)
    if sn:
        try:
            clauses.append("status_code=?"); params.append(int(sn))
        except Exception:
            clauses.append("CAST(status_code AS TEXT)=?"); params.append(sn)
    if scn:
        clauses.append("upper(COALESCE(burp_scope_status,'UNKNOWN'))=?"); params.append(scn)
    if tn:
        clauses.append("upper(COALESCE(tool,''))=?"); params.append(tn)
    if cutoff and not cutoff_event:
        clauses.append("captured_at>=?"); params.append(cutoff)
    if qn:
        clauses.append("(lower(url) LIKE ? OR lower(hostname) LIKE ? OR lower(path) LIKE ? OR lower(method) LIKE ?)")
        like=f"%{qn}%"; params.extend([like,like,like,like])
    # Freeze one capture-window per read. Previously the rows query and MAX(id)
    # query were separate snapshots; a Burp event committed between them could be
    # absent from `raw` but still advance `latest_event_id`, causing the browser
    # cursor to skip that event forever. Bound the query by a snapshot max taken
    # first so anything arriving during this poll is picked up by the next one.
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        max_row = conn.execute("SELECT COALESCE(MAX(id),0) id FROM workbench_capture_events").fetchone()
        latest_id = int(max_row["id"] or 0)
        clauses.append("id<=?")
        params.append(latest_id)
        query = "SELECT * FROM workbench_capture_events WHERE " + " AND ".join(clauses) + " ORDER BY id DESC LIMIT ?"
        params.append(max(1000, int(limit) * 8))
        raw = [dict(r) for r in conn.execute(query, tuple(params)).fetchall()]

    filtered: list[dict[str, Any]] = []
    for row in raw:
        if hide_static and _is_static(row):
            continue
        row["is_unread"] = not bool(row.get("seen_at"))
        filtered.append(row)
        if len(filtered) >= max(1, int(limit)):
            break
    filtered.reverse()
    _enrich_event_rows(filtered)
    hosts = sorted({str(r.get("hostname") or "") for r in filtered if r.get("hostname")})
    tools = sorted({str(r.get("tool") or "").upper() for r in filtered if r.get("tool")})
    return {
        "rows": filtered,
        "hosts": hosts,
        "tools": tools,
        "projects": source_catalog(include_inbox=True),
        "count": len(filtered),
        "unread_count": sum(1 for r in filtered if r.get("is_unread")),
        "latest_event_id": latest_id,
    }


def _decode_json(value: Any) -> Any:
    if value is None or value == "":
        return None
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value))
    except Exception:
        return value


def detail(source_key: str, exchange_id: int) -> dict[str, Any] | None:
    source = source_for_key(source_key)
    if not source:
        return None
    paths = source["paths"]
    with core.db_connect(paths) as conn:
        _init_context_schema(conn)
        inspector = http_inspector.extract_exchange(conn, int(exchange_id))
        if not inspector:
            return None
        ex = dict(inspector["exchange"])
        # Raw bytes are already returned as decoded request/response text below.
        # Avoid duplicating multi-megabyte base64 blobs in the Workbench JSON API.
        for noisy_key in ("request_b64", "response_b64", "request_headers_json", "response_headers_json", "query_json", "request_hash", "response_hash", "fingerprint"):
            ex.pop(noisy_key, None)

        # Reuse the exact semantic memory already used by HTTP Inspector and the
        # Burp context integration instead of inventing a second interpretation
        # layer for the Workbench.
        try:
            annotations = http_inspector.learned_annotations(conn, int(exchange_id))
        except Exception:
            annotations = [dict(a) for a in (inspector.get("annotations") or [])]

        identity = None
        identity_rows = _safe_query(conn, """
            SELECT i.id,i.name,i.kind,ic.id context_id,ic.label context_label,ic.role,ic.tenant,xi.confidence,xi.source
              FROM exchange_identities xi JOIN identities i ON i.id=xi.identity_id
              LEFT JOIN identity_contexts ic ON ic.id=xi.context_id
             WHERE xi.exchange_id=? LIMIT 1
        """, (int(exchange_id),))
        if identity_rows:
            identity = identity_rows[0]

        objects = _safe_query(conn, """
            SELECT DISTINCT bo.id,bot.name type_name,bo.identifier_preview,bo.identifier_raw,boo.source_location
              FROM business_object_observations boo
              JOIN business_objects bo ON bo.id=boo.business_object_id
              JOIN business_object_types bot ON bot.id=bo.object_type_id
             WHERE boo.exchange_id=? ORDER BY bot.name,bo.id LIMIT 12
        """, (int(exchange_id),))
        signals = _safe_query(conn, """
            SELECT id,kind,category,severity,title,evidence_json,last_seen_at
              FROM signal_occurrences WHERE exchange_id=? AND dismissed_at IS NULL
             ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,last_seen_at DESC LIMIT 10
        """, (int(exchange_id),))
        for signal in signals:
            signal["evidence"] = _decode_json(signal.pop("evidence_json", None))

        flows = _safe_query(conn, """
            SELECT f.id,f.name,fs.id step_id,fs.position,fs.label,fs.state_label
              FROM flow_steps fs JOIN flows f ON f.id=fs.flow_id
             WHERE fs.exchange_id=? AND fs.included=1 ORDER BY f.id,fs.position LIMIT 10
        """, (int(exchange_id),))

        related_map: dict[int, dict[str, Any]] = {}
        object_ids = [int(o["id"]) for o in objects if o.get("id")]
        if object_ids:
            marks = ",".join("?" for _ in object_ids)
            rels = _safe_query(conn, f"""
                SELECT DISTINCT e.id,e.status_code,e.last_seen_at,o.method,r.path,h.hostname,'object' relation
                  FROM business_object_observations boo
                  JOIN http_exchanges e ON e.id=boo.exchange_id
                  JOIN resource_operations o ON o.id=e.operation_id
                  JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id
                 WHERE boo.business_object_id IN ({marks}) AND e.id<>?
                 ORDER BY e.last_seen_at DESC LIMIT 12
            """, tuple(object_ids) + (int(exchange_id),))
            for row in rels:
                related_map[int(row["id"])] = row
        if identity and identity.get("id"):
            rels = _safe_query(conn, """
                SELECT e.id,e.status_code,e.last_seen_at,o.method,r.path,h.hostname,'identity' relation
                  FROM exchange_identities xi JOIN http_exchanges e ON e.id=xi.exchange_id
                  JOIN resource_operations o ON o.id=e.operation_id
                  JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id
                 WHERE xi.identity_id=? AND e.id<>? ORDER BY e.last_seen_at DESC LIMIT 12
            """, (int(identity["id"]), int(exchange_id)))
            for row in rels:
                related_map.setdefault(int(row["id"]), row)
        if not related_map:
            rels = _safe_query(conn, """
                SELECT e2.id,e2.status_code,e2.last_seen_at,o2.method,r2.path,h2.hostname,'host' relation
                  FROM http_exchanges e1 JOIN resource_operations o1 ON o1.id=e1.operation_id JOIN resources r1 ON r1.id=o1.resource_id
                  JOIN hosts h1 ON h1.id=r1.host_id
                  JOIN hosts h2 ON h2.hostname=h1.hostname JOIN resources r2 ON r2.host_id=h2.id
                  JOIN resource_operations o2 ON o2.resource_id=r2.id JOIN http_exchanges e2 ON e2.operation_id=o2.id
                 WHERE e1.id=? AND e2.id<>? ORDER BY e2.last_seen_at DESC LIMIT 8
            """, (int(exchange_id), int(exchange_id)))
            for row in rels:
                related_map[int(row["id"])] = row

        related = list(related_map.values())[:10]
        for row in related:
            row["target_key"] = source["key"]

        # Catalogs and scalar observations used by the Workbench inline semantics
        # popover. This reuses HTTP Inspector's parser/source-of-truth; the browser
        # never invents a second model of what a value is.
        identity_options = _safe_query(conn, "SELECT id,name,kind FROM identities ORDER BY lower(name),id LIMIT 300")
        object_type_options = _safe_query(conn, "SELECT id,name FROM business_object_types ORDER BY lower(name),id LIMIT 300")
        try:
            field_semantics = http_inspector.field_semantics(conn)
        except Exception:
            field_semantics = []
        safe_values: list[dict[str, Any]] = []
        for raw_value in inspector.get("values") or []:
            item = dict(raw_value)
            ann = dict(item.get("annotation") or {})
            safe_values.append({
                "side": str(item.get("side") or ""),
                "location": str(item.get("location") or ""),
                "key": str(item.get("key") or ""),
                "value": str(item.get("value") or "")[:12000],
                "preview": str(item.get("preview") or "")[:500],
                "detected_type": str(item.get("detected_type") or "scalar"),
                "default_classification": str(item.get("default_classification") or "ignore"),
                "annotation": {
                    "classification": str(ann.get("classification") or ""),
                    "identity_id": int(ann.get("identity_id") or 0) or None,
                    "object_type": str(ann.get("object_type") or ""),
                } if ann else None,
                "jwt_claims": [
                    {
                        "key": str(c.get("key") or ""),
                        "value": str(c.get("value") or "")[:12000],
                        "location": str(c.get("location") or ""),
                        "default_classification": str(c.get("default_classification") or "ignore"),
                        "field_semantic": ({
                            "classification": str((c.get("field_semantic") or {}).get("classification") or ""),
                            "object_type": str((c.get("field_semantic") or {}).get("object_type") or ""),
                        } if c.get("field_semantic") else None),
                        "annotation": ({
                            "classification": str((c.get("annotation") or {}).get("classification") or ""),
                            "identity_id": int((c.get("annotation") or {}).get("identity_id") or 0) or None,
                            "object_type": str((c.get("annotation") or {}).get("object_type") or ""),
                        } if c.get("annotation") else None),
                    }
                    for c in (item.get("jwt_claims") or [])
                ],
            })

        identity_match_map: dict[int, dict[str, Any]] = {}
        semantic_counts = {"auth": 0, "resolver": 0, "context": 0, "entity": 0}
        safe_annotations: list[dict[str, Any]] = []
        for raw_ann in annotations or []:
            ann = dict(raw_ann)
            cls = str(ann.get("classification") or "").lower()
            if cls in semantic_counts:
                semantic_counts[cls] += 1
            iid = int(ann.get("identity_id") or 0)
            if iid:
                item = identity_match_map.setdefault(iid, {
                    "id": iid,
                    "name": str(ann.get("identity_name") or f"Identity #{iid}"),
                    "classifications": [],
                })
                if cls and cls not in item["classifications"]:
                    item["classifications"].append(cls)
            safe_annotations.append({
                "side": str(ann.get("side") or ""),
                "location": str(ann.get("location") or ""),
                "key_name": str(ann.get("key_name") or ""),
                "value_raw": str(ann.get("value_raw") or ann.get("value_preview") or ""),
                "value_preview": str(ann.get("value_preview") or ""),
                "classification": cls,
                "identity_id": iid or None,
                "identity_name": str(ann.get("identity_name") or ""),
                "object_type": str(ann.get("object_type") or ""),
                "match_reason": str(ann.get("match_reason") or ""),
                "source_exchange_id": ann.get("source_exchange_id"),
            })

        active_scope_authorized = False
        if not bool(source["inbox"]):
            try:
                target_meta = core.get_target(str(source["key"])) or {}
                host_value = str(ex.get("hostname") or "").strip().lower().rstrip(".")
                active_scope_authorized = any(
                    core.host_matches_scope(host_value, str(scope or "").strip().lower().rstrip("."))
                    for scope in (target_meta.get("scopes") or [target_meta.get("domain")])
                    if str(scope or "").strip()
                )
            except Exception:
                active_scope_authorized = False

        return {
            "target_key": source["key"],
            "target_name": source["name"],
            "is_inbox": bool(source["inbox"]),
            "active_scope_authorized": bool(active_scope_authorized),
            "exchange": ex,
            "request_text": inspector.get("request_text") or "",
            "response_text": inspector.get("response_text") or "",
            "identity": identity,
            "identity_matches": list(identity_match_map.values()),
            "annotations": safe_annotations,
            "values": safe_values,
            "identity_options": identity_options,
            "object_type_options": object_type_options,
            "field_semantics": field_semantics,
            "semantic_counts": semantic_counts,
            "objects": objects,
            "signals": signals,
            "flows": flows,
            "related": related,
        }



def detail_event(event_id: int, *, mark_seen: bool = True) -> dict[str, Any] | None:
    event = get_capture_event(int(event_id))
    if not event:
        return None
    item = detail(str(event.get("target_key") or ""), int(event.get("exchange_id") or 0))
    if not item:
        return None
    if mark_seen and not event.get("seen_at"):
        mark_event_seen(int(event_id))
        event["seen_at"] = core.now_iso()
    if event.get("mutation_diff_json"):
        try:
            event["mutation_diff"] = json.loads(str(event.get("mutation_diff_json") or "[]"))
        except Exception:
            event["mutation_diff"] = []
    else:
        event["mutation_diff"] = []
    try:
        import negro_evidence as evidence_tools
        gpaths = ensure_inbox_paths()
        with core.db_connect(gpaths) as gconn:
            evidence_tools.init_schema(gconn)
            evidence_rows = [dict(r) for r in gconn.execute(
                "SELECT * FROM experiment_evidence WHERE event_id=? ORDER BY id DESC", (int(event_id),)
            ).fetchall()]
        item["event_evidence"] = evidence_rows
    except Exception:
        item["event_evidence"] = []
    item["event"] = event
    item["event_id"] = int(event_id)
    return item
