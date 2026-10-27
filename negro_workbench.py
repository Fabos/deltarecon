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
        """
    )


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


def create_checkpoint(*, label: str = "", target_hint: str = "all") -> dict[str, Any]:
    """Create a visual cut in history without deleting any HTTP exchange."""
    paths = ensure_inbox_paths()
    cutoff = core.now_iso()
    clean_label = str(label or "").strip()[:120]
    if not clean_label:
        clean_label = f"Checkpoint {cutoff[11:16]}"
    with core.db_connect(paths) as conn:
        _init_workbench_schema(conn)
        cur = conn.execute(
            "INSERT INTO workbench_checkpoints(label,cutoff_at,target_hint,created_at) VALUES(?,?,?,?)",
            (clean_label, cutoff, str(target_hint or "all")[:120], cutoff),
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


def list_traffic(*, q: str = "", target: str = "all", host: str = "", method: str = "", status: str = "", scope: str = "", tool: str = "", hide_static: bool = True, since: str = "", limit: int = 300) -> dict[str, Any]:
    qn = str(q or "").strip().lower()
    hn = str(host or "").strip().lower()
    mn = str(method or "").strip().upper()
    sn = str(status or "").strip()
    scn = str(scope or "").strip().upper()
    tn = str(tool or "").strip().upper()
    requested_target = str(target or "all")
    cutoff = str(since or "").strip()
    rows: list[dict[str, Any]] = []
    hosts: set[str] = set()
    tools: set[str] = set()

    for source in source_catalog(include_inbox=True):
        if requested_target not in {"", "all"} and source["key"] != requested_target:
            continue
        try:
            if source["inbox"]:
                paths = ensure_inbox_paths()
            else:
                target_obj = core.get_target(str(source["key"]))
                if not target_obj:
                    continue
                paths = core.ensure_workspace(Path(str(target_obj.get("workspace") or "")).expanduser(), str(target_obj.get("domain") or source["key"]), scopes=target_obj.get("scopes"), project_name=target_obj.get("name"))
            with core.db_connect(paths) as conn:
                _init_context_schema(conn)
                data = _safe_query(conn, """
                    SELECT e.id,e.status_code,e.first_seen_at,e.last_seen_at,e.request_size,e.response_size,
                           e.environment,e.burp_scope_status,e.source,e.tool,
                           o.method,o.resource_id,o.authenticated_observed,o.request_content_type,o.response_content_type,
                           r.url,r.path,r.query,h.hostname,
                           (SELECT i.name FROM exchange_identities xi JOIN identities i ON i.id=xi.identity_id WHERE xi.exchange_id=e.id LIMIT 1) identity_name,
                           (SELECT bot.name FROM business_object_observations boo JOIN business_objects bo ON bo.id=boo.business_object_id JOIN business_object_types bot ON bot.id=bo.object_type_id WHERE boo.exchange_id=e.id LIMIT 1) object_type,
                           (SELECT f.name FROM flow_steps fs JOIN flows f ON f.id=fs.flow_id WHERE fs.exchange_id=e.id AND fs.included=1 ORDER BY fs.position LIMIT 1) flow_name,
                           (SELECT COUNT(*) FROM signal_occurrences so WHERE so.exchange_id=e.id AND so.dismissed_at IS NULL) signal_count
                      FROM http_exchanges e
                      JOIN resource_operations o ON o.id=e.operation_id
                      JOIN resources r ON r.id=o.resource_id
                      JOIN hosts h ON h.id=r.host_id
                     ORDER BY e.last_seen_at DESC
                     LIMIT ?
                """, (max(200, int(limit) * 2),))
                for row in data:
                    row["target_key"] = str(source["key"])
                    row["target_name"] = str(source["name"])
                    row["is_inbox"] = bool(source["inbox"])
                    row["compound_id"] = f"{source['key']}:{row['id']}"
                    hosts.add(str(row.get("hostname") or ""))
                    if row.get("tool"):
                        tools.add(str(row["tool"]).upper())
                    hay = " ".join(str(row.get(k) or "") for k in ("method", "hostname", "path", "url", "status_code", "identity_name", "object_type", "flow_name", "source", "tool")).lower()
                    if cutoff and str(row.get("last_seen_at") or "") < cutoff:
                        continue
                    if qn and qn not in hay:
                        continue
                    if hn and hn not in str(row.get("hostname") or "").lower():
                        continue
                    if mn and str(row.get("method") or "").upper() != mn:
                        continue
                    if sn and str(row.get("status_code") or "") != sn:
                        continue
                    if scn and str(row.get("burp_scope_status") or "UNKNOWN").upper() != scn:
                        continue
                    if tn and str(row.get("tool") or "").upper() != tn:
                        continue
                    if hide_static and _is_static(row):
                        continue
                    row["tags"] = _row_tags(row)
                    rows.append(row)
        except Exception:
            continue

    rows.sort(key=lambda r: str(r.get("last_seen_at") or r.get("first_seen_at") or ""), reverse=True)
    rows = rows[: max(1, int(limit))]
    return {
        "rows": rows,
        "hosts": sorted(x for x in hosts if x),
        "tools": sorted(tools),
        "projects": source_catalog(include_inbox=True),
        "count": len(rows),
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

        return {
            "target_key": source["key"],
            "target_name": source["name"],
            "is_inbox": bool(source["inbox"]),
            "exchange": ex,
            "request_text": inspector.get("request_text") or "",
            "response_text": inspector.get("response_text") or "",
            "identity": identity,
            "identity_matches": list(identity_match_map.values()),
            "annotations": safe_annotations,
            "semantic_counts": semantic_counts,
            "objects": objects,
            "signals": signals,
            "flows": flows,
            "related": related,
        }
