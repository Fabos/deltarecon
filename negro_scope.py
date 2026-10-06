from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

VALID = {"IN_SCOPE", "EXCLUDED", "UNKNOWN"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_status(value: str | bool | None) -> str:
    if isinstance(value, bool):
        return "IN_SCOPE" if value else "EXCLUDED"
    text = str(value or "UNKNOWN").strip().upper()
    if text in {"IN", "IN_SCOPE", "INSCOPE", "TRUE", "1"}:
        return "IN_SCOPE"
    if text in {"OUT", "EXCLUDED", "OUT_OF_SCOPE", "FALSE", "0"}:
        return "EXCLUDED"
    return "UNKNOWN"


def init_schema(conn: sqlite3.Connection) -> None:
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(http_exchanges)")}
    if "burp_scope_status" not in cols:
        conn.execute("ALTER TABLE http_exchanges ADD COLUMN burp_scope_status TEXT NOT NULL DEFAULT 'UNKNOWN'")
    if "burp_scope_updated_at" not in cols:
        conn.execute("ALTER TABLE http_exchanges ADD COLUMN burp_scope_updated_at TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_http_exchanges_burp_scope ON http_exchanges(burp_scope_status)")


def set_exchange_scope(conn: sqlite3.Connection, exchange_id: int, status: str | bool | None, *, at: str | None = None) -> str:
    init_schema(conn)
    normalized = normalize_status(status)
    conn.execute(
        "UPDATE http_exchanges SET burp_scope_status=?, burp_scope_updated_at=? WHERE id=?",
        (normalized, at or now_iso(), int(exchange_id)),
    )
    return normalized


def set_resource_scope(conn: sqlite3.Connection, resource_id: int, status: str | bool | None, *, at: str | None = None) -> list[int]:
    init_schema(conn)
    normalized = normalize_status(status)
    ts = at or now_iso()
    ids = [int(r["id"]) for r in conn.execute(
        "SELECT e.id FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id WHERE o.resource_id=?",
        (int(resource_id),),
    ).fetchall()]
    if ids:
        conn.execute(
            """UPDATE http_exchanges SET burp_scope_status=?,burp_scope_updated_at=?
               WHERE operation_id IN (SELECT id FROM resource_operations WHERE resource_id=?)""",
            (normalized, ts, int(resource_id)),
        )
    return ids


def candidate_urls(conn: sqlite3.Connection, limit: int = 10000) -> list[dict]:
    rows = conn.execute(
        """SELECT DISTINCT r.id AS resource_id,r.url
           FROM resources r JOIN resource_operations o ON o.resource_id=r.id
           JOIN http_exchanges e ON e.operation_id=o.id
           WHERE r.url IS NOT NULL AND r.url<>''
           ORDER BY r.id LIMIT ?""",
        (max(1, min(int(limit), 50000)),),
    ).fetchall()
    return [dict(r) for r in rows]


def set_host_scope(conn: sqlite3.Connection, hostname: str, status: str | bool | None, *, at: str | None = None) -> int:
    """Update all observed exchanges for one host in a single SQL statement."""
    init_schema(conn)
    normalized = normalize_status(status)
    ts = at or now_iso()
    host = str(hostname or "").strip().lower().rstrip(".")
    if not host:
        return 0
    row = conn.execute("SELECT id FROM hosts WHERE lower(hostname)=?", (host,)).fetchone()
    if not row:
        return 0
    host_id = int(row["id"])
    count = conn.execute(
        """SELECT COUNT(*) c FROM http_exchanges e
           JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id
           WHERE r.host_id=? AND COALESCE(e.burp_scope_status,'UNKNOWN')<>?""",
        (host_id, normalized),
    ).fetchone()["c"]
    conn.execute(
        """UPDATE http_exchanges SET burp_scope_status=?,burp_scope_updated_at=?
           WHERE operation_id IN (SELECT o.id FROM resource_operations o JOIN resources r ON r.id=o.resource_id WHERE r.host_id=?)""",
        (normalized, ts, host_id),
    )
    # Keep search_documents in sync in bulk. Older DBs may not have the column yet.
    try:
        conn.execute(
            """UPDATE search_documents SET burp_scope_status=? WHERE exchange_id IN (
                   SELECT e.id FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
                   JOIN resources r ON r.id=o.resource_id WHERE r.host_id=?
               )""",
            (normalized, host_id),
        )
    except sqlite3.OperationalError:
        pass
    return int(count or 0)
