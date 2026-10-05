from __future__ import annotations

import fnmatch
import re
import sqlite3
from typing import Any

ENVIRONMENTS = ("PROD", "QA", "STAGING", "DEV", "UNKNOWN")

# Conservative defaults. Rules are ordered from most explicit non-production
# environments to production. UNKNOWN is preferred over guessing PROD.
DEFAULT_RULES: list[tuple[str, str, int]] = [
    (r"(^|[.-])(qa|quality|uat)([.-]|$)", "QA", 10),
    (r"(^|[.-])(stg|stage|staging|preprod|pre-prod)([.-]|$)", "STAGING", 20),
    (r"(^|[.-])(dev|development|sandbox|test|testing)([.-]|$)", "DEV", 30),
    (r"(^|[.-])(prod|production)([.-]|$)", "PROD", 40),
]


def init_schema(conn: sqlite3.Connection) -> None:
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(http_exchanges)")}
    if "environment" not in cols:
        conn.execute("ALTER TABLE http_exchanges ADD COLUMN environment TEXT NOT NULL DEFAULT 'UNKNOWN'")
    if "environment_source" not in cols:
        conn.execute("ALTER TABLE http_exchanges ADD COLUMN environment_source TEXT NOT NULL DEFAULT 'auto'")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_http_exchanges_environment ON http_exchanges(environment,last_seen_at)")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS environment_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL,
            environment TEXT NOT NULL,
            priority INTEGER NOT NULL DEFAULT 100,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(pattern, environment)
        );
        CREATE INDEX IF NOT EXISTS idx_environment_rules_priority ON environment_rules(enabled,priority,id);
        """
    )


def normalize_environment(value: str | None) -> str:
    value = str(value or "").strip().upper()
    return value if value in ENVIRONMENTS else "UNKNOWN"


def _rule_matches(pattern: str, hostname: str) -> bool:
    """Project rules are friendly hostname globs. Prefix with re: for regex."""
    pattern = str(pattern or "").strip().lower().rstrip(".")
    host = str(hostname or "").strip().lower().rstrip(".")
    if not pattern or not host:
        return False
    if pattern.startswith("re:"):
        try:
            return bool(re.search(pattern[3:], host, re.I))
        except re.error:
            return False
    return fnmatch.fnmatchcase(host, pattern)


def get_default_environment(conn: sqlite3.Connection | None) -> str:
    if conn is None:
        return "PROD"
    row = conn.execute("SELECT value FROM meta WHERE key='environment_default'").fetchone()
    return normalize_environment(row["value"] if row else "PROD")


def infer_environment(hostname: str, conn: sqlite3.Connection | None = None) -> tuple[str, str]:
    host = str(hostname or "").strip().lower().rstrip(".")
    if not host:
        return "UNKNOWN", "auto"
    if conn is not None:
        init_schema(conn)
        rows = conn.execute(
            "SELECT pattern,environment FROM environment_rules WHERE enabled=1 ORDER BY priority,id"
        ).fetchall()
        for row in rows:
            if _rule_matches(str(row["pattern"]), host):
                return normalize_environment(row["environment"]), "rule"
    for pattern, env, _priority in DEFAULT_RULES:
        if re.search(pattern, host, re.I):
            return env, "auto"
    return get_default_environment(conn), "auto"


def list_environment_rules(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    init_schema(conn)
    return [dict(r) for r in conn.execute(
        "SELECT id,pattern,environment,priority,enabled,created_at,updated_at FROM environment_rules ORDER BY priority,id"
    ).fetchall()]


def rules_as_text(conn: sqlite3.Connection) -> str:
    lines=[]
    for row in list_environment_rules(conn):
        if int(row.get("enabled") or 0) != 1:
            continue
        lines.append(f"{row['pattern']} = {normalize_environment(row['environment'])}")
    return "\n".join(lines)


def parse_rules_text(text: str) -> list[tuple[str, str]]:
    out=[]
    for lineno, raw in enumerate(str(text or "").splitlines(), start=1):
        line=raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"Regla inválida en línea {lineno}: usa patrón = AMBIENTE")
        pattern, env = [x.strip() for x in line.split("=", 1)]
        env=normalize_environment(env)
        if not pattern:
            raise ValueError(f"Regla inválida en línea {lineno}: falta hostname/patrón")
        if env == "UNKNOWN" and line.split("=",1)[1].strip().upper() != "UNKNOWN":
            raise ValueError(f"Ambiente inválido en línea {lineno}")
        out.append((pattern.lower().rstrip("."), env))
    return out


def reclassify_non_manual(conn: sqlite3.Connection) -> dict[str, int]:
    init_schema(conn)
    rows=conn.execute(
        """SELECT e.id,h.hostname FROM http_exchanges e
           JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id
           WHERE COALESCE(e.environment_source,'auto')<>'manual'"""
    ).fetchall()
    changed=0
    for row in rows:
        env, source=infer_environment(str(row["hostname"]), conn)
        current=conn.execute("SELECT environment,environment_source FROM http_exchanges WHERE id=?",(int(row["id"]),)).fetchone()
        if not current or current["environment"] != env or current["environment_source"] != source:
            exchange_id=int(row["id"])
            conn.execute("UPDATE http_exchanges SET environment=?,environment_source=? WHERE id=?",(env,source,exchange_id))
            # Keep structured/free-text Search consistent with the new classification.
            try:
                import negro_search as search_tools
                search_tools.index_exchange(conn, exchange_id)
            except Exception:
                # Search can be rebuilt independently; classification itself must not fail.
                pass
            changed += 1
    return {"scanned": len(rows), "changed": changed}


def replace_project_rules(conn: sqlite3.Connection, text: str, default_environment: str, *, now: str) -> dict[str, Any]:
    init_schema(conn)
    rules=parse_rules_text(text)
    default_env=normalize_environment(default_environment)
    conn.execute("DELETE FROM environment_rules")
    for priority,(pattern,env) in enumerate(rules, start=1):
        conn.execute(
            "INSERT INTO environment_rules(pattern,environment,priority,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (pattern,env,priority,1,now,now),
        )
    conn.execute(
        "INSERT INTO meta(key,value) VALUES('environment_default',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (default_env,),
    )
    stats=reclassify_non_manual(conn)
    return {"rules": len(rules), "default_environment": default_env, **stats}


def _normalized_path(path: str) -> str:
    parts=[]
    for part in str(path or "/").split("/"):
        if not part:
            parts.append(part); continue
        if re.fullmatch(r"\d+", part):
            parts.append("{id}")
        elif re.fullmatch(r"[0-9a-f]{8}-[0-9a-f-]{27,}", part, re.I):
            parts.append("{uuid}")
        elif re.fullmatch(r"[0-9a-f]{16,}", part, re.I):
            parts.append("{hex}")
        else:
            parts.append(part)
    return "/".join(parts) or "/"


def set_exchange_environment(conn: sqlite3.Connection, exchange_id: int, environment: str, *, source: str = "manual") -> dict[str, Any]:
    init_schema(conn)
    env = normalize_environment(environment)
    if env == "UNKNOWN" and str(environment or "").strip().upper() not in {"", "UNKNOWN"}:
        raise ValueError("Ambiente inválido")
    row = conn.execute("SELECT id FROM http_exchanges WHERE id=?", (int(exchange_id),)).fetchone()
    if not row:
        raise ValueError("Request no encontrada")
    conn.execute(
        "UPDATE http_exchanges SET environment=?,environment_source=? WHERE id=?",
        (env, str(source or "manual")[:24], int(exchange_id)),
    )
    return {"exchange_id": int(exchange_id), "environment": env, "source": str(source or "manual")[:24]}


def redetect_exchange(conn: sqlite3.Connection, exchange_id: int) -> dict[str, Any]:
    init_schema(conn)
    row = conn.execute(
        """SELECT e.id,h.hostname FROM http_exchanges e
           JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id
           WHERE e.id=?""",
        (int(exchange_id),),
    ).fetchone()
    if not row:
        raise ValueError("Request no encontrada")
    env, source = infer_environment(str(row["hostname"]), conn)
    conn.execute("UPDATE http_exchanges SET environment=?,environment_source=? WHERE id=?", (env, source, int(exchange_id)))
    return {"exchange_id": int(exchange_id), "environment": env, "source": source}


def counterpart_candidates(conn: sqlite3.Connection, exchange_id: int, limit: int = 8) -> list[dict[str, Any]]:
    """Observed counterparts only. No vulnerability claim is made."""
    init_schema(conn)
    row = conn.execute(
        """SELECT e.id,e.environment,o.method,r.path,r.id resource_id,h.hostname
           FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id WHERE e.id=?""",
        (int(exchange_id),),
    ).fetchone()
    if not row:
        return []
    env = normalize_environment(row["environment"])
    target_template = _normalized_path(str(row["path"]))
    rows = conn.execute(
        """SELECT e.id,e.environment,e.status_code,e.last_seen_at,o.method,r.path,r.id resource_id,h.hostname
           FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id
           WHERE e.id<>? AND upper(o.method)=upper(?) AND e.environment<>? AND e.environment<>'UNKNOWN'
           ORDER BY e.last_seen_at DESC LIMIT 400""",
        (int(exchange_id), str(row["method"]), env),
    ).fetchall()
    out=[]
    for candidate in rows:
        item=dict(candidate)
        if _normalized_path(str(item.get("path") or "/")) != target_template:
            continue
        item["normalized_path"] = target_template
        out.append(item)
        if len(out) >= max(1, min(int(limit), 30)):
            break
    return out
