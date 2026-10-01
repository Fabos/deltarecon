from __future__ import annotations

"""Business Objects, cross-host correlation and conservative pattern observations.

Negro never treats a correlated object or an unusual pattern as proof of a
vulnerability.  This module only structures evidence already captured by the
researcher so it is easier to notice relationships across hosts, identities,
flows and state observations.
"""

import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any


IDENTIFIER_HINTS = (
    "id", "uuid", "reference", "ref", "account", "user", "member", "seller",
    "buyer", "customer", "order", "invoice", "payment", "shipment", "tenant",
    "organization", "org", "cart", "product", "item", "subscription", "transaction",
)
STATE_HINTS = ("status", "state", "phase", "stage")
SENSITIVE_HINTS = (
    "authorization", "cookie", "token", "secret", "password", "passwd", "session",
    "apikey", "api_key", "access_key", "refresh",
)
GENERIC_VALUES = {
    "", "0", "1", "true", "false", "null", "none", "ok", "success", "active",
    "inactive", "enabled", "disabled", "pending", "created", "updated", "deleted",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_schema(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS business_object_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            name_key TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS business_object_identifiers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            object_type_id INTEGER NOT NULL,
            normalized_name TEXT NOT NULL,
            source_observation_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(object_type_id, normalized_name),
            FOREIGN KEY(object_type_id) REFERENCES business_object_types(id) ON DELETE CASCADE,
            FOREIGN KEY(source_observation_id) REFERENCES parameter_observations(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS business_objects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            object_type_id INTEGER NOT NULL,
            identifier_hash TEXT NOT NULL,
            identifier_preview TEXT,
            identifier_raw TEXT,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(object_type_id, identifier_hash),
            FOREIGN KEY(object_type_id) REFERENCES business_object_types(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS business_object_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            business_object_id INTEGER NOT NULL,
            identifier_id INTEGER NOT NULL,
            parameter_observation_id INTEGER NOT NULL,
            exchange_id INTEGER NOT NULL,
            resource_id INTEGER NOT NULL,
            host_id INTEGER NOT NULL,
            source_location TEXT,
            observed_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(identifier_id, parameter_observation_id),
            FOREIGN KEY(business_object_id) REFERENCES business_objects(id) ON DELETE CASCADE,
            FOREIGN KEY(identifier_id) REFERENCES business_object_identifiers(id) ON DELETE CASCADE,
            FOREIGN KEY(parameter_observation_id) REFERENCES parameter_observations(id) ON DELETE CASCADE,
            FOREIGN KEY(exchange_id) REFERENCES http_exchanges(id) ON DELETE CASCADE,
            FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE,
            FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS business_object_relation_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            object_a_id INTEGER NOT NULL,
            object_b_id INTEGER NOT NULL,
            exchange_id INTEGER NOT NULL,
            relation_type TEXT NOT NULL DEFAULT 'co_observed',
            created_at TEXT NOT NULL,
            UNIQUE(object_a_id, object_b_id, exchange_id, relation_type),
            FOREIGN KEY(object_a_id) REFERENCES business_objects(id) ON DELETE CASCADE,
            FOREIGN KEY(object_b_id) REFERENCES business_objects(id) ON DELETE CASCADE,
            FOREIGN KEY(exchange_id) REFERENCES http_exchanges(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_bo_identifiers_name ON business_object_identifiers(normalized_name, object_type_id);
        CREATE INDEX IF NOT EXISTS idx_bo_objects_type ON business_objects(object_type_id, last_seen_at);
        CREATE INDEX IF NOT EXISTS idx_bo_obs_object ON business_object_observations(business_object_id, observed_at, exchange_id);
        CREATE INDEX IF NOT EXISTS idx_bo_obs_exchange ON business_object_observations(exchange_id, business_object_id);
        CREATE INDEX IF NOT EXISTS idx_bo_obs_host ON business_object_observations(host_id, business_object_id);
        CREATE INDEX IF NOT EXISTS idx_bo_rel_a ON business_object_relation_observations(object_a_id, object_b_id);
        CREATE INDEX IF NOT EXISTS idx_bo_rel_b ON business_object_relation_observations(object_b_id, object_a_id);
        """
    )


def _name_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())[:120]


def _normalize_name(value: str) -> str:
    raw = str(value or "").strip().lower().replace("-", "_")
    return re.sub(r"[^a-z0-9_]", "", raw)[:160]


def _identifierish(name: str, location: str = "") -> bool:
    n = _normalize_name(name)
    hay = f"{n} {str(location or '').lower()}"
    if any(x in hay for x in SENSITIVE_HINTS):
        return False
    if any(x == n or x in n for x in STATE_HINTS):
        return False
    if n == "id" or n.endswith("id") or n.endswith("_id") or n.endswith("uuid") or n.endswith("_uuid"):
        return True
    return any(x in hay for x in IDENTIFIER_HINTS)


def _infer_type(identifier_name: str) -> str:
    n = _normalize_name(identifier_name)
    compact = n.replace("_", "")
    for suffix in ("identifier", "uuid", "id"):
        if compact.endswith(suffix):
            compact = compact[: -len(suffix)]
            break
    if compact.endswith("s") and len(compact) > 3:
        compact = compact[:-1]
    return compact[:1].upper() + compact[1:] if compact else "Object"


def _normalize_path(path: str) -> str:
    parts: list[str] = []
    for seg in str(path or "").split("/"):
        if not seg:
            continue
        if re.fullmatch(r"\d{2,}", seg) or re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", seg) or (
            len(seg) >= 8 and any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg)
        ):
            parts.append("{id}")
        else:
            parts.append(seg)
    return "/" + "/".join(parts)


def _safe_value(value: Any, limit: int = 180) -> str:
    text = str(value if value is not None else "").replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _valid_identifier_value(value: Any) -> bool:
    text = str(value if value is not None else "").strip()
    if not text:
        return False
    if text.lower() in GENERIC_VALUES:
        return False
    if len(text) > 2000:
        return False
    return True


def ensure_type(conn, name: str) -> int:
    init_schema(conn)
    display = str(name or "").strip()[:100]
    if not display:
        raise ValueError("Object type requerido")
    key = _name_key(display)
    if not key:
        raise ValueError("Object type inválido")
    now = now_iso()
    conn.execute(
        """INSERT INTO business_object_types(name,name_key,created_at,updated_at) VALUES(?,?,?,?)
           ON CONFLICT(name_key) DO UPDATE SET updated_at=excluded.updated_at""",
        (display, key, now, now),
    )
    row = conn.execute("SELECT id FROM business_object_types WHERE name_key=?", (key,)).fetchone()
    return int(row["id"])


def ensure_identifier(conn, object_type: str, normalized_name: str, *, source_observation_id: int | None = None) -> int:
    """Teach one alias/identifier field for a Business Object type.

    `Order` may therefore recognize `orderId`, `order_id` and a host-specific
    `id` if the researcher explicitly teaches those fields.
    """
    init_schema(conn)
    name = _normalize_name(normalized_name)
    if not name:
        raise ValueError("Identifier field requerido")
    type_id = ensure_type(conn, object_type)
    now = now_iso()
    conn.execute(
        """INSERT INTO business_object_identifiers(object_type_id,normalized_name,source_observation_id,created_at,updated_at)
           VALUES(?,?,?,?,?)
           ON CONFLICT(object_type_id,normalized_name) DO UPDATE SET
             source_observation_id=COALESCE(business_object_identifiers.source_observation_id,excluded.source_observation_id),
             updated_at=excluded.updated_at""",
        (type_id, name, source_observation_id, now, now),
    )
    row = conn.execute(
        "SELECT id FROM business_object_identifiers WHERE object_type_id=? AND normalized_name=?",
        (type_id, name),
    ).fetchone()
    identifier_id = int(row["id"])
    refresh_identifier(conn, identifier_id)
    return identifier_id


def track_observation(conn, observation_id: int, object_type: str = "") -> dict[str, Any]:
    init_schema(conn)
    obs = conn.execute("SELECT * FROM parameter_observations WHERE id=?", (int(observation_id),)).fetchone()
    if not obs:
        raise ValueError("Observación no encontrada")
    name = str(obs["normalized_name"] or obs["name"] or "")
    if not _identifierish(name, str(obs["location"] or "")):
        raise ValueError("El campo seleccionado no parece un identificador de objeto")
    inferred = str(object_type or _infer_type(name)).strip()
    identifier_id = ensure_identifier(conn, inferred, name, source_observation_id=int(observation_id))
    ident = conn.execute(
        """SELECT bi.*,bt.name object_type FROM business_object_identifiers bi
           JOIN business_object_types bt ON bt.id=bi.object_type_id WHERE bi.id=?""",
        (identifier_id,),
    ).fetchone()
    obj = conn.execute(
        """SELECT bo.id FROM business_objects bo JOIN business_object_types bt ON bt.id=bo.object_type_id
           WHERE bo.object_type_id=? AND bo.identifier_hash=?""",
        (int(ident["object_type_id"]), str(obs["value_hash"])),
    ).fetchone()
    return {
        "identifier_id": identifier_id,
        "object_type_id": int(ident["object_type_id"]),
        "object_type": str(ident["object_type"]),
        "business_object_id": int(obj["id"]) if obj else None,
    }


def _observe_identifier_row(conn, identifier: dict[str, Any], obs: dict[str, Any]) -> int | None:
    value_raw = str(obs.get("value_raw") or obs.get("value_preview") or "")
    if not _valid_identifier_value(value_raw):
        return None
    now = now_iso()
    value_hash = str(obs.get("value_hash") or "")
    if not value_hash:
        return None
    observed_at = str(obs.get("first_seen_at") or now)
    conn.execute(
        """INSERT INTO business_objects(object_type_id,identifier_hash,identifier_preview,identifier_raw,first_seen_at,last_seen_at,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(object_type_id,identifier_hash) DO UPDATE SET
             identifier_preview=COALESCE(business_objects.identifier_preview,excluded.identifier_preview),
             identifier_raw=COALESCE(business_objects.identifier_raw,excluded.identifier_raw),
             first_seen_at=CASE WHEN business_objects.first_seen_at<=excluded.first_seen_at THEN business_objects.first_seen_at ELSE excluded.first_seen_at END,
             last_seen_at=CASE WHEN business_objects.last_seen_at>=excluded.last_seen_at THEN business_objects.last_seen_at ELSE excluded.last_seen_at END,
             updated_at=excluded.updated_at""",
        (
            int(identifier["object_type_id"]), value_hash, _safe_value(obs.get("value_preview") or value_raw), value_raw,
            observed_at, observed_at, now, now,
        ),
    )
    obj = conn.execute(
        "SELECT id FROM business_objects WHERE object_type_id=? AND identifier_hash=?",
        (int(identifier["object_type_id"]), value_hash),
    ).fetchone()
    if not obj:
        return None
    object_id = int(obj["id"])
    conn.execute(
        """INSERT INTO business_object_observations(
               business_object_id,identifier_id,parameter_observation_id,exchange_id,resource_id,host_id,source_location,observed_at,created_at)
           SELECT ?,?,?,?,?,r.host_id,?,?,? FROM resources r WHERE r.id=?
           ON CONFLICT(identifier_id,parameter_observation_id) DO UPDATE SET
             business_object_id=excluded.business_object_id,exchange_id=excluded.exchange_id,
             resource_id=excluded.resource_id,host_id=excluded.host_id,source_location=excluded.source_location,observed_at=excluded.observed_at""",
        (
            object_id, int(identifier["id"]), int(obs["id"]), int(obs["exchange_id"]), int(obs["resource_id"]),
            str(obs.get("location") or "")[:300], observed_at, now, int(obs["resource_id"]),
        ),
    )
    return object_id


def refresh_relations_for_exchange(conn, exchange_id: int) -> int:
    init_schema(conn)
    ids = [int(r["business_object_id"]) for r in conn.execute(
        "SELECT DISTINCT business_object_id FROM business_object_observations WHERE exchange_id=? ORDER BY business_object_id",
        (int(exchange_id),),
    ).fetchall()]
    added = 0
    now = now_iso()
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            a, b = sorted((ids[i], ids[j]))
            cur = conn.execute(
                """INSERT OR IGNORE INTO business_object_relation_observations(object_a_id,object_b_id,exchange_id,relation_type,created_at)
                   VALUES(?,?,?,?,?)""",
                (a, b, int(exchange_id), "co_observed", now),
            )
            added += max(0, int(cur.rowcount or 0))
    return added


def refresh_identifier(conn, identifier_id: int) -> dict[str, int]:
    init_schema(conn)
    ident_row = conn.execute("SELECT * FROM business_object_identifiers WHERE id=?", (int(identifier_id),)).fetchone()
    if not ident_row:
        raise ValueError("Identifier definition no encontrada")
    ident = dict(ident_row)
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM parameter_observations WHERE normalized_name=? ORDER BY exchange_id,id",
        (str(ident["normalized_name"]),),
    ).fetchall()]
    object_ids: set[int] = set()
    exchange_ids: set[int] = set()
    for obs in rows:
        object_id = _observe_identifier_row(conn, ident, obs)
        if object_id:
            object_ids.add(object_id)
            exchange_ids.add(int(obs["exchange_id"]))
    for exchange_id in exchange_ids:
        refresh_relations_for_exchange(conn, exchange_id)
    return {"observations": len(rows), "objects": len(object_ids), "exchanges": len(exchange_ids)}


def refresh_exchange(conn, exchange_id: int) -> dict[str, int]:
    """Apply currently taught Business Object identifiers to one captured exchange."""
    init_schema(conn)
    rows = [dict(r) for r in conn.execute(
        """SELECT p.*,bi.id identifier_id,bi.object_type_id
           FROM parameter_observations p JOIN business_object_identifiers bi ON bi.normalized_name=p.normalized_name
           WHERE p.exchange_id=? ORDER BY p.id,bi.id""",
        (int(exchange_id),),
    ).fetchall()]
    observed: set[int] = set()
    for row in rows:
        ident = {"id": int(row["identifier_id"]), "object_type_id": int(row["object_type_id"])}
        object_id = _observe_identifier_row(conn, ident, row)
        if object_id:
            observed.add(object_id)
    relations = refresh_relations_for_exchange(conn, int(exchange_id)) if observed else 0
    return {"objects": len(observed), "relations_added": relations}


def rebuild(conn) -> dict[str, int]:
    init_schema(conn)
    conn.execute("DELETE FROM business_object_relation_observations")
    conn.execute("DELETE FROM business_object_observations")
    conn.execute("DELETE FROM business_objects")
    identifiers = [int(r["id"]) for r in conn.execute("SELECT id FROM business_object_identifiers ORDER BY id").fetchall()]
    obs_count = 0
    for identifier_id in identifiers:
        result = refresh_identifier(conn, identifier_id)
        obs_count += int(result.get("observations", 0))
    return {
        "identifiers": len(identifiers),
        "objects": int(conn.execute("SELECT COUNT(*) c FROM business_objects").fetchone()["c"] or 0),
        "observations": int(conn.execute("SELECT COUNT(*) c FROM business_object_observations").fetchone()["c"] or 0),
        "relations": int(conn.execute("SELECT COUNT(*) c FROM business_object_relation_observations").fetchone()["c"] or 0),
        "source_observations_scanned": obs_count,
    }


def list_types(conn) -> list[dict[str, Any]]:
    init_schema(conn)
    return [dict(r) for r in conn.execute(
        """SELECT bt.*,
                  (SELECT COUNT(*) FROM business_object_identifiers bi WHERE bi.object_type_id=bt.id) identifier_count,
                  (SELECT COUNT(*) FROM business_objects bo WHERE bo.object_type_id=bt.id) object_count,
                  (SELECT COUNT(DISTINCT boo.host_id) FROM business_object_observations boo JOIN business_objects bo ON bo.id=boo.business_object_id WHERE bo.object_type_id=bt.id) host_count,
                  (SELECT COUNT(*) FROM business_objects bo WHERE bo.object_type_id=bt.id AND (SELECT COUNT(DISTINCT host_id) FROM business_object_observations x WHERE x.business_object_id=bo.id)>1) cross_host_objects
           FROM business_object_types bt ORDER BY lower(bt.name)"""
    ).fetchall()]


def candidate_identifiers(conn, *, limit: int = 80) -> list[dict[str, Any]]:
    init_schema(conn)
    tracked = {str(r["normalized_name"]) for r in conn.execute("SELECT normalized_name FROM business_object_identifiers").fetchall()}
    rows = [dict(r) for r in conn.execute(
        """SELECT p.normalized_name,MIN(p.name) name,COUNT(*) observations,COUNT(DISTINCT p.value_hash) distinct_values,
                  COUNT(DISTINCT p.exchange_id) exchanges,COUNT(DISTINCT h.hostname) hosts,MAX(p.first_seen_at) last_seen_at,
                  MIN(p.id) sample_observation_id,MIN(p.location) sample_location
           FROM parameter_observations p JOIN resources r ON r.id=p.resource_id JOIN hosts h ON h.id=r.host_id
           GROUP BY p.normalized_name ORDER BY observations DESC LIMIT 500"""
    ).fetchall()]
    out: list[dict[str, Any]] = []
    for row in rows:
        name = str(row["normalized_name"] or "")
        if name in tracked or not _identifierish(name, str(row.get("sample_location") or "")):
            continue
        row["suggested_type"] = _infer_type(name)
        out.append(row)
        if len(out) >= max(1, min(int(limit), 200)):
            break
    return out


def list_objects(conn, *, type_id: int | None = None, q: str = "", limit: int = 300) -> list[dict[str, Any]]:
    init_schema(conn)
    where: list[str] = []
    args: list[Any] = []
    if type_id:
        where.append("bo.object_type_id=?")
        args.append(int(type_id))
    if str(q or "").strip():
        where.append("(lower(COALESCE(bo.identifier_raw,bo.identifier_preview,'')) LIKE ? OR lower(bt.name) LIKE ?)")
        needle = f"%{str(q).strip().lower()}%"
        args.extend([needle, needle])
    sql = """
        SELECT bo.*,bt.name object_type,
               (SELECT COUNT(*) FROM business_object_observations x WHERE x.business_object_id=bo.id) observation_count,
               (SELECT COUNT(DISTINCT host_id) FROM business_object_observations x WHERE x.business_object_id=bo.id) host_count,
               (SELECT COUNT(DISTINCT COALESCE(ei.identity_id,0)) FROM business_object_observations x LEFT JOIN exchange_identities ei ON ei.exchange_id=x.exchange_id WHERE x.business_object_id=bo.id AND ei.identity_id IS NOT NULL) identity_count,
               (SELECT COUNT(DISTINCT CASE WHEN rr.object_a_id=bo.id THEN rr.object_b_id ELSE rr.object_a_id END) FROM business_object_relation_observations rr WHERE rr.object_a_id=bo.id OR rr.object_b_id=bo.id) relation_count
        FROM business_objects bo JOIN business_object_types bt ON bt.id=bo.object_type_id
    """
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY bo.last_seen_at DESC,bo.id DESC LIMIT ?"
    args.append(max(1, min(int(limit), 1000)))
    rows = [dict(r) for r in conn.execute(sql, args).fetchall()]
    for row in rows:
        row["cross_host"] = int(row.get("host_count") or 0) > 1
    return rows


def _observation_rows(conn, object_id: int) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute(
        """SELECT boo.*,bi.normalized_name identifier_name,h.hostname,r.path,r.url,o.method,e.status_code,e.first_seen_at,
                  ei.identity_id,i.name identity_name,ei.context_id,ic.label context_label
           FROM business_object_observations boo
           JOIN business_object_identifiers bi ON bi.id=boo.identifier_id
           JOIN http_exchanges e ON e.id=boo.exchange_id JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=boo.resource_id JOIN hosts h ON h.id=boo.host_id
           LEFT JOIN exchange_identities ei ON ei.exchange_id=boo.exchange_id
           LEFT JOIN identities i ON i.id=ei.identity_id LEFT JOIN identity_contexts ic ON ic.id=ei.context_id
           WHERE boo.business_object_id=? ORDER BY e.first_seen_at,boo.id""",
        (int(object_id),),
    ).fetchall()]


def _related_objects(conn, object_id: int) -> list[dict[str, Any]]:
    rows = [dict(r) for r in conn.execute(
        """SELECT other.id,other.identifier_raw,other.identifier_preview,bt.name object_type,
                  COUNT(DISTINCT rel.exchange_id) occurrences,MIN(rel.created_at) first_seen_at,MAX(rel.created_at) last_seen_at
           FROM business_object_relation_observations rel
           JOIN business_objects other ON other.id=CASE WHEN rel.object_a_id=? THEN rel.object_b_id ELSE rel.object_a_id END
           JOIN business_object_types bt ON bt.id=other.object_type_id
           WHERE rel.object_a_id=? OR rel.object_b_id=?
           GROUP BY other.id ORDER BY occurrences DESC,lower(bt.name),other.id""",
        (int(object_id), int(object_id), int(object_id)),
    ).fetchall()]
    return rows


def _state_rows(conn, object_type: str, identifier_hash: str) -> list[dict[str, Any]]:
    # State tracking predates Business Objects. Bind conservatively by explicit
    # object type name + exact identifier hash; no semantic guessing is performed.
    try:
        rows = [dict(r) for r in conn.execute(
            """SELECT bso.*,bst.state_field,bst.object_identifier_name,h.hostname,r.id resource_id,r.path,o.method,
                      ei.identity_id,i.name identity_name
               FROM business_state_observations bso JOIN business_state_tracks bst ON bst.id=bso.track_id
               JOIN http_exchanges e ON e.id=bso.exchange_id JOIN resource_operations o ON o.id=e.operation_id
               JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id
               LEFT JOIN exchange_identities ei ON ei.exchange_id=e.id LEFT JOIN identities i ON i.id=ei.identity_id
               WHERE lower(bst.object_type)=lower(?) AND bso.object_identifier_value_hash=?
               ORDER BY bso.observed_at,bso.id""",
            (str(object_type), str(identifier_hash)),
        ).fetchall()]
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    last_by_field: dict[str, str] = {}
    for row in rows:
        field = str(row.get("state_field") or "state")
        value = str(row.get("state_value_raw") or row.get("state_value_preview") or "")
        if last_by_field.get(field) == value:
            continue
        last_by_field[field] = value
        row["state"] = value
        out.append(row)
    return out


def _peer_object_ids(conn, object_type_id: int, current_id: int) -> list[int]:
    return [int(r["id"]) for r in conn.execute(
        "SELECT id FROM business_objects WHERE object_type_id=? AND id<>? ORDER BY id",
        (int(object_type_id), int(current_id)),
    ).fetchall()]


def _set_baseline(values: list[frozenset[str]], *, minimum: int = 3, ratio: float = 0.6) -> tuple[frozenset[str] | None, int, int]:
    if not values:
        return None, 0, 0
    counts = Counter(values)
    baseline, count = counts.most_common(1)[0]
    total = len(values)
    if count < minimum or count / max(1, total) < ratio:
        return None, count, total
    return baseline, count, total


def pattern_anomalies(conn, object_id: int) -> list[dict[str, Any]]:
    """Return differences from repeated peer patterns, never vulnerability verdicts."""
    init_schema(conn)
    obj = conn.execute(
        """SELECT bo.*,bt.name object_type FROM business_objects bo JOIN business_object_types bt ON bt.id=bo.object_type_id WHERE bo.id=?""",
        (int(object_id),),
    ).fetchone()
    if not obj:
        return []
    observations = _observation_rows(conn, int(object_id))
    peer_ids = _peer_object_ids(conn, int(obj["object_type_id"]), int(object_id))
    if not peer_ids:
        return []
    peer_observations = {peer_id: _observation_rows(conn, peer_id) for peer_id in peer_ids}
    anomalies: list[dict[str, Any]] = []

    # 1) Status pattern: same normalized operation + same identity, peers repeatedly
    # produce one status but this object produced another.
    current_by_key: dict[tuple[str, int], set[int]] = defaultdict(set)
    for row in observations:
        sig = f"{str(row.get('method') or '').upper()} {_normalize_path(str(row.get('path') or ''))}"
        identity_id = int(row["identity_id"]) if row.get("identity_id") else 0
        if row.get("status_code") is not None:
            current_by_key[(sig, identity_id)].add(int(row["status_code"]))
    for (sig, identity_id), current_statuses in current_by_key.items():
        peer_statuses: list[int] = []
        for peer_id in peer_ids:
            seen_for_peer: set[int] = set()
            for row in peer_observations.get(peer_id, []):
                psig = f"{str(row.get('method') or '').upper()} {_normalize_path(str(row.get('path') or ''))}"
                pid = int(row["identity_id"]) if row.get("identity_id") else 0
                if psig == sig and pid == identity_id and row.get("status_code") is not None:
                    seen_for_peer.add(int(row["status_code"]))
            # Count a peer only when its observation is unambiguous for this key.
            if len(seen_for_peer) == 1:
                peer_statuses.append(next(iter(seen_for_peer)))
        if len(peer_statuses) < 3:
            continue
        dominant, count = Counter(peer_statuses).most_common(1)[0]
        if count < 3 or count / len(peer_statuses) < 0.75:
            continue
        different = sorted(s for s in current_statuses if s != dominant)
        if different:
            identity_name = next((str(r.get("identity_name")) for r in observations if (int(r["identity_id"]) if r.get("identity_id") else 0) == identity_id and r.get("identity_name")), "Anonymous / Unknown" if not identity_id else f"Identity #{identity_id}")
            anomalies.append({
                "kind": "status_pattern", "title": "Resultado HTTP diferente al patrón observado",
                "operation": sig, "identity_id": identity_id or None, "identity_name": identity_name,
                "baseline": str(dominant), "current": ", ".join(str(x) for x in different),
                "peer_count": len(peer_statuses), "baseline_count": count,
                "message": f"Para {identity_name} en {sig}, {count}/{len(peer_statuses)} objetos comparables devolvieron HTTP {dominant}; esta instancia también mostró {', '.join(str(x) for x in different)}.",
            })

    # Helper sets per object for relation/identity/host spread patterns.
    def relation_types(oid: int) -> frozenset[str]:
        rows = conn.execute(
            """SELECT DISTINCT bt.name FROM business_object_relation_observations rel
               JOIN business_objects other ON other.id=CASE WHEN rel.object_a_id=? THEN rel.object_b_id ELSE rel.object_a_id END
               JOIN business_object_types bt ON bt.id=other.object_type_id
               WHERE rel.object_a_id=? OR rel.object_b_id=?""",
            (oid, oid, oid),
        ).fetchall()
        return frozenset(str(r["name"]) for r in rows)

    def identity_names(oid: int) -> frozenset[str]:
        rows = conn.execute(
            """SELECT DISTINCT COALESCE(i.name,'') name FROM business_object_observations boo
               LEFT JOIN exchange_identities ei ON ei.exchange_id=boo.exchange_id LEFT JOIN identities i ON i.id=ei.identity_id
               WHERE boo.business_object_id=? AND ei.identity_id IS NOT NULL""", (oid,)
        ).fetchall()
        return frozenset(str(r["name"] or "") for r in rows if str(r["name"] or ""))

    def host_names(oid: int) -> frozenset[str]:
        return frozenset(str(r["hostname"]) for r in conn.execute(
            """SELECT DISTINCT h.hostname FROM business_object_observations boo JOIN hosts h ON h.id=boo.host_id
               WHERE boo.business_object_id=?""", (oid,)
        ).fetchall())

    current_rel = relation_types(int(object_id))
    peer_rel = [relation_types(x) for x in peer_ids]
    baseline_rel, count_rel, total_rel = _set_baseline(peer_rel)
    if baseline_rel is not None and current_rel != baseline_rel:
        missing = sorted(baseline_rel - current_rel)
        extra = sorted(current_rel - baseline_rel)
        anomalies.append({
            "kind": "relationship_pattern", "title": "Relaciones diferentes al patrón observado",
            "baseline": ", ".join(sorted(baseline_rel)) or "(sin relaciones)",
            "current": ", ".join(sorted(current_rel)) or "(sin relaciones)",
            "missing": missing, "extra": extra, "peer_count": total_rel, "baseline_count": count_rel,
            "message": f"{count_rel}/{total_rel} objetos comparables mostraron el mismo conjunto de tipos relacionados. Esta instancia difiere en la evidencia observada hasta ahora.",
        })

    current_ids = identity_names(int(object_id))
    peer_id_sets = [identity_names(x) for x in peer_ids]
    # Compare count rather than exact account names: peers naturally belong to different users.
    peer_counts = [len(x) for x in peer_id_sets]
    if peer_counts:
        dominant_count, dom_n = Counter(peer_counts).most_common(1)[0]
        if dom_n >= 3 and dom_n / len(peer_counts) >= 0.7 and len(current_ids) != dominant_count:
            anomalies.append({
                "kind": "identity_spread", "title": "Cobertura de identidades diferente",
                "baseline": f"{dominant_count} identidad(es)", "current": f"{len(current_ids)} identidad(es)",
                "identities": sorted(current_ids), "peer_count": len(peer_counts), "baseline_count": dom_n,
                "message": f"{dom_n}/{len(peer_counts)} objetos comparables fueron observados con {dominant_count} identidad(es); esta instancia aparece con {len(current_ids)}.",
            })

    current_hosts = host_names(int(object_id))
    peer_hosts = [host_names(x) for x in peer_ids]
    baseline_hosts, count_hosts, total_hosts = _set_baseline(peer_hosts)
    if baseline_hosts is not None and current_hosts != baseline_hosts:
        anomalies.append({
            "kind": "host_spread", "title": "Recorrido cross-host diferente",
            "baseline": ", ".join(sorted(baseline_hosts)) or "(sin hosts)",
            "current": ", ".join(sorted(current_hosts)) or "(sin hosts)",
            "missing": sorted(baseline_hosts - current_hosts), "extra": sorted(current_hosts - baseline_hosts),
            "peer_count": total_hosts, "baseline_count": count_hosts,
            "message": f"{count_hosts}/{total_hosts} objetos comparables aparecieron en el mismo conjunto de hosts; esta instancia tiene una huella de hosts distinta.",
        })

    return anomalies


def object_detail(conn, object_id: int) -> dict[str, Any] | None:
    init_schema(conn)
    obj = conn.execute(
        """SELECT bo.*,bt.name object_type FROM business_objects bo JOIN business_object_types bt ON bt.id=bo.object_type_id WHERE bo.id=?""",
        (int(object_id),),
    ).fetchone()
    if not obj:
        return None
    base = dict(obj)
    observations = _observation_rows(conn, int(object_id))
    # Deduplicate multiple identifier aliases seen in the exact same exchange for timeline readability.
    timeline: list[dict[str, Any]] = []
    seen_exchange: set[int] = set()
    for row in observations:
        eid = int(row["exchange_id"])
        if eid in seen_exchange:
            continue
        seen_exchange.add(eid)
        timeline.append(row)
    hosts = [dict(r) for r in conn.execute(
        """SELECT h.id,h.hostname,COUNT(DISTINCT boo.exchange_id) exchanges,MIN(boo.observed_at) first_seen_at,MAX(boo.observed_at) last_seen_at
           FROM business_object_observations boo JOIN hosts h ON h.id=boo.host_id WHERE boo.business_object_id=?
           GROUP BY h.id ORDER BY exchanges DESC,lower(h.hostname)""", (int(object_id),)
    ).fetchall()]
    identities = [dict(r) for r in conn.execute(
        """SELECT i.id,i.name,COUNT(DISTINCT boo.exchange_id) exchanges,MIN(boo.observed_at) first_seen_at,MAX(boo.observed_at) last_seen_at
           FROM business_object_observations boo JOIN exchange_identities ei ON ei.exchange_id=boo.exchange_id
           JOIN identities i ON i.id=ei.identity_id WHERE boo.business_object_id=? GROUP BY i.id ORDER BY exchanges DESC,lower(i.name)""",
        (int(object_id),),
    ).fetchall()]
    aliases = [dict(r) for r in conn.execute(
        """SELECT bi.id,bi.normalized_name,COUNT(boo.id) observations FROM business_object_identifiers bi
           LEFT JOIN business_object_observations boo ON boo.identifier_id=bi.id AND boo.business_object_id=?
           WHERE bi.object_type_id=? GROUP BY bi.id ORDER BY observations DESC,bi.normalized_name""",
        (int(object_id), int(base["object_type_id"])),
    ).fetchall()]
    flows = [dict(r) for r in conn.execute(
        """SELECT f.id,f.name,COUNT(DISTINCT fs.id) steps FROM business_object_observations boo
           JOIN flow_steps fs ON fs.exchange_id=boo.exchange_id AND fs.included=1 JOIN flows f ON f.id=fs.flow_id
           WHERE boo.business_object_id=? GROUP BY f.id ORDER BY f.updated_at DESC""", (int(object_id),)
    ).fetchall()]
    states = _state_rows(conn, str(base["object_type"]), str(base["identifier_hash"]))
    related = _related_objects(conn, int(object_id))
    anomalies = pattern_anomalies(conn, int(object_id))
    base["display_value"] = str(base.get("identifier_raw") or base.get("identifier_preview") or "")
    base["cross_host"] = len(hosts) > 1
    return {
        "object": base, "observations": observations, "timeline": timeline, "hosts": hosts, "identities": identities,
        "aliases": aliases, "flows": flows, "states": states, "related": related, "anomalies": anomalies,
    }


def objects_for_flow(conn, flow_id: int) -> list[dict[str, Any]]:
    init_schema(conn)
    return [dict(r) for r in conn.execute(
        """SELECT bo.id,bo.identifier_raw,bo.identifier_preview,bt.name object_type,
                  COUNT(DISTINCT fs.id) step_count,COUNT(DISTINCT boo.host_id) host_count,MIN(fs.position) first_position
           FROM flow_steps fs JOIN business_object_observations boo ON boo.exchange_id=fs.exchange_id
           JOIN business_objects bo ON bo.id=boo.business_object_id JOIN business_object_types bt ON bt.id=bo.object_type_id
           WHERE fs.flow_id=? AND fs.included=1
           GROUP BY bo.id ORDER BY first_position,lower(bt.name),bo.id""",
        (int(flow_id),),
    ).fetchall()]


def overview(conn, *, q: str = "", type_id: int | None = None, limit: int = 250) -> dict[str, Any]:
    init_schema(conn)
    types = list_types(conn)
    objects = list_objects(conn, type_id=type_id, q=q, limit=limit)
    candidates = candidate_identifiers(conn, limit=50)
    stats_row = conn.execute(
        """SELECT (SELECT COUNT(*) FROM business_object_types) types,
                  (SELECT COUNT(*) FROM business_object_identifiers) identifiers,
                  (SELECT COUNT(*) FROM business_objects) objects,
                  (SELECT COUNT(*) FROM business_object_observations) observations,
                  (SELECT COUNT(*) FROM business_object_relation_observations) relation_observations,
                  (SELECT COUNT(*) FROM business_objects bo WHERE (SELECT COUNT(DISTINCT host_id) FROM business_object_observations x WHERE x.business_object_id=bo.id)>1) cross_host_objects"""
    ).fetchone()
    # Keep page cost bounded. Only evaluate recent/high-evidence objects for pattern cards.
    anomaly_cards: list[dict[str, Any]] = []
    for obj in objects[:24]:
        items = pattern_anomalies(conn, int(obj["id"]))
        if items:
            anomaly_cards.append({"object": obj, "items": items})
            if len(anomaly_cards) >= 20:
                break
    return {"stats": dict(stats_row), "types": types, "objects": objects, "candidates": candidates, "anomaly_cards": anomaly_cards}
