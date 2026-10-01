#!/usr/bin/env python3
"""Human-taught Custom Signals for Negro.

Custom Signals reuse the existing signal_occurrences pipeline. A rule is a
project-local deterministic matcher over evidence Negro already captured; it
never sends network traffic and never creates a vulnerability verdict.
"""
from __future__ import annotations

import base64
import fnmatch
import json
import re
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_schema(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS custom_signal_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT NOT NULL DEFAULT 'other',
            severity TEXT NOT NULL DEFAULT 'info',
            enabled INTEGER NOT NULL DEFAULT 1,
            methods_json TEXT NOT NULL DEFAULT '[]',
            statuses_json TEXT NOT NULL DEFAULT '[]',
            path_terms_json TEXT NOT NULL DEFAULT '[]',
            parameter_names_json TEXT NOT NULL DEFAULT '[]',
            request_terms_json TEXT NOT NULL DEFAULT '[]',
            response_terms_json TEXT NOT NULL DEFAULT '[]',
            header_names_json TEXT NOT NULL DEFAULT '[]',
            object_types_json TEXT NOT NULL DEFAULT '[]',
            identity_mode TEXT NOT NULL DEFAULT 'any',
            suggested_action TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_custom_signal_rules_enabled ON custom_signal_rules(enabled, updated_at);
        """
    )
    signal_cols = {row["name"] for row in conn.execute("PRAGMA table_info(signal_occurrences)")}
    if signal_cols and "signal_level" not in signal_cols:
        conn.execute("ALTER TABLE signal_occurrences ADD COLUMN signal_level TEXT NOT NULL DEFAULT 'local'")


def _loads_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    try:
        data = json.loads(value or "[]")
    except Exception:
        data = []
    return [str(x).strip() for x in data if str(x).strip()] if isinstance(data, list) else []


def _rule_dict(row) -> dict[str, Any]:
    item = dict(row)
    for key in (
        "methods_json", "statuses_json", "path_terms_json", "parameter_names_json",
        "request_terms_json", "response_terms_json", "header_names_json", "object_types_json",
    ):
        item[key[:-5]] = _loads_list(item.get(key))
    item["enabled"] = bool(item.get("enabled"))
    return item


def list_rules(conn) -> list[dict[str, Any]]:
    init_schema(conn)
    rows = conn.execute(
        """SELECT r.*,
                  (SELECT COUNT(*) FROM signal_occurrences s WHERE s.kind='custom_signal:'||r.id AND s.dismissed_at IS NULL) signal_count,
                  (SELECT COUNT(*) FROM signal_occurrences s WHERE s.kind='custom_signal:'||r.id AND s.dismissed_at IS NULL AND s.reviewed_at IS NULL) pending_count
           FROM custom_signal_rules r ORDER BY r.enabled DESC, lower(r.name), r.id"""
    ).fetchall()
    return [_rule_dict(r) for r in rows]


def get_rule(conn, rule_id: int) -> dict[str, Any] | None:
    init_schema(conn)
    row = conn.execute("SELECT * FROM custom_signal_rules WHERE id=?", (int(rule_id),)).fetchone()
    return _rule_dict(row) if row else None


def _clean_list(values: list[str] | tuple[str, ...] | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values or []:
        item = str(raw or "").strip()
        if not item:
            continue
        low = item.lower()
        if low in seen:
            continue
        seen.add(low); out.append(item)
    return out


def save_rule(conn, *, rule_id: int | None = None, name: str, description: str = "", category: str = "other",
              severity: str = "info", enabled: bool = True, methods: list[str] | None = None,
              statuses: list[str] | None = None, path_terms: list[str] | None = None,
              parameter_names: list[str] | None = None, request_terms: list[str] | None = None,
              response_terms: list[str] | None = None, header_names: list[str] | None = None,
              object_types: list[str] | None = None, identity_mode: str = "any",
              suggested_action: str = "") -> int:
    init_schema(conn)
    name = str(name or "").strip()
    if not name:
        raise ValueError("El nombre de la regla es obligatorio")
    category = str(category or "other").strip().lower() or "other"
    severity = str(severity or "info").strip().lower()
    if severity not in {"info", "low", "medium", "high"}:
        severity = "info"
    identity_mode = str(identity_mode or "any").strip().lower()
    if identity_mode not in {"any", "present", "absent"}:
        identity_mode = "any"
    payload = {
        "methods_json": json.dumps([x.upper() for x in _clean_list(methods)], ensure_ascii=False),
        "statuses_json": json.dumps(_clean_list(statuses), ensure_ascii=False),
        "path_terms_json": json.dumps(_clean_list(path_terms), ensure_ascii=False),
        "parameter_names_json": json.dumps(_clean_list(parameter_names), ensure_ascii=False),
        "request_terms_json": json.dumps(_clean_list(request_terms), ensure_ascii=False),
        "response_terms_json": json.dumps(_clean_list(response_terms), ensure_ascii=False),
        "header_names_json": json.dumps(_clean_list(header_names), ensure_ascii=False),
        "object_types_json": json.dumps(_clean_list(object_types), ensure_ascii=False),
    }
    has_condition = any(json.loads(v) for v in payload.values()) or identity_mode != "any"
    if not has_condition:
        raise ValueError("Define al menos una condición para que la regla no coincida con todo")
    now = _now()
    values = (
        name, str(description or "").strip(), category, severity, 1 if enabled else 0,
        payload["methods_json"], payload["statuses_json"], payload["path_terms_json"],
        payload["parameter_names_json"], payload["request_terms_json"], payload["response_terms_json"],
        payload["header_names_json"], payload["object_types_json"], identity_mode,
        str(suggested_action or "").strip(), now,
    )
    if rule_id:
        exists = conn.execute("SELECT id FROM custom_signal_rules WHERE id=?", (int(rule_id),)).fetchone()
        if not exists:
            raise ValueError("Custom Signal no encontrado")
        conn.execute(
            """UPDATE custom_signal_rules SET name=?,description=?,category=?,severity=?,enabled=?,methods_json=?,statuses_json=?,path_terms_json=?,parameter_names_json=?,request_terms_json=?,response_terms_json=?,header_names_json=?,object_types_json=?,identity_mode=?,suggested_action=?,updated_at=? WHERE id=?""",
            (*values, int(rule_id)),
        )
        return int(rule_id)
    cur = conn.execute(
        """INSERT INTO custom_signal_rules(name,description,category,severity,enabled,methods_json,statuses_json,path_terms_json,parameter_names_json,request_terms_json,response_terms_json,header_names_json,object_types_json,identity_mode,suggested_action,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (*values[:-1], now, now),
    )
    return int(cur.lastrowid)


def delete_rule(conn, rule_id: int) -> None:
    init_schema(conn)
    conn.execute("DELETE FROM signal_occurrences WHERE kind=?", (f"custom_signal:{int(rule_id)}",))
    conn.execute("DELETE FROM custom_signal_rules WHERE id=?", (int(rule_id),))


def _decode(value: Any) -> str:
    try:
        return base64.b64decode(str(value or ""), validate=False).decode("utf-8", errors="replace") if value else ""
    except Exception:
        return ""


def _headers(value: Any) -> dict[str, str]:
    try:
        data = json.loads(value or "[]") if not isinstance(value, (list, dict)) else value
    except Exception:
        data = []
    out: dict[str, str] = {}
    if isinstance(data, dict):
        for k, v in data.items(): out[str(k).lower()] = str(v)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                name = str(item.get("name") or item.get("key") or "").strip()
                val = str(item.get("value") or "")
                if name: out[name.lower()] = val
            elif isinstance(item, str) and ":" in item:
                name, val = item.split(":", 1); out[name.strip().lower()] = val.strip()
    return out


def _any_term(haystack: str, terms: list[str]) -> tuple[bool, str | None]:
    if not terms:
        return True, None
    low = haystack.lower()
    for term in terms:
        if term.lower() in low:
            return True, term
    return False, None


def _any_name(names: list[str], patterns: list[str]) -> tuple[bool, str | None]:
    if not patterns:
        return True, None
    for pattern in patterns:
        p = pattern.lower().strip()
        for name in names:
            n = name.lower()
            if (any(ch in p for ch in "*?[") and fnmatch.fnmatch(n, p)) or (not any(ch in p for ch in "*?[") and p in n):
                return True, f"{pattern}→{name}"
    return False, None


def _exchange_context(conn, exchange_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        """SELECT e.id,e.operation_id,e.status_code,e.request_b64,e.response_b64,e.request_headers_json,e.response_headers_json,
                  o.method,o.resource_id,r.path,r.url,h.hostname
           FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id WHERE e.id=?""",
        (int(exchange_id),),
    ).fetchone()
    if not row:
        return None
    ctx = dict(row)
    ctx["request_text"] = _decode(row["request_b64"])
    ctx["response_text"] = _decode(row["response_b64"])
    req_headers = _headers(row["request_headers_json"]); resp_headers = _headers(row["response_headers_json"])
    ctx["header_names"] = sorted(set(req_headers) | set(resp_headers))
    ctx["parameter_names"] = [str(x["normalized_name"]) for x in conn.execute(
        "SELECT DISTINCT normalized_name FROM parameter_observations WHERE exchange_id=? ORDER BY normalized_name", (int(exchange_id),)
    ).fetchall()]
    ctx["identity"] = conn.execute(
        """SELECT i.id,i.name FROM exchange_identities ei JOIN identities i ON i.id=ei.identity_id WHERE ei.exchange_id=? LIMIT 1""",
        (int(exchange_id),),
    ).fetchone()
    try:
        ctx["object_types"] = [str(x["name"]) for x in conn.execute(
            """SELECT DISTINCT bt.name FROM business_object_observations boo JOIN business_objects bo ON bo.id=boo.business_object_id JOIN business_object_types bt ON bt.id=bo.object_type_id WHERE boo.exchange_id=? ORDER BY bt.name""",
            (int(exchange_id),),
        ).fetchall()]
    except Exception:
        ctx["object_types"] = []
    return ctx


def match_rule(rule: dict[str, Any], ctx: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    matched: dict[str, Any] = {}
    methods = [x.upper() for x in rule.get("methods", [])]
    if methods:
        if str(ctx.get("method") or "").upper() not in methods: return False, {}
        matched["method"] = str(ctx.get("method") or "").upper()
    statuses = {str(x) for x in rule.get("statuses", [])}
    if statuses:
        status = str(ctx.get("status_code") if ctx.get("status_code") is not None else "")
        if status not in statuses: return False, {}
        matched["status"] = status
    ok, term = _any_term(str(ctx.get("path") or ""), rule.get("path_terms", []))
    if not ok: return False, {}
    if term: matched["path_contains"] = term
    ok, term = _any_name(ctx.get("parameter_names", []), rule.get("parameter_names", []))
    if not ok: return False, {}
    if term: matched["parameter"] = term
    ok, term = _any_term(str(ctx.get("request_text") or ""), rule.get("request_terms", []))
    if not ok: return False, {}
    if term: matched["request_contains"] = term
    ok, term = _any_term(str(ctx.get("response_text") or ""), rule.get("response_terms", []))
    if not ok: return False, {}
    if term: matched["response_contains"] = term
    ok, term = _any_name(ctx.get("header_names", []), rule.get("header_names", []))
    if not ok: return False, {}
    if term: matched["header"] = term
    ok, term = _any_name(ctx.get("object_types", []), rule.get("object_types", []))
    if not ok: return False, {}
    if term: matched["object_type"] = term
    identity_present = bool(ctx.get("identity"))
    mode = str(rule.get("identity_mode") or "any")
    if mode == "present" and not identity_present: return False, {}
    if mode == "absent" and identity_present: return False, {}
    if mode != "any": matched["identity"] = dict(ctx["identity"]) if identity_present else "none"
    return True, matched


def _persist_match(conn, rule: dict[str, Any], ctx: dict[str, Any], matched: dict[str, Any]) -> int:
    now = _now(); rid = int(rule["id"]); exid = int(ctx["id"])
    dedupe = f"custom_signal:{rid}:exchange:{exid}"
    why = {
        "message": f"Coincidió con tu Custom Signal ‘{rule['name']}’. Negro sólo conserva la coincidencia; tú decides si merece una prueba.",
        "rule_match": matched,
        "suggested_action": rule.get("suggested_action") or "",
    }
    evidence = {
        "source": "custom_signal", "custom_rule_id": rid, "custom_rule_name": rule["name"],
        "method": ctx.get("method"), "path": ctx.get("path"), "host": ctx.get("hostname"),
        "status": ctx.get("status_code"), "rule_match": matched,
        "suggested_action": rule.get("suggested_action") or "",
    }
    row = conn.execute("SELECT id FROM signal_occurrences WHERE dedupe_key=?", (dedupe,)).fetchone()
    if row:
        conn.execute(
            """UPDATE signal_occurrences SET last_seen_at=?,title=?,category=?,severity=?,why_json=?,evidence_json=?,source='custom_signal',signal_level='local' WHERE id=?""",
            (now, rule["name"], rule.get("category") or "other", rule.get("severity") or "info", json.dumps(why, ensure_ascii=False), json.dumps(evidence, ensure_ascii=False), int(row["id"])),
        )
        return int(row["id"])
    cur = conn.execute(
        """INSERT INTO signal_occurrences(dedupe_key,exchange_id,operation_id,resource_id,kind,category,severity,title,why_json,evidence_json,source,occurrences,first_seen_at,last_seen_at,signal_level)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?,?,'local')""",
        (dedupe, exid, int(ctx["operation_id"]), int(ctx["resource_id"]), f"custom_signal:{rid}", rule.get("category") or "other", rule.get("severity") or "info", rule["name"], json.dumps(why, ensure_ascii=False), json.dumps(evidence, ensure_ascii=False), "custom_signal", now, now),
    )
    return int(cur.lastrowid)


def evaluate_exchange(conn, exchange_id: int, *, rule_id: int | None = None) -> dict[str, Any]:
    init_schema(conn)
    ctx = _exchange_context(conn, int(exchange_id))
    if not ctx:
        return {"exchange_id": int(exchange_id), "matched": 0, "rule_ids": []}
    if rule_id:
        row = conn.execute("SELECT * FROM custom_signal_rules WHERE id=? AND enabled=1", (int(rule_id),)).fetchone()
        rows = [row] if row else []
    else:
        rows = conn.execute("SELECT * FROM custom_signal_rules WHERE enabled=1 ORDER BY id").fetchall()
    matched_ids: list[int] = []
    for row in rows:
        if not row: continue
        rule = _rule_dict(row)
        ok, matched = match_rule(rule, ctx)
        if not ok: continue
        _persist_match(conn, rule, ctx, matched); matched_ids.append(int(rule["id"]))
    return {"exchange_id": int(exchange_id), "matched": len(matched_ids), "rule_ids": matched_ids}


def apply_rule_to_history(conn, rule_id: int, *, limit: int = 0) -> dict[str, int]:
    init_schema(conn)
    rule = get_rule(conn, int(rule_id))
    if not rule:
        raise ValueError("Custom Signal no encontrado")
    # A re-run is an explicit reinterpretation of stored evidence. Remove only
    # occurrences produced by this custom rule, never built-in Signals.
    conn.execute("DELETE FROM signal_occurrences WHERE kind=?", (f"custom_signal:{int(rule_id)}",))
    sql = "SELECT id FROM http_exchanges ORDER BY id"
    params: tuple[Any, ...] = ()
    if limit and int(limit) > 0:
        sql = "SELECT id FROM http_exchanges ORDER BY id DESC LIMIT ?"
        params = (int(limit),)
    ids = [int(r["id"]) for r in conn.execute(sql, params).fetchall()]
    scanned = matched = 0
    for exid in ids:
        scanned += 1
        result = evaluate_exchange(conn, exid, rule_id=int(rule_id))
        matched += int(result.get("matched") or 0)
    return {"rule_id": int(rule_id), "scanned": scanned, "matched": matched}


def recalculate_all(conn, *, limit: int = 0) -> dict[str, int]:
    init_schema(conn)
    ids = [int(r["id"]) for r in conn.execute("SELECT id FROM custom_signal_rules WHERE enabled=1 ORDER BY id").fetchall()]
    scanned = matched = 0
    for rid in ids:
        result = apply_rule_to_history(conn, rid, limit=limit)
        scanned += int(result["scanned"]); matched += int(result["matched"])
    return {"rules": len(ids), "scanned": scanned, "matched": matched}
