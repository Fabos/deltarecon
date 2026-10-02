#!/usr/bin/env python3
"""Reglas personalizadas y Señales para Negro.

Una Regla describe una condición observable. Cuando hace match, Negro genera
una Señal explicable usando evidencia ya capturada. Las reglas nunca envían
tráfico ni declaran vulnerabilidades.
"""
from __future__ import annotations

import base64
import fnmatch
import json
import re
import urllib.parse
from pathlib import Path
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
            exact_values_json TEXT NOT NULL DEFAULT '[]',
            regex_terms_json TEXT NOT NULL DEFAULT '[]',
            host_terms_json TEXT NOT NULL DEFAULT '[]',
            identity_mode TEXT NOT NULL DEFAULT 'any',
            rule_kind TEXT NOT NULL DEFAULT 'watch',
            origin_type TEXT,
            origin_id INTEGER,
            origin_note TEXT,
            suggested_action TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_custom_signal_rules_enabled ON custom_signal_rules(enabled, updated_at);
        """
    )
    rule_cols = {row["name"] for row in conn.execute("PRAGMA table_info(custom_signal_rules)")}
    additive = {
        "exact_values_json": "TEXT NOT NULL DEFAULT '[]'",
        "regex_terms_json": "TEXT NOT NULL DEFAULT '[]'",
        "host_terms_json": "TEXT NOT NULL DEFAULT '[]'",
        "rule_kind": "TEXT NOT NULL DEFAULT 'watch'",
        "origin_type": "TEXT",
        "origin_id": "INTEGER",
        "origin_note": "TEXT",
    }
    for col, ddl in additive.items():
        if col not in rule_cols:
            conn.execute(f"ALTER TABLE custom_signal_rules ADD COLUMN {col} {ddl}")
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
        "exact_values_json", "regex_terms_json", "host_terms_json",
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
              object_types: list[str] | None = None, exact_values: list[str] | None = None,
              regex_terms: list[str] | None = None, host_terms: list[str] | None = None,
              identity_mode: str = "any", rule_kind: str = "watch",
              origin_type: str | None = None, origin_id: int | None = None, origin_note: str = "",
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
    rule_kind = str(rule_kind or "watch").strip().lower()
    if rule_kind not in {"watch", "technique", "correlation"}:
        rule_kind = "watch"
    origin_type = str(origin_type or "").strip().lower() or None
    if origin_type not in {None, "request", "hypothesis", "manual"}:
        origin_type = "manual"
    for pattern in _clean_list(regex_terms):
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Regex inválida: {pattern} · {exc}")
    payload = {
        "methods_json": json.dumps([x.upper() for x in _clean_list(methods)], ensure_ascii=False),
        "statuses_json": json.dumps(_clean_list(statuses), ensure_ascii=False),
        "path_terms_json": json.dumps(_clean_list(path_terms), ensure_ascii=False),
        "parameter_names_json": json.dumps(_clean_list(parameter_names), ensure_ascii=False),
        "request_terms_json": json.dumps(_clean_list(request_terms), ensure_ascii=False),
        "response_terms_json": json.dumps(_clean_list(response_terms), ensure_ascii=False),
        "header_names_json": json.dumps(_clean_list(header_names), ensure_ascii=False),
        "object_types_json": json.dumps(_clean_list(object_types), ensure_ascii=False),
        "exact_values_json": json.dumps(_clean_list(exact_values), ensure_ascii=False),
        "regex_terms_json": json.dumps(_clean_list(regex_terms), ensure_ascii=False),
        "host_terms_json": json.dumps(_clean_list(host_terms), ensure_ascii=False),
    }
    has_condition = any(json.loads(v) for v in payload.values()) or identity_mode != "any"
    if not has_condition:
        raise ValueError("Define al menos una condición para que la regla no coincida con todo")
    now = _now()
    values = (
        name, str(description or "").strip(), category, severity, 1 if enabled else 0,
        payload["methods_json"], payload["statuses_json"], payload["path_terms_json"],
        payload["parameter_names_json"], payload["request_terms_json"], payload["response_terms_json"],
        payload["header_names_json"], payload["object_types_json"], payload["exact_values_json"],
        payload["regex_terms_json"], payload["host_terms_json"], identity_mode, rule_kind, origin_type,
        int(origin_id) if origin_id is not None else None, str(origin_note or "").strip(),
        str(suggested_action or "").strip(), now,
    )
    if rule_id:
        exists = conn.execute("SELECT id FROM custom_signal_rules WHERE id=?", (int(rule_id),)).fetchone()
        if not exists:
            raise ValueError("Regla personalizada no encontrada")
        conn.execute(
            """UPDATE custom_signal_rules SET name=?,description=?,category=?,severity=?,enabled=?,methods_json=?,statuses_json=?,path_terms_json=?,parameter_names_json=?,request_terms_json=?,response_terms_json=?,header_names_json=?,object_types_json=?,exact_values_json=?,regex_terms_json=?,host_terms_json=?,identity_mode=?,rule_kind=?,origin_type=?,origin_id=?,origin_note=?,suggested_action=?,updated_at=? WHERE id=?""",
            (*values, int(rule_id)),
        )
        return int(rule_id)
    cur = conn.execute(
        """INSERT INTO custom_signal_rules(name,description,category,severity,enabled,methods_json,statuses_json,path_terms_json,parameter_names_json,request_terms_json,response_terms_json,header_names_json,object_types_json,exact_values_json,regex_terms_json,host_terms_json,identity_mode,rule_kind,origin_type,origin_id,origin_note,suggested_action,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
    parameter_rows = conn.execute(
        "SELECT DISTINCT normalized_name,value_raw,value_preview FROM parameter_observations WHERE exchange_id=? ORDER BY normalized_name",
        (int(exchange_id),)
    ).fetchall()
    ctx["parameter_names"] = [str(x["normalized_name"]) for x in parameter_rows]
    ctx["parameter_values"] = [str(x["value_raw"] or x["value_preview"] or "") for x in parameter_rows if str(x["value_raw"] or x["value_preview"] or "").strip()]
    ctx["request_headers"] = req_headers
    ctx["response_headers"] = resp_headers
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


def _combined_text(ctx: dict[str, Any]) -> str:
    parts = [str(ctx.get("hostname") or ""), str(ctx.get("path") or ""), str(ctx.get("request_text") or ""), str(ctx.get("response_text") or "")]
    for bucket in (ctx.get("request_headers") or {}, ctx.get("response_headers") or {}):
        for k, v in bucket.items():
            parts.extend([str(k), str(v)])
    parts.extend(str(v) for v in (ctx.get("parameter_values") or []))
    return "\n".join(parts)


def _any_exact(haystack: str, values: list[str]) -> tuple[bool, str | None]:
    if not values:
        return True, None
    for value in values:
        if value in haystack:
            return True, value
    return False, None


def _any_regex(haystack: str, patterns: list[str]) -> tuple[bool, str | None]:
    if not patterns:
        return True, None
    for pattern in patterns:
        try:
            if re.search(pattern, haystack, re.MULTILINE):
                return True, pattern
        except re.error:
            continue
    return False, None


def _js_context(conn, asset_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        """SELECT j.id,j.host_id,j.url,j.local_path,j.local_analysis_json,j.source,h.hostname
           FROM js_assets j JOIN hosts h ON h.id=j.host_id WHERE j.id=?""",
        (int(asset_id),),
    ).fetchone()
    if not row:
        return None
    item = dict(row)
    text = ""
    local_path = str(item.get("local_path") or "")
    if local_path:
        try:
            text = Path(local_path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = ""
    if not text:
        text = str(item.get("local_analysis_json") or "")
    parsed = urllib.parse.urlsplit(str(item.get("url") or ""))
    item["path"] = parsed.path or "/"
    item["text"] = text
    resource = conn.execute("SELECT id FROM resources WHERE url=? LIMIT 1", (str(item.get("url") or ""),)).fetchone()
    if not resource:
        resource = conn.execute(
            """SELECT r.id FROM resources r JOIN hosts h ON h.id=r.host_id
               WHERE h.hostname=? AND r.path=? ORDER BY r.id LIMIT 1""",
            (str(item.get("hostname") or ""), item["path"]),
        ).fetchone()
    item["resource_id"] = int(resource["id"]) if resource else None
    return item


def _js_parameter_match(text: str, patterns: list[str]) -> tuple[bool, str | None]:
    if not patterns:
        return True, None
    names = list(dict.fromkeys(re.findall(r"[A-Za-z_$][A-Za-z0-9_$.-]{1,100}", text or "")))
    return _any_name(names, patterns)


def match_js_rule(rule: dict[str, Any], ctx: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    # JavaScript has no HTTP status/method/Identity context by itself. Rules that
    # require those dimensions stay scoped to captured Requests.
    if rule.get("methods") or rule.get("statuses") or rule.get("header_names") or rule.get("object_types"):
        return False, {}
    if str(rule.get("identity_mode") or "any") != "any":
        return False, {}
    if rule.get("request_terms") or rule.get("response_terms"):
        return False, {}
    matched: dict[str, Any] = {}
    ok, term = _any_name([str(ctx.get("hostname") or "")], rule.get("host_terms", []))
    if not ok: return False, {}
    if term: matched["host_contiene"] = term
    ok, term = _any_term(str(ctx.get("path") or ""), rule.get("path_terms", []))
    if not ok: return False, {}
    if term: matched["ruta_contiene"] = term
    text = str(ctx.get("text") or "")
    ok, term = _js_parameter_match(text, rule.get("parameter_names", []))
    if not ok: return False, {}
    if term: matched["key_en_javascript"] = term
    ok, term = _any_exact(text, rule.get("exact_values", []))
    if not ok: return False, {}
    if term: matched["valor_exacto"] = term
    ok, term = _any_regex(text, rule.get("regex_terms", []))
    if not ok: return False, {}
    if term: matched["patron_regex"] = term
    return True, matched


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
    ok, term = _any_name([str(ctx.get("hostname") or "")], rule.get("host_terms", []))
    if not ok: return False, {}
    if term: matched["host_contiene"] = term
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
    if term: matched["tipo_objeto"] = term
    combined = _combined_text(ctx)
    ok, term = _any_exact(combined, rule.get("exact_values", []))
    if not ok: return False, {}
    if term: matched["valor_exacto"] = term
    ok, term = _any_regex(combined, rule.get("regex_terms", []))
    if not ok: return False, {}
    if term: matched["patron_regex"] = term
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
        "message": f"La regla ‘{rule['name']}’ encontró una coincidencia. Negro conserva la evidencia y el contexto; tú decides qué significa.",
        "rule_match": matched,
        "suggested_action": rule.get("suggested_action") or "",
    }
    evidence = {
        "source": "regla_personalizada", "custom_rule_id": rid, "custom_rule_name": rule["name"],
        "rule_kind": rule.get("rule_kind") or "watch", "origin_type": rule.get("origin_type"),
        "origin_id": rule.get("origin_id"), "origin_note": rule.get("origin_note") or "",
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


def _persist_js_match(conn, rule: dict[str, Any], ctx: dict[str, Any], matched: dict[str, Any]) -> int:
    now = _now(); rid = int(rule["id"]); aid = int(ctx["id"])
    dedupe = f"custom_signal:{rid}:js:{aid}"
    why = {
        "message": f"La regla ‘{rule['name']}’ encontró una coincidencia en JavaScript analizado.",
        "rule_match": matched, "suggested_action": rule.get("suggested_action") or "",
    }
    evidence = {
        "source":"javascript", "custom_rule_id":rid, "custom_rule_name":rule["name"],
        "rule_kind":rule.get("rule_kind") or "watch", "origin_type":rule.get("origin_type"),
        "origin_id":rule.get("origin_id"), "origin_note":rule.get("origin_note") or "",
        "js_asset_id":aid, "js_url":ctx.get("url"), "host":ctx.get("hostname"), "host_id":ctx.get("host_id"),
        "path":ctx.get("path"), "rule_match":matched, "suggested_action":rule.get("suggested_action") or "",
    }
    row = conn.execute("SELECT id FROM signal_occurrences WHERE dedupe_key=?", (dedupe,)).fetchone()
    values=(now,rule["name"],rule.get("category") or "other",rule.get("severity") or "info",json.dumps(why,ensure_ascii=False),json.dumps(evidence,ensure_ascii=False))
    if row:
        conn.execute("""UPDATE signal_occurrences SET last_seen_at=?,title=?,category=?,severity=?,why_json=?,evidence_json=?,source='custom_signal',signal_level='local' WHERE id=?""", (*values,int(row["id"])))
        return int(row["id"])
    cur=conn.execute(
        """INSERT INTO signal_occurrences(dedupe_key,exchange_id,operation_id,resource_id,kind,category,severity,title,why_json,evidence_json,source,occurrences,first_seen_at,last_seen_at,signal_level)
           VALUES(?,NULL,NULL,?,?,?,?,?,?,?,'custom_signal',1,?,?,'local')""",
        (dedupe,ctx.get("resource_id"),f"custom_signal:{rid}",rule.get("category") or "other",rule.get("severity") or "info",rule["name"],json.dumps(why,ensure_ascii=False),json.dumps(evidence,ensure_ascii=False),now,now),
    )
    return int(cur.lastrowid)


def evaluate_js_asset(conn, asset_id: int, *, rule_id: int | None = None) -> dict[str, Any]:
    init_schema(conn)
    ctx=_js_context(conn,int(asset_id))
    if not ctx or not str(ctx.get("text") or "").strip():
        return {"js_asset_id":int(asset_id),"matched":0,"rule_ids":[]}
    if rule_id:
        row=conn.execute("SELECT * FROM custom_signal_rules WHERE id=? AND enabled=1",(int(rule_id),)).fetchone(); rows=[row] if row else []
    else:
        rows=conn.execute("SELECT * FROM custom_signal_rules WHERE enabled=1 ORDER BY id").fetchall()
    matched_ids=[]
    for row in rows:
        if not row: continue
        rule=_rule_dict(row); ok,matched=match_js_rule(rule,ctx)
        if not ok: continue
        _persist_js_match(conn,rule,ctx,matched); matched_ids.append(int(rule["id"]))
    return {"js_asset_id":int(asset_id),"matched":len(matched_ids),"rule_ids":matched_ids}


def apply_rule_to_history(conn, rule_id: int, *, limit: int = 0) -> dict[str, int]:
    init_schema(conn)
    rule = get_rule(conn, int(rule_id))
    if not rule:
        raise ValueError("Regla personalizada no encontrada")
    # A re-run is an explicit reinterpretation of stored evidence. Remove only
    # occurrences produced by this custom rule, never built-in Signals.
    conn.execute("DELETE FROM signal_occurrences WHERE kind=?", (f"custom_signal:{int(rule_id)}",))
    sql = "SELECT id FROM http_exchanges ORDER BY id"
    params: tuple[Any, ...] = ()
    if limit and int(limit) > 0:
        sql = "SELECT id FROM http_exchanges ORDER BY id DESC LIMIT ?"
        params = (int(limit),)
    ids = [int(r["id"]) for r in conn.execute(sql, params).fetchall()]
    request_scanned = js_scanned = matched = 0
    for exid in ids:
        request_scanned += 1
        result = evaluate_exchange(conn, exid, rule_id=int(rule_id))
        matched += int(result.get("matched") or 0)
    js_sql = "SELECT id FROM js_assets WHERE local_path IS NOT NULL OR local_analysis_json IS NOT NULL ORDER BY id"
    js_params: tuple[Any, ...] = ()
    if limit and int(limit) > 0:
        js_sql = "SELECT id FROM js_assets WHERE local_path IS NOT NULL OR local_analysis_json IS NOT NULL ORDER BY id DESC LIMIT ?"
        js_params = (int(limit),)
    for row in conn.execute(js_sql, js_params).fetchall():
        js_scanned += 1
        result = evaluate_js_asset(conn, int(row["id"]), rule_id=int(rule_id))
        matched += int(result.get("matched") or 0)
    return {"rule_id": int(rule_id), "scanned": request_scanned + js_scanned, "requests_scanned": request_scanned, "js_scanned": js_scanned, "matched": matched}


def recalculate_all(conn, *, limit: int = 0) -> dict[str, int]:
    init_schema(conn)
    ids = [int(r["id"]) for r in conn.execute("SELECT id FROM custom_signal_rules WHERE enabled=1 ORDER BY id").fetchall()]
    scanned = matched = 0
    for rid in ids:
        result = apply_rule_to_history(conn, rid, limit=limit)
        scanned += int(result["scanned"]); matched += int(result["matched"])
    return {"rules": len(ids), "scanned": scanned, "matched": matched}
