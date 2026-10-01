from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import negro_hunter as hunter


BUSINESS_HINTS = (
    "owner", "user", "account", "tenant", "role", "permission", "price", "amount",
    "total", "status", "state", "coupon", "discount", "order", "seller", "buyer",
    "customer", "product", "item", "plan", "scope", "client", "redirect", "id",
)
SENSITIVE_HINTS = (
    "authorization", "cookie", "set-cookie", "token", "secret", "password", "passwd",
    "session", "apikey", "api_key", "access_key", "refresh",
)
NOISY_HEADERS = {"date", "content-length", "connection", "accept-encoding"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _decode_b64(value: str | None) -> str:
    if not value:
        return ""
    try:
        return base64.b64decode(value, validate=False).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _split_http(text: str) -> tuple[str, str]:
    if "\r\n\r\n" in text:
        return text.split("\r\n\r\n", 1)
    if "\n\n" in text:
        return text.split("\n\n", 1)
    return text, ""


def _headers(head: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in head.replace("\r\n", "\n").split("\n")[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip().lower()
        val = v.strip()
        if key in out:
            out[key] += "\n" + val
        else:
            out[key] = val
    return out


def _normalize_name(name: str) -> str:
    raw = str(name or "").strip().lower().replace("-", "_")
    return re.sub(r"[^a-z0-9_]", "", raw)[:160] or raw[:160]


def _is_sensitive(name: str, location: str = "") -> bool:
    hay = (_normalize_name(name) + " " + str(location or "").lower())
    return any(x in hay for x in SENSITIVE_HINTS)


def _safe_value(value: Any, *, name: str = "", location: str = "", limit: int = 140) -> str:
    text = str(value if value is not None else "").replace("\r", " ").replace("\n", " ")
    if _is_sensitive(name, location):
        return hunter._mask_value(text)
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text




def _path_parameters(req_head: str) -> list[dict[str, str]]:
    """Extract likely object identifiers from request path segments."""
    first = req_head.replace("\r\n", "\n").split("\n")[0] if req_head else ""
    parts = first.split()
    if len(parts) < 2:
        return []
    try:
        path = urllib.parse.urlsplit(parts[1]).path
    except Exception:
        return []
    segments = [urllib.parse.unquote(x) for x in path.split("/") if x]
    out: list[dict[str, str]] = []
    uuid_re = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}$")
    mixed_re = re.compile(r"^[A-Za-z0-9_-]{6,80}$")
    for idx, seg in enumerate(segments):
        looks_id = bool(re.fullmatch(r"\d{2,}", seg) or uuid_re.fullmatch(seg) or re.fullmatch(r"[0-9a-fA-F]{8,64}", seg))
        if not looks_id and mixed_re.fullmatch(seg) and any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg):
            looks_id = True
        if not looks_id:
            continue
        previous = segments[idx - 1] if idx > 0 else "path"
        base = _normalize_name(previous).rstrip("s") or "path"
        name = f"{base}_id"
        pattern = "/" + "/".join(segments[:idx] + ["{id}"])
        out.append({"name": name, "value": seg, "location": f"path:{pattern}"})
    return out

def _response_parameters(resp_body: str, response_ct: str) -> list[dict[str, str]]:
    """Extract scalar response fields as observations; never mutates traffic."""
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(name: Any, value: Any, where: str) -> None:
        n = str(name or "").strip()
        if not n:
            return
        v = str(value if value is not None else "")[:4000]
        key = (n.lower(), v[:1000], where)
        if key in seen:
            return
        seen.add(key)
        found.append({"name": n, "value": v, "location": where})

    body = str(resp_body or "")[:1_500_000]
    ct = str(response_ct or "").lower()
    if not body:
        return found
    if "application/json" in ct or body.lstrip().startswith(("{", "[")):
        try:
            obj = json.loads(body)
            for key, path, value in hunter._json_fields(obj):
                if not isinstance(value, (dict, list)):
                    add(key, value, f"response_json:{path}")
        except Exception:
            pass
    if "application/x-www-form-urlencoded" in ct:
        try:
            for key, values in urllib.parse.parse_qs(body, keep_blank_values=True).items():
                for value in values:
                    add(key, value, "response_form")
        except Exception:
            pass
    return found


def persist_exchange_parameters(conn, exchange_id: int) -> int:
    """(Re)extract request + response scalar parameters for one stored exchange."""
    row = conn.execute(
        """SELECT e.*,o.id AS operation_id,o.resource_id,o.request_content_type,o.response_content_type
           FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id WHERE e.id=?""",
        (int(exchange_id),),
    ).fetchone()
    if not row:
        return 0
    req = _decode_b64(row["request_b64"])
    resp = _decode_b64(row["response_b64"])
    req_head, req_body = _split_http(req)
    _resp_head, resp_body = _split_http(resp)
    request_params = hunter._request_parameters(req_head, req_body, str(row["request_content_type"] or ""), row["query_json"])
    request_params += _path_parameters(req_head)
    response_params = _response_parameters(resp_body, str(row["response_content_type"] or ""))
    before = int(conn.execute("SELECT COUNT(*) c FROM parameter_observations WHERE exchange_id=?", (int(exchange_id),)).fetchone()["c"] or 0)
    hunter._persist_parameter_observations(
        conn,
        exchange_id=int(exchange_id),
        operation_id=int(row["operation_id"]),
        resource_id=int(row["resource_id"]),
        params=request_params + response_params,
    )
    after = int(conn.execute("SELECT COUNT(*) c FROM parameter_observations WHERE exchange_id=?", (int(exchange_id),)).fetchone()["c"] or 0)
    return max(0, after - before)


def rebuild_parameter_observations(conn) -> dict[str, int]:
    """Rebuild derived parameter observations from stored HTTP evidence."""
    ids = [int(r["id"]) for r in conn.execute("SELECT id FROM http_exchanges ORDER BY id").fetchall()]
    conn.execute("DELETE FROM parameter_observations")
    total = 0
    for exchange_id in ids:
        total += persist_exchange_parameters(conn, exchange_id)
    conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('parameters_rebuilt_at',?)", (now_iso(),))
    return {"exchanges": len(ids), "observations": total}


def stats(conn) -> dict[str, Any]:
    row = conn.execute(
        """SELECT COUNT(*) observations,COUNT(DISTINCT normalized_name) names,
                  COUNT(DISTINCT value_hash) values_count,COUNT(DISTINCT exchange_id) exchanges
           FROM parameter_observations"""
    ).fetchone()
    stamp = conn.execute("SELECT value FROM meta WHERE key='parameters_rebuilt_at'").fetchone()
    return {
        "observations": int(row["observations"] or 0),
        "names": int(row["names"] or 0),
        "values": int(row["values_count"] or 0),
        "exchanges": int(row["exchanges"] or 0),
        "rebuilt_at": stamp["value"] if stamp else None,
    }


def locations(conn) -> list[str]:
    return [str(r["location"]) for r in conn.execute("SELECT DISTINCT location FROM parameter_observations ORDER BY location").fetchall()]


def list_parameters(conn, *, q: str = "", location: str = "", host: str = "", limit: int = 250) -> list[dict[str, Any]]:
    where: list[str] = []
    args: list[Any] = []
    if q.strip():
        where.append("(lower(p.normalized_name) LIKE ? OR lower(p.name) LIKE ?)")
        needle = f"%{q.strip().lower()}%"
        args.extend([needle, needle])
    if location.strip():
        where.append("lower(p.location) LIKE ?")
        args.append(f"%{location.strip().lower()}%")
    if host.strip():
        where.append("lower(h.hostname) LIKE ?")
        args.append(f"%{host.strip().lower()}%")
    sql = """
        SELECT p.normalized_name,MIN(p.name) AS name,
               COUNT(*) AS observations,COUNT(DISTINCT p.value_hash) AS distinct_values,
               COUNT(DISTINCT p.exchange_id) AS exchanges,COUNT(DISTINCT p.resource_id) AS resources,
               COUNT(DISTINCT h.hostname) AS hosts,
               GROUP_CONCAT(DISTINCT p.location) AS locations,
               MAX(p.first_seen_at) AS last_seen_at
        FROM parameter_observations p
        JOIN resources r ON r.id=p.resource_id
        JOIN hosts h ON h.id=r.host_id
    """
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " GROUP BY p.normalized_name ORDER BY observations DESC, p.normalized_name LIMIT ?"
    args.append(max(1, min(int(limit), 1000)))
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def parameter_detail(conn, normalized_name: str, *, limit: int = 300) -> dict[str, Any] | None:
    normalized = _normalize_name(normalized_name)
    summary = conn.execute(
        """SELECT p.normalized_name,MIN(p.name) name,COUNT(*) observations,
                  COUNT(DISTINCT p.value_hash) distinct_values,COUNT(DISTINCT p.exchange_id) exchanges,
                  COUNT(DISTINCT p.resource_id) resources,COUNT(DISTINCT h.hostname) hosts,
                  GROUP_CONCAT(DISTINCT p.location) locations
           FROM parameter_observations p JOIN resources r ON r.id=p.resource_id JOIN hosts h ON h.id=r.host_id
           WHERE p.normalized_name=? GROUP BY p.normalized_name""",
        (normalized,),
    ).fetchone()
    if not summary:
        return None
    values = [dict(r) for r in conn.execute(
        """SELECT p.value_hash,MIN(p.value_preview) value_preview,MIN(COALESCE(p.value_raw,p.value_preview)) value_raw,COUNT(*) occurrences,
                  COUNT(DISTINCT p.exchange_id) exchanges,COUNT(DISTINCT p.resource_id) resources,
                  MAX(p.first_seen_at) last_seen_at
           FROM parameter_observations p WHERE p.normalized_name=?
           GROUP BY p.value_hash ORDER BY occurrences DESC,last_seen_at DESC LIMIT 100""",
        (normalized,),
    ).fetchall()]
    observations = [dict(r) for r in conn.execute(
        """SELECT p.*,h.hostname,r.path,o.method,e.status_code,e.first_seen_at exchange_seen_at
           FROM parameter_observations p
           JOIN http_exchanges e ON e.id=p.exchange_id
           JOIN resource_operations o ON o.id=p.operation_id
           JOIN resources r ON r.id=p.resource_id
           JOIN hosts h ON h.id=r.host_id
           WHERE p.normalized_name=? ORDER BY e.id DESC LIMIT ?""",
        (normalized, max(1, min(int(limit), 1000))),
    ).fetchall()]
    return {"summary": dict(summary), "values": values, "observations": observations}


def follow_observation(conn, observation_id: int, *, limit: int = 500) -> dict[str, Any] | None:
    base = conn.execute(
        """SELECT p.*,h.hostname,r.path,o.method,e.status_code,e.first_seen_at exchange_seen_at
           FROM parameter_observations p
           JOIN http_exchanges e ON e.id=p.exchange_id
           JOIN resource_operations o ON o.id=p.operation_id
           JOIN resources r ON r.id=p.resource_id
           JOIN hosts h ON h.id=r.host_id WHERE p.id=?""",
        (int(observation_id),),
    ).fetchone()
    if not base:
        return None
    occurrences = [dict(r) for r in conn.execute(
        """SELECT p.*,h.hostname,r.path,o.method,e.status_code,e.first_seen_at exchange_seen_at
           FROM parameter_observations p
           JOIN http_exchanges e ON e.id=p.exchange_id
           JOIN resource_operations o ON o.id=p.operation_id
           JOIN resources r ON r.id=p.resource_id
           JOIN hosts h ON h.id=r.host_id
           WHERE p.value_hash=? ORDER BY e.id ASC,p.id ASC LIMIT ?""",
        (str(base["value_hash"]), max(1, min(int(limit), 2000))),
    ).fetchall()]
    return {"base": dict(base), "occurrences": occurrences}


def related_exchanges(conn, exchange_id: int, *, limit: int = 60) -> dict[str, Any] | None:
    """Find nearby HTTP evidence without pretending that proximity is severity.

    v0.23.2 deliberately ignores same-host-only noise and hides OPTIONS unless the
    origin itself is OPTIONS. Exact shared values and the same resource are the
    primary evidence. Common values are discounted by project frequency.
    """
    base = conn.execute(
        """SELECT e.id,e.response_hash,o.resource_id,o.id operation_id,r.host_id,h.hostname,r.path,o.method,e.status_code,e.first_seen_at
           FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id WHERE e.id=?""",
        (int(exchange_id),),
    ).fetchone()
    if not base:
        return None
    base_params = [dict(r) for r in conn.execute(
        """SELECT normalized_name,value_hash,COALESCE(value_raw,value_preview) value_text,location
           FROM parameter_observations WHERE exchange_id=?""",
        (int(exchange_id),),
    ).fetchall()]
    base_hashes: dict[str, dict[str, Any]] = {}
    for r in base_params:
        base_hashes.setdefault(str(r["value_hash"]), r)
    base_names = {str(r["normalized_name"]) for r in base_params}

    # Frequency lets us discount generic values such as role=customer or status=active.
    value_freq: dict[str, int] = {}
    if base_hashes:
        placeholders = ",".join("?" for _ in base_hashes)
        for row in conn.execute(
            f"SELECT value_hash,COUNT(DISTINCT exchange_id) n FROM parameter_observations WHERE value_hash IN ({placeholders}) GROUP BY value_hash",
            list(base_hashes.keys()),
        ).fetchall():
            value_freq[str(row["value_hash"])] = int(row["n"] or 0)

    candidate_ids: set[int] = set()
    if base_hashes:
        placeholders = ",".join("?" for _ in base_hashes)
        for row in conn.execute(
            f"SELECT DISTINCT exchange_id FROM parameter_observations WHERE value_hash IN ({placeholders}) AND exchange_id<>? LIMIT 700",
            [*base_hashes.keys(), int(exchange_id)],
        ).fetchall():
            candidate_ids.add(int(row["exchange_id"]))
    # Same resource is useful even when response values changed.
    for row in conn.execute(
        """SELECT e.id FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
           WHERE e.id<>? AND o.resource_id=? ORDER BY e.id DESC LIMIT 250""",
        (int(exchange_id), int(base["resource_id"])),
    ).fetchall():
        candidate_ids.add(int(row["id"]))

    scored: list[dict[str, Any]] = []
    for candidate_id in candidate_ids:
        row = conn.execute(
            """SELECT e.id,e.response_hash,o.resource_id,o.id operation_id,r.host_id,h.hostname,r.path,o.method,e.status_code,e.first_seen_at
               FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
               JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id WHERE e.id=?""",
            (candidate_id,),
        ).fetchone()
        if not row:
            continue
        if str(base["method"]).upper() != "OPTIONS" and str(row["method"]).upper() == "OPTIONS":
            continue
        params = [dict(r) for r in conn.execute(
            """SELECT normalized_name,value_hash,COALESCE(value_raw,value_preview) value_text,location
               FROM parameter_observations WHERE exchange_id=?""",
            (candidate_id,),
        ).fetchall()]
        hashes: dict[str, dict[str, Any]] = {}
        for r in params:
            hashes.setdefault(str(r["value_hash"]), r)
        names = {str(r["normalized_name"]) for r in params}
        shared_hashes = sorted(set(base_hashes) & set(hashes))
        shared_names = sorted(base_names & names)
        same_resource = int(row["resource_id"]) == int(base["resource_id"])
        same_operation = int(row["operation_id"]) == int(base["operation_id"])

        # Same host or a generic parameter name alone is not useful enough to surface.
        if not shared_hashes and not same_resource:
            continue

        value_labels: list[str] = []
        weighted_value_score = 0
        distinctive = 0
        for hv in shared_hashes:
            item = base_hashes[hv]
            freq = int(value_freq.get(hv, 999999))
            if freq <= 4:
                weight = 8
                distinctive += 1
            elif freq <= 12:
                weight = 6
                distinctive += 1
            elif freq <= 50:
                weight = 3
            else:
                weight = 1
            weighted_value_score += weight
            if len(value_labels) < 6:
                value_labels.append(f"{item['normalized_name']}={item['value_text']}")

        score = min(42, weighted_value_score)
        if same_resource:
            score += 7
        if same_operation:
            score += 3

        if shared_hashes and same_resource:
            relation_kind = "same_resource_values"
            primary = f"MISMO RECURSO · {len(shared_hashes)} valor{'es' if len(shared_hashes) != 1 else ''} exacto{'s' if len(shared_hashes) != 1 else ''}"
        elif shared_hashes:
            relation_kind = "same_object_values"
            primary = f"VALORES DEL MISMO OBJETO · {len(shared_hashes)} coincidencia{'s' if len(shared_hashes) != 1 else ''} exacta{'s' if len(shared_hashes) != 1 else ''}"
        else:
            relation_kind = "same_resource"
            primary = "MISMO RECURSO · otra observación"

        if len(shared_hashes) >= 2 or (same_resource and len(shared_hashes) >= 1) or distinctive >= 2:
            strength = "strong"
            strength_label = "Relación fuerte"
        elif len(shared_hashes) >= 1:
            strength = "medium"
            strength_label = "Relación media"
        else:
            strength = "weak"
            strength_label = "Relación débil"

        reasons: list[str] = []
        if value_labels:
            reasons.append("Valores exactos: " + ", ".join(value_labels))
        if same_operation:
            reasons.append("Misma operación HTTP")
        elif same_resource:
            reasons.append("Mismo recurso")
        # Names explain shape, but never create a relation by themselves.
        if shared_names:
            reasons.append("Campos compartidos: " + ", ".join(shared_names[:8]))

        item = dict(row)
        item.update({
            "score": score,
            "relation_kind": relation_kind,
            "primary": primary,
            "strength": strength,
            "strength_label": strength_label,
            "reasons": reasons,
            "shared_values": len(shared_hashes),
            "shared_names": len(shared_names),
        })
        scored.append(item)

    scored.sort(key=lambda x: ({"strong": 0, "medium": 1, "weak": 2}[x["strength"]], -int(x["score"]), abs(int(x["id"]) - int(exchange_id))))
    max_items = max(1, min(int(limit), 200))
    selected = scored[:max_items]
    groups = {
        "strong": [x for x in selected if x["strength"] == "strong"],
        "medium": [x for x in selected if x["strength"] == "medium"],
        "weak": [x for x in selected if x["strength"] == "weak"],
    }
    return {"base": dict(base), "related": selected, "groups": groups, "counts": {k: len(v) for k, v in groups.items()}}

def _flatten_json(value: Any, prefix: str = "$") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, val in value.items():
            path = f"{prefix}.{key}"
            if isinstance(val, (dict, list)):
                out.update(_flatten_json(val, path))
            else:
                out[path] = val
    elif isinstance(value, list):
        for idx, val in enumerate(value[:250]):
            path = f"{prefix}[{idx}]"
            if isinstance(val, (dict, list)):
                out.update(_flatten_json(val, path))
            else:
                out[path] = val
    return out


def _business_priority(key: str) -> int:
    k = str(key or "").lower()
    return 0 if any(hint in k for hint in BUSINESS_HINTS) else 1


def _safe_header_value(name: str, value: str) -> str:
    if _is_sensitive(name, "header"):
        return hunter._mask_value(value)
    return _safe_value(value, name=name, location="header", limit=220)


def _exchange_model(conn, exchange_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        """SELECT e.*,o.method,o.resource_id,r.path,r.url,h.hostname
           FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id WHERE e.id=?""",
        (int(exchange_id),),
    ).fetchone()
    if not row:
        return None
    req = _decode_b64(row["request_b64"]); resp = _decode_b64(row["response_b64"])
    req_head, req_body = _split_http(req); resp_head, resp_body = _split_http(resp)
    first = req_head.replace("\r\n", "\n").split("\n")[0] if req_head else ""
    target = first.split()[1] if len(first.split()) >= 2 else str(row["path"] or "")
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(target).query, keep_blank_values=True))
    req_headers = _headers(req_head); resp_headers = _headers(resp_head)
    req_json: dict[str, Any] = {}; resp_json: dict[str, Any] = {}
    try: req_json = _flatten_json(json.loads(req_body)) if req_body.strip() else {}
    except Exception: pass
    try: resp_json = _flatten_json(json.loads(resp_body)) if resp_body.strip() else {}
    except Exception: pass
    return {
        "id": int(row["id"]), "resource_id": int(row["resource_id"]), "host": str(row["hostname"]),
        "path": str(row["path"]), "method": str(row["method"]), "status": str(row["status_code"] or ""),
        "seen_at": str(row["first_seen_at"] or ""), "query": query,
        "request_headers": req_headers, "response_headers": resp_headers,
        "request_json": req_json, "response_json": resp_json,
        "request_body_hash": hashlib.sha256(req_body.encode(errors="ignore")).hexdigest()[:16] if req_body else "",
        "response_body_hash": hashlib.sha256(resp_body.encode(errors="ignore")).hexdigest()[:16] if resp_body else "",
        "request_body_size": len(req_body.encode(errors="ignore")), "response_body_size": len(resp_body.encode(errors="ignore")),
    }


def _diff_mapping(surface: str, a: dict[str, Any], b: dict[str, Any], *, headers: bool = False) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in sorted(set(a) | set(b), key=lambda k: (_business_priority(str(k)), str(k).lower())):
        av = a.get(key); bv = b.get(key)
        if av == bv:
            continue
        if headers and str(key).lower() in NOISY_HEADERS:
            continue
        if headers:
            av = _safe_header_value(str(key), str(av or "")); bv = _safe_header_value(str(key), str(bv or ""))
        else:
            av = _safe_value(av, name=str(key), location=surface); bv = _safe_value(bv, name=str(key), location=surface)
        rows.append({"surface": surface, "key": str(key), "a": av, "b": bv, "business": _business_priority(str(key)) == 0})
    return rows


def smart_diff(conn, exchange_a: int, exchange_b: int) -> dict[str, Any] | None:
    a = _exchange_model(conn, int(exchange_a)); b = _exchange_model(conn, int(exchange_b))
    if not a or not b:
        return None
    changes: list[dict[str, Any]] = []
    top_a = {"method": a["method"], "host": a["host"], "path": a["path"], "status": a["status"]}
    top_b = {"method": b["method"], "host": b["host"], "path": b["path"], "status": b["status"]}
    changes += _diff_mapping("HTTP", top_a, top_b)
    changes += _diff_mapping("query", a["query"], b["query"])
    changes += _diff_mapping("request JSON", a["request_json"], b["request_json"])
    changes += _diff_mapping("response JSON", a["response_json"], b["response_json"])
    changes += _diff_mapping("request headers", a["request_headers"], b["request_headers"], headers=True)
    changes += _diff_mapping("response headers", a["response_headers"], b["response_headers"], headers=True)
    changes.sort(key=lambda x: (0 if x["business"] else 1, x["surface"], x["key"].lower()))
    return {
        "a": a, "b": b, "changes": changes,
        "business_changes": sum(1 for x in changes if x["business"]),
        "other_changes": sum(1 for x in changes if not x["business"]),
    }


def search_hits(conn, terms: list[tuple[str, str]], *, host_filters: list[str] | None = None, limit: int = 80) -> list[dict[str, Any]]:
    """Return parameter/value observations relevant to a universal Search query.

    This is intentionally a drill-down companion to Search, not a second search
    engine. It uses the normalized parameter table so Search can expose actions
    such as Follow Value without forcing the user to open Parameter Explorer first.
    """
    usable = [(str(k or "contains"), str(v or "").strip()) for k, v in terms if str(v or "").strip()]
    usable = [(k, v) for k, v in usable if k in {"contains", "param", "request", "response", "body", "path"}]
    if not usable:
        return []
    clauses: list[str] = []
    args: list[Any] = []
    for kind, value in usable:
        needle = f"%{value.lower()}%"
        base = "(lower(p.name) LIKE ? OR lower(p.normalized_name) LIKE ? OR lower(COALESCE(p.value_raw,p.value_preview,'')) LIKE ? OR lower(p.location) LIKE ?)"
        local_args: list[Any] = [needle, needle, needle, needle]
        if kind == "param":
            base = "(lower(p.name) LIKE ? OR lower(p.normalized_name) LIKE ?)"
            local_args = [needle, needle]
        elif kind == "request":
            base = "(" + base + " AND p.location NOT LIKE 'response_%')"
        elif kind == "response":
            base = "(" + base + " AND p.location LIKE 'response_%')"
        elif kind == "path":
            base = "(" + base + " AND p.location LIKE 'path:%')"
        clauses.append(base)
        args.extend(local_args)
    if host_filters:
        host_clauses = []
        for host in host_filters:
            host_clauses.append("lower(h.hostname) LIKE ?")
            args.append(f"%{str(host).lower()}%")
        clauses.append("(" + " OR ".join(host_clauses) + ")")
    sql = """
        SELECT p.id,p.exchange_id,p.operation_id,p.resource_id,p.name,p.normalized_name,p.location,p.value_hash,p.value_preview,p.value_raw,p.first_seen_at,
               h.hostname,r.path,o.method,e.status_code,
               (SELECT COUNT(*) FROM parameter_observations px WHERE px.value_hash=p.value_hash) value_occurrences,
               (SELECT COUNT(DISTINCT px.exchange_id) FROM parameter_observations px WHERE px.value_hash=p.value_hash) value_exchanges
        FROM parameter_observations p
        JOIN http_exchanges e ON e.id=p.exchange_id
        JOIN resource_operations o ON o.id=p.operation_id
        JOIN resources r ON r.id=p.resource_id
        JOIN hosts h ON h.id=r.host_id
    """
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY e.id DESC,p.id DESC LIMIT ?"
    args.append(max(1, min(int(limit), 300)))
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def matching_observations_for_exchange(conn, exchange_id: int, terms: list[tuple[str, str]], *, limit: int = 8) -> list[dict[str, Any]]:
    usable = [(str(k or "contains"), str(v or "").strip().lower()) for k, v in terms if str(v or "").strip()]
    if not usable:
        return []
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM parameter_observations WHERE exchange_id=? ORDER BY id", (int(exchange_id),)
    ).fetchall()]
    out: list[dict[str, Any]] = []
    for row in rows:
        hay = " ".join([str(row.get("name") or ""), str(row.get("normalized_name") or ""), str(row.get("value_raw") or row.get("value_preview") or ""), str(row.get("location") or "")]).lower()
        ok = True
        for kind, value in usable:
            if kind in {"cookie", "header", "signal"}:
                continue
            if kind == "param":
                phay = (str(row.get("name") or "") + " " + str(row.get("normalized_name") or "")).lower()
                if value not in phay:
                    ok = False; break
            elif kind == "response" and not str(row.get("location") or "").startswith("response_"):
                ok = False; break
            elif kind == "request" and str(row.get("location") or "").startswith("response_"):
                ok = False; break
            elif kind == "path" and not str(row.get("location") or "").startswith("path:"):
                ok = False; break
            elif value not in hay:
                ok = False; break
        if ok:
            out.append(row)
        if len(out) >= limit:
            break
    return out
