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



GENERIC_VALUE_WORDS = {
    "true", "false", "ok", "success", "successful", "null", "none", "yes", "no",
    "active", "inactive", "enabled", "disabled", "customer", "user", "admin", "guest",
    "pending", "completed", "complete", "created", "updated", "deleted", "unknown",
}
GENERIC_FIELD_NAMES = {
    "id", "ok", "status", "state", "type", "role", "roleid", "role_id", "enabled", "active",
}
IDENTIFIER_HINTS = (
    "id", "uuid", "email", "phone", "reference", "ref", "account", "user", "member", "seller",
    "buyer", "customer", "order", "invoice", "payment", "shipment", "tenant", "organization", "org",
)


def _value_is_noise(value: Any, *, name: str = "") -> bool:
    text = str(value if value is not None else "").strip()
    low = text.lower()
    n = _normalize_name(name)
    if not text:
        return True
    if low in GENERIC_VALUE_WORDS:
        return True
    if low in {"0", "1"} and n in GENERIC_FIELD_NAMES:
        return True
    if len(text) == 1 and text.isdigit():
        return True
    return False


def _identifierish(name: str, location: str = "") -> bool:
    hay = (_normalize_name(name) + " " + str(location or "").lower())
    return any(h in hay for h in IDENTIFIER_HINTS)


def _observation_display(obs: dict[str, Any]) -> str:
    location = str(obs.get("location") or "")
    name = str(obs.get("normalized_name") or obs.get("name") or "value")
    return f"{location} · {name}" if location else name


def _exchange_value_correlations(conn, exchange_a: int, exchange_b: int, *, limit: int = 80) -> list[dict[str, Any]]:
    """Exact-value matches between two exchanges, including differently named fields.

    This deliberately does not infer semantic equivalence. When the same distinctive
    value appears under different names/JSON paths, Negro calls it an alias candidate
    so the hunter can decide whether userId/memberId/etc. represent the same concept.
    """
    rows_a = [dict(r) for r in conn.execute(
        """SELECT id,name,normalized_name,location,value_hash,COALESCE(value_raw,value_preview) value_text
           FROM parameter_observations WHERE exchange_id=?""", (int(exchange_a),)
    ).fetchall()]
    rows_b = [dict(r) for r in conn.execute(
        """SELECT id,name,normalized_name,location,value_hash,COALESCE(value_raw,value_preview) value_text
           FROM parameter_observations WHERE exchange_id=?""", (int(exchange_b),)
    ).fetchall()]
    by_a: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_b: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows_a:
        by_a[str(row["value_hash"])].append(row)
    for row in rows_b:
        by_b[str(row["value_hash"])].append(row)
    shared = set(by_a) & set(by_b)
    if not shared:
        return []

    placeholders = ",".join("?" for _ in shared)
    freqs = {
        str(r["value_hash"]): int(r["n"] or 0)
        for r in conn.execute(
            f"SELECT value_hash,COUNT(DISTINCT exchange_id) n FROM parameter_observations WHERE value_hash IN ({placeholders}) GROUP BY value_hash",
            list(shared),
        ).fetchall()
    }
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for hv in shared:
        freq = freqs.get(hv, 999999)
        for oa in by_a[hv]:
            for ob in by_b[hv]:
                value = str(oa.get("value_text") or ob.get("value_text") or "")
                if _value_is_noise(value, name=str(oa.get("normalized_name") or "")) and _value_is_noise(value, name=str(ob.get("normalized_name") or "")):
                    continue
                na = str(oa.get("normalized_name") or "")
                nb = str(ob.get("normalized_name") or "")
                key = (hv, na, str(oa.get("location") or ""), nb, str(ob.get("location") or ""))
                if key in seen:
                    continue
                seen.add(key)
                alias = na != nb or str(oa.get("location") or "") != str(ob.get("location") or "")
                idish = _identifierish(na, str(oa.get("location") or "")) or _identifierish(nb, str(ob.get("location") or ""))
                if freq <= 4:
                    strength = "strong"
                elif freq <= 12:
                    strength = "medium"
                else:
                    strength = "weak"
                # A distinctive identifier earns one level; a generic, highly reused value loses one.
                if idish and freq <= 20:
                    strength = "strong" if strength == "medium" else strength
                if (na in GENERIC_FIELD_NAMES and nb in GENERIC_FIELD_NAMES) and freq > 8:
                    strength = "weak"
                out.append({
                    "value": _safe_value(value, name=na or nb, location="correlation", limit=180),
                    "value_hash": hv,
                    "frequency": freq,
                    "a_name": na or str(oa.get("name") or "value"),
                    "a_location": str(oa.get("location") or ""),
                    "b_name": nb or str(ob.get("name") or "value"),
                    "b_location": str(ob.get("location") or ""),
                    "alias_candidate": alias,
                    "identifierish": idish,
                    "strength": strength,
                    "label": "Mismo valor · nombres/rutas distintos" if alias else "Mismo valor · mismo campo",
                })
    order = {"strong": 0, "medium": 1, "weak": 2}
    out.sort(key=lambda x: (order[x["strength"]], 0 if x["alias_candidate"] else 1, x["frequency"], str(x["value"])))
    return out[: max(1, min(int(limit), 300))]

def related_exchanges(conn, exchange_id: int, *, limit: int = 60) -> dict[str, Any] | None:
    """Find exchanges related by exact observed values or the same resource.

    The result is evidence of correlation only. It never claims that two endpoints
    represent the same object, identity, or vulnerability. v0.25 discounts generic
    values (ok=true, role=customer, status=active), ignores same-host-only matches,
    and keeps full field locations so the hunter can understand why a match exists.
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
        """SELECT id,name,normalized_name,value_hash,COALESCE(value_raw,value_preview) value_text,location
           FROM parameter_observations WHERE exchange_id=?""", (int(exchange_id),)
    ).fetchall()]
    base_by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in base_params:
        base_by_hash[str(r["value_hash"])].append(r)
    base_names = {str(r["normalized_name"]) for r in base_params}

    value_freq: dict[str, int] = {}
    if base_by_hash:
        placeholders = ",".join("?" for _ in base_by_hash)
        for row in conn.execute(
            f"SELECT value_hash,COUNT(DISTINCT exchange_id) n FROM parameter_observations WHERE value_hash IN ({placeholders}) GROUP BY value_hash",
            list(base_by_hash.keys()),
        ).fetchall():
            value_freq[str(row["value_hash"])] = int(row["n"] or 0)

    candidate_ids: set[int] = set()
    if base_by_hash:
        placeholders = ",".join("?" for _ in base_by_hash)
        for row in conn.execute(
            f"SELECT DISTINCT exchange_id FROM parameter_observations WHERE value_hash IN ({placeholders}) AND exchange_id<>? LIMIT 900",
            [*base_by_hash.keys(), int(exchange_id)],
        ).fetchall():
            candidate_ids.add(int(row["exchange_id"]))
    for row in conn.execute(
        """SELECT e.id FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
           WHERE e.id<>? AND o.resource_id=? ORDER BY e.id DESC LIMIT 300""",
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
            """SELECT id,name,normalized_name,value_hash,COALESCE(value_raw,value_preview) value_text,location
               FROM parameter_observations WHERE exchange_id=?""", (candidate_id,)
        ).fetchall()]
        cand_by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in params:
            cand_by_hash[str(r["value_hash"])].append(r)
        names = {str(r["normalized_name"]) for r in params}
        shared_hashes = sorted(set(base_by_hash) & set(cand_by_hash))
        shared_names = sorted(base_names & names)
        same_resource = int(row["resource_id"]) == int(base["resource_id"])
        same_operation = int(row["operation_id"]) == int(base["operation_id"])
        if not shared_hashes and not same_resource:
            continue

        matches: list[dict[str, Any]] = []
        weighted = 0
        distinctive = 0
        meaningful_hashes = 0
        for hv in shared_hashes:
            freq = int(value_freq.get(hv, 999999))
            # Keep the best explanatory pair for this exact value.
            best = None
            best_score = -1
            for aobs in base_by_hash[hv]:
                for bobs in cand_by_hash[hv]:
                    value = str(aobs.get("value_text") or bobs.get("value_text") or "")
                    noise = _value_is_noise(value, name=str(aobs.get("normalized_name") or "")) and _value_is_noise(value, name=str(bobs.get("normalized_name") or ""))
                    idish = _identifierish(str(aobs.get("normalized_name") or ""), str(aobs.get("location") or "")) or _identifierish(str(bobs.get("normalized_name") or ""), str(bobs.get("location") or ""))
                    score = (4 if idish else 0) + (3 if str(aobs.get("normalized_name")) != str(bobs.get("normalized_name")) else 0) + (2 if not noise else -5)
                    if score > best_score:
                        best_score = score
                        best = (aobs, bobs, value, noise, idish)
            if not best:
                continue
            aobs, bobs, value, noise, idish = best
            if noise:
                # Generic booleans/role/status values may still explain a same-resource
                # observation, but they should never create a useful relation alone.
                continue
            meaningful_hashes += 1
            if freq <= 4:
                weight = 9; distinctive += 1
            elif freq <= 12:
                weight = 6; distinctive += 1
            elif freq <= 50:
                weight = 3
            else:
                weight = 1
            if idish:
                weight += 2
            weighted += weight
            if len(matches) < 8:
                matches.append({
                    "value": _safe_value(value, name=str(aobs.get("normalized_name") or ""), location="related", limit=160),
                    "frequency": freq,
                    "a_name": str(aobs.get("normalized_name") or aobs.get("name") or "value"),
                    "a_location": str(aobs.get("location") or ""),
                    "b_name": str(bobs.get("normalized_name") or bobs.get("name") or "value"),
                    "b_location": str(bobs.get("location") or ""),
                    "alias_candidate": str(aobs.get("normalized_name") or "") != str(bobs.get("normalized_name") or "") or str(aobs.get("location") or "") != str(bobs.get("location") or ""),
                    "identifierish": idish,
                })

        if meaningful_hashes == 0 and not same_resource:
            continue
        score = min(50, weighted) + (8 if same_resource else 0) + (3 if same_operation else 0)
        if meaningful_hashes:
            primary = f"VALORES EXACTOS COMPARTIDOS · {meaningful_hashes}"
        elif same_operation:
            primary = "MISMA OPERACIÓN · otra observación"
        else:
            primary = "MISMO RECURSO · otra observación"

        if meaningful_hashes >= 2 or distinctive >= 2 or (same_resource and meaningful_hashes >= 1):
            strength = "strong"; strength_label = "Relación fuerte"
        elif meaningful_hashes >= 1 or same_operation:
            strength = "medium"; strength_label = "Relación media"
        else:
            strength = "weak"; strength_label = "Relación débil"

        reasons: list[str] = []
        if same_operation:
            reasons.append("Misma operación HTTP")
        elif same_resource:
            reasons.append("Mismo recurso")
        if shared_names and not matches:
            reasons.append("Estructura similar: " + ", ".join(shared_names[:8]))

        item = dict(row)
        item.update({
            "score": score,
            "primary": primary,
            "strength": strength,
            "strength_label": strength_label,
            "reasons": reasons,
            "matches": matches,
            "shared_values": meaningful_hashes,
            "shared_names": len(shared_names),
        })
        scored.append(item)

    scored.sort(key=lambda x: ({"strong": 0, "medium": 1, "weak": 2}[x["strength"]], -int(x["score"]), abs(int(x["id"]) - int(exchange_id))))
    selected = scored[: max(1, min(int(limit), 200))]
    groups = {k: [x for x in selected if x["strength"] == k] for k in ("strong", "medium", "weak")}
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
    correlations = _exchange_value_correlations(conn, int(exchange_a), int(exchange_b))
    return {
        "a": a, "b": b, "changes": changes,
        "correlations": correlations,
        "strong_correlations": [x for x in correlations if x["strength"] == "strong"],
        "medium_correlations": [x for x in correlations if x["strength"] == "medium"],
        "weak_correlations": [x for x in correlations if x["strength"] == "weak"],
        "alias_candidates": sum(1 for x in correlations if x["alias_candidate"]),
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
