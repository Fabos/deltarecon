from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any

CLASSIFICATIONS = ("auth", "resolver", "context", "entity", "ignore")
JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
TOKEN_HINTS = ("token", "jwt", "authorization", "access_token", "accesstoken", "id_token", "idtoken", "session", "sid")
IDENTITY_HINTS = ("user", "member", "account", "customer", "email", "username", "login", "subject", "sub", "document")
CONTEXT_HINTS = ("role", "tenant", "scope", "permission", "organization", "org")
TRACKING_HINTS = ("_ga", "_gid", "_fbp", "_gcl", "_ttp", "ttcsid", "__cf_bm", "dtcookie", "acceptedcookies", "aceptedcookies")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", errors="ignore")).hexdigest()


def init_schema(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS http_value_annotations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exchange_id INTEGER NOT NULL,
            side TEXT NOT NULL,
            location TEXT NOT NULL,
            key_name TEXT NOT NULL,
            value_hash TEXT NOT NULL,
            value_preview TEXT,
            value_raw TEXT,
            classification TEXT NOT NULL DEFAULT 'ignore',
            identity_id INTEGER,
            object_type TEXT,
            note TEXT,
            source TEXT NOT NULL DEFAULT 'manual',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(exchange_id,side,location,key_name,value_hash),
            FOREIGN KEY(exchange_id) REFERENCES http_exchanges(id) ON DELETE CASCADE,
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_http_value_annotations_exchange ON http_value_annotations(exchange_id,side,classification);
        CREATE INDEX IF NOT EXISTS idx_http_value_annotations_identity ON http_value_annotations(identity_id,classification);
        CREATE INDEX IF NOT EXISTS idx_http_value_annotations_hash ON http_value_annotations(value_hash,classification);
        """
    )
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(http_value_annotations)")}
    if "value_raw" not in cols:
        conn.execute("ALTER TABLE http_value_annotations ADD COLUMN value_raw TEXT")


def decode_b64(value: str | None) -> str:
    if not value:
        return ""
    try:
        return base64.b64decode(value, validate=False).decode("utf-8", errors="replace")
    except Exception:
        return ""


def split_http(text: str) -> tuple[str, str]:
    if "\r\n\r\n" in text:
        return text.split("\r\n\r\n", 1)
    if "\n\n" in text:
        return text.split("\n\n", 1)
    return text, ""


def header_pairs(head: str) -> list[tuple[str, str]]:
    rows = []
    for line in head.replace("\r\n", "\n").split("\n")[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        rows.append((name.strip(), value.strip()))
    return rows


def jwt_parts(token: str) -> dict[str, Any] | None:
    token = str(token or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if not JWT_RE.match(token):
        return None
    try:
        def dec(part: str):
            raw = part + "=" * (-len(part) % 4)
            return json.loads(base64.urlsafe_b64decode(raw.encode()).decode("utf-8", errors="replace"))
        header = dec(token.split(".")[0])
        claims = dec(token.split(".")[1])
        if not isinstance(header, dict) or not isinstance(claims, dict):
            return None
        return {"token": token, "header": header, "claims": claims}
    except Exception:
        return None


def default_classification(key: str, value: str, location: str) -> str:
    low = str(key or "").strip().lower().replace("-", "_")
    lloc = str(location or "").lower()
    if any(low == x or low.startswith(x + "_") for x in TRACKING_HINTS):
        return "ignore"
    if jwt_parts(value):
        return "auth"
    if low in {"authorization", "x_auth_token", "x_access_token", "x_session_token"}:
        return "auth"
    if any(h in low for h in TOKEN_HINTS) and len(str(value or "")) >= 12:
        return "auth"
    if any(h in low for h in CONTEXT_HINTS):
        return "context"
    if any(h in low for h in IDENTITY_HINTS) and len(str(value or "")) >= 2:
        return "resolver"
    if (low.endswith("id") or low.endswith("_id") or low.endswith("uuid") or low.endswith("_uuid")) and "response" in lloc:
        return "entity"
    return "ignore"


def default_claim_classification(key: str) -> str:
    low = str(key or "").lower()
    if low in {"sub", "email", "user_id", "userid", "account_id", "accountid", "username", "login"}:
        return "resolver"
    if low in {"role", "roles", "tenant", "tenantid", "tenant_id", "scope", "scp", "aud", "permissions"}:
        return "context"
    return "ignore"


def _append(out: list[dict[str, Any]], seen: set[tuple[str, str, str]], *, side: str, location: str, key: str, value: Any) -> None:
    if isinstance(value, (dict, list)) or value is None:
        return
    text = str(value)
    sig = (location, str(key), sha(text))
    if sig in seen:
        return
    seen.add(sig)
    jwt = jwt_parts(text)
    out.append({
        "side": side,
        "location": location,
        "key": str(key),
        "value": text,
        "value_hash": sig[2],
        "preview": text if len(text) <= 180 else text[:177] + "…",
        "detected_type": "JWT" if jwt else "scalar",
        "jwt": jwt,
        "jwt_claims": ([{"key": str(k), "value": str(v), "default_classification": default_claim_classification(str(k))} for k, v in (jwt.get("claims") or {}).items()] if jwt else []),
        "default_classification": default_classification(str(key), text, location),
    })


def _json_values(obj: Any, prefix: str = "$"):
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}"
            if isinstance(value, (dict, list)):
                yield from _json_values(value, path)
            else:
                yield str(key), path, value
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            path = f"{prefix}[{idx}]"
            if isinstance(value, (dict, list)):
                yield from _json_values(value, path)
            else:
                yield str(idx), path, value


def extract_message(text: str, side: str) -> list[dict[str, Any]]:
    head, body = split_http(text)
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    pairs = header_pairs(head)
    content_type = ""
    for name, value in pairs:
        low = name.lower()
        if low == "content-type":
            content_type = value.lower()
        _append(out, seen, side=side, location=f"{side}_header:{name}", key=name, value=value)
        if side == "request" and low == "cookie":
            for piece in value.split(";"):
                if "=" in piece:
                    ck, cv = piece.split("=", 1)
                    _append(out, seen, side=side, location=f"request_cookie:{ck.strip()}", key=ck.strip(), value=cv.strip())
        if side == "response" and low == "set-cookie":
            first = value.split(";", 1)[0]
            if "=" in first:
                ck, cv = first.split("=", 1)
                _append(out, seen, side=side, location=f"response_cookie:{ck.strip()}", key=ck.strip(), value=cv.strip())
    first_line = head.replace("\r\n", "\n").split("\n", 1)[0]
    if side == "request":
        parts = first_line.split(" ")
        if len(parts) >= 2:
            try:
                url = urllib.parse.urlsplit(parts[1])
                for key, values in urllib.parse.parse_qs(url.query, keep_blank_values=True).items():
                    for value in values:
                        _append(out, seen, side=side, location=f"request_query:{key}", key=key, value=value)
            except Exception:
                pass
    raw_body = str(body or "")
    stripped = raw_body.lstrip()
    if raw_body and ("json" in content_type or stripped.startswith(("{", "["))):
        try:
            obj = json.loads(raw_body)
            for key, path, value in _json_values(obj):
                _append(out, seen, side=side, location=f"{side}_json:{path}", key=key, value=value)
        except Exception:
            pass
    if raw_body and "application/x-www-form-urlencoded" in content_type:
        try:
            for key, values in urllib.parse.parse_qs(raw_body, keep_blank_values=True).items():
                for value in values:
                    _append(out, seen, side=side, location=f"{side}_form:{key}", key=key, value=value)
        except Exception:
            pass
    return out


def extract_exchange(conn, exchange_id: int) -> dict[str, Any] | None:
    init_schema(conn)
    row = conn.execute(
        """SELECT e.*,o.method,o.resource_id,r.path,r.url,h.hostname
           FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id WHERE e.id=?""",
        (int(exchange_id),),
    ).fetchone()
    if not row:
        return None
    ex = dict(row)
    request_text = decode_b64(ex.get("request_b64"))
    response_text = decode_b64(ex.get("response_b64"))
    values = extract_message(request_text, "request") + extract_message(response_text, "response")
    anns = [dict(r) for r in conn.execute("SELECT * FROM http_value_annotations WHERE exchange_id=?", (int(exchange_id),)).fetchall()]
    amap = {(a["side"], a["location"], a["key_name"], a["value_hash"]): a for a in anns}
    for item in values:
        item["annotation"] = amap.get((item["side"], item["location"], item["key"], item["value_hash"]))
        # Claims are first-class observations too.  Keep their explicit teaching
        # attached to the JWT row so the Inspector can distinguish confirmed
        # evidence from suggestions/default heuristics after a reload.
        for claim in item.get("jwt_claims") or []:
            claim_loc = f"{item['location']}#jwt:{claim['key']}"
            claim_key = f"jwt.{claim['key']}"
            claim_hash = sha(str(claim.get("value") or ""))
            claim["location"] = claim_loc
            claim["value_hash"] = claim_hash
            claim["annotation"] = amap.get((item["side"], claim_loc, claim_key, claim_hash)) or amap.get((item["side"], claim_loc, str(claim["key"]), claim_hash))
    return {"exchange": ex, "request_text": request_text, "response_text": response_text, "values": values, "annotations": anns}


def save_annotation(conn, exchange_id: int, *, side: str, location: str, key: str, value: str,
                    classification: str, identity_id: int | None = None, object_type: str = "", note: str = "",
                    source: str = "http_inspector") -> int:
    init_schema(conn)
    cls = str(classification or "ignore").lower()
    if cls not in CLASSIFICATIONS:
        raise ValueError("Clasificación inválida")
    if cls in {"auth", "resolver", "context"} and not identity_id:
        raise ValueError("Selecciona una Identity para AUTH/RESOLVER/CONTEXT")
    if cls == "entity" and not str(object_type or "").strip():
        raise ValueError("Indica el tipo de Entity")
    vh = sha(value)
    previous = conn.execute(
        "SELECT * FROM http_value_annotations WHERE exchange_id=? AND side=? AND location=? AND key_name=? AND value_hash=?",
        (int(exchange_id), side, location, key, vh),
    ).fetchone()
    previous = dict(previous) if previous else None
    now = now_iso()
    conn.execute(
        """INSERT INTO http_value_annotations(exchange_id,side,location,key_name,value_hash,value_preview,value_raw,classification,identity_id,object_type,note,source,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(exchange_id,side,location,key_name,value_hash) DO UPDATE SET
             value_preview=excluded.value_preview,value_raw=excluded.value_raw,classification=excluded.classification,identity_id=excluded.identity_id,
             object_type=excluded.object_type,note=excluded.note,source=excluded.source,updated_at=excluded.updated_at""",
        (int(exchange_id), side, location, key, vh, value[:500], value, cls, identity_id, str(object_type or "")[:100] or None,
         str(note or "")[:1000], source, now, now),
    )
    row = conn.execute(
        "SELECT id FROM http_value_annotations WHERE exchange_id=? AND side=? AND location=? AND key_name=? AND value_hash=?",
        (int(exchange_id), side, location, key, vh),
    ).fetchone()
    ann_id = int(row["id"])

    # If the researcher changes the meaning of a value, remove the old Identity
    # semantics before applying the new one. The HTTP evidence itself remains.
    if previous and previous.get("identity_id") and (previous.get("classification") != cls or int(previous.get("identity_id") or 0) != int(identity_id or 0)):
        try:
            import negro_identity as identity_tools
            old_iid = int(previous["identity_id"])
            old_cls = str(previous.get("classification") or "")
            if old_cls == "resolver":
                conn.execute(
                    "UPDATE identity_resolvers SET enabled=0,classification='ignore',updated_at=? WHERE identity_id=? AND selector=? AND value_hash=?",
                    (now_iso(), old_iid, location, vh),
                )
                identity_tools.recompute_identity_attribution(conn, old_iid)
            elif old_cls == "auth":
                conn.execute(
                    "UPDATE auth_materials SET active=0,classification='ignore' WHERE identity_id=? AND fingerprint=?",
                    (old_iid, vh),
                )
        except Exception:
            pass

    if identity_id and cls in {"auth", "resolver", "context"}:
        import negro_identity as identity_tools
        identity_tools.init_schema(conn)
        # Explicitly choosing an Identity from the Inspector is also an anchor for
        # this Request. It should survive later resolver recalculations.
        try:
            identity_tools.assign_exchange(conn, int(exchange_id), int(identity_id), learn_auth=False, source="http_inspector", notes=f"HTTP Inspector · {classification.upper()} · {location}")
        except Exception:
            pass
        if cls == "auth":
            jwt = jwt_parts(value)
            if "cookie:" in location.lower():
                material_type, material_name = "cookie", key
            elif jwt:
                # A JWT returned as accessToken/idToken usually becomes a Bearer
                # credential on subsequent Requests. Store the mechanism rather
                # than the JSON field name so Identity can recognize/replay it.
                material_type, material_name = "bearer", "Bearer"
            elif "header:" in location.lower() and key.lower() not in {"authorization"}:
                material_type, material_name = "header", key
            else:
                material_type, material_name = "token", key
            material = {"material_type": material_type, "name": material_name, "value": (jwt or {}).get("token", value), "fingerprint": sha((jwt or {}).get("token", value)),
                        "preview": value[:120], "claims": (jwt or {}).get("claims", {})}
            identity_tools._learn_material(conn, int(identity_id), None, material, source=source, classification="auth")
        elif cls == "resolver":
            now2 = now_iso()
            selector = location
            conn.execute(
                """INSERT INTO identity_resolvers(identity_id,context_id,resolver_type,selector,value_hash,value_preview,value_raw,enabled,source,created_at,updated_at,classification,anchor_exchange_id)
                   VALUES(?,NULL,'http_value',?,?,?,?,1,?,?,?,'resolver',?)
                   ON CONFLICT(identity_id,context_id,resolver_type,selector,value_hash) DO UPDATE SET
                     value_preview=excluded.value_preview,value_raw=excluded.value_raw,enabled=1,source=excluded.source,
                     updated_at=excluded.updated_at,classification='resolver',anchor_exchange_id=excluded.anchor_exchange_id""",
                (int(identity_id), selector, vh, value[:120], value, source, now2, now2, int(exchange_id)),
            )
            try:
                identity_tools.recompute_identity_attribution(conn, int(identity_id))
            except Exception:
                pass
        # Context is deliberately annotation-first. It enriches the inspector/map
        # without pretending every role/tenant scalar is an authentication resolver.

    if cls == "entity":
        import negro_objects as object_tools
        import negro_parameters as parameter_tools
        try:
            parameter_tools.persist_exchange_parameters(conn, int(exchange_id))
        except Exception:
            pass
        obs = conn.execute(
            """SELECT id FROM parameter_observations WHERE exchange_id=? AND lower(normalized_name)=lower(?) AND value_hash=? ORDER BY id LIMIT 1""",
            (int(exchange_id), str(key).strip().lower().replace("-", "_"), vh),
        ).fetchone()
        if not obs:
            obs = conn.execute(
                """SELECT id FROM parameter_observations WHERE exchange_id=? AND lower(name)=lower(?) AND value_hash=? ORDER BY id LIMIT 1""",
                (int(exchange_id), key, vh),
            ).fetchone()
        if obs:
            object_tools.track_observation(conn, int(obs["id"]), str(object_type).strip(), allow_manual=True)

    # Inspector-created Identity anchors exist only while at least one active
    # AUTH/RESOLVER/CONTEXT annotation on this exchange supports them.
    old_iid = int(previous.get("identity_id") or 0) if previous else 0
    cleanup_ids = {x for x in (old_iid, int(identity_id or 0)) if x}
    for iid in cleanup_ids:
        active = conn.execute(
            """SELECT COUNT(*) c FROM http_value_annotations
               WHERE exchange_id=? AND identity_id=? AND classification IN ('auth','resolver','context')""",
            (int(exchange_id), iid),
        ).fetchone()
        if int(active["c"] or 0) == 0:
            conn.execute("DELETE FROM exchange_identities WHERE exchange_id=? AND identity_id=? AND source='http_inspector'", (int(exchange_id), iid))
    return ann_id


def annotation_css(cls: str) -> str:
    return {"auth":"http-ann-auth","resolver":"http-ann-resolver","context":"http-ann-context","entity":"http-ann-entity","ignore":""}.get(cls, "")


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", str(value or "").strip().lower().replace("-", "_"))

def _auth_fingerprint_candidates(item: dict[str, Any]) -> set[str]:
    value = str(item.get("value") or "").strip()
    out = {sha(value)} if value else set()
    jwt = jwt_parts(value)
    if jwt:
        out.add(sha(str(jwt.get("token") or "")))
    if value.lower().startswith("bearer "):
        out.add(sha(value[7:].strip()))
    return {x for x in out if x}

STRONG_JWT_IDENTITY_CLAIMS = {
    "sub", "subject", "user_id", "userid", "account_id", "accountid",
    "member_id", "memberid", "customer_id", "customerid", "email", "username", "login",
}


def _resolver_claim_name(row: dict[str, Any]) -> str:
    selector = str(row.get("selector") or "")
    resolver_type = str(row.get("resolver_type") or "")
    if resolver_type == "jwt_claim" and selector.startswith("jwt:"):
        return selector.split(":", 1)[1]
    if "#jwt:" in selector:
        return selector.rsplit("#jwt:", 1)[1]
    return ""


def _jwt_identity_matches(claims: dict[str, Any], resolver_rows: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    """Return confirmed Identity resolver evidence that supports one JWT.

    A claim-specific resolver is strongest.  For strong actor claims such as sub or
    email, a unique value match against another confirmed resolver is also useful: it
    lets a freshly rotated JWT be attributed without teaching every token again.
    """
    out: dict[int, list[dict[str, Any]]] = {}
    for raw_claim, raw_value in (claims or {}).items():
        claim = _normalized_key(str(raw_claim))
        if claim not in STRONG_JWT_IDENTITY_CLAIMS:
            continue
        vh = sha(str(raw_value))
        for rr in resolver_rows:
            if str(rr.get("value_hash") or "") != vh:
                continue
            learned_claim = _normalized_key(_resolver_claim_name(rr))
            # If the resolver was explicitly a JWT claim, do not cross claim names.
            if learned_claim and learned_claim != claim:
                continue
            iid = int(rr.get("identity_id") or 0)
            if not iid:
                continue
            out.setdefault(iid, []).append({
                "claim": str(raw_claim), "value": str(raw_value),
                "resolver_id": rr.get("id"), "selector": rr.get("selector"),
                "anchor_exchange_id": rr.get("anchor_exchange_id"),
            })
    return out


def auto_learn_jwt_auth(conn, exchange_id: int) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    """Persist rotated JWTs as AUTH when confirmed resolvers identify one actor.

    This is intentionally conservative: ambiguous/conflicting resolver matches are
    never auto-bound.  The returned map is also used by the Inspector UI.
    """
    init_schema(conn)
    try:
        import negro_identity as identity_tools
        identity_tools.init_schema(conn)
    except Exception:
        return {}
    payload = extract_exchange(conn, int(exchange_id))
    if not payload:
        return {}
    resolver_rows = [dict(r) for r in conn.execute(
        "SELECT * FROM identity_resolvers WHERE enabled=1 AND COALESCE(classification,'resolver')='resolver'"
    ).fetchall()]
    identities = {int(r["id"]): str(r["name"]) for r in conn.execute("SELECT id,name FROM identities").fetchall()}
    result: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for item in payload.get("values") or []:
        parsed = item.get("jwt") or jwt_parts(str(item.get("value") or ""))
        if not parsed or not isinstance(parsed.get("claims"), dict):
            continue
        matches = _jwt_identity_matches(parsed.get("claims") or {}, resolver_rows)
        key = (str(item.get("side")), str(item.get("location")), str(item.get("key")), str(item.get("value_hash")))
        if len(matches) != 1:
            if len(matches) > 1:
                result[key] = {"state": "conflict", "identity_ids": sorted(matches), "reason": "JWT claims point to more than one Identity"}
            continue
        iid, evidence = next(iter(matches.items()))
        token = str(parsed.get("token") or item.get("value") or "")
        material = {
            "material_type": "bearer", "name": "Bearer", "value": token,
            "fingerprint": sha(token), "preview": token[:120], "claims": parsed.get("claims") or {},
        }
        identity_tools._learn_material(conn, iid, None, material, source="jwt_resolver_auto", classification="auth")
        existing = conn.execute("SELECT identity_id FROM exchange_identities WHERE exchange_id=?", (int(exchange_id),)).fetchone()
        if not existing:
            try:
                identity_tools.assign_exchange(conn, int(exchange_id), iid, learn_auth=False, source="jwt_resolver_auto", notes=f"JWT auto-attributed by confirmed resolver claim {evidence[0]['claim']}")
            except Exception:
                pass
        result[key] = {
            "state": "auto_auth", "identity_id": iid, "identity_name": identities.get(iid, ""),
            "reason": f"JWT claim {evidence[0]['claim']} matched a confirmed resolver",
            "evidence": evidence,
        }
    return result


def resolver_value_suggestions(conn, exchange_id: int) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    """Suggest a new resolver key when a known resolver value appears under a new key.

    Recognition by value is useful, but the new key is never promoted permanently
    without human confirmation.  Conflicting Identity matches are surfaced instead.
    """
    init_schema(conn)
    payload = extract_exchange(conn, int(exchange_id))
    if not payload or not _table_exists(conn, "identity_resolvers"):
        return {}
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM identity_resolvers WHERE enabled=1 AND COALESCE(classification,'resolver')='resolver'"
    ).fetchall()]
    identities = {int(r["id"]): str(r["name"]) for r in conn.execute("SELECT id,name FROM identities").fetchall()} if _table_exists(conn, "identities") else {}
    explicit = {(str(a.get("side")), str(a.get("location")), str(a.get("key_name")), str(a.get("value_hash"))) for a in payload.get("annotations") or []}
    out: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for item in payload.get("values") or []:
        ikey = (str(item.get("side")), str(item.get("location")), str(item.get("key")), str(item.get("value_hash")))
        if ikey in explicit or item.get("jwt"):
            continue
        matches = [r for r in rows if str(r.get("value_hash") or "") == str(item.get("value_hash") or "")]
        by_identity: dict[int, list[dict[str, Any]]] = {}
        for rr in matches:
            iid = int(rr.get("identity_id") or 0)
            if iid:
                by_identity.setdefault(iid, []).append(rr)
        if len(by_identity) == 1:
            iid, evidence = next(iter(by_identity.items()))
            # Same key/path is already known resolver behavior, not a new suggestion.
            current_key = _normalized_key(str(item.get("key") or ""))
            already_known = False
            for rr in evidence:
                selector = str(rr.get("selector") or "")
                if selector == str(item.get("location") or ""):
                    already_known = True; break
                anchor = conn.execute(
                    "SELECT key_name FROM http_value_annotations WHERE identity_id=? AND classification='resolver' AND value_hash=? AND location=? ORDER BY id DESC LIMIT 1",
                    (iid, str(rr.get("value_hash") or ""), selector),
                ).fetchone()
                if anchor and _normalized_key(str(anchor["key_name"] or "")) == current_key:
                    already_known = True; break
            if not already_known:
                out[ikey] = {
                    "state": "suggested_resolver", "identity_id": iid, "identity_name": identities.get(iid, ""),
                    "reason": "Same confirmed resolver value appeared under a new key",
                    "known_selectors": [str(x.get("selector") or "") for x in evidence[:4]],
                }
        elif len(by_identity) > 1:
            out[ikey] = {
                "state": "conflict", "identity_ids": sorted(by_identity),
                "identity_names": [identities.get(i, str(i)) for i in sorted(by_identity)],
                "reason": "This value is a resolver for more than one Identity",
            }
    return out


def decorate_inspector_identity_state(conn, inspector: dict[str, Any], learned: list[dict[str, Any]] | None = None, auto_jwt: dict | None = None) -> dict[str, int]:
    """Attach UI-only state: confirmed, recognized, suggested, pending, conflict."""
    learned = list(learned or [])
    auto_jwt = auto_jwt or {}
    suggestions = resolver_value_suggestions(conn, int(inspector["exchange"]["id"]))
    by_obs: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for a in learned:
        key = (str(a.get("side")), str(a.get("location")), str(a.get("key_name")), str(a.get("value_hash")))
        by_obs.setdefault(key, []).append(a)
    counts = {"confirmed": 0, "recognized": 0, "suggested": 0, "pending": 0, "conflict": 0}
    for item in inspector.get("values") or []:
        key = (str(item.get("side")), str(item.get("location")), str(item.get("key")), str(item.get("value_hash")))
        explicit = item.get("annotation")
        learned_here = [a for a in by_obs.get(key, []) if not a.get("id")]
        auto = auto_jwt.get(key)
        suggestion = suggestions.get(key)
        item["learned_annotations"] = learned_here
        item["identity_suggestion"] = suggestion
        item["auto_jwt"] = auto
        if explicit:
            item["ui_state"] = "confirmed"
            item["ui_label"] = f"{str(explicit.get('classification') or '').upper()} confirmed"
        elif auto and auto.get("state") == "conflict":
            item["ui_state"] = "conflict"; item["ui_label"] = "Identity conflict"
        elif auto and auto.get("state") == "auto_auth":
            item["ui_state"] = "recognized"; item["ui_label"] = f"AUTH · {auto.get('identity_name') or ''}"
        elif learned_here:
            top = sorted(learned_here, key=lambda a: {"auth":4,"resolver":3,"entity":2,"context":1}.get(str(a.get("classification")),0), reverse=True)[0]
            item["ui_state"] = "recognized"; item["ui_label"] = _annotation_label(top)
            item["recognized_annotation"] = top
        elif suggestion and suggestion.get("state") == "conflict":
            item["ui_state"] = "conflict"; item["ui_label"] = "Resolver conflict"
        elif suggestion:
            item["ui_state"] = "suggested"; item["ui_label"] = f"MATCH · {suggestion.get('identity_name') or ''}"
        else:
            item["ui_state"] = "pending"; item["ui_label"] = "Pending"
        counts[item["ui_state"]] = counts.get(item["ui_state"], 0) + 1

        # Claims: explicit annotations are authoritative; otherwise show confirmed
        # claim resolvers when they match this Identity/value.
        for claim in item.get("jwt_claims") or []:
            ann = claim.get("annotation")
            if ann:
                claim["ui_state"] = "confirmed"
                iid = int(ann.get("identity_id") or 0)
                name = conn.execute("SELECT name FROM identities WHERE id=?", (iid,)).fetchone() if iid else None
                claim["identity_name"] = str(name["name"]) if name else ""
                continue
            cvh = str(claim.get("value_hash") or sha(str(claim.get("value") or "")))
            claim_key = _normalized_key(str(claim.get("key") or ""))
            matches = []
            for rr in conn.execute("SELECT * FROM identity_resolvers WHERE enabled=1 AND COALESCE(classification,'resolver')='resolver' AND value_hash=?", (cvh,)).fetchall() if _table_exists(conn, "identity_resolvers") else []:
                rd = dict(rr); known_claim = _normalized_key(_resolver_claim_name(rd))
                if known_claim and known_claim != claim_key:
                    continue
                matches.append(rd)
            ids = sorted({int(x.get("identity_id") or 0) for x in matches if int(x.get("identity_id") or 0)})
            if len(ids) == 1:
                name = conn.execute("SELECT name FROM identities WHERE id=?", (ids[0],)).fetchone()
                claim["ui_state"] = "recognized"; claim["identity_id"] = ids[0]; claim["identity_name"] = str(name["name"]) if name else ""
            elif len(ids) > 1:
                claim["ui_state"] = "conflict"
            else:
                claim["ui_state"] = "pending"

        # Stable server-side search index for HTTP Inspector.  Do not depend on
        # DOM text layout/details/selects: include nested JWT claims and learned
        # Identity context explicitly so searches such as `nickname`, `Fabian`,
        # `jwt.sub` or a resolver value work even when claims are collapsed.
        search_parts = [
            str(item.get("side") or ""),
            str(item.get("location") or ""),
            str(item.get("key") or ""),
            str(item.get("value") or ""),
            str(item.get("preview") or ""),
            str(item.get("detected_type") or ""),
            str(item.get("ui_state") or ""),
            str(item.get("ui_label") or ""),
        ]
        if suggestion:
            search_parts.extend([str(suggestion.get("identity_name") or ""), str(suggestion.get("state") or "")])
        if explicit:
            search_parts.extend([str(explicit.get("classification") or ""), str(explicit.get("identity_id") or "")])
            iid = int(explicit.get("identity_id") or 0)
            if iid:
                row = conn.execute("SELECT name FROM identities WHERE id=?", (iid,)).fetchone()
                if row:
                    search_parts.append(str(row["name"] or ""))
        if auto:
            search_parts.extend([str(auto.get("identity_name") or ""), str(auto.get("reason") or "")])
        for claim in item.get("jwt_claims") or []:
            search_parts.extend([
                f"jwt.{claim.get('key') or ''}",
                str(claim.get("key") or ""),
                str(claim.get("value") or ""),
                str(claim.get("ui_state") or ""),
                str(claim.get("identity_name") or ""),
            ])
            cann = claim.get("annotation") or {}
            search_parts.append(str(cann.get("classification") or ""))
        item["search_blob"] = " ".join(x for x in search_parts if x).lower()
    return counts


def learned_annotations(conn, exchange_id: int) -> list[dict[str, Any]]:
    """Return explicit + learned annotations applicable to one exchange.

    Explicit annotations on the exchange always win. Learned matches are projected
    conservatively from active Identity auth/resolvers/context evidence and taught
    Business Object identifiers. Exact path+value is preferred; key+value is a
    fallback only when the learned evidence used the same semantic key.
    """
    init_schema(conn)
    try:
        import negro_identity as identity_tools
        import negro_objects as object_tools
        identity_tools.init_schema(conn); object_tools.init_schema(conn)
    except Exception:
        pass
    # Rotated JWTs are learned as AUTH as soon as a confirmed resolver claim
    # identifies exactly one actor. This is idempotent and deliberately refuses
    # ambiguous Identity matches.
    try:
        auto_learn_jwt_auth(conn, int(exchange_id))
    except Exception:
        pass
    payload = extract_exchange(conn, int(exchange_id))
    if not payload:
        return []
    values = payload.get("values") or []
    explicit = [dict(a) for a in payload.get("annotations") or []]
    out = list(explicit)
    explicit_keys = {(str(a.get("side")), str(a.get("location")), str(a.get("key_name")), str(a.get("value_hash"))) for a in explicit}

    identities = {int(r["id"]): str(r["name"]) for r in conn.execute("SELECT id,name FROM identities").fetchall()} if _table_exists(conn, "identities") else {}
    for a in out:
        iid=int(a.get("identity_id") or 0)
        if iid and not a.get("identity_name"):
            a["identity_name"] = identities.get(iid, "")
        a.setdefault("match_reason", "explicit teaching")
        a.setdefault("source_exchange_id", int(exchange_id))

    # Active AUTH material. Match the actual secret/token value, not the display name.
    auth_rows = []
    if _table_exists(conn, "auth_materials"):
        auth_rows = [dict(r) for r in conn.execute("SELECT * FROM auth_materials WHERE active=1 AND COALESCE(classification,'auth')='auth'").fetchall()]
    auth_by_fp: dict[str, list[dict[str, Any]]] = {}
    for r in auth_rows:
        auth_by_fp.setdefault(str(r.get("fingerprint") or ""), []).append(r)

    # Resolver knowledge with the original key, when available.
    resolver_rows = []
    if _table_exists(conn, "identity_resolvers"):
        resolver_rows = [dict(r) for r in conn.execute("SELECT * FROM identity_resolvers WHERE enabled=1 AND COALESCE(classification,'resolver')='resolver'").fetchall()]
    anchor_key: dict[tuple[int,str,str], str] = {}
    if resolver_rows:
        try:
            for r in conn.execute("""SELECT a.identity_id,a.location,a.value_hash,a.key_name FROM http_value_annotations a
                                      WHERE a.classification='resolver' AND a.identity_id IS NOT NULL""").fetchall():
                anchor_key[(int(r["identity_id"]), str(r["location"]), str(r["value_hash"]))] = str(r["key_name"] or "")
        except Exception:
            pass

    # Explicit HTTP Inspector decisions are the primary source of truth for
    # projection across Workbench/Burp. Derived auth/resolver tables remain useful
    # for replay/attribution, but a UI must never lose a researcher decision just
    # because that secondary layer is stale.
    explicit_rules = []
    try:
        explicit_rules = [dict(r) for r in conn.execute("""SELECT a.*,i.name identity_name
            FROM http_value_annotations a LEFT JOIN identities i ON i.id=a.identity_id
            WHERE a.classification IN ('auth','resolver','context','entity')
            ORDER BY a.updated_at DESC,a.id DESC""").fetchall()]
    except Exception:
        explicit_rules = []

    # CONTEXT is annotation-led; project previously taught same path/key/value.
    context_rows = []
    try:
        context_rows = [dict(r) for r in conn.execute("""SELECT a.*,i.name identity_name FROM http_value_annotations a
                    LEFT JOIN identities i ON i.id=a.identity_id
                    WHERE a.classification='context' AND a.identity_id IS NOT NULL""").fetchall()]
    except Exception:
        pass

    # Taught entities are backed by object identifiers and concrete object values.
    entity_map: dict[tuple[str,str], list[dict[str, Any]]] = {}
    try:
        for r in conn.execute("""SELECT bi.normalized_name,bo.identifier_hash,bt.name object_type,bo.identifier_raw,bo.identifier_preview
            FROM business_object_identifiers bi JOIN business_object_types bt ON bt.id=bi.object_type_id
            JOIN business_objects bo ON bo.object_type_id=bt.id""").fetchall():
            entity_map.setdefault((_normalized_key(r["normalized_name"]), str(r["identifier_hash"])), []).append(dict(r))
    except Exception:
        pass

    def add(item: dict[str, Any], cls: str, *, identity_id: int|None=None, identity_name: str="", object_type: str="", source_exchange_id: int|None=None, match_reason: str="learned"):
        ek=(str(item.get("side")),str(item.get("location")),str(item.get("key")),str(item.get("value_hash")))
        if ek in explicit_keys:
            return
        # Do not add duplicate learned meaning for the same exact observation/class/owner.
        sig=(ek,cls,int(identity_id or 0),object_type)
        for a in out:
            if ( (str(a.get("side")),str(a.get("location")),str(a.get("key_name")),str(a.get("value_hash"))), str(a.get("classification")), int(a.get("identity_id") or 0), str(a.get("object_type") or "") ) == sig:
                return
        out.append({
            "id": None, "exchange_id": int(exchange_id), "side": item.get("side"), "location": item.get("location"),
            "key_name": item.get("key"), "value_hash": item.get("value_hash"), "value_preview": item.get("preview"),
            "value_raw": item.get("value"), "classification": cls, "identity_id": identity_id, "identity_name": identity_name,
            "object_type": object_type or None, "source": "learned", "source_exchange_id": source_exchange_id,
            "match_reason": match_reason,
        })

    for item in values:
        # Direct projection from explicit Inspector teaching. This intentionally
        # prefers same path+value, then same semantic key+value. AUTH may also match
        # the exact secret value across locations (e.g. response token -> Bearer).
        for r in explicit_rules:
            cls=str(r.get("classification") or "")
            if str(r.get("value_hash") or "") != str(item.get("value_hash") or ""):
                continue
            exact_path=str(r.get("location") or "")==str(item.get("location") or "")
            same_key=_normalized_key(str(r.get("key_name") or ""))==_normalized_key(str(item.get("key") or ""))
            auth_value = cls=="auth"
            if exact_path or same_key or auth_value:
                iid=int(r.get("identity_id") or 0) or None
                add(item,cls,identity_id=iid,identity_name=str(r.get("identity_name") or identities.get(iid or 0,"")),
                    object_type=str(r.get("object_type") or ""),source_exchange_id=r.get("exchange_id"),
                    match_reason=("explicit auth value" if auth_value and not (exact_path or same_key) else ("explicit path+value" if exact_path else "explicit key+value")))

        # If the value itself is a JWT, use an active jwt_claim resolver to infer
        # the actor and annotate the whole token as AUTH. This makes rotated login
        # tokens explainable in Workbench/Burp without requiring the exact token
        # bytes to have been seen before.
        parsed_jwt = jwt_parts(str(item.get("value") or ""))
        if parsed_jwt and isinstance(parsed_jwt.get("claims"), dict):
            claims=parsed_jwt.get("claims") or {}
            for rr in resolver_rows:
                selector=str(rr.get("selector") or "")
                rtype=str(rr.get("resolver_type") or "")
                # Claims taught from HTTP Inspector are stored as http_value with
                # a selector ending in #jwt:<claim>. Older flows may use jwt_claim.
                if rtype == "jwt_claim":
                    claim_name=selector.split(".")[-1].split(":")[-1]
                elif "#jwt:" in selector:
                    claim_name=selector.rsplit("#jwt:",1)[1]
                else:
                    continue
                if claim_name not in claims:
                    continue
                cv=str(claims.get(claim_name))
                if sha(cv) != str(rr.get("value_hash") or ""):
                    continue
                iid=int(rr.get("identity_id") or 0) or None
                add(item,"auth",identity_id=iid,identity_name=identities.get(iid or 0,""),
                    source_exchange_id=rr.get("anchor_exchange_id"),match_reason=f"JWT claim {claim_name} resolver")

        # AUTH
        for fp in _auth_fingerprint_candidates(item):
            for r in auth_by_fp.get(fp, []):
                iid=int(r.get("identity_id") or 0) or None
                add(item,"auth",identity_id=iid,identity_name=identities.get(iid or 0,""),match_reason="auth value/fingerprint")
        # RESOLVER
        for r in resolver_rows:
            if str(r.get("value_hash") or "") != str(item.get("value_hash") or ""):
                continue
            iid=int(r.get("identity_id") or 0) or None
            selector=str(r.get("selector") or "")
            learned_key=anchor_key.get((iid or 0, selector, str(r.get("value_hash") or "")), "")
            exact_path = selector == str(item.get("location") or "")
            same_key = bool(learned_key) and _normalized_key(learned_key)==_normalized_key(str(item.get("key") or ""))
            if exact_path or same_key:
                add(item,"resolver",identity_id=iid,identity_name=identities.get(iid or 0,""),source_exchange_id=r.get("anchor_exchange_id"),match_reason="resolver path+value" if exact_path else "resolver key+value")
        # CONTEXT
        for r in context_rows:
            if str(r.get("value_hash") or "") != str(item.get("value_hash") or ""):
                continue
            exact_path=str(r.get("location") or "")==str(item.get("location") or "")
            same_key=_normalized_key(str(r.get("key_name") or ""))==_normalized_key(str(item.get("key") or ""))
            if exact_path or same_key:
                iid=int(r.get("identity_id") or 0) or None
                add(item,"context",identity_id=iid,identity_name=str(r.get("identity_name") or identities.get(iid or 0,"")),source_exchange_id=r.get("exchange_id"),match_reason="context path+value" if exact_path else "context key+value")
        # ENTITY
        for er in entity_map.get((_normalized_key(str(item.get("key") or "")), str(item.get("value_hash") or "")), []):
            add(item,"entity",object_type=str(er.get("object_type") or ""),match_reason="entity identifier key+value")
    return out

def _table_exists(conn, name: str) -> bool:
    try:
        return bool(conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone())
    except Exception:
        return False

def _annotation_label(a: dict[str, Any]) -> str:
    cls=str(a.get("classification") or "").upper()
    owner=str(a.get("identity_name") or a.get("object_type") or "").strip()
    return f"{cls} · {owner}" if owner else cls

def _span_ranges(text: str, a: dict[str, Any]) -> list[tuple[int,int]]:
    """Locate an observation using its structural location when possible."""
    value=str(a.get("value_raw") or a.get("value_preview") or "")
    if not value: return []
    loc=str(a.get("location") or ""); key=str(a.get("key_name") or "")
    ranges=[]
    # Headers: match the named header first, then the exact value within that line.
    if "_header:" in loc:
        target=loc.split(":",1)[1]
        for m in re.finditer(rf"(?mi)^(?P<name>{re.escape(target)})\s*:\s*(?P<val>[^\r\n]*)\r?$", text):
            lineval=m.group("val"); idx=lineval.find(value)
            if idx>=0:
                st=m.start("val")+idx; ranges.append((st,st+len(value)))
        return ranges
    # Cookies: constrain by cookie name.
    if "_cookie:" in loc:
        cname=loc.split(":",1)[1]
        for m in re.finditer(rf"(?i)(?:^|[;,:]\s*){re.escape(cname)}\s*=\s*(?P<val>[^;\r\n]+)", text):
            vv=m.group("val").strip(); idx=vv.find(value)
            if idx>=0:
                st=m.start("val") + (len(m.group("val"))-len(m.group("val").lstrip())) + idx; ranges.append((st,st+len(value)))
        return ranges
    # JSON/form/query: same semantic key plus value. This is conservative enough
    # to avoid painting every equal scalar elsewhere in a large message.
    if "_json:" in loc:
        # JSON string or scalar. Locate key then the exact raw value after it.
        for km in re.finditer(rf'(?s)"{re.escape(key)}"\s*:\s*', text):
            window=text[km.end():km.end()+max(256,len(value)+32)]
            vi=window.find(value)
            if vi>=0:
                st=km.end()+vi; ranges.append((st,st+len(value)))
        return ranges
    if "_query:" in loc or "_form:" in loc:
        for m in re.finditer(rf"(?:^|[?&]){re.escape(key)}=(?P<val>[^&\s]*)", text):
            vv=urllib.parse.unquote_plus(m.group("val"));
            if vv==value:
                ranges.append((m.start("val"),m.end("val")))
        return ranges
    # Fallback only when the exact value is unique in the message.
    starts=[m.start() for m in re.finditer(re.escape(value), text)]
    if len(starts)==1:
        ranges=[(starts[0],starts[0]+len(value))]
    return ranges

def highlighted_html(text: str, annotations: list[dict[str, Any]], side: str) -> str:
    """Render precise inline annotations without corrupting nested HTML replacements."""
    text=str(text or "")
    relevant=[a for a in annotations if str(a.get("side"))==side and str(a.get("classification"))!="ignore" and (a.get("value_raw") or a.get("value_preview"))]
    spans=[]
    occupied=[]
    # Stronger/longer evidence wins overlapping ranges.
    priority={"auth":4,"resolver":3,"entity":2,"context":1}
    relevant.sort(key=lambda a:(priority.get(str(a.get("classification")),0),len(str(a.get("value_raw") or a.get("value_preview") or ""))),reverse=True)
    for a in relevant[:250]:
        for st,en in _span_ranges(text,a):
            if st<0 or en<=st: continue
            if any(not (en<=x or st>=y) for x,y in occupied): continue
            occupied.append((st,en)); spans.append((st,en,a))
    spans.sort(key=lambda x:x[0])
    out=[]; pos=0
    for st,en,a in spans:
        out.append(html.escape(text[pos:st]))
        css=annotation_css(str(a.get("classification") or "")); label=_annotation_label(a)
        title=label
        if a.get("match_reason"): title += f" · {a.get('match_reason')}"
        if a.get("source_exchange_id"): title += f" · aprendido en Request #{a.get('source_exchange_id')}"
        out.append(f'<span class="http-annotation {css}" data-label="{html.escape(label)}" title="{html.escape(title)}">{html.escape(text[st:en])}</span>')
        pos=en
    out.append(html.escape(text[pos:]))
    return ''.join(out)
