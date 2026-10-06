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


def highlighted_html(text: str, annotations: list[dict[str, Any]], side: str) -> str:
    # Highlight values conservatively. Longest first avoids highlighting a small ID
    # inside a larger token. IGNORE remains unstyled but its decision is preserved.
    raw = html.escape(text or "")
    relevant = [a for a in annotations if a.get("side") == side and a.get("classification") != "ignore" and (a.get("value_raw") or a.get("value_preview"))]
    relevant.sort(key=lambda a: len(str(a.get("value_raw") or a.get("value_preview") or "")), reverse=True)
    for a in relevant[:100]:
        value = str(a.get("value_raw") or a.get("value_preview") or "")
        if not value or len(value) > 5000:
            continue
        escaped = html.escape(value)
        css = annotation_css(str(a.get("classification") or ""))
        label = html.escape(str(a.get("classification") or "").upper())
        title = html.escape(f"{label} · {a.get('key_name') or ''}")
        replacement = f'<mark class="http-annotation {css}" title="{title}">{escaped}</mark>'
        raw = raw.replace(escaped, replacement)
    return raw
