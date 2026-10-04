from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

import negro_hunter as hunter


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_schema(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS identities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL DEFAULT 'account',
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS identity_contexts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_id INTEGER NOT NULL,
            label TEXT NOT NULL,
            role TEXT,
            tenant TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(identity_id, label),
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS auth_materials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_id INTEGER NOT NULL,
            context_id INTEGER,
            material_type TEXT NOT NULL,
            material_name TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            masked_preview TEXT,
            raw_value TEXT,
            source TEXT NOT NULL DEFAULT 'manual',
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            UNIQUE(identity_id, context_id, material_type, material_name, fingerprint),
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE CASCADE,
            FOREIGN KEY(context_id) REFERENCES identity_contexts(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS identity_resolvers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_id INTEGER NOT NULL,
            context_id INTEGER,
            resolver_type TEXT NOT NULL,
            selector TEXT NOT NULL,
            value_hash TEXT NOT NULL,
            value_preview TEXT,
            value_raw TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            source TEXT NOT NULL DEFAULT 'manual',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(identity_id, context_id, resolver_type, selector, value_hash),
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE CASCADE,
            FOREIGN KEY(context_id) REFERENCES identity_contexts(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS exchange_identities (
            exchange_id INTEGER PRIMARY KEY,
            identity_id INTEGER NOT NULL,
            context_id INTEGER,
            source TEXT NOT NULL,
            confidence TEXT NOT NULL DEFAULT 'high',
            resolver_id INTEGER,
            assigned_at TEXT NOT NULL,
            notes TEXT,
            FOREIGN KEY(exchange_id) REFERENCES http_exchanges(id) ON DELETE CASCADE,
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE CASCADE,
            FOREIGN KEY(context_id) REFERENCES identity_contexts(id) ON DELETE SET NULL,
            FOREIGN KEY(resolver_id) REFERENCES identity_resolvers(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_auth_material_fingerprint ON auth_materials(fingerprint, active);
        CREATE INDEX IF NOT EXISTS idx_identity_resolvers_lookup ON identity_resolvers(resolver_type, selector, value_hash, enabled);
        CREATE INDEX IF NOT EXISTS idx_exchange_identities_identity ON exchange_identities(identity_id, context_id, assigned_at);
        """
    )
    auth_cols = {row["name"] for row in conn.execute("PRAGMA table_info(auth_materials)")}
    if "raw_value" not in auth_cols:
        conn.execute("ALTER TABLE auth_materials ADD COLUMN raw_value TEXT")
    resolver_cols = {row["name"] for row in conn.execute("PRAGMA table_info(identity_resolvers)")}
    if "value_raw" not in resolver_cols:
        conn.execute("ALTER TABLE identity_resolvers ADD COLUMN value_raw TEXT")
        resolver_cols.add("value_raw")
    if "anchor_exchange_id" not in resolver_cols:
        conn.execute("ALTER TABLE identity_resolvers ADD COLUMN anchor_exchange_id INTEGER")
        resolver_cols.add("anchor_exchange_id")
    if "anchor_observation_id" not in resolver_cols:
        conn.execute("ALTER TABLE identity_resolvers ADD COLUMN anchor_observation_id INTEGER")


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


def _headers(head: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    lines = head.replace("\r\n", "\n").split("\n")
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        out.setdefault(key.strip().lower(), []).append(value.strip())
    return out


def _sha(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", errors="ignore")).hexdigest()


def _jwt_payload(token: str) -> dict[str, Any]:
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return {}
    try:
        raw = parts[1] + "=" * (-len(parts[1]) % 4)
        obj = json.loads(base64.urlsafe_b64decode(raw.encode()).decode("utf-8", errors="replace"))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _material_preview(value: str) -> str:
    return hunter._mask_value(str(value or ""))


def extract_auth_materials(conn, exchange_id: int) -> list[dict[str, Any]]:
    row = conn.execute("SELECT request_b64 FROM http_exchanges WHERE id=?", (int(exchange_id),)).fetchone()
    if not row:
        return []
    req = _decode_b64(row["request_b64"])
    head, _ = _split_http(req)
    headers = _headers(head)
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for cookie_line in headers.get("cookie", []):
        for piece in cookie_line.split(";"):
            if "=" not in piece:
                continue
            name, value = piece.split("=", 1)
            name, value = name.strip(), value.strip()
            if not name or not value:
                continue
            key = ("cookie", name.lower(), _sha(value))
            if key in seen:
                continue
            seen.add(key)
            out.append({"material_type": "cookie", "name": name, "value": value, "fingerprint": key[2], "preview": _material_preview(value), "claims": {}})

    for auth in headers.get("authorization", []):
        raw = auth.strip()
        if not raw:
            continue
        scheme, _, credential = raw.partition(" ")
        credential = credential.strip() or raw
        typ = "bearer" if scheme.lower() == "bearer" and credential != raw else "authorization"
        key = (typ, scheme.lower() or "authorization", _sha(credential))
        if key in seen:
            continue
        seen.add(key)
        claims = _jwt_payload(credential) if typ == "bearer" else {}
        out.append({"material_type": typ, "name": scheme or "Authorization", "value": credential, "fingerprint": key[2], "preview": _material_preview(credential), "claims": claims})

    # Common custom authentication headers.  These are kept explicit rather than
    # treating every X-* header as a credential.  The researcher still decides
    # whether a detected material belongs to an Identity Context.
    for header_name in ("x-api-key", "api-key", "x-auth-token", "x-access-token", "x-session-token"):
        for value in headers.get(header_name, []):
            raw = value.strip()
            if not raw:
                continue
            key = ("header", header_name, _sha(raw))
            if key in seen:
                continue
            seen.add(key)
            out.append({"material_type": "header", "name": header_name, "value": raw, "fingerprint": key[2], "preview": _material_preview(raw), "claims": {}})
    return out


def create_identity(conn, name: str, *, kind: str = "account", notes: str = "") -> int:
    init_schema(conn)
    name = str(name or "").strip()[:120]
    if not name:
        raise ValueError("Nombre de identidad requerido")
    now = now_iso()
    row = conn.execute("SELECT id FROM identities WHERE lower(name)=lower(?)", (name,)).fetchone()
    if row:
        return int(row["id"])
    cur = conn.execute("INSERT INTO identities(name,kind,notes,created_at,updated_at) VALUES(?,?,?,?,?)", (name, str(kind or "account")[:40], str(notes or "")[:2000], now, now))
    return int(cur.lastrowid)


def create_context(conn, identity_id: int, label: str, *, role: str = "", tenant: str = "", notes: str = "") -> int:
    init_schema(conn)
    label = str(label or "").strip()[:120]
    if not label:
        raise ValueError("Etiqueta de contexto requerida")
    now = now_iso()
    row = conn.execute("SELECT id FROM identity_contexts WHERE identity_id=? AND lower(label)=lower(?)", (int(identity_id), label)).fetchone()
    if row:
        return int(row["id"])
    cur = conn.execute(
        "INSERT INTO identity_contexts(identity_id,label,role,tenant,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
        (int(identity_id), label, str(role or "")[:120], str(tenant or "")[:160], str(notes or "")[:2000], now, now),
    )
    return int(cur.lastrowid)


def _context_belongs(conn, identity_id: int, context_id: int | None) -> int | None:
    if not context_id:
        return None
    row = conn.execute("SELECT id FROM identity_contexts WHERE id=? AND identity_id=?", (int(context_id), int(identity_id))).fetchone()
    if not row:
        raise ValueError("El contexto no pertenece a la identidad")
    return int(row["id"])


def _learn_material(conn, identity_id: int, context_id: int | None, material: dict[str, Any], *, source: str) -> None:
    now = now_iso()
    conn.execute(
        """INSERT INTO auth_materials(identity_id,context_id,material_type,material_name,fingerprint,masked_preview,raw_value,source,first_seen_at,last_seen_at,active)
           VALUES(?,?,?,?,?,?,?,?,?,?,1)
           ON CONFLICT(identity_id,context_id,material_type,material_name,fingerprint)
           DO UPDATE SET last_seen_at=excluded.last_seen_at,active=1,masked_preview=excluded.masked_preview,raw_value=excluded.raw_value""",
        (int(identity_id), context_id, material["material_type"], str(material["name"])[:160], material["fingerprint"], material["preview"], str(material.get("value") or ""), source, now, now),
    )


def _learn_stable_jwt_claims(conn, identity_id: int, context_id: int | None, material: dict[str, Any], *, source: str) -> int:
    claims = material.get("claims") or {}
    if not isinstance(claims, dict):
        return 0
    stable = ("sub", "user_id", "userid", "userId", "account_id", "accountid", "accountId", "email")
    count = 0
    now = now_iso()
    for key in stable:
        if key not in claims or claims[key] in (None, ""):
            continue
        value = str(claims[key])
        selector = f"jwt:{key}"
        vh = _sha(value)
        conn.execute(
            """INSERT INTO identity_resolvers(identity_id,context_id,resolver_type,selector,value_hash,value_preview,value_raw,enabled,source,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,1,?,?,?)
               ON CONFLICT(identity_id,context_id,resolver_type,selector,value_hash)
               DO UPDATE SET value_preview=excluded.value_preview,value_raw=excluded.value_raw,enabled=1,updated_at=excluded.updated_at""",
            (int(identity_id), context_id, "jwt_claim", selector, vh, value[:120], value, source, now, now),
        )
        count += 1
    return count



SELF_IDENTITY_PATHS = {
    "/me", "/whoami", "/userinfo", "/user/me", "/users/me", "/account/me", "/accounts/me",
    "/profile/me", "/session/me", "/api/me", "/api/user/me", "/api/users/me",
}
ACTOR_IDENTITY_NAMES = {
    "id", "userid", "user_id", "accountid", "account_id", "email", "username", "login", "sub", "subject",
}
OPTIONAL_ACTOR_NAMES = {"phone", "mobile", "displayname", "display_name", "name"}
NON_ACTOR_NAMES = {
    "role", "roleid", "role_id", "status", "state", "ownerid", "owner_id", "sellerid", "seller_id",
    "buyerid", "buyer_id", "customerid", "customer_id", "tenantid", "tenant_id", "orderid", "order_id",
    "productid", "product_id", "itemid", "item_id", "invoiceid", "invoice_id", "resourceid", "resource_id",
}


def _looks_self_identity_path(path: str) -> bool:
    raw = "/" + str(path or "").split("?", 1)[0].strip("/").lower()
    if raw in SELF_IDENTITY_PATHS:
        return True
    # Common current-user/profile forms, without treating arbitrary /users/{id} as self.
    return raw.endswith(("/me", "/whoami", "/userinfo", "/current-user", "/current_user", "/my-profile", "/my_profile"))


def resolver_suitability(conn, observation_id: int) -> dict[str, Any]:
    """Explain whether a parameter observation is suitable to identify the actor.

    Object ownership fields intentionally do not become actor resolvers: ownerId=101
    may describe the object owner while the request was made by another identity.
    """
    init_schema(conn)
    row = conn.execute(
        """SELECT p.*,r.path,o.method,h.hostname FROM parameter_observations p
           JOIN resource_operations o ON o.id=p.operation_id
           JOIN resources r ON r.id=p.resource_id JOIN hosts h ON h.id=r.host_id
           WHERE p.id=?""",
        (int(observation_id),),
    ).fetchone()
    if not row:
        return {"allowed": False, "recommended": False, "kind": "unknown", "reason": "Observación no encontrada"}
    name = str(row["normalized_name"] or "").lower()
    location = str(row["location"] or "").lower()
    path = str(row["path"] or "")
    self_path = _looks_self_identity_path(path)
    is_response = location.startswith("response_json:") or location.startswith("response_form")
    if name in NON_ACTOR_NAMES or any(tok in name for tok in ("owner", "tenant", "order", "invoice", "product", "item")):
        return {"allowed": False, "recommended": False, "kind": "object_or_context", "reason": "Describe objeto/contexto; no demuestra quién hizo la request", "self_path": self_path, "observation": dict(row)}
    if self_path and is_response and name in ACTOR_IDENTITY_NAMES:
        return {"allowed": True, "recommended": True, "kind": "actor", "reason": "Identificador estable observado en un endpoint de identidad propia", "self_path": True, "observation": dict(row)}
    if self_path and is_response and name in OPTIONAL_ACTOR_NAMES:
        return {"allowed": True, "recommended": False, "kind": "actor_optional", "reason": "Puede identificar la cuenta, pero conviene confirmarlo manualmente", "self_path": True, "observation": dict(row)}
    return {"allowed": False, "recommended": False, "kind": "not_actor", "reason": "No es un identificador de actor suficientemente confiable en este contexto", "self_path": self_path, "observation": dict(row)}


def candidate_identity_resolvers(conn, exchange_id: int) -> dict[str, list[dict[str, Any]]]:
    rows = conn.execute(
        """SELECT id,name,normalized_name,location,value_hash,value_preview,value_raw
           FROM parameter_observations WHERE exchange_id=? ORDER BY id""",
        (int(exchange_id),),
    ).fetchall()
    candidates: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        suitability = resolver_suitability(conn, int(row["id"]))
        item.update({k: suitability.get(k) for k in ("allowed", "recommended", "kind", "reason")})
        if item["allowed"]:
            candidates.append(item)
        elif str(row["location"] or "").lower().startswith("response_json:"):
            ignored.append(item)
    return {"candidates": candidates, "ignored": ignored}

def assign_exchange(conn, exchange_id: int, identity_id: int, *, context_id: int | None = None, learn_auth: bool = True, resolver_observation_ids: list[int] | None = None, source: str = "manual", notes: str = "") -> dict[str, Any]:
    init_schema(conn)
    identity = conn.execute("SELECT * FROM identities WHERE id=?", (int(identity_id),)).fetchone()
    if not identity:
        raise ValueError("Identidad no encontrada")
    context_id = _context_belongs(conn, int(identity_id), context_id)
    ex = conn.execute("SELECT id FROM http_exchanges WHERE id=?", (int(exchange_id),)).fetchone()
    if not ex:
        raise ValueError("Exchange no encontrado")
    now = now_iso()
    conn.execute(
        """INSERT INTO exchange_identities(exchange_id,identity_id,context_id,source,confidence,resolver_id,assigned_at,notes)
           VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(exchange_id) DO UPDATE SET identity_id=excluded.identity_id,context_id=excluded.context_id,source=excluded.source,
             confidence=excluded.confidence,resolver_id=excluded.resolver_id,assigned_at=excluded.assigned_at,notes=excluded.notes""",
        (int(exchange_id), int(identity_id), context_id, source, "high", None, now, str(notes or "")[:2000]),
    )
    materials = extract_auth_materials(conn, int(exchange_id)) if learn_auth else []
    resolvers = 0
    for material in materials:
        _learn_material(conn, int(identity_id), context_id, material, source=source)
        if material["material_type"] == "bearer":
            resolvers += _learn_stable_jwt_claims(conn, int(identity_id), context_id, material, source=source)
    parameter_resolvers = 0
    for observation_id in (resolver_observation_ids or []):
        obs = conn.execute("SELECT exchange_id FROM parameter_observations WHERE id=?", (int(observation_id),)).fetchone()
        if not obs or int(obs["exchange_id"]) != int(exchange_id):
            continue
        add_parameter_resolver(conn, int(observation_id), int(identity_id), context_id=context_id, source="manual_assignment")
        parameter_resolvers += 1

    # v0.41.5: a human assignment should teach Negro once, not create a new
    # administrative step.  As soon as we learn auth material or a stable resolver,
    # resolve compatible historical traffic automatically.  Future Burp traffic was
    # already resolved incrementally in ingest; this closes the retrospective gap.
    history = {"exchanges": 0, "resolved": 0, "newly_resolved": 0}
    if learn_auth or parameter_resolvers or resolvers:
        try:
            history = resolve_all(conn)
        except Exception:
            # Identity assignment itself must never fail because a retrospective
            # convenience pass could not complete.
            history = {"exchanges": 0, "resolved": 0, "newly_resolved": 0}
    return {
        "exchange_id": int(exchange_id), "identity_id": int(identity_id), "context_id": context_id,
        "materials": len(materials), "jwt_resolvers": resolvers, "parameter_resolvers": parameter_resolvers,
        "history_resolved": int(history.get("newly_resolved") or 0),
    }



def learn_auth_materials(conn, exchange_id: int, identity_id: int, *, context_id: int | None = None,
                         fingerprints: list[str] | None = None, source: str = "manual") -> dict[str, Any]:
    """Learn only the auth materials the researcher selected from one exchange."""
    init_schema(conn)
    if not conn.execute("SELECT id FROM identities WHERE id=?", (int(identity_id),)).fetchone():
        raise ValueError("Identidad no encontrada")
    context_id = _context_belongs(conn, int(identity_id), context_id)
    selected = {str(x) for x in (fingerprints or []) if str(x)}
    materials = extract_auth_materials(conn, int(exchange_id))
    if fingerprints is not None:
        materials = [m for m in materials if str(m.get("fingerprint")) in selected]
    learned = 0
    jwt_resolvers = 0
    for material in materials:
        _learn_material(conn, int(identity_id), context_id, material, source=source)
        learned += 1
        if material.get("material_type") == "bearer":
            jwt_resolvers += _learn_stable_jwt_claims(conn, int(identity_id), context_id, material, source=source)
    return {"materials": learned, "jwt_resolvers": jwt_resolvers, "fingerprints": [m["fingerprint"] for m in materials]}


def update_identity_auth_from_exchange(conn, exchange_id: int, identity_id: int, *, context_id: int | None = None,
                                       fingerprints: list[str] | None = None, source: str = "manual_update") -> dict[str, Any]:
    """Explicitly declare the selected auth material as the current material for an identity.

    Older fingerprints are preserved as history but marked inactive for the same
    material type/name, so Send as Identity deterministically uses the latest value.
    """
    init_schema(conn)
    context_id = _context_belongs(conn, int(identity_id), context_id)
    selected = {str(x) for x in (fingerprints or []) if str(x)}
    materials = extract_auth_materials(conn, int(exchange_id))
    if fingerprints is not None:
        materials = [m for m in materials if str(m.get("fingerprint")) in selected]
    for material in materials:
        conn.execute(
            """UPDATE auth_materials SET active=0
               WHERE identity_id=? AND context_id IS ? AND material_type=? AND lower(material_name)=lower(?)""",
            (int(identity_id), context_id, str(material["material_type"]), str(material["name"])),
        )
        _learn_material(conn, int(identity_id), context_id, material, source=source)
        if material.get("material_type") == "bearer":
            _learn_stable_jwt_claims(conn, int(identity_id), context_id, material, source=source)
    return {"materials": len(materials), "fingerprints": [m["fingerprint"] for m in materials]}


def current_auth_materials(conn, identity_id: int, *, context_id: int | None = None) -> list[dict[str, Any]]:
    """Return the freshest active value for each auth slot of an identity."""
    init_schema(conn)
    context_id = _context_belongs(conn, int(identity_id), context_id)
    _backfill_raw_identity_values(conn, int(identity_id))
    if context_id is not None:
        rows = conn.execute(
            """SELECT * FROM auth_materials WHERE identity_id=? AND active=1 AND (context_id=? OR context_id IS NULL)
               ORDER BY CASE WHEN context_id=? THEN 0 ELSE 1 END,last_seen_at DESC,id DESC""",
            (int(identity_id), context_id, context_id),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM auth_materials WHERE identity_id=? AND active=1 ORDER BY last_seen_at DESC,id DESC",
            (int(identity_id),),
        ).fetchall()
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        item = dict(row)
        slot = (str(item.get("material_type") or ""), str(item.get("material_name") or "").lower())
        if slot in seen or not str(item.get("raw_value") or ""):
            continue
        seen.add(slot)
        out.append(item)
    return out


def _known_auth_cookie_names(conn) -> set[str]:
    return {str(r["material_name"] or "").lower() for r in conn.execute(
        "SELECT DISTINCT material_name FROM auth_materials WHERE material_type='cookie'"
    ).fetchall() if str(r["material_name"] or "")}


def _known_custom_auth_headers(conn) -> set[str]:
    return {str(r["material_name"] or "").lower() for r in conn.execute(
        "SELECT DISTINCT material_name FROM auth_materials WHERE material_type='header'"
    ).fetchall() if str(r["material_name"] or "")}


def rewrite_exchange_as_identity(conn, exchange_id: int, identity_id: int | None, *, context_id: int | None = None) -> dict[str, Any]:
    """Return an observed raw request with only known authentication material swapped.

    identity_id=None produces an Anonymous variant: Authorization and auth material
    known to Negro are removed while unrelated headers/cookies are preserved.
    """
    init_schema(conn)
    row = conn.execute(
        """SELECT e.request_b64,o.method,r.url,r.path FROM http_exchanges e
           JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id
           WHERE e.id=?""", (int(exchange_id),)
    ).fetchone()
    if not row or not row["request_b64"]:
        raise ValueError("Exchange sin request raw disponible")
    try:
        raw = base64.b64decode(str(row["request_b64"]), validate=False).decode("iso-8859-1")
    except Exception as exc:
        raise ValueError("No pude decodificar la request raw") from exc
    head, body = _split_http(raw)
    lines = head.replace("\r\n", "\n").split("\n")
    if not lines:
        raise ValueError("Request inválida")
    request_line = lines[0]
    parsed_headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        parsed_headers.append((name.strip(), value.strip()))

    target_materials = current_auth_materials(conn, int(identity_id), context_id=context_id) if identity_id else []
    target_cookies = {str(m["material_name"]): str(m["raw_value"]) for m in target_materials if m["material_type"] == "cookie"}
    target_headers = {str(m["material_name"]).lower(): (str(m["material_name"]), str(m["raw_value"])) for m in target_materials if m["material_type"] == "header"}
    target_authorization: str | None = None
    for m in target_materials:
        typ = str(m["material_type"])
        if typ == "bearer":
            target_authorization = "Bearer " + str(m["raw_value"])
            break
        if typ == "authorization":
            # material_name stores the scheme when present.
            scheme = str(m["material_name"] or "Authorization")
            value = str(m["raw_value"])
            target_authorization = value if scheme.lower() == "authorization" else f"{scheme} {value}"
            break

    known_cookie_names = _known_auth_cookie_names(conn)
    known_custom_headers = _known_custom_auth_headers(conn)
    rebuilt: list[tuple[str, str]] = []
    cookie_pairs: list[tuple[str, str]] = []
    cookie_header_name = "Cookie"
    for name, value in parsed_headers:
        low = name.lower()
        if low == "authorization":
            continue
        if low in known_custom_headers:
            continue
        if low == "cookie":
            cookie_header_name = name
            for piece in value.split(";"):
                if "=" not in piece:
                    continue
                cn, cv = piece.split("=", 1)
                cn, cv = cn.strip(), cv.strip()
                if not cn or cn.lower() in known_cookie_names:
                    continue
                cookie_pairs.append((cn, cv))
            continue
        rebuilt.append((name, value))

    if identity_id:
        for cn, cv in target_cookies.items():
            cookie_pairs = [(n, v) for n, v in cookie_pairs if n.lower() != cn.lower()]
            cookie_pairs.append((cn, cv))
        if target_authorization:
            rebuilt.append(("Authorization", target_authorization))
        for _low, (name, value) in target_headers.items():
            rebuilt.append((name, value))
    if cookie_pairs:
        rebuilt.append((cookie_header_name, "; ".join(f"{n}={v}" for n, v in cookie_pairs)))

    newline = "\r\n"
    new_head = newline.join([request_line] + [f"{n}: {v}" for n, v in rebuilt])
    new_raw = new_head + newline + newline + body
    return {
        "request_b64": base64.b64encode(new_raw.encode("iso-8859-1", errors="replace")).decode("ascii"),
        "method": str(row["method"]), "url": str(row["url"]), "path": str(row["path"]),
        "identity_id": int(identity_id) if identity_id else None, "context_id": context_id,
        "materials": [{"type": m["material_type"], "name": m["material_name"], "preview": m["masked_preview"]} for m in target_materials],
    }

def add_parameter_resolver(conn, observation_id: int, identity_id: int, *, context_id: int | None = None, source: str = "manual") -> int:
    init_schema(conn)
    context_id = _context_belongs(conn, int(identity_id), context_id)
    obs = conn.execute("SELECT * FROM parameter_observations WHERE id=?", (int(observation_id),)).fetchone()
    if not obs:
        raise ValueError("Observación de parámetro no encontrada")
    suitability = resolver_suitability(conn, int(observation_id))
    if not suitability.get("allowed"):
        raise ValueError("Este valor no debe usarse como resolver de actor: " + str(suitability.get("reason") or "contexto insuficiente"))
    selector = str(obs["normalized_name"])
    now = now_iso()
    conn.execute(
        """INSERT INTO identity_resolvers(identity_id,context_id,resolver_type,selector,value_hash,value_preview,value_raw,enabled,source,created_at,updated_at,anchor_exchange_id,anchor_observation_id)
           VALUES(?,?,?,?,?,?,?,1,?,?,?,?,?)
           ON CONFLICT(identity_id,context_id,resolver_type,selector,value_hash)
           DO UPDATE SET value_preview=excluded.value_preview,value_raw=excluded.value_raw,enabled=1,updated_at=excluded.updated_at,
                         anchor_exchange_id=COALESCE(identity_resolvers.anchor_exchange_id,excluded.anchor_exchange_id),
                         anchor_observation_id=COALESCE(identity_resolvers.anchor_observation_id,excluded.anchor_observation_id)""",
        (int(identity_id), context_id, "parameter", selector, str(obs["value_hash"]), str(obs["value_preview"] or "")[:120], str(obs["value_raw"] or obs["value_preview"] or ""), source, now, now, int(obs["exchange_id"]), int(observation_id)),
    )
    row = conn.execute(
        "SELECT id FROM identity_resolvers WHERE identity_id=? AND context_id IS ? AND resolver_type='parameter' AND selector=? AND value_hash=?",
        (int(identity_id), context_id, selector, str(obs["value_hash"])),
    ).fetchone()
    return int(row["id"])


def _material_matches(conn, materials: list[dict[str, Any]]) -> list[tuple[int, int | None, int | None, str]]:
    matches: list[tuple[int, int | None, int | None, str]] = []
    for material in materials:
        for row in conn.execute(
            "SELECT id,identity_id,context_id FROM auth_materials WHERE fingerprint=? AND active=1",
            (material["fingerprint"],),
        ).fetchall():
            matches.append((int(row["identity_id"]), int(row["context_id"]) if row["context_id"] else None, None, "auth_material"))
        claims = material.get("claims") or {}
        if isinstance(claims, dict):
            for key, value in claims.items():
                selector = f"jwt:{key}"
                vh = _sha(str(value))
                for row in conn.execute(
                    "SELECT id,identity_id,context_id FROM identity_resolvers WHERE enabled=1 AND resolver_type='jwt_claim' AND selector=? AND value_hash=?",
                    (selector, vh),
                ).fetchall():
                    matches.append((int(row["identity_id"]), int(row["context_id"]) if row["context_id"] else None, int(row["id"]), "jwt_claim"))
    return matches


def resolve_exchange(conn, exchange_id: int, *, force: bool = False) -> dict[str, Any] | None:
    init_schema(conn)
    if not force:
        current = conn.execute("SELECT * FROM exchange_identities WHERE exchange_id=?", (int(exchange_id),)).fetchone()
        if current:
            return dict(current)
    materials = extract_auth_materials(conn, int(exchange_id))
    matches = _material_matches(conn, materials)
    # Parameter resolver, e.g. a stable /me id observed in this exchange.
    for row in conn.execute(
        """SELECT ir.id,ir.identity_id,ir.context_id FROM identity_resolvers ir
           JOIN parameter_observations p ON p.normalized_name=ir.selector AND p.value_hash=ir.value_hash
           WHERE ir.enabled=1 AND ir.resolver_type='parameter' AND p.exchange_id=?""",
        (int(exchange_id),),
    ).fetchall():
        matches.append((int(row["identity_id"]), int(row["context_id"]) if row["context_id"] else None, int(row["id"]), "parameter"))
    identities = {m[0] for m in matches}
    if len(identities) != 1:
        return None
    identity_id = next(iter(identities))
    same = [m for m in matches if m[0] == identity_id]
    contexts = {m[1] for m in same if m[1] is not None}
    context_id = next(iter(contexts)) if len(contexts) == 1 else None
    resolver_id = next((m[2] for m in same if m[2] is not None), None)
    source = "+".join(sorted({m[3] for m in same}))[:120]
    now = now_iso()
    conn.execute(
        """INSERT INTO exchange_identities(exchange_id,identity_id,context_id,source,confidence,resolver_id,assigned_at)
           VALUES(?,?,?,?,?,?,?)
           ON CONFLICT(exchange_id) DO UPDATE SET identity_id=excluded.identity_id,context_id=excluded.context_id,source=excluded.source,
             confidence=excluded.confidence,resolver_id=excluded.resolver_id,assigned_at=excluded.assigned_at""",
        (int(exchange_id), identity_id, context_id, source, "high", resolver_id, now),
    )
    # Important for rotating sessions: once a stable resolver identifies an exchange,
    # remember the fresh token/cookie fingerprint for future requests in the same session.
    for material in materials:
        _learn_material(conn, identity_id, context_id, material, source="resolver")
    return dict(conn.execute("SELECT * FROM exchange_identities WHERE exchange_id=?", (int(exchange_id),)).fetchone())


def resolve_all(conn, *, limit: int = 100000) -> dict[str, int]:
    init_schema(conn)
    ids = [int(r["id"]) for r in conn.execute("SELECT id FROM http_exchanges ORDER BY id DESC LIMIT ?", (max(1, int(limit)),)).fetchall()]
    before = {int(r["exchange_id"]) for r in conn.execute("SELECT exchange_id FROM exchange_identities").fetchall()}
    resolved = 0
    newly_resolved: list[int] = []
    for exchange_id in ids:
        if resolve_exchange(conn, exchange_id):
            resolved += 1
            if exchange_id not in before:
                newly_resolved.append(exchange_id)
    # Identity is part of identifier memory. Historical resolution therefore needs
    # to refresh the lightweight identifier projection so Graph/Follow Value sees
    # the actor immediately without a separate rebuild button.
    if newly_resolved:
        try:
            import negro_objects as object_tools
            object_tools.init_schema(conn)
            for exchange_id in newly_resolved:
                object_tools.index_exchange_identifiers(conn, int(exchange_id))
        except Exception:
            pass
    return {"exchanges": len(ids), "resolved": resolved, "newly_resolved": len(newly_resolved)}


def list_identities(conn) -> list[dict[str, Any]]:
    init_schema(conn)
    rows = conn.execute(
        """SELECT i.*,
                  (SELECT COUNT(*) FROM identity_contexts c WHERE c.identity_id=i.id) contexts,
                  (SELECT COUNT(*) FROM auth_materials a WHERE a.identity_id=i.id AND a.active=1) auth_materials,
                  (SELECT COUNT(*) FROM identity_resolvers r WHERE r.identity_id=i.id AND r.enabled=1) resolvers,
                  (SELECT COUNT(*) FROM exchange_identities e WHERE e.identity_id=i.id) exchanges
           FROM identities i ORDER BY lower(i.name)"""
    ).fetchall()
    return [dict(r) for r in rows]


def contexts(conn, identity_id: int | None = None) -> list[dict[str, Any]]:
    init_schema(conn)
    if identity_id:
        rows = conn.execute("SELECT * FROM identity_contexts WHERE identity_id=? ORDER BY lower(label)", (int(identity_id),)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM identity_contexts ORDER BY identity_id,lower(label)").fetchall()
    return [dict(r) for r in rows]


def _backfill_raw_identity_values(conn, identity_id: int) -> None:
    """Recover exact local values for workspaces created before v0.23.1."""
    # Parameter resolvers can be recovered from the structured observation table.
    conn.execute(
        """UPDATE identity_resolvers
           SET value_raw=(SELECT COALESCE(p.value_raw,p.value_preview) FROM parameter_observations p
                          WHERE p.normalized_name=identity_resolvers.selector AND p.value_hash=identity_resolvers.value_hash
                          AND COALESCE(p.value_raw,p.value_preview) IS NOT NULL LIMIT 1)
           WHERE identity_id=? AND resolver_type='parameter' AND COALESCE(value_raw,'')=''""",
        (int(identity_id),),
    )
    # Auth material can be recovered exactly from exchanges already associated with the identity.
    ex_ids = [int(r["exchange_id"]) for r in conn.execute("SELECT exchange_id FROM exchange_identities WHERE identity_id=?", (int(identity_id),)).fetchall()]
    for exchange_id in ex_ids[:500]:
        for material in extract_auth_materials(conn, exchange_id):
            conn.execute(
                """UPDATE auth_materials SET raw_value=? WHERE identity_id=? AND fingerprint=? AND COALESCE(raw_value,'')=''""",
                (str(material.get("value") or ""), int(identity_id), str(material["fingerprint"])),
            )
            if material.get("claims"):
                for key, value in material["claims"].items():
                    selector=f"jwt:{key}"
                    vh=_sha(str(value))
                    conn.execute(
                        """UPDATE identity_resolvers SET value_raw=? WHERE identity_id=? AND resolver_type='jwt_claim' AND selector=? AND value_hash=? AND COALESCE(value_raw,'')=''""",
                        (str(value), int(identity_id), selector, vh),
                    )


def identity_detail(conn, identity_id: int) -> dict[str, Any] | None:
    init_schema(conn)
    try:
        import negro_objects as object_tools
        object_tools.init_schema(conn)
    except Exception:
        pass
    identity = conn.execute("SELECT * FROM identities WHERE id=?", (int(identity_id),)).fetchone()
    if not identity:
        return None
    _backfill_raw_identity_values(conn, int(identity_id))
    ctx = contexts(conn, int(identity_id))
    materials = [dict(r) for r in conn.execute(
        "SELECT * FROM auth_materials WHERE identity_id=? ORDER BY last_seen_at DESC LIMIT 100", (int(identity_id),)
    ).fetchall()]
    resolvers = [dict(r) for r in conn.execute(
        "SELECT * FROM identity_resolvers WHERE identity_id=? ORDER BY enabled DESC,updated_at DESC LIMIT 100", (int(identity_id),)
    ).fetchall()]
    exchanges = [dict(r) for r in conn.execute(
        """SELECT ei.*,h.hostname,r.id resource_id,r.path,o.method,e.status_code,e.first_seen_at,e.last_seen_at,c.label context_label
           FROM exchange_identities ei JOIN http_exchanges e ON e.id=ei.exchange_id
           JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id
           LEFT JOIN identity_contexts c ON c.id=ei.context_id
           WHERE ei.identity_id=? ORDER BY e.last_seen_at DESC,e.id DESC LIMIT 160""", (int(identity_id),)
    ).fetchall()]
    request_count = int(conn.execute(
        "SELECT COUNT(*) c FROM exchange_identities WHERE identity_id=?", (int(identity_id),)
    ).fetchone()["c"] or 0)
    endpoint_count = int(conn.execute(
        """SELECT COUNT(DISTINCT o.resource_id) c FROM exchange_identities ei
           JOIN http_exchanges e ON e.id=ei.exchange_id JOIN resource_operations o ON o.id=e.operation_id
           WHERE ei.identity_id=?""", (int(identity_id),)
    ).fetchone()["c"] or 0)
    flow_count = int(conn.execute(
        """SELECT COUNT(DISTINCT fs.flow_id) c FROM exchange_identities ei
           JOIN flow_steps fs ON fs.exchange_id=ei.exchange_id AND fs.included=1 WHERE ei.identity_id=?""", (int(identity_id),)
    ).fetchone()["c"] or 0)
    object_count = int(conn.execute(
        """SELECT COUNT(DISTINCT boo.business_object_id) c FROM exchange_identities ei
           JOIN business_object_observations boo ON boo.exchange_id=ei.exchange_id WHERE ei.identity_id=?""", (int(identity_id),)
    ).fetchone()["c"] or 0)
    actions = [dict(r) for r in conn.execute(
        """SELECT o.method,r.path,COUNT(*) requests,GROUP_CONCAT(DISTINCT COALESCE(e.status_code,'—')) statuses
           FROM exchange_identities ei JOIN http_exchanges e ON e.id=ei.exchange_id
           JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id
           WHERE ei.identity_id=? GROUP BY o.method,r.path ORDER BY requests DESC,r.path LIMIT 24""", (int(identity_id),)
    ).fetchall()]
    pivots = [dict(r) for r in conn.execute(
        """SELECT im.value_hash,MAX(COALESCE(NULLIF(im.value_raw,''),im.value_preview,'')) value,
                  GROUP_CONCAT(DISTINCT im.normalized_name) keys,COUNT(DISTINCT im.exchange_id) requests,
                  COUNT(DISTINCT im.resource_id) endpoints
           FROM identifier_observation_index im WHERE im.identity_id=?
           GROUP BY im.value_hash HAVING TRIM(MAX(COALESCE(NULLIF(im.value_raw,''),im.value_preview,'')))<>''
           ORDER BY requests DESC,endpoints DESC LIMIT 24""", (int(identity_id),)
    ).fetchall()]
    activity = {
        "requests": request_count, "endpoints": endpoint_count, "flows": flow_count, "objects": object_count,
        "actions": actions, "pivots": pivots,
    }
    return {"identity": dict(identity), "contexts": ctx, "materials": materials, "resolvers": resolvers, "exchanges": exchanges, "activity": activity}


def assignment_context(conn, exchange_id: int) -> dict[str, Any] | None:
    init_schema(conn)
    row = conn.execute(
        """SELECT e.id exchange_id,e.request_b64,e.response_b64,h.hostname,r.id resource_id,r.path,o.method,e.status_code,e.first_seen_at
           FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id WHERE e.id=?""",
        (int(exchange_id),),
    ).fetchone()
    if not row:
        return None
    current = conn.execute(
        """SELECT ei.*,i.name identity_name,c.label context_label FROM exchange_identities ei
           JOIN identities i ON i.id=ei.identity_id LEFT JOIN identity_contexts c ON c.id=ei.context_id
           WHERE ei.exchange_id=?""", (int(exchange_id),)
    ).fetchone()
    exchange = dict(row)
    exchange["request_text"] = _decode_b64(row["request_b64"])
    exchange["response_text"] = _decode_b64(row["response_b64"])
    exchange.pop("request_b64", None); exchange.pop("response_b64", None)
    observations = [dict(r) for r in conn.execute(
        """SELECT id,name,normalized_name,location,value_hash,value_preview,value_raw FROM parameter_observations
           WHERE exchange_id=? ORDER BY CASE WHEN location LIKE 'response_json:%' THEN 0 ELSE 1 END,id LIMIT 80""",
        (int(exchange_id),),
    ).fetchall()]
    resolver_candidates = candidate_identity_resolvers(conn, int(exchange_id))
    return {"exchange": exchange, "current": dict(current) if current else None, "materials": extract_auth_materials(conn, int(exchange_id)), "observations": observations, "resolver_candidates": resolver_candidates["candidates"], "resolver_ignored": resolver_candidates["ignored"]}


def stats(conn) -> dict[str, int]:
    init_schema(conn)
    total = int(conn.execute("SELECT COUNT(*) c FROM http_exchanges").fetchone()["c"] or 0)
    assigned = int(conn.execute("SELECT COUNT(*) c FROM exchange_identities").fetchone()["c"] or 0)
    return {
        "identities": int(conn.execute("SELECT COUNT(*) c FROM identities").fetchone()["c"] or 0),
        "contexts": int(conn.execute("SELECT COUNT(*) c FROM identity_contexts").fetchone()["c"] or 0),
        "assigned": assigned,
        "unknown": max(0, total - assigned),
    }


def _route_shape(path: str) -> str:
    raw = str(path or "/")
    parts = []
    uuid_re = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}$")
    hex_re = re.compile(r"^[0-9a-fA-F]{12,64}$")
    for seg in raw.split("/"):
        if re.fullmatch(r"\d{2,}", seg or "") or uuid_re.fullmatch(seg or "") or hex_re.fullmatch(seg or ""):
            parts.append("{id}")
        else:
            parts.append(seg)
    return "/".join(parts) or "/"


def authorization_matrix(conn, identity_ids: list[int] | None = None, *, limit_routes: int = 500) -> dict[str, Any]:
    """Observed-only authorization matrix.

    Cells describe only exchanges actually captured for an identity. Missing cells
    are explicitly `not_observed`; they never mean allowed or denied.
    """
    init_schema(conn)
    all_identities = list_identities(conn)
    selected = [int(x) for x in (identity_ids or []) if int(x) > 0]
    if not selected:
        selected = [int(x["id"]) for x in all_identities]
    selected_set = set(selected)
    rows = conn.execute(
        """SELECT ei.identity_id,ei.context_id,ei.exchange_id,i.name identity_name,c.label context_label,
                  h.hostname,r.path,o.method,e.status_code,e.first_seen_at
           FROM exchange_identities ei
           JOIN identities i ON i.id=ei.identity_id
           LEFT JOIN identity_contexts c ON c.id=ei.context_id
           JOIN http_exchanges e ON e.id=ei.exchange_id
           JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id
           JOIN hosts h ON h.id=r.host_id
           ORDER BY e.id"""
    ).fetchall()
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for r in rows:
        iid = int(r["identity_id"])
        if iid not in selected_set:
            continue
        shape = _route_shape(str(r["path"] or "/"))
        key = (str(r["hostname"]), str(r["method"]), shape)
        item = grouped.setdefault(key, {"host": key[0], "method": key[1], "shape": key[2], "cells": {}, "objects": set()})
        item["objects"].add(str(r["path"] or "/"))
        cell = item["cells"].setdefault(iid, {"count": 0, "statuses": {}, "examples": [], "contexts": set()})
        cell["count"] += 1
        status = str(r["status_code"] if r["status_code"] is not None else "—")
        cell["statuses"][status] = int(cell["statuses"].get(status, 0)) + 1
        if len(cell["examples"]) < 4:
            cell["examples"].append({"exchange_id": int(r["exchange_id"]), "path": str(r["path"]), "status": status})
        if r["context_label"]:
            cell["contexts"].add(str(r["context_label"]))
    out = []
    for item in grouped.values():
        cells = {}
        for iid in selected:
            raw = item["cells"].get(iid)
            if not raw:
                cells[iid] = {"observed": False, "count": 0, "statuses": {}, "examples": [], "contexts": []}
            else:
                cells[iid] = {**raw, "observed": True, "contexts": sorted(raw["contexts"])}
        out.append({**item, "objects": sorted(item["objects"]), "cells": cells})
    out.sort(key=lambda x: (x["host"], x["shape"], x["method"]))
    identities_by_id = {int(x["id"]): x for x in all_identities if int(x["id"]) in selected_set}
    return {"identities": [identities_by_id[i] for i in selected if i in identities_by_id], "rows": out[: max(1, min(int(limit_routes), 2000))]}
