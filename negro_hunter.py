#!/usr/bin/env python3
"""Negro Recon v0.9 hunter intelligence layer.

Low-impact, policy-aware reconnaissance helpers plus deterministic lead generation.
This module deliberately avoids exploitation, credential use, state-changing requests,
form submission, resource claiming, and mass brute force defaults.
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import ipaddress
import json
import random
import re
import socket
import sys
import string
import time
import urllib.parse
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable

import negro_intel as intel
import negro_rules as rulebook

GRAPH_AI_PROMPT_VERSION = "0.16.0-burp-signals-v1-context-fusion-v2-memory-v0.36.0"

try:
    import requests
    from requests import Response
except Exception:  # surfaced by runtime_dependency_status/install-web
    requests = None  # type: ignore
    Response = Any  # type: ignore

try:
    import dns.query
    import dns.resolver
    import dns.reversename
    import dns.zone
except Exception:
    dns = None  # type: ignore


POLICY_PROFILES: dict[str, dict[str, Any]] = {
    "conservative": {
        "label": "Conservador / bug bounty",
        "description": "Pasivo primero y acciones activas pequeñas, dirigidas y explícitas.",
        "allow_axfr": True,
        "allow_active_dns": True,
        "active_dns_max_candidates": 25,
        "active_dns_delay_s": 0.35,
        "allow_vhost": True,
        "vhost_max_candidates": 25,
        "vhost_delay_s": 0.45,
        "crawl_max_urls": 200,
        "crawl_max_depth": 2,
        "crawl_delay_s": 0.35,
        "crawl_follow_external": False,
        "crawl_submit_forms": False,
        "allow_cors_probe": True,
    },
    "mercadolibre": {
        "label": "Mercado Libre / bajo impacto",
        "description": "Perfil conservador para evitar massive automated scanning: pocos candidatos y bajo rate.",
        "allow_axfr": True,
        "allow_active_dns": True,
        "active_dns_max_candidates": 20,
        "active_dns_delay_s": 0.55,
        "allow_vhost": True,
        "vhost_max_candidates": 20,
        "vhost_delay_s": 0.65,
        "crawl_max_urls": 120,
        "crawl_max_depth": 2,
        "crawl_delay_s": 0.6,
        "crawl_follow_external": False,
        "crawl_submit_forms": False,
        "allow_cors_probe": True,
    },
    "lab": {
        "label": "Laboratorio autorizado",
        "description": "Para HTB/labs explícitamente diseñados para enumeración activa.",
        "allow_axfr": True,
        "allow_active_dns": True,
        "active_dns_max_candidates": 5000,
        "active_dns_delay_s": 0.0,
        "allow_vhost": True,
        "vhost_max_candidates": 5000,
        "vhost_delay_s": 0.0,
        "crawl_max_urls": 1500,
        "crawl_max_depth": 5,
        "crawl_delay_s": 0.0,
        "crawl_follow_external": False,
        "crawl_submit_forms": False,
        "allow_cors_probe": True,
    },
}

DEFAULT_POLICY = "conservative"

REDIRECT_PARAMS = {
    "redirect", "redirect_url", "redirect_uri", "return", "returnurl", "return_url",
    "next", "continue", "callback", "url", "dest", "destination", "goto", "target",
    "returnto", "return_to", "checkout_url", "domain_name",
}
# Generic names such as url/target are ambiguous: in passive Burp traffic we only
# call them redirect clues when the route/response is navigation-like. Otherwise
# they remain eligible as URL-fetch/SSRF clues.
STRONG_REDIRECT_PARAMS = {
    "redirect", "redirect_url", "redirect_uri", "return", "returnurl", "return_url",
    "next", "continue", "goto", "returnto", "return_to", "checkout_url",
}
AMBIGUOUS_REDIRECT_PARAMS = REDIRECT_PARAMS - STRONG_REDIRECT_PARAMS
URLISH_PARAMS = {"url", "uri", "target", "destination", "dest", "endpoint", "webhook", "feed", "proxy", "fetch", "import", "image", "file", "src", "source"}
OBJECT_NOUNS = {"order", "orders", "user", "users", "account", "accounts", "document", "documents", "invoice", "invoices", "customer", "customers", "profile", "profiles"}
DOM_SOURCES = ["location.search", "location.hash", "document.url", "document.documenturi", "window.name", "postmessage", "event.data"]
DOM_SINKS = ["innerhtml", "outerhtml", "insertadjacenthtml", "document.write", "eval(", "settimeout(", "setinterval("]
NAV_SINKS = ["window.location", "location.href", "location.assign", "location.replace", "document.location"]

# High-signal client/server clues observed passively in Burp traffic.  Values are
# always masked before they are persisted as notifications/leads.  A match is a
# clue for manual validation, never an automatic vulnerability verdict.
SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    ("google_api_key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "medium"),
    ("aws_access_key", "AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ("github_token", "GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{50,255})\b"), "high"),
    ("stripe_live_secret", "Stripe live secret", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b"), "high"),
    ("slack_token", "Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"), "high"),
    ("google_oauth_secret", "Google OAuth client secret", re.compile(r"\bGOCSPX-[0-9A-Za-z_-]{20,}\b"), "high"),
    ("sendgrid_key", "SendGrid API key", re.compile(r"\bSG\.[0-9A-Za-z_-]{12,}\.[0-9A-Za-z_-]{24,}\b"), "high"),
    ("twilio_api_key", "Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high"),
    ("mailgun_key", "Mailgun API key", re.compile(r"\bkey-[0-9a-fA-F]{32}\b"), "high"),
    ("private_key", "Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "high"),
]

SENSITIVE_RESPONSE_KEYS = {
    "password", "passwd", "pwd", "pass", "client_secret", "private_key",
    "api_key", "apikey", "api-key", "secret", "access_key", "secret_key",
    "refresh_token", "access_token", "auth_token", "session_token", "token",
    "session", "session_id", "sessionid", "authorization",
}
IDENTITY_KEYS = {"user", "username", "email", "login", "account", "userid", "user_id"}
QUERY_SECRET_KEYS = {"password", "passwd", "pwd", "token", "access_token", "refresh_token", "api_key", "apikey", "secret"}

# Access-control intelligence.  These are intentionally heuristic names: a match
# creates a hypothesis/review aid, never a confirmed finding.
OBJECT_ID_KEYS = {
    "id", "userid", "user_id", "accountid", "account_id", "orderid", "order_id",
    "documentid", "document_id", "invoiceid", "invoice_id", "ticketid", "ticket_id",
    "profileid", "profile_id", "sellerid", "seller_id", "customerid", "customer_id",
    "ownerid", "owner_id", "resourceid", "resource_id",
}
PRIVILEGED_FIELD_KEYS = {
    "role", "roleid", "role_id", "roles", "permission", "permissions", "scope", "scopes",
    "isadmin", "is_admin", "admin", "privilege", "privileges", "ownerid", "owner_id",
    "status", "state", "approved", "verified", "featured", "tier", "level",
}
SENSITIVE_ACTION_TOKENS = {
    "admin", "internal", "manage", "management", "approve", "approval", "promote", "role",
    "permission", "delete", "remove", "publish", "feature", "export", "refund", "confirm",
    "complete", "finalize", "verify", "moderate", "suspend", "ban",
}


DETECTOR_CATALOG = rulebook.CATALOG


def _project_detector_layers(conn) -> tuple[dict[str, Any], dict[str, Any]]:
    project_rules: dict[str, Any] = {}
    legacy: dict[str, Any] = {}
    if conn is not None:
        try:
            row = conn.execute("SELECT value FROM meta WHERE key='detector_rules_json'").fetchone()
            if row and row["value"]:
                parsed = json.loads(row["value"])
                if isinstance(parsed, dict):
                    project_rules = parsed
        except Exception:
            project_rules = {}
        try:
            row = conn.execute("SELECT value FROM meta WHERE key='detectors_json'").fetchone()
            if row and row["value"]:
                parsed = json.loads(row["value"])
                if isinstance(parsed, dict):
                    legacy = parsed
        except Exception:
            legacy = {}
    return project_rules, legacy


def detector_settings(detector_id: str, conn=None) -> dict[str, Any]:
    """Return the effective transparent rule set for a detector.

    Merge order: built-in Negro knowledge -> personal library -> project overrides.
    Legacy v0.18 enabled flags are honoured when no new project override exists.
    """
    settings = intel.load_settings()
    personal_library = settings.get("detector_rule_library") if isinstance(settings.get("detector_rule_library"), dict) else {}
    project_rules, legacy = _project_detector_layers(conn)
    global_layer = personal_library.get(detector_id) if isinstance(personal_library.get(detector_id), dict) else {}
    project_layer = project_rules.get(detector_id) if isinstance(project_rules.get(detector_id), dict) else {}
    effective = rulebook.merge_detector_rules(detector_id, global_layer, project_layer)
    # v0.38 retires the old noisy integrated catalogue. Keep the implementation
    # readable for backward compatibility, but do not allow legacy overrides to
    # silently re-enable retired built-ins in upgraded projects.
    if detector_id in getattr(rulebook, "RETIRED_BUILTIN_RULE_IDS", set()):
        effective["enabled"] = False
        effective["retired"] = True
        return effective
    normalized_global=rulebook.normalize_layer(global_layer)
    normalized_project=rulebook.normalize_layer(project_layer)
    legacy_global=settings.get("detectors") if isinstance(settings.get("detectors"),dict) else {}
    old_global=legacy_global.get(detector_id) if isinstance(legacy_global.get(detector_id),dict) else {}
    if "enabled" not in normalized_global and "enabled" in old_global:
        effective["enabled"] = bool(old_global.get("enabled"))
    if "enabled" not in normalized_project:
        old = legacy.get(detector_id) if isinstance(legacy.get(detector_id), dict) else {}
        if "enabled" in old:
            effective["enabled"] = bool(old.get("enabled"))
    else:
        effective["enabled"] = bool(normalized_project.get("enabled"))
    return effective


def detector_enabled(detector_id: str, conn=None) -> bool:
    return bool(detector_settings(detector_id, conn).get("enabled", True))


def detector_rule_list(detector_id: str, name: str, conn=None) -> list[str]:
    return rulebook.rule_list(detector_settings(detector_id, conn), name)


def detector_rule_bool(detector_id: str, name: str, conn=None, default: bool = False) -> bool:
    return rulebook.rule_bool(detector_settings(detector_id, conn), name, default)


def detector_rule_int(detector_id: str, name: str, conn=None, default: int = 0) -> int:
    return rulebook.rule_int(detector_settings(detector_id, conn), name, default)


def detector_sensitivity(detector_id: str, conn=None) -> str:
    """Compatibility shim for old extensions/tests; v0.19 no longer uses presets."""
    return "custom"

def project_scopes_from_conn(conn, domain: str) -> list[str]:
    try:
        row=conn.execute("SELECT value FROM meta WHERE key='scopes_json'").fetchone()
        raw=json.loads(row["value"]) if row and row["value"] else []
        scopes=[str(x).strip().lower().rstrip('.') for x in raw if str(x).strip()] if isinstance(raw,list) else []
    except Exception:
        scopes=[]
    d=str(domain or '').strip().lower().rstrip('.')
    if d and d not in scopes: scopes.insert(0,d)
    return scopes

def host_in_project_scope(host: str, scopes: list[str]) -> bool:
    h=str(host or '').strip().lower().rstrip('.')
    return any(h==s or h.endswith('.'+s) for s in scopes if s)

TAKEOVER_PROVIDERS = [
    ("github", ("github.io",), ("there isn't a github pages site here", "for root urls")),
    ("heroku", ("herokudns.com", "herokuapp.com"), ("no such app", "heroku | no such app")),
    ("azure", ("azurewebsites.net", "cloudapp.net", "trafficmanager.net"), ("404 web site not found", "the resource you are looking for has been removed")),
    ("netlify", ("netlify.app",), ("not found - request id", "page not found")),
    ("vercel", ("vercel.app", "now.sh"), ("the deployment could not be found", "deployment_not_found")),
    ("fastly", ("fastly.net",), ("fastly error: unknown domain", "unknown domain")),
    ("amazon_s3", ("s3.amazonaws.com", "s3-website"), ("nosuchbucket", "the specified bucket does not exist")),
]

DOC_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".ppt", ".pptx", ".txt", ".xml", ".json", ".yaml", ".yml"}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".bak", ".old", ".sql", ".dump"}


OPERATION_TEST_CATALOG: dict[str, dict[str, str]] = {
    "authorization": {"label":"Autorización / IDOR", "category":"access_control", "hint":"Compara el mismo objeto/acción entre sesiones, usuarios o roles autorizados. Mantén constante todo salvo la identidad o el identificador que estés validando."},
    "session_access": {"label":"Acceso sin sesión", "category":"authentication", "hint":"Repite la request sin cookies/Authorization y compara status, datos y efectos. Descarta rápido si el recurso es deliberadamente público."},
    "cors": {"label":"CORS", "category":"browser_security", "hint":"Prueba un Origin controlado y revisa ACAO/credentials. Una señal interesante aún requiere demostrar impacto con datos o acciones permitidas."},
    "parameter_tampering": {"label":"Manipulación de parámetros", "category":"input", "hint":"Modifica un parámetro real cada vez: límites, ids, flags, estados, cantidades o valores observados. Compara respuesta y efecto server-side."},
    "method_variation": {"label":"Métodos HTTP alternativos", "category":"protocol", "hint":"Comprueba si GET/POST/PUT/PATCH/DELETE equivalentes cambian controles de acceso o validación. Evita cambios de estado fuera de datos autorizados."},
    "content_type": {"label":"Content-Type / diferencias de parser", "category":"protocol", "hint":"En operaciones con body, compara parsers compatibles (por ejemplo JSON vs form) sólo cuando la aplicación/servidor lo acepte. Busca diferencias de validación o autorización."},
    "csrf": {"label":"CSRF / acción con cookie", "category":"browser_security", "hint":"Si la acción cambia estado y depende de cookies, revisa SameSite/token/Origin/Referer y si una petición cross-site equivalente sería aceptada."},
    "business_logic": {"label":"Lógica de negocio / estado", "category":"business_logic", "hint":"Identifica la condición que gobierna la operación (state, limit, price, promo, ownership, sequence) y comprueba que el backend la revalide al ejecutar la acción sensible."},
    "cache": {"label":"Caché / variación por usuario", "category":"cache", "hint":"En respuestas GET, observa headers de cache y si contenido autenticado/personalizado puede mezclarse entre variantes o usuarios."},
    "rate_limit": {"label":"Límites de frecuencia / abuso", "category":"abuse", "hint":"En login, OTP, reset o validaciones repetibles, comprueba de forma acotada si hay controles de frecuencia y si se aplican a la dimensión correcta."},
    "client_trust": {"label":"Confianza en cliente / feature flags", "category":"client_side", "hint":"Si el cliente recibe flags/config, altera una sola respuesta, observa UI/requests nuevas y verifica luego que el backend aplique autorización por sí mismo."},
    "url_handling": {"label":"Redirecciones / manejo de URL", "category":"url_flow", "hint":"Cuando exista un parámetro URL/redirect real, verifica validación, normalización y destino permitido sin salir del alcance autorizado."},
    "mass_assignment": {"label":"Asignación masiva / campos ocultos", "category":"api", "hint":"En JSON de creación/edición, prueba únicamente campos reales/relacionados y observa si el backend acepta propiedades que la interfaz no debería controlar."},
    "referer_trust": {"label":"Autorización basada en Referer", "category":"access_control", "hint":"Si la acción parece privilegiada y envía Referer, compara el comportamiento al quitarlo o modificarlo. Referer puede aportar contexto, pero no debe sustituir la autorización server-side."},
    "proxy_path_access": {"label":"Control por ruta en proxy/frontend", "category":"access_control", "hint":"Si un 403 parece provenir de una capa distinta al backend, compara fingerprints y revisa discrepancias de routing/normalización. X-Original-URL/X-Rewrite-URL sólo tienen sentido cuando existe evidencia de varias capas."},
    "redirect_body": {"label":"Datos antes de redirigir", "category":"access_control", "hint":"En 3xx revisa el body antes de seguir Location. Una redirección no evita una filtración si los datos sensibles ya fueron incluidos en la respuesta."},
}

TEST_STATUSES = {"pending", "testing", "negative", "interesting", "confirmed", "not_applicable"}


def _operation_test_keys(conn, operation_id: int) -> list[str]:
    row = conn.execute(
        """SELECT o.*,r.path,r.query,r.url FROM resource_operations o JOIN resources r ON r.id=o.resource_id WHERE o.id=?""",
        (operation_id,),
    ).fetchone()
    if not row:
        return []
    method = str(row["method"] or "GET").upper()
    path = str(row["path"] or "").lower()
    response_ct = str(row["response_content_type"] or "").lower()
    request_ct = str(row["request_content_type"] or "").lower()
    static_ext = Path(urllib.parse.urlsplit(str(row["url"] or "")).path).suffix.lower()
    is_static = static_ext in {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"}

    keys: list[str] = ["cors"]
    if method in {"GET", "HEAD"}:
        keys.append("cache")
    if is_static:
        return list(dict.fromkeys(keys))

    keys += ["authorization", "parameter_tampering", "method_variation"]
    authish = bool(row["authenticated_observed"]) or any(x in path for x in ("login", "auth", "account", "profile", "session", "me", "user"))
    if authish:
        keys.append("session_access")
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        keys.append("business_logic")
        if bool(row["authenticated_observed"]):
            keys.append("csrf")
    if method in {"POST", "PUT", "PATCH"} and ("json" in request_ct or not request_ct):
        keys += ["content_type", "mass_assignment"]
    if any(x in path for x in ("login", "otp", "password", "reset", "verify", "code", "token")):
        keys.append("rate_limit")
    if any(x in path for x in ("feature", "flag", "config", "setting", "experiment")):
        keys.append("client_trust")

    # Referer is client-controlled.  Do not call this a vulnerability; simply
    # remind the hunter when a sensitive-looking state change carries it.
    ex_headers = conn.execute("SELECT request_headers_json,status_code FROM http_exchanges WHERE operation_id=? ORDER BY last_seen_at DESC LIMIT 1", (operation_id,)).fetchone()
    latest_headers = _header_map(ex_headers["request_headers_json"]) if ex_headers else {}
    ref_cfg=detector_settings("referer_access_control", conn)
    ref_methods={x.upper() for x in rulebook.rule_list(ref_cfg,"methods")}
    ref_tokens=[x.lower() for x in rulebook.rule_list(ref_cfg,"sensitive_path_tokens")]
    if latest_headers.get("referer") and method in ref_methods and any(tok in path for tok in ref_tokens):
        keys.append("referer_trust")
    if ex_headers and int(ex_headers["status_code"] or 0) in {301,302,303,307,308}:
        keys.append("redirect_body")
    if ex_headers and int(ex_headers["status_code"] or 0) == 403:
        keys.append("proxy_path_access")

    query_keys: set[str] = set()
    ex = conn.execute("SELECT query_json FROM http_exchanges WHERE operation_id=? ORDER BY last_seen_at DESC LIMIT 1", (operation_id,)).fetchone()
    if ex:
        try:
            q = json.loads(ex["query_json"] or "{}")
            if isinstance(q, dict):
                query_keys = {str(k).lower() for k in q}
        except Exception:
            pass
    redirect_keys={x.lower() for x in detector_rule_list("open_redirect","parameter_keys",conn)}
    ssrf_keys={x.lower() for x in detector_rule_list("ssrf_surface","parameter_keys",conn)}
    if query_keys & (redirect_keys | ssrf_keys):
        keys.append("url_handling")
    object_cfg=detector_settings("access_object_reference",conn)
    object_keys={re.sub(r"[^a-z0-9]","",str(x).lower()) for x in rulebook.rule_list(object_cfg,"identifier_keys")}
    object_suffixes=[re.sub(r"[^a-z0-9]","",str(x).lower()) for x in rulebook.rule_list(object_cfg,"identifier_suffixes")]
    qcompact={re.sub(r"[^a-z0-9]","",str(x).lower()) for x in query_keys}
    object_query=any(x in object_keys or any(x.endswith(suf) for suf in object_suffixes if suf) for x in qcompact)
    object_path=(rulebook.rule_bool(object_cfg,"detect_numeric_path",True) and bool(re.search(r"/(?:\d+)(?:/|$)",path))) or (rulebook.rule_bool(object_cfg,"detect_uuid_path",True) and bool(re.search(r"/[0-9a-f]{8}-[0-9a-f-]{27,}(?:/|$)",path,re.I)))
    if object_query or object_path:
        if "authorization" not in keys:
            keys.append("authorization")
    return list(dict.fromkeys(keys))


def ensure_operation_test_coverage(conn, operation_id: int) -> list[dict[str, Any]]:
    init_schema(conn)
    now = now_iso()
    for key in _operation_test_keys(conn, operation_id):
        meta = OPERATION_TEST_CATALOG[key]
        conn.execute(
            """INSERT OR IGNORE INTO operation_test_coverage(operation_id,test_key,label,category,status,notes,source,created_at,updated_at)
               VALUES(?,?,?,?, 'pending','', 'recommended', ?, ?)""",
            (operation_id, key, meta["label"], meta["category"], now, now),
        )
    rows = conn.execute("SELECT * FROM operation_test_coverage WHERE operation_id=? ORDER BY id", (operation_id,)).fetchall()
    out=[]
    for r in rows:
        d=dict(r)
        d["hint"] = OPERATION_TEST_CATALOG.get(str(r["test_key"]), {}).get("hint", "Registra qué probaste y qué observaste.")
        out.append(d)
    return out


def update_operation_test_coverage(conn, operation_id: int, test_key: str, status: str, notes: str = "", source: str = "manual") -> dict[str, Any]:
    init_schema(conn)
    if status not in TEST_STATUSES:
        raise ValueError("Estado de prueba inválido")
    ensure_operation_test_coverage(conn, operation_id)
    row = conn.execute("SELECT id FROM operation_test_coverage WHERE operation_id=? AND test_key=?", (operation_id, test_key)).fetchone()
    if not row:
        meta = OPERATION_TEST_CATALOG.get(test_key, {"label": test_key.replace("_", " ").title(), "category": "custom"})
        now=now_iso()
        conn.execute("INSERT INTO operation_test_coverage(operation_id,test_key,label,category,status,notes,source,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", (operation_id,test_key,meta["label"],meta["category"],status,notes[:2000],source,now,now))
    else:
        conn.execute("UPDATE operation_test_coverage SET status=?,notes=?,source=?,updated_at=? WHERE operation_id=? AND test_key=?", (status,notes[:2000],source,now_iso(),operation_id,test_key))
    final = conn.execute("SELECT * FROM operation_test_coverage WHERE operation_id=? AND test_key=?", (operation_id,test_key)).fetchone()
    return dict(final)


def operation_test_summary(conn, operation_id: int) -> dict[str, int]:
    ensure_operation_test_coverage(conn, operation_id)
    out={k:0 for k in TEST_STATUSES}
    for r in conn.execute("SELECT status,COUNT(*) c FROM operation_test_coverage WHERE operation_id=? GROUP BY status", (operation_id,)).fetchall():
        out[str(r["status"])] = int(r["c"])
    return out


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _require_requests() -> None:
    if requests is None:
        raise RuntimeError("Falta requests. Ejecuta ./install-web.sh")


def _require_dns() -> None:
    try:
        import dns.resolver  # noqa: F401
    except Exception as exc:
        raise RuntimeError("Falta dnspython. Ejecuta ./install-web.sh") from exc


def get_policy(conn) -> tuple[str, dict[str, Any]]:
    row = conn.execute("SELECT value FROM meta WHERE key='policy_profile'").fetchone()
    name = str(row["value"]) if row and str(row["value"]) in POLICY_PROFILES else DEFAULT_POLICY
    return name, dict(POLICY_PROFILES[name])


def set_policy(conn, profile: str) -> dict[str, Any]:
    if profile not in POLICY_PROFILES:
        raise ValueError(f"Perfil inválido: {profile}")
    conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('policy_profile',?)", (profile,))
    return {"profile": profile, **POLICY_PROFILES[profile]}


def policy_summary(conn) -> dict[str, Any]:
    name, data = get_policy(conn)
    return {"profile": name, **data}


def assert_policy(conn, action: str, requested_count: int = 0) -> dict[str, Any]:
    name, p = get_policy(conn)
    checks = {
        "axfr": (p.get("allow_axfr", False), None),
        "active_dns": (p.get("allow_active_dns", False), int(p.get("active_dns_max_candidates", 0))),
        "vhost": (p.get("allow_vhost", False), int(p.get("vhost_max_candidates", 0))),
        "cors": (p.get("allow_cors_probe", False), None),
    }
    allowed, limit = checks.get(action, (True, None))
    if not allowed:
        raise RuntimeError(f"La política '{name}' bloquea la acción {action}")
    if limit is not None and requested_count > limit:
        raise RuntimeError(f"La política '{name}' limita {action} a {limit} candidatos; solicitados: {requested_count}")
    return p


def init_schema(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_type TEXT NOT NULL,
            src_id INTEGER,
            relation TEXT NOT NULL,
            dst_type TEXT NOT NULL,
            dst_value TEXT NOT NULL,
            source TEXT NOT NULL,
            evidence_json TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(src_type, src_id, relation, dst_type, dst_value, source)
        );
        CREATE TABLE IF NOT EXISTS leads_v2 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lead_key TEXT NOT NULL UNIQUE,
            host_id INTEGER,
            resource_id INTEGER,
            lead_type TEXT NOT NULL,
            title TEXT NOT NULL,
            confidence TEXT NOT NULL,
            review_priority TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'candidate',
            evidence_json TEXT NOT NULL,
            why_interesting TEXT,
            next_test TEXT,
            confirm_if TEXT,
            discard_if TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ai_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_type TEXT NOT NULL,
            evidence_hash TEXT NOT NULL,
            model TEXT NOT NULL,
            status TEXT NOT NULL,
            estimate_json TEXT,
            usage_json TEXT,
            result_json TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(task_type, evidence_hash, model)
        );
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            summary TEXT,
            notes TEXT,
            source_hypothesis_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(source_hypothesis_id)
        );
        CREATE TABLE IF NOT EXISTS investigation_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            relation TEXT NOT NULL DEFAULT 'supports',
            created_at TEXT NOT NULL,
            UNIQUE(investigation_id, entity_type, entity_id, relation),
            FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS ai_idea_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            origin_type TEXT NOT NULL DEFAULT 'flow',
            flow_id INTEGER,
            investigation_id INTEGER,
            model TEXT NOT NULL,
            evidence_hash TEXT NOT NULL,
            summary TEXT,
            context_snapshot_json TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(origin_type, flow_id, investigation_id, model, evidence_hash),
            FOREIGN KEY(flow_id) REFERENCES flows(id) ON DELETE SET NULL,
            FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS ai_ideas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id INTEGER NOT NULL,
            flow_id INTEGER,
            investigation_id INTEGER,
            question TEXT NOT NULL,
            alias TEXT,
            category TEXT,
            priority TEXT,
            rationale TEXT,
            facts_json TEXT,
            unknowns_json TEXT,
            test_goal TEXT,
            confirm_if TEXT,
            discard_if TEXT,
            runner_json TEXT,
            status TEXT NOT NULL DEFAULT 'new',
            decision_reason TEXT,
            converted_hypothesis_id INTEGER,
            reconsidered_from_idea_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(batch_id) REFERENCES ai_idea_batches(id) ON DELETE CASCADE,
            FOREIGN KEY(flow_id) REFERENCES flows(id) ON DELETE SET NULL,
            FOREIGN KEY(investigation_id) REFERENCES investigations(id) ON DELETE SET NULL,
            FOREIGN KEY(converted_hypothesis_id) REFERENCES leads_v2(id) ON DELETE SET NULL,
            FOREIGN KEY(reconsidered_from_idea_id) REFERENCES ai_ideas(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS hypothesis_requirements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lead_id INTEGER NOT NULL,
            requirement_type TEXT NOT NULL DEFAULT 'identifier',
            key_pattern TEXT NOT NULL,
            description TEXT,
            identity_mode TEXT NOT NULL DEFAULT 'any',
            identity_id INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            matched_observation_id INTEGER,
            matched_signal_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(lead_id) REFERENCES leads_v2(id) ON DELETE CASCADE,
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE SET NULL,
            FOREIGN KEY(matched_observation_id) REFERENCES parameter_observations(id) ON DELETE SET NULL,
            FOREIGN KEY(matched_signal_id) REFERENCES signal_occurrences(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS operation_test_coverage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operation_id INTEGER NOT NULL,
            test_key TEXT NOT NULL,
            label TEXT NOT NULL,
            category TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            notes TEXT,
            source TEXT NOT NULL DEFAULT 'recommended',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(operation_id, test_key),
            FOREIGN KEY(operation_id) REFERENCES resource_operations(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS signal_occurrences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dedupe_key TEXT NOT NULL UNIQUE,
            exchange_id INTEGER,
            operation_id INTEGER,
            resource_id INTEGER,
            kind TEXT NOT NULL,
            category TEXT,
            severity TEXT NOT NULL DEFAULT 'info',
            title TEXT NOT NULL,
            why_json TEXT,
            evidence_json TEXT,
            source TEXT NOT NULL DEFAULT 'engine',
            occurrences INTEGER NOT NULL DEFAULT 1,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            reviewed_at TEXT,
            dismissed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS parameter_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exchange_id INTEGER NOT NULL,
            operation_id INTEGER NOT NULL,
            resource_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            normalized_name TEXT NOT NULL,
            location TEXT NOT NULL,
            value_hash TEXT NOT NULL,
            value_preview TEXT,
            value_raw TEXT,
            first_seen_at TEXT NOT NULL,
            UNIQUE(exchange_id, normalized_name, location, value_hash)
        );
        CREATE INDEX IF NOT EXISTS idx_operation_test_coverage ON operation_test_coverage(operation_id,status,test_key);
        CREATE INDEX IF NOT EXISTS idx_leads_v2_priority ON leads_v2(review_priority, confidence, updated_at);
        CREATE INDEX IF NOT EXISTS idx_relationships_src ON relationships(src_type, src_id, relation);
        CREATE INDEX IF NOT EXISTS idx_signal_occurrences_resource ON signal_occurrences(resource_id, reviewed_at, last_seen_at);
        CREATE INDEX IF NOT EXISTS idx_signal_occurrences_exchange ON signal_occurrences(exchange_id, kind);
        CREATE INDEX IF NOT EXISTS idx_parameter_observations_name ON parameter_observations(normalized_name, resource_id);
        CREATE INDEX IF NOT EXISTS idx_parameter_observations_value ON parameter_observations(value_hash, resource_id);
        CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status, updated_at);
        CREATE INDEX IF NOT EXISTS idx_investigation_links_entity ON investigation_links(entity_type, entity_id);
        CREATE INDEX IF NOT EXISTS idx_investigation_links_investigation ON investigation_links(investigation_id, entity_type, entity_id);
        CREATE INDEX IF NOT EXISTS idx_ai_idea_batches_flow ON ai_idea_batches(flow_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_ai_idea_batches_investigation ON ai_idea_batches(investigation_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_ai_ideas_flow ON ai_ideas(flow_id, status, updated_at);
        CREATE INDEX IF NOT EXISTS idx_ai_ideas_investigation ON ai_ideas(investigation_id, status, updated_at);
        CREATE INDEX IF NOT EXISTS idx_hypothesis_requirements_open ON hypothesis_requirements(status,key_pattern,lead_id);
        CREATE INDEX IF NOT EXISTS idx_hypothesis_requirements_lead ON hypothesis_requirements(lead_id,status,id);
        """
    )
    # v0.12.2: leads_v2 also acts as the persistent hypothesis store.
    # Additive migration keeps old workspaces intact.
    lead_cols = {row["name"] for row in conn.execute("PRAGMA table_info(leads_v2)")}
    if "source" not in lead_cols:
        conn.execute("ALTER TABLE leads_v2 ADD COLUMN source TEXT NOT NULL DEFAULT 'ENGINE'")
    if "parent_lead_id" not in lead_cols:
        conn.execute("ALTER TABLE leads_v2 ADD COLUMN parent_lead_id INTEGER")
    if "test_plan_json" not in lead_cols:
        conn.execute("ALTER TABLE leads_v2 ADD COLUMN test_plan_json TEXT")
    if "result_notes" not in lead_cols:
        conn.execute("ALTER TABLE leads_v2 ADD COLUMN result_notes TEXT")
    if "last_tested_at" not in lead_cols:
        conn.execute("ALTER TABLE leads_v2 ADD COLUMN last_tested_at TEXT")
    if "rule_active" not in lead_cols:
        conn.execute("ALTER TABLE leads_v2 ADD COLUMN rule_active INTEGER NOT NULL DEFAULT 1")
    if "last_rule_eval_at" not in lead_cols:
        conn.execute("ALTER TABLE leads_v2 ADD COLUMN last_rule_eval_at TEXT")
    if "promoted_investigation_id" not in lead_cols:
        conn.execute("ALTER TABLE leads_v2 ADD COLUMN promoted_investigation_id INTEGER")

    parameter_cols = {row["name"] for row in conn.execute("PRAGMA table_info(parameter_observations)")}
    if "value_raw" not in parameter_cols:
        conn.execute("ALTER TABLE parameter_observations ADD COLUMN value_raw TEXT")

    signal_cols = {row["name"] for row in conn.execute("PRAGMA table_info(signal_occurrences)")}
    if "signal_level" not in signal_cols:
        conn.execute("ALTER TABLE signal_occurrences ADD COLUMN signal_level TEXT NOT NULL DEFAULT 'local'")
    signal_cols = {row["name"] for row in conn.execute("PRAGMA table_info(signal_occurrences)")}
    if "human_decision" not in signal_cols:
        conn.execute("ALTER TABLE signal_occurrences ADD COLUMN human_decision TEXT NOT NULL DEFAULT 'new'")
    if "decision_reason" not in signal_cols:
        conn.execute("ALTER TABLE signal_occurrences ADD COLUMN decision_reason TEXT")
    if "decision_at" not in signal_cols:
        conn.execute("ALTER TABLE signal_occurrences ADD COLUMN decision_at TEXT")
    if "decision_occurrences" not in signal_cols:
        conn.execute("ALTER TABLE signal_occurrences ADD COLUMN decision_occurrences INTEGER NOT NULL DEFAULT 0")
    if "reconsideration_needed" not in signal_cols:
        conn.execute("ALTER TABLE signal_occurrences ADD COLUMN reconsideration_needed INTEGER NOT NULL DEFAULT 0")

    row = conn.execute("SELECT value FROM meta WHERE key='policy_profile'").fetchone()
    if not row:
        conn.execute("INSERT INTO meta(key,value) VALUES('policy_profile',?)", (DEFAULT_POLICY,))

    # Contexto compuesto · Fase 1. Keep the generic Investigation relation graph
    # synchronized with older one-to-one/origin fields without deleting them.
    # The backfill is stamped and additive, so existing workspaces stay compatible.
    backfill_investigation_links(conn)


def relationship(conn, src_type: str, src_id: int | None, relation: str, dst_type: str, dst_value: str, source: str, evidence: Any = None) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO relationships(src_type,src_id,relation,dst_type,dst_value,source,evidence_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (src_type, src_id, relation, dst_type, dst_value, source, json.dumps(evidence, ensure_ascii=False) if evidence is not None else None, now_iso()),
    )


# Canonical many-to-many context graph for Investigation.  Historical fields such
# as leads_v2.promoted_investigation_id and runners.investigation_id remain as
# compatibility/origin pointers, but membership is represented by investigation_links.
INVESTIGATION_ENTITY_TABLES: dict[str, tuple[str, str]] = {
    "exchange": ("http_exchanges", "Request"),
    "resource": ("resources", "Endpoint"),
    "signal": ("signal_occurrences", "Signal"),
    "hypothesis": ("leads_v2", "Hipótesis"),
    "flow": ("flows", "Flujo"),
    "business_object": ("business_objects", "Entity"),
    "identity": ("identities", "Identity"),
    "identity_context": ("identity_contexts", "Contexto de Identity"),
    "runner": ("runners", "Runner"),
    "ai_idea": ("ai_ideas", "Idea IA"),
    "finding": ("findings", "Finding"),
}


def _table_exists(conn, table: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (str(table),)).fetchone())


def backfill_investigation_links(conn) -> dict[str, int]:
    """Migrate historical Investigation pointers into the generic relation graph.

    This is intentionally additive: no legacy column/table is removed.  Separate
    stamps let optional schemas (notably Runner) be migrated the first time they
    actually exist, even if hunter.init_schema() ran earlier in the workspace.
    """
    now = now_iso()
    counts = {"base": 0, "runner": 0}

    base_stamp = conn.execute("SELECT value FROM meta WHERE key='context_compound_phase1_links_base'").fetchone()
    if not base_stamp:
        before = int(conn.execute("SELECT COUNT(*) c FROM investigation_links").fetchone()["c"] or 0)
        # Investigation created/promoted from a hypothesis.
        conn.execute(
            """INSERT OR IGNORE INTO investigation_links(investigation_id,entity_type,entity_id,relation,created_at)
               SELECT i.id,'hypothesis',i.source_hypothesis_id,'pursuing',COALESCE(i.created_at,?)
               FROM investigations i JOIN leads_v2 h ON h.id=i.source_hypothesis_id
               WHERE i.source_hypothesis_id IS NOT NULL""",
            (now,),
        )
        # Compatibility pointer on Hypothesis -> its primary/promoted Investigation.
        conn.execute(
            """INSERT OR IGNORE INTO investigation_links(investigation_id,entity_type,entity_id,relation,created_at)
               SELECT h.promoted_investigation_id,'hypothesis',h.id,'pursuing',COALESCE(h.updated_at,h.created_at,?)
               FROM leads_v2 h JOIN investigations i ON i.id=h.promoted_investigation_id
               WHERE h.promoted_investigation_id IS NOT NULL""",
            (now,),
        )
        # Finding already uses its own many-entity model; mirror Investigation edges
        # so the Investigation workspace has one canonical membership graph.
        if _table_exists(conn, "finding_entities"):
            conn.execute(
                """INSERT OR IGNORE INTO investigation_links(investigation_id,entity_type,entity_id,relation,created_at)
                   SELECT fe.entity_id,'finding',fe.finding_id,'decision',COALESCE(fe.created_at,?)
                   FROM finding_entities fe
                   JOIN investigations i ON i.id=fe.entity_id
                   JOIN findings f ON f.id=fe.finding_id
                   WHERE fe.entity_type='investigation'""",
                (now,),
            )
        # AI Ideas may carry an origin Investigation directly.  Preserve that origin
        # as context without changing the AI idea lifecycle.
        if _table_exists(conn, "ai_ideas"):
            conn.execute(
                """INSERT OR IGNORE INTO investigation_links(investigation_id,entity_type,entity_id,relation,created_at)
                   SELECT a.investigation_id,'ai_idea',a.id,'context',COALESCE(a.created_at,?)
                   FROM ai_ideas a JOIN investigations i ON i.id=a.investigation_id
                   WHERE a.investigation_id IS NOT NULL""",
                (now,),
            )
        after = int(conn.execute("SELECT COUNT(*) c FROM investigation_links").fetchone()["c"] or 0)
        counts["base"] = max(0, after - before)
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('context_compound_phase1_links_base',?)", (now,))

    # runners is an optional schema and may be initialized after hunter.init_schema.
    # Do not stamp it until the table actually exists.
    if _table_exists(conn, "runners"):
        runner_stamp = conn.execute("SELECT value FROM meta WHERE key='context_compound_phase1_links_runner'").fetchone()
        if not runner_stamp:
            before = int(conn.execute("SELECT COUNT(*) c FROM investigation_links").fetchone()["c"] or 0)
            cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(runners)").fetchall()}
            if "investigation_id" in cols:
                conn.execute(
                    """INSERT OR IGNORE INTO investigation_links(investigation_id,entity_type,entity_id,relation,created_at)
                       SELECT r.investigation_id,'runner',r.id,'test',COALESCE(r.created_at,?)
                       FROM runners r JOIN investigations i ON i.id=r.investigation_id
                       WHERE r.investigation_id IS NOT NULL""",
                    (now,),
                )
            after = int(conn.execute("SELECT COUNT(*) c FROM investigation_links").fetchone()["c"] or 0)
            counts["runner"] = max(0, after - before)
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('context_compound_phase1_links_runner',?)", (now,))
    return counts


def _assert_investigation_entity(conn, entity_type: str, entity_id: int) -> tuple[str, str]:
    et = str(entity_type or "").strip().lower()
    spec = INVESTIGATION_ENTITY_TABLES.get(et)
    if not spec:
        raise ValueError("Tipo de contexto no soportado")
    table, label = spec
    if not _table_exists(conn, table):
        raise ValueError(f"{label} no disponible en este workspace")
    if int(entity_id) <= 0 or not conn.execute(f"SELECT id FROM {table} WHERE id=?", (int(entity_id),)).fetchone():
        raise ValueError(f"{label} no encontrado")
    return et, label


def list_hypothesis_requirements(conn, lead_id: int) -> list[dict[str, Any]]:
    """Return the explicit pieces still needed by one human-visible hypothesis."""
    init_schema(conn)
    rows = conn.execute(
        """SELECT hr.*,i.name identity_name,p.name matched_name,p.value_preview matched_value_preview,
                  p.value_raw matched_value_raw,p.exchange_id matched_exchange_id,p.location matched_location
           FROM hypothesis_requirements hr
           LEFT JOIN identities i ON i.id=hr.identity_id
           LEFT JOIN parameter_observations p ON p.id=hr.matched_observation_id
           WHERE hr.lead_id=? ORDER BY CASE hr.status WHEN 'pending' THEN 0 WHEN 'matched' THEN 1 ELSE 2 END,hr.id""",
        (int(lead_id),),
    ).fetchall()
    return [dict(r) for r in rows]


def add_hypothesis_requirement(conn, lead_id: int, *, key_pattern: str, description: str = "",
                               identity_mode: str = "any", identity_id: int | None = None,
                               requirement_type: str = "identifier") -> int:
    """Persist one missing piece for a hypothesis.

    Requirements are intentionally small and explainable.  They are not a DSL;
    the first useful primitive is an identifier key (exact or glob pattern) plus
    optional identity context.
    """
    init_schema(conn)
    lead = conn.execute("SELECT id FROM leads_v2 WHERE id=?", (int(lead_id),)).fetchone()
    if not lead:
        raise ValueError("Hipótesis no encontrada")
    key = str(key_pattern or "").strip().lower().replace("-", "_")[:160]
    key = re.sub(r"[^a-z0-9_*?\[\]-]", "", key)
    if not key:
        raise ValueError("Indica la key/identificador que falta, por ejemplo order_id o cardId")
    mode = str(identity_mode or "any").strip().lower()
    if mode not in {"any", "specific", "different"}:
        mode = "any"
    iid = int(identity_id) if identity_id else None
    if mode in {"specific", "different"} and not iid:
        raise ValueError("Selecciona una identidad para ese requisito")
    now = now_iso()
    # Avoid duplicate pending requirements when AI/manual input describes the same need.
    existing = conn.execute(
        """SELECT id FROM hypothesis_requirements
           WHERE lead_id=? AND lower(key_pattern)=lower(?) AND identity_mode=? AND COALESCE(identity_id,0)=COALESCE(?,0)
             AND status IN ('pending','matched') ORDER BY id LIMIT 1""",
        (int(lead_id), key, mode, iid),
    ).fetchone()
    if existing:
        return int(existing["id"])
    cur = conn.execute(
        """INSERT INTO hypothesis_requirements(lead_id,requirement_type,key_pattern,description,identity_mode,identity_id,status,created_at,updated_at)
           VALUES(?,?,?,?,?,?,'pending',?,?)""",
        (int(lead_id), str(requirement_type or "identifier")[:40], key,
         str(description or "").strip()[:500], mode, iid, now, now),
    )
    requirement_id = int(cur.lastrowid)
    # The missing piece may already exist in stored evidence.  Check the local
    # identifier index immediately so a newly articulated hypothesis can benefit
    # from memory accumulated hours/days earlier without touching the target.
    try:
        match_requirement_history(conn, requirement_id)
    except Exception:
        pass
    return requirement_id


def update_hypothesis_requirement(conn, lead_id: int, requirement_id: int, *, status: str) -> dict[str, Any]:
    init_schema(conn)
    state = str(status or "pending").lower()
    if state not in {"pending", "matched", "dismissed"}:
        raise ValueError("Estado de pieza pendiente inválido")
    row = conn.execute("SELECT * FROM hypothesis_requirements WHERE id=? AND lead_id=?", (int(requirement_id), int(lead_id))).fetchone()
    if not row:
        raise ValueError("Pieza pendiente no encontrada")
    conn.execute(
        """UPDATE hypothesis_requirements SET status=?,
             matched_observation_id=CASE WHEN ?='pending' THEN NULL ELSE matched_observation_id END,
             matched_signal_id=CASE WHEN ?='pending' THEN NULL ELSE matched_signal_id END,
             updated_at=? WHERE id=?""",
        (state, state, state, now_iso(), int(requirement_id)),
    )
    out = conn.execute("SELECT * FROM hypothesis_requirements WHERE id=?", (int(requirement_id),)).fetchone()
    return dict(out)


def _persist_correlation_signal(conn, *, dedupe_key: str, exchange_id: int | None, operation_id: int | None,
                                resource_id: int | None, title: str, why: dict[str, Any], evidence: dict[str, Any],
                                severity: str = "info") -> int:
    """Upsert one persisted Correlation Signal without creating another signal system."""
    init_schema(conn)
    now = now_iso()
    row = conn.execute("SELECT id,occurrences FROM signal_occurrences WHERE dedupe_key=?", (str(dedupe_key),)).fetchone()
    if row:
        conn.execute(
            """UPDATE signal_occurrences SET exchange_id=COALESCE(?,exchange_id),operation_id=COALESCE(?,operation_id),
                 resource_id=COALESCE(?,resource_id),title=?,category='correlation',severity=?,why_json=?,evidence_json=?,
                 source='correlation',signal_level='correlation',occurrences=occurrences+1,last_seen_at=?,
                 reconsideration_needed=CASE WHEN COALESCE(human_decision,'new')='dismissed' THEN 1 ELSE reconsideration_needed END WHERE id=?""",
            (exchange_id, operation_id, resource_id, title[:240], severity,
             json.dumps(why, ensure_ascii=False), json.dumps(evidence, ensure_ascii=False), now, int(row["id"])),
        )
        return int(row["id"])
    cur = conn.execute(
        """INSERT INTO signal_occurrences(dedupe_key,exchange_id,operation_id,resource_id,kind,category,severity,title,why_json,evidence_json,source,occurrences,first_seen_at,last_seen_at,signal_level)
           VALUES(?,?,?,?,?,'correlation',?,?,?,?,?,1,?,?, 'correlation')""",
        (str(dedupe_key), exchange_id, operation_id, resource_id, "correlation",
         severity, title[:240], json.dumps(why, ensure_ascii=False), json.dumps(evidence, ensure_ascii=False), "correlation", now, now),
    )
    return int(cur.lastrowid)


def _identifier_pattern_matches(pattern: str, normalized_name: str) -> bool:
    p = str(pattern or "").lower().replace("-", "_")
    name = str(normalized_name or "").lower().replace("-", "_")
    if any(ch in p for ch in "*?["):
        return fnmatch.fnmatch(name, p)
    return p == name or p.replace("_", "") == name.replace("_", "")


def evaluate_correlation_memory(conn, exchange_id: int) -> dict[str, Any]:
    """Incrementally correlate identifier memory for one newly observed Request.

    This function performs indexed lookups only for identifier-like values in the
    current Request.  It never scans every Request pair and never asserts a
    vulnerability.  Interesting matches are persisted in the existing Signals
    table with `signal_level='correlation'`.
    """
    import negro_objects as object_tools

    init_schema(conn)
    object_tools.init_schema(conn)
    object_tools.index_exchange_identifiers(conn, int(exchange_id))
    current = [dict(r) for r in conn.execute(
        """SELECT im.*,o.method,r.path,h.hostname,e.status_code,i.name identity_name
           FROM identifier_observation_index im JOIN resource_operations o ON o.id=im.operation_id
           JOIN resources r ON r.id=im.resource_id JOIN hosts h ON h.id=im.host_id
           JOIN http_exchanges e ON e.id=im.exchange_id LEFT JOIN identities i ON i.id=im.identity_id
           WHERE im.exchange_id=? ORDER BY im.id""", (int(exchange_id),)
    ).fetchall()]
    if not current:
        return {"exchange_id": int(exchange_id), "identifier_observations": 0, "signals": 0, "requirements_matched": 0}

    pending = [dict(r) for r in conn.execute(
        """SELECT hr.*,l.title hypothesis_title FROM hypothesis_requirements hr
           JOIN leads_v2 l ON l.id=hr.lead_id
           WHERE hr.status='pending' AND COALESCE(l.rule_active,1)=1 AND l.status NOT IN ('negative','discarded')
           ORDER BY hr.id LIMIT 800"""
    ).fetchall()]
    emitted: set[int] = set(); matched_requirements = 0

    # 1) A value appears that can fill a piece explicitly missing from an open hypothesis.
    for obs in current:
        iid = int(obs["identity_id"]) if obs.get("identity_id") else None
        for req in pending:
            if not _identifier_pattern_matches(str(req["key_pattern"]), str(obs["normalized_name"])):
                continue
            mode = str(req.get("identity_mode") or "any")
            expected_iid = int(req["identity_id"]) if req.get("identity_id") else None
            if mode == "specific" and iid != expected_iid:
                continue
            if mode == "different" and (iid is None or iid == expected_iid):
                continue
            value = str(obs.get("value_raw") or obs.get("value_preview") or "")
            identity_text = str(obs.get("identity_name") or (f"Identity #{iid}" if iid else "sin Identity"))
            title = f"Pieza pendiente encontrada: {obs['normalized_name']}"
            why = {
                "message": f"{obs['normalized_name']} apareció en una nueva Request y puede completar una pieza pendiente de ‘{req['hypothesis_title']}’. Esto es una correlación, no una vulnerabilidad.",
                "hypothesis_id": int(req["lead_id"]), "requirement_id": int(req["id"]),
            }
            evidence = {
                "source": "correlation_memory", "correlation_type": "hypothesis_requirement_match",
                "hypothesis_id": int(req["lead_id"]), "requirement_id": int(req["id"]),
                "identifier": str(obs["normalized_name"]), "value": value[:240], "value_hash": str(obs["value_hash"]),
                "direction": str(obs["direction"]), "location": str(obs["source_location"]),
                "identity_id": iid, "identity_name": identity_text,
                "host": str(obs["hostname"]), "method": str(obs["method"]), "path": str(obs["path"]),
                "node_ids": [f"exchange:{int(exchange_id)}", f"resource:{int(obs['resource_id'])}"] + ([f"identity:{iid}"] if iid else []) + [f"lead:{int(req['lead_id'])}"],
            }
            signal_id = _persist_correlation_signal(
                conn, dedupe_key=f"correlation:req:{int(req['id'])}:value:{obs['value_hash']}:identity:{iid or 0}",
                exchange_id=int(exchange_id), operation_id=int(obs["operation_id"]), resource_id=int(obs["resource_id"]),
                title=title, why=why, evidence=evidence, severity="low",
            )
            conn.execute(
                """UPDATE hypothesis_requirements SET status='matched',matched_observation_id=?,matched_signal_id=?,updated_at=?
                   WHERE id=? AND status='pending'""",
                (int(obs["parameter_observation_id"]), int(signal_id), now_iso(), int(req["id"])),
            )
            matched_requirements += 1; emitted.add(signal_id)

    # 2) Same exact identifier value observed as output elsewhere and as input to
    # a state-changing/sensitive operation.  Group by producer/consumer endpoints
    # instead of emitting one signal for every UUID/ID.
    sensitive_terms = ("cancel", "delete", "remove", "update", "edit", "transfer", "refund", "pay", "payment", "card", "role", "admin", "approve", "redeem")
    for obs in current:
        peers = [dict(r) for r in conn.execute(
            """SELECT im.*,o.method,r.path,h.hostname,e.status_code,i.name identity_name
               FROM identifier_observation_index im JOIN resource_operations o ON o.id=im.operation_id
               JOIN resources r ON r.id=im.resource_id JOIN hosts h ON h.id=im.host_id
               JOIN http_exchanges e ON e.id=im.exchange_id LEFT JOIN identities i ON i.id=im.identity_id
               WHERE im.normalized_name=? AND im.value_hash=? AND im.exchange_id<>?
               ORDER BY im.observed_at DESC LIMIT 60""",
            (str(obs["normalized_name"]), str(obs["value_hash"]), int(exchange_id)),
        ).fetchall()]
        for peer in peers:
            if str(peer.get("direction")) == str(obs.get("direction")):
                continue
            producer = obs if obs.get("direction") == "output" else peer
            consumer = obs if obs.get("direction") == "input" else peer
            method = str(consumer.get("method") or "").upper()
            path = str(consumer.get("path") or "").lower()
            if method not in {"POST", "PUT", "PATCH", "DELETE"} and not any(x in path for x in sensitive_terms):
                continue
            cross_context = int(producer.get("host_id") or 0) != int(consumer.get("host_id") or 0) or (
                producer.get("identity_id") and consumer.get("identity_id") and int(producer["identity_id"]) != int(consumer["identity_id"])
            )
            if not cross_context:
                continue
            value = str(obs.get("value_raw") or obs.get("value_preview") or "")
            title = f"{obs['normalized_name']} conecta dos partes del target"
            why = {
                "message": f"El mismo {obs['normalized_name']} fue observado como salida en un endpoint y como entrada en una operación sensible distinta. Puede ser una oportunidad de prueba; no demuestra autorización débil.",
                "identifier": str(obs["normalized_name"]),
            }
            evidence = {
                "source": "correlation_memory", "correlation_type": "produced_then_consumed",
                "identifier": str(obs["normalized_name"]), "value": value[:240], "value_hash": str(obs["value_hash"]),
                "producer": {"exchange_id": int(producer["exchange_id"]), "resource_id": int(producer["resource_id"]), "host": producer["hostname"], "method": producer["method"], "path": producer["path"], "identity_id": producer.get("identity_id"), "identity_name": producer.get("identity_name")},
                "consumer": {"exchange_id": int(consumer["exchange_id"]), "resource_id": int(consumer["resource_id"]), "host": consumer["hostname"], "method": consumer["method"], "path": consumer["path"], "identity_id": consumer.get("identity_id"), "identity_name": consumer.get("identity_name")},
                "node_ids": [f"exchange:{int(producer['exchange_id'])}", f"resource:{int(producer['resource_id'])}", f"exchange:{int(consumer['exchange_id'])}", f"resource:{int(consumer['resource_id'])}"],
            }
            signal_id = _persist_correlation_signal(
                conn, dedupe_key=f"correlation:io:{obs['normalized_name']}:{int(producer['resource_id'])}:{int(consumer['resource_id'])}",
                exchange_id=int(consumer["exchange_id"]), operation_id=int(consumer["operation_id"]), resource_id=int(consumer["resource_id"]),
                title=title, why=why, evidence=evidence, severity="info",
            )
            emitted.add(signal_id)

    return {"exchange_id": int(exchange_id), "identifier_observations": len(current), "signals": len(emitted), "requirements_matched": matched_requirements}


def match_requirement_history(conn, requirement_id: int, *, max_requests: int = 120) -> dict[str, Any]:
    """Try to satisfy one new requirement using evidence Negro already remembers."""
    import negro_objects as object_tools

    init_schema(conn); object_tools.init_schema(conn)
    req = conn.execute("SELECT * FROM hypothesis_requirements WHERE id=?", (int(requirement_id),)).fetchone()
    if not req or str(req["status"]) != "pending":
        return {"requirement_id": int(requirement_id), "checked": 0, "matched": False}
    pattern = str(req["key_pattern"] or "")
    rows = conn.execute(
        """SELECT DISTINCT normalized_name FROM identifier_observation_index
           ORDER BY normalized_name LIMIT 3000"""
    ).fetchall()
    names = [str(r["normalized_name"]) for r in rows if _identifier_pattern_matches(pattern, str(r["normalized_name"]))]
    if not names:
        return {"requirement_id": int(requirement_id), "checked": 0, "matched": False}
    marks = ",".join("?" for _ in names)
    exrows = conn.execute(
        f"""SELECT DISTINCT exchange_id FROM identifier_observation_index
            WHERE normalized_name IN ({marks}) ORDER BY observed_at DESC LIMIT ?""",
        (*names, max(1, min(int(max_requests), 500))),
    ).fetchall()
    checked = 0
    for row in exrows:
        checked += 1
        evaluate_correlation_memory(conn, int(row["exchange_id"]))
        state = conn.execute("SELECT status FROM hypothesis_requirements WHERE id=?", (int(requirement_id),)).fetchone()
        if state and str(state["status"]) == "matched":
            return {"requirement_id": int(requirement_id), "checked": checked, "matched": True}
    return {"requirement_id": int(requirement_id), "checked": checked, "matched": False}


def _resolve_records(hostname: str, rtype: str, timeout: float = 4.0) -> list[str]:
    _require_dns()
    import dns.resolver
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        ans = resolver.resolve(hostname, rtype, raise_on_no_answer=False)
    except Exception:
        return []
    out: list[str] = []
    if ans.rrset is None:
        return out
    for r in ans:
        if rtype in {"MX"}:
            out.append(f"{r.preference} {str(r.exchange).rstrip('.')}")
        elif rtype in {"SOA"}:
            out.append(str(r))
        elif rtype in {"NS", "CNAME", "PTR"}:
            out.append(str(r).rstrip("."))
        elif rtype == "TXT":
            try:
                out.append("".join(x.decode() if isinstance(x, bytes) else str(x) for x in r.strings))
            except Exception:
                out.append(str(r).strip('"'))
        else:
            out.append(str(r))
    return sorted(set(out))


def dns_infrastructure(domain: str, timeout: float = 4.0) -> dict[str, Any]:
    records: dict[str, Any] = {}
    for rtype in ("A", "AAAA", "NS", "MX", "SOA", "TXT"):
        records[rtype] = _resolve_records(domain, rtype, timeout)
    # SRV names worth asking directly; absence is normal.
    srv: dict[str, list[str]] = {}
    for label in ("_sip._tcp", "_sip._udp", "_xmpp-server._tcp", "_autodiscover._tcp"):
        vals = _resolve_records(f"{label}.{domain}", "SRV", timeout)
        if vals:
            srv[label] = vals
    records["SRV"] = srv
    reverse: dict[str, str] = {}
    for ip in (records.get("A", []) or [])[:20]:
        try:
            reverse[ip] = socket.gethostbyaddr(ip)[0].rstrip(".")
        except Exception:
            pass
    records["PTR"] = reverse
    return {"domain": domain, "records": records, "observed_at": now_iso()}


def axfr_check(domain: str, nameservers: Iterable[str], timeout: float = 5.0) -> dict[str, Any]:
    _require_dns()
    import dns.query
    import dns.resolver
    import dns.zone
    results: list[dict[str, Any]] = []
    for ns in list(nameservers)[:12]:
        ns = str(ns).rstrip(".")
        ips = _resolve_records(ns, "A", timeout) + _resolve_records(ns, "AAAA", timeout)
        if not ips:
            results.append({"nameserver": ns, "status": "unresolved", "records": []})
            continue
        success = False
        last_error = None
        for ip in ips[:2]:
            try:
                xfr = dns.query.xfr(ip, domain, lifetime=timeout, relativize=False)
                zone = dns.zone.from_xfr(xfr, relativize=False)
                rows: list[dict[str, str]] = []
                if zone:
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                rows.append({"name": str(name).rstrip("."), "type": __import__("dns.rdatatype", fromlist=["to_text"]).to_text(rdataset.rdtype), "value": str(rdata)})
                results.append({"nameserver": ns, "ip": ip, "status": "success", "records": rows})
                success = True
                break
            except Exception as exc:
                last_error = str(exc)
        if not success:
            results.append({"nameserver": ns, "status": "refused_or_failed", "error": (last_error or "transfer failed")[:300], "records": []})
    return {"domain": domain, "results": results, "observed_at": now_iso()}


def generate_smart_host_candidates(domain: str, known_hosts: Iterable[str], max_candidates: int = 50) -> list[str]:
    domain = domain.lower().rstrip(".")
    labels: set[str] = set()
    tokens: set[str] = {"api", "auth", "login", "admin", "portal", "app", "web", "dev", "stage", "staging", "test", "qa", "preprod", "old", "legacy"}
    envs = ["dev", "stage", "stg", "test", "qa", "preprod", "prod"]
    for host in known_hosts:
        h = host.lower().rstrip(".")
        if not (h == domain or h.endswith("." + domain)):
            continue
        left = h[: -(len(domain) + 1)] if h != domain else ""
        if not left:
            continue
        first = left.split(".")[0]
        labels.add(first)
        for part in re.split(r"[-_.]", first):
            if 2 <= len(part) <= 24:
                tokens.add(part)
    candidates: set[str] = set()
    for token in sorted(tokens):
        candidates.add(f"{token}.{domain}")
    bases = sorted({x for x in tokens if x not in set(envs) and len(x) >= 3})[:30]
    for base in bases:
        for env in envs:
            candidates.add(f"{base}-{env}.{domain}")
            candidates.add(f"{env}-{base}.{domain}")
    known = {h.lower().rstrip('.') for h in known_hosts}
    return sorted(x for x in candidates if x not in known)[:max_candidates]


def _wildcard_dns(domain: str) -> dict[str, Any]:
    answers: list[dict[str, list[str]]] = []
    for _ in range(2):
        label = "negro-" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
        fqdn = f"{label}.{domain}"
        a = _resolve_records(fqdn, "A", 3)
        aaaa = _resolve_records(fqdn, "AAAA", 3)
        answers.append({"host": fqdn, "A": a, "AAAA": aaaa})
    wildcard = any(x["A"] or x["AAAA"] for x in answers)
    signatures = sorted({v for x in answers for v in (x["A"] + x["AAAA"])})
    return {"detected": wildcard, "signatures": signatures, "samples": answers}


def active_dns_validate(domain: str, candidates: Iterable[str], delay_s: float = 0.35) -> dict[str, Any]:
    candidates = list(dict.fromkeys(str(x).lower().rstrip(".") for x in candidates))
    wildcard = _wildcard_dns(domain)
    found: list[dict[str, Any]] = []
    filtered: list[str] = []
    sig = set(wildcard.get("signatures", []))
    for fqdn in candidates:
        a = _resolve_records(fqdn, "A", 3)
        aaaa = _resolve_records(fqdn, "AAAA", 3)
        cn = _resolve_records(fqdn, "CNAME", 3)
        current_sig = set(a + aaaa)
        if (a or aaaa or cn) and wildcard.get("detected") and current_sig and current_sig.issubset(sig) and not cn:
            filtered.append(fqdn)
        elif a or aaaa or cn:
            found.append({"hostname": fqdn, "A": a, "AAAA": aaaa, "CNAME": cn})
        if delay_s:
            time.sleep(delay_s)
    return {"domain": domain, "wildcard": wildcard, "tested": len(candidates), "found": found, "wildcard_filtered": filtered, "observed_at": now_iso()}


def _session() -> Any:
    _require_requests()
    s = requests.Session()
    s.trust_env = False
    s.headers.update({"User-Agent": "NegroRecon/0.9 (+authorized-security-research)"})
    s.max_redirects = 5
    return s


def _safe_request(session, method: str, url: str, *, timeout: float = 8.0, headers: dict[str, str] | None = None, allow_redirects: bool = False) -> Response:
    return session.request(method, url, headers=headers or {}, timeout=timeout, allow_redirects=allow_redirects, verify=False, stream=False)


def vhost_discover(base_url: str, candidates: Iterable[str], delay_s: float = 0.45) -> dict[str, Any]:
    session = _session()
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("base_url debe ser http(s)://host[:port]")
    random_host = "negro-" + "".join(random.choice(string.ascii_lowercase) for _ in range(18)) + ".invalid"
    try:
        baseline = _safe_request(session, "GET", base_url, headers={"Host": random_host})
        baseline_sig = (baseline.status_code, len(baseline.content), hashlib.sha256(baseline.content).hexdigest()[:16], baseline.headers.get("Location"))
    except Exception as exc:
        raise RuntimeError(f"No se pudo medir baseline VHost: {exc}")
    found: list[dict[str, Any]] = []
    for host in list(candidates):
        try:
            r = _safe_request(session, "GET", base_url, headers={"Host": host})
            sig = (r.status_code, len(r.content), hashlib.sha256(r.content).hexdigest()[:16], r.headers.get("Location"))
            if sig != baseline_sig:
                found.append({"hostname": host, "status": r.status_code, "size": len(r.content), "location": r.headers.get("Location"), "signature": sig[2]})
        except Exception as exc:
            found.append({"hostname": host, "error": str(exc)[:180]})
        if delay_s:
            time.sleep(delay_s)
    return {"base_url": base_url, "baseline": {"status": baseline_sig[0], "size": baseline_sig[1], "hash": baseline_sig[2], "location": baseline_sig[3]}, "tested": len(list(candidates)) if not isinstance(candidates, list) else len(candidates), "found": found, "observed_at": now_iso()}


class ReconHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.comments: list[str] = []
        self.meta: list[dict[str, str]] = []
        self._form: dict[str, Any] | None = None
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        d = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag in {"a", "link"} and d.get("href"):
            self.links.append(d["href"])
        elif tag in {"img", "source", "video", "audio", "iframe"} and d.get("src"):
            self.links.append(d["src"])
        elif tag == "script" and d.get("src"):
            self.scripts.append(d["src"])
            self.links.append(d["src"])
        elif tag == "form":
            self._form = {"action": d.get("action", ""), "method": (d.get("method") or "GET").upper(), "fields": []}
            self.forms.append(self._form)
        elif tag in {"input", "select", "textarea", "button"} and self._form is not None:
            name = d.get("name") or d.get("id")
            if name:
                self._form["fields"].append({"name": name, "type": d.get("type", tag)})
        elif tag == "meta":
            item = {k: v for k, v in d.items() if k in {"name", "property", "content", "http-equiv"}}
            if item:
                self.meta.append(item)
    def handle_endtag(self, tag: str):
        if tag.lower() == "form":
            self._form = None
    def handle_comment(self, data: str):
        cleaned = re.sub(r"\s+", " ", data).strip()
        if cleaned:
            self.comments.append(cleaned[:1200])


def parse_robots(text: str) -> dict[str, Any]:
    groups: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    sitemaps: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = [x.strip() for x in line.split(":", 1)]
        kl = key.lower()
        if kl == "user-agent":
            if current is None or current.get("rules"):
                current = {"user_agents": [], "rules": [], "crawl_delay": None}
                groups.append(current)
            current["user_agents"].append(value)
        elif kl == "sitemap":
            sitemaps.append(value)
        elif current is not None and kl in {"allow", "disallow"}:
            current["rules"].append({"directive": kl, "path": value})
        elif current is not None and kl == "crawl-delay":
            try:
                current["crawl_delay"] = float(value)
            except Exception:
                current["crawl_delay"] = value
    return {"groups": groups, "sitemaps": sorted(set(sitemaps))}


def _robots_disallowed(robots: dict[str, Any], path: str) -> bool:
    matched_allow = ""
    matched_disallow = ""
    for group in robots.get("groups", []):
        agents = [str(x).lower() for x in group.get("user_agents", [])]
        if "*" not in agents:
            continue
        for rule in group.get("rules", []):
            p = str(rule.get("path") or "")
            if not p or not path.startswith(p.rstrip("$")):
                continue
            if rule.get("directive") == "allow" and len(p) > len(matched_allow):
                matched_allow = p
            if rule.get("directive") == "disallow" and len(p) > len(matched_disallow):
                matched_disallow = p
    return bool(matched_disallow and len(matched_disallow) >= len(matched_allow))


def _fingerprints(headers: dict[str, str], text: str, url: str) -> list[dict[str, Any]]:
    low = text.lower()
    hlow = {k.lower(): str(v) for k, v in headers.items()}
    out: list[dict[str, Any]] = []
    server = hlow.get("server")
    if server:
        out.append({"technology": server, "category": "server", "confidence": "high", "evidence": "Server header"})
    powered = hlow.get("x-powered-by")
    if powered:
        out.append({"technology": powered, "category": "framework", "confidence": "high", "evidence": "X-Powered-By header"})
    if "wordpress" in hlow.get("x-redirect-by", "").lower() or "/wp-json/" in low or "/wp-content/" in low:
        out.append({"technology": "WordPress", "category": "cms", "confidence": "high", "evidence": "wp-json/wp-content/X-Redirect-By"})
    if "joomla" in low or "option=com_" in low or "/media/system/js/" in low:
        out.append({"technology": "Joomla", "category": "cms", "confidence": "medium", "evidence": "HTML signature"})
    if "drupal" in low or "/sites/default/" in low:
        out.append({"technology": "Drupal", "category": "cms", "confidence": "medium", "evidence": "HTML signature"})
    if "/_next/" in low:
        out.append({"technology": "Next.js", "category": "frontend", "confidence": "high", "evidence": "/_next/ assets"})
    if "/_nuxt/" in low:
        out.append({"technology": "Nuxt", "category": "frontend", "confidence": "high", "evidence": "/_nuxt/ assets"})
    # Passive WAF/CDN fingerprints from response, without extra probing.
    joined = " ".join(f"{k}:{v}" for k, v in hlow.items()).lower()
    if "cf-ray" in hlow or "cloudflare" in joined:
        out.append({"technology": "Cloudflare", "category": "edge_waf", "confidence": "high", "evidence": "response headers"})
    if "akamai" in joined or "x-akamai" in joined:
        out.append({"technology": "Akamai", "category": "edge_waf", "confidence": "medium", "evidence": "response headers"})
    if "incap_ses" in joined or "imperva" in joined:
        out.append({"technology": "Imperva", "category": "edge_waf", "confidence": "medium", "evidence": "response headers"})
    if "wordfence" in low:
        out.append({"technology": "Wordfence", "category": "waf", "confidence": "medium", "evidence": "page content"})
    seen = set()
    dedup = []
    for item in out:
        key = (item["technology"], item["category"])
        if key not in seen:
            seen.add(key)
            dedup.append(item)
    return dedup


def fetch_text(url: str, timeout: float = 8.0, max_bytes: int = 1_500_000) -> dict[str, Any]:
    session = _session()
    try:
        r = _safe_request(session, "GET", url, timeout=timeout, allow_redirects=False)
    except Exception as exc:
        return {"url": url, "error": str(exc)[:400]}
    body = r.content[:max_bytes]
    enc = r.encoding or "utf-8"
    try:
        text = body.decode(enc, errors="replace")
    except Exception:
        text = body.decode("utf-8", errors="replace")
    return {"url": url, "status": r.status_code, "headers": dict(r.headers), "text": text, "bytes": len(body)}


def web_recon(hostname: str, *, timeout: float = 8.0) -> dict[str, Any]:
    session = _session()
    base_candidates = [f"https://{hostname}/", f"http://{hostname}/"]
    chosen = None
    chain: list[dict[str, Any]] = []
    final_text = ""
    final_headers: dict[str, str] = {}
    for base in base_candidates:
        try:
            current = base
            for _ in range(6):
                r = _safe_request(session, "GET", current, timeout=timeout, allow_redirects=False)
                chain.append({"url": current, "status": r.status_code, "location": r.headers.get("Location"), "server": r.headers.get("Server"), "x_powered_by": r.headers.get("X-Powered-By"), "x_redirect_by": r.headers.get("X-Redirect-By")})
                if r.is_redirect and r.headers.get("Location"):
                    nxt = urllib.parse.urljoin(current, r.headers["Location"])
                    current = nxt
                    continue
                chosen = current
                final_headers = dict(r.headers)
                ctype = r.headers.get("Content-Type", "")
                if "text" in ctype or "html" in ctype or not ctype:
                    final_text = r.content[:1_500_000].decode(r.encoding or "utf-8", errors="replace")
                break
            if chosen:
                break
        except Exception:
            continue
    if not chosen:
        raise RuntimeError(f"No se pudo conectar por HTTPS ni HTTP a {hostname}")
    parsed = ReconHTMLParser()
    try:
        parsed.feed(final_text)
    except Exception:
        pass
    robots_url = urllib.parse.urljoin(chosen, "/robots.txt")
    robots_raw = fetch_text(robots_url, timeout=timeout, max_bytes=500_000)
    robots = parse_robots(robots_raw.get("text", "")) if robots_raw.get("status") == 200 else {"groups": [], "sitemaps": []}
    well_known_paths = [
        "/.well-known/security.txt", "/.well-known/openid-configuration",
        "/.well-known/assetlinks.json", "/.well-known/change-password", "/.well-known/mta-sts.txt",
    ]
    well_known: dict[str, Any] = {}
    for path in well_known_paths:
        item = fetch_text(urllib.parse.urljoin(chosen, path), timeout=timeout, max_bytes=750_000)
        if item.get("status") in {200, 301, 302, 307, 308}:
            summary: dict[str, Any] = {k: item.get(k) for k in ("url", "status", "headers", "bytes")}
            text = item.get("text", "")
            if path.endswith("openid-configuration") and item.get("status") == 200:
                try:
                    data = json.loads(text)
                    summary["json"] = data
                except Exception:
                    summary["text_sample"] = text[:3000]
            elif path.endswith("assetlinks.json") and item.get("status") == 200:
                try:
                    summary["json"] = json.loads(text)
                except Exception:
                    summary["text_sample"] = text[:3000]
            else:
                summary["text_sample"] = text[:6000]
            well_known[path] = summary
    fingerprints = _fingerprints(final_headers, final_text, chosen)
    directory_listing = bool(re.search(r"<title>\s*index of /|<h1>\s*index of /", final_text, re.I))
    return {
        "hostname": hostname,
        "final_url": chosen,
        "redirect_chain": chain,
        "headers": final_headers,
        "fingerprints": fingerprints,
        "robots_url": robots_url,
        "robots": robots,
        "well_known": well_known,
        "forms": parsed.forms[:100],
        "comments": parsed.comments[:100],
        "meta": parsed.meta[:100],
        "directory_listing": directory_listing,
        "observed_at": now_iso(),
    }


def crawl(hostname: str, *, domain: str | None = None, max_urls: int = 200, max_depth: int = 2, delay_s: float = 0.35, respect_robots: bool = True, timeout: float = 8.0) -> dict[str, Any]:
    session = _session()
    seed = f"https://{hostname}/"
    try:
        r0 = _safe_request(session, "GET", seed, timeout=timeout, allow_redirects=True)
        seed = r0.url
    except Exception:
        seed = f"http://{hostname}/"
    seed_parsed = urllib.parse.urlsplit(seed)
    root_host = seed_parsed.hostname or hostname
    root_domain = (domain or hostname).lower().rstrip(".")
    robots_data = fetch_text(urllib.parse.urljoin(seed, "/robots.txt"), timeout=timeout, max_bytes=500_000)
    robots = parse_robots(robots_data.get("text", "")) if robots_data.get("status") == 200 else {"groups": [], "sitemaps": []}
    robot_delays = [g.get("crawl_delay") for g in robots.get("groups", []) if isinstance(g.get("crawl_delay"), (int, float))]
    effective_delay = max([delay_s] + robot_delays) if robot_delays else delay_s

    q: deque[tuple[str, int]] = deque([(seed, 0)])
    for sm in robots.get("sitemaps", [])[:5]:
        try:
            if urllib.parse.urlsplit(sm).hostname in {root_host, hostname} or str(sm).endswith(root_domain):
                q.append((sm, 0))
        except Exception:
            pass
    visited: set[str] = set()
    pages: list[dict[str, Any]] = []
    links: set[str] = set()
    js_files: set[str] = set()
    documents: set[str] = set()
    external: set[str] = set()
    emails: set[str] = set()
    comments: list[dict[str, str]] = []
    forms: list[dict[str, Any]] = []
    new_hosts: set[str] = set()

    def canonical(url: str) -> str | None:
        try:
            p = urllib.parse.urlsplit(url)
            if p.scheme not in {"http", "https"} or not p.hostname:
                return None
            # Remove fragment, sort query to reduce duplicates.
            query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(p.query, keep_blank_values=True)))
            return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path or "/", query, ""))
        except Exception:
            return None

    while q and len(visited) < max_urls:
        url, depth = q.popleft()
        c = canonical(url)
        if not c or c in visited:
            continue
        p = urllib.parse.urlsplit(c)
        host = (p.hostname or "").lower()
        in_scope = host == hostname or host.endswith("." + root_domain)
        if not in_scope:
            external.add(c)
            continue
        if respect_robots and _robots_disallowed(robots, p.path or "/"):
            continue
        visited.add(c)
        try:
            r = _safe_request(session, "GET", c, timeout=timeout, allow_redirects=True)
        except Exception as exc:
            pages.append({"url": c, "depth": depth, "error": str(exc)[:180]})
            continue
        ctype = r.headers.get("Content-Type", "")
        body = r.content[:1_500_000]
        page = {"url": c, "final_url": r.url, "depth": depth, "status": r.status_code, "content_type": ctype, "size": len(body), "title": "", "directory_listing": False}
        if "html" not in ctype.lower() and "text" not in ctype.lower() and "xml" not in ctype.lower() and ctype:
            pages.append(page)
            ext = Path(urllib.parse.urlsplit(c).path).suffix.lower()
            if ext in DOC_EXTENSIONS or ext in ARCHIVE_EXTENSIONS:
                documents.add(c)
            continue
        text = body.decode(r.encoding or "utf-8", errors="replace")
        # Sitemap XML is structured discovery, not ordinary HTML. Import <loc> entries
        # and enqueue only in-scope URLs within the configured crawl depth/budget.
        if "xml" in ctype.lower() or (p.path or "").lower().endswith(("sitemap.xml", ".xml")):
            for loc in re.findall(r"<loc>\s*(.*?)\s*</loc>", text, re.I | re.S)[:5000]:
                loc = re.sub(r"&amp;", "&", loc.strip())
                u = canonical(urllib.parse.urljoin(c, loc))
                if not u:
                    continue
                up = urllib.parse.urlsplit(u)
                uh = (up.hostname or "").lower()
                ext = Path(up.path).suffix.lower()
                if uh == hostname or uh.endswith("." + root_domain):
                    links.add(u)
                    if uh != hostname:
                        new_hosts.add(uh)
                    if ext == ".js":
                        js_files.add(u)
                    if ext in DOC_EXTENSIONS or ext in ARCHIVE_EXTENSIONS:
                        documents.add(u)
                    elif depth < max_depth:
                        q.append((u, depth + 1))
                else:
                    external.add(u)
        mtitle = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        if mtitle:
            page["title"] = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", mtitle.group(1))).strip()[:250]
        page["directory_listing"] = bool(re.search(r"<title>\s*index of /|<h1>\s*index of /", text, re.I))
        pages.append(page)
        for email in re.findall(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", text, re.I):
            emails.add(email)
        parser = ReconHTMLParser()
        try:
            parser.feed(text)
        except Exception:
            pass
        for com in parser.comments[:50]:
            comments.append({"url": c, "comment": com})
        for f in parser.forms[:50]:
            action = urllib.parse.urljoin(c, f.get("action") or c)
            forms.append({"page": c, "action": action, "method": f.get("method", "GET"), "fields": f.get("fields", [])})
        for raw in parser.links:
            u = canonical(urllib.parse.urljoin(c, raw))
            if not u:
                continue
            up = urllib.parse.urlsplit(u)
            uh = (up.hostname or "").lower()
            ext = Path(up.path).suffix.lower()
            if uh == hostname or uh.endswith("." + root_domain):
                links.add(u)
                if uh != hostname:
                    new_hosts.add(uh)
                if ext == ".js":
                    js_files.add(u)
                if ext in DOC_EXTENSIONS or ext in ARCHIVE_EXTENSIONS:
                    documents.add(u)
                if depth < max_depth and ext not in DOC_EXTENSIONS | ARCHIVE_EXTENSIONS and ext not in {".jpg", ".jpeg", ".png", ".gif", ".svg", ".woff", ".woff2", ".css"}:
                    q.append((u, depth + 1))
            else:
                external.add(u)
        for raw in parser.scripts:
            u = canonical(urllib.parse.urljoin(c, raw))
            if u:
                if urllib.parse.urlsplit(u).hostname == hostname or str(urllib.parse.urlsplit(u).hostname or "").endswith("." + root_domain):
                    js_files.add(u)
                else:
                    external.add(u)
        if effective_delay:
            time.sleep(effective_delay)
    return {
        "hostname": hostname,
        "seed": seed,
        "visited": len(visited),
        "pages": pages,
        "links": sorted(links),
        "js_files": sorted(js_files),
        "documents": sorted(documents),
        "forms": forms[:500],
        "comments": comments[:1000],
        "emails": sorted(emails),
        "external_urls": sorted(external)[:2000],
        "new_hosts": sorted(new_hosts),
        "robots_respected": respect_robots,
        "effective_delay_s": effective_delay,
        "max_urls": max_urls,
        "max_depth": max_depth,
        "observed_at": now_iso(),
    }


def cors_probe(url: str, timeout: float = 8.0, replay_headers: dict[str, str] | None = None) -> dict[str, Any]:
    """Low-impact CORS probe.

    When replay_headers are supplied (for example from a Burp exchange), Negro
    preserves the authenticated browsing context while replacing Origin with a
    controlled value. This is important for endpoints that only expose their
    CORS policy after login.
    """
    session = _session()
    origin = "https://negro-validation.invalid"
    headers: dict[str, str] = {}
    blocked = {"host", "content-length", "connection", "proxy-connection", "origin", ":authority", ":method", ":path", ":scheme"}
    for name, value in (replay_headers or {}).items():
        if str(name).lower().strip() in blocked:
            continue
        headers[str(name)] = str(value)
    headers["Origin"] = origin
    try:
        r = _safe_request(session, "GET", url, timeout=timeout, headers=headers, allow_redirects=False)
        allow_origin = r.headers.get("Access-Control-Allow-Origin")
        allow_credentials = r.headers.get("Access-Control-Allow-Credentials")
        reflected = bool(allow_origin and allow_origin.strip() == origin)
        credentials = str(allow_credentials or "").strip().lower() == "true"
        return {
            "url": url,
            "status": r.status_code,
            "origin_sent": origin,
            "allow_origin": allow_origin,
            "allow_credentials": allow_credentials,
            "origin_reflected": reflected,
            "credentials_allowed": credentials,
            "interesting": bool(reflected or allow_origin == "*"),
            "likely_credentialed_cors": bool(reflected and credentials),
            "replayed_context": bool(replay_headers),
            "vary": r.headers.get("Vary"),
            "content_type": r.headers.get("Content-Type"),
            "body_size": len(r.content),
            "observed_at": now_iso(),
        }
    except Exception as exc:
        return {"url": url, "error": str(exc)[:400], "replayed_context": bool(replay_headers), "observed_at": now_iso()}


def search_queries(domain: str, technologies: Iterable[str] = (), keywords: Iterable[str] = ()) -> list[dict[str, str]]:
    queries = [
        ("General", f"site:{domain}"),
        ("Authentication", f"site:{domain} (inurl:login OR inurl:auth OR inurl:oauth OR inurl:sso)"),
        ("Documents", f"site:{domain} (filetype:pdf OR filetype:docx OR filetype:xlsx)"),
        ("API docs", f"site:{domain} (inurl:api OR inurl:swagger OR inurl:openapi)"),
        ("Backups/config", f"site:{domain} (inurl:backup OR inurl:config OR ext:sql OR ext:bak)"),
        ("OAuth/OpenID", f"site:{domain} (\"redirect_uri\" OR \"OpenID\" OR \"OAuth\")"),
    ]
    tech = " ".join(technologies).lower()
    if "wordpress" in tech:
        queries.append(("WordPress", f"site:{domain} (inurl:wp-content OR inurl:wp-json OR inurl:wp-admin)"))
    if "joomla" in tech:
        queries.append(("Joomla", f"site:{domain} inurl:administrator"))
    for kw in list(dict.fromkeys(str(x).strip() for x in keywords if str(x).strip()))[:5]:
        if re.fullmatch(r"[A-Za-z0-9_-]{3,40}", kw):
            queries.append((f"Keyword: {kw}", f"site:{domain} \"{kw}\" filetype:pdf"))
    return [{"label": a, "query": b} for a, b in queries[:12]]


def _confidence_rank(v: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(v, 0)


def _priority_rank(v: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(v, 0)


def upsert_lead(conn, *, lead_key: str, host_id: int | None, resource_id: int | None, lead_type: str, title: str, confidence: str, review_priority: str, evidence: list[dict[str, Any]], why: str, next_test: str, confirm_if: str, discard_if: str, source: str = "ENGINE", parent_lead_id: int | None = None) -> tuple[int, bool]:
    now = now_iso()
    existing = conn.execute("SELECT id,confidence,review_priority,status,rule_active FROM leads_v2 WHERE lead_key=?", (lead_key,)).fetchone()
    if existing:
        # Never downgrade confidence/priority automatically and preserve human status.
        confidence = max([existing["confidence"], confidence], key=_confidence_rank)
        review_priority = max([existing["review_priority"], review_priority], key=_priority_rank)
        conn.execute(
            "UPDATE leads_v2 SET host_id=?,resource_id=?,lead_type=?,title=?,confidence=?,review_priority=?,evidence_json=?,why_interesting=?,next_test=?,confirm_if=?,discard_if=?,source=COALESCE(source,?),parent_lead_id=COALESCE(parent_lead_id,?),rule_active=1,last_rule_eval_at=?,updated_at=? WHERE lead_key=?",
            (host_id, resource_id, lead_type, title, confidence, review_priority, json.dumps(evidence, ensure_ascii=False), why, next_test, confirm_if, discard_if, source, parent_lead_id, now, now, lead_key),
        )
        return int(existing["id"]), False
    else:
        cur = conn.execute(
            "INSERT INTO leads_v2(lead_key,host_id,resource_id,lead_type,title,confidence,review_priority,status,evidence_json,why_interesting,next_test,confirm_if,discard_if,created_at,updated_at,source,parent_lead_id,rule_active,last_rule_eval_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (lead_key, host_id, resource_id, lead_type, title, confidence, review_priority, "candidate", json.dumps(evidence, ensure_ascii=False), why, next_test, confirm_if, discard_if, now, now, source, parent_lead_id, 1, now),
        )
        return int(cur.lastrowid), True


def _iter_js_analysis(conn) -> Iterable[tuple[Any, dict[str, Any], dict[str, Any] | None]]:
    rows = conn.execute("SELECT j.*, h.hostname FROM js_assets j JOIN hosts h ON h.id=j.host_id").fetchall()
    for r in rows:
        try:
            local = json.loads(r["local_analysis_json"] or "{}")
        except Exception:
            local = {}
        try:
            sm = json.loads(r["sourcemap_analysis_json"] or "null")
        except Exception:
            sm = None
        yield r, local, sm if isinstance(sm, dict) else None



def _safe_b64_text(value: str | None, limit: int = 1_500_000) -> str:
    if not value:
        return ""
    try:
        raw = base64.b64decode(value, validate=False)[:limit]
    except Exception:
        return ""
    return raw.decode("utf-8", errors="replace")


def _split_http_message(text: str) -> tuple[str, str]:
    if "\r\n\r\n" in text:
        return text.split("\r\n\r\n", 1)
    if "\n\n" in text:
        return text.split("\n\n", 1)
    return text, ""


def _header_map(raw: str | None) -> dict[str, str]:
    try:
        rows = json.loads(raw or "[]")
    except Exception:
        rows = []
    out: dict[str, str] = {}
    if isinstance(rows, dict):
        rows = [{"name": k, "value": v} for k, v in rows.items()]
    for item in rows if isinstance(rows, list) else []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("key") or "").strip().lower()
        value = str(item.get("value") or "").strip()
        if name:
            out[name] = value
    return out


def _mask_value(value: Any) -> str:
    text = str(value or "")
    if not text:
        return "(vacío)"
    if len(text) <= 8:
        return "•" * min(len(text), 8)
    return f"{text[:4]}…{text[-4:]} (len={len(text)})"


def _secret_fingerprint(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", errors="ignore")).hexdigest()[:16]




def _secret_pattern_entry(secret_type: str):
    wanted = str(secret_type or "").lower()
    for stype, label, regex, severity in SECRET_PATTERNS:
        if stype.lower() == wanted:
            return stype, label, regex, severity
    return None


def _masked_secret_context(text: str, start: int, end: int, *, radius: int = 240) -> str:
    """Return a small forensic window without persisting raw secret values."""
    left = max(0, int(start) - radius)
    right = min(len(text), int(end) + radius)
    snippet = text[left:right]
    # Mask every secret signature we already know, not only the current match.
    for _stype, _label, regex, _severity in SECRET_PATTERNS:
        snippet = regex.sub(lambda m: _mask_value(m.group(0)), snippet)
    # Also mask structured sensitive fields that may sit next to the matched secret.
    # A provenance window must never turn into a second secret-disclosure channel.
    sensitive_names = sorted({str(x) for x in globals().get("SENSITIVE_RESPONSE_KEYS", set()) if str(x)}, key=len, reverse=True)
    if sensitive_names:
        names = "|".join(re.escape(x) for x in sensitive_names)
        kv = re.compile(r"(?i)([\"']?(?:" + names + r")[\"']?\s*[:=]\s*[\"'])([^\"'\r\n]{1,500})([\"'])")
        snippet = kv.sub(lambda m: m.group(1) + _mask_value(m.group(2)) + m.group(3), snippet)
    snippet = re.sub(r"(?i)(Authorization\s*:\s*(?:Bearer|Basic)\s+)([^\s\r\n]+)", lambda m: m.group(1)+_mask_value(m.group(2)), snippet)
    # Keep the evidence readable in one card while preserving nearby code/config.
    return snippet.replace("\x00", "").strip()[:1200]


def secret_evidence_details(conn, evidence: dict[str, Any]) -> dict[str, Any] | None:
    """Resolve one persisted secret clue back to the exact stored Burp exchange.

    The raw secret is never returned.  This works for older leads that only stored
    exchange_id + fingerprint, so upgrading Negro immediately makes historical
    hypotheses explainable without re-enumerating or re-capturing traffic.
    """
    if not isinstance(evidence, dict):
        return None
    stype = str(evidence.get("secret_type") or "")
    entry = _secret_pattern_entry(stype)
    try:
        exchange_id = int(evidence.get("exchange_id") or 0)
    except Exception:
        exchange_id = 0
    if not entry or not exchange_id:
        return None
    _stype, label, regex, _severity = entry
    row = conn.execute(
        """SELECT e.id,e.request_b64,e.response_b64,e.status_code,e.source,e.tool,
                  o.method,r.id AS resource_id,r.url,r.path
           FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id WHERE e.id=?""",
        (exchange_id,),
    ).fetchone()
    if not row:
        return None
    surface = str(evidence.get("surface") or "response").lower()
    full = _safe_b64_text(row["request_b64"] if surface == "request" else row["response_b64"])
    _head, body = _split_http_message(full)
    target_fp = str(evidence.get("fingerprint") or "")
    match = None
    for candidate in regex.finditer(body[:1_500_000]):
        if not target_fp or _secret_fingerprint(candidate.group(0)) == target_fp:
            match = candidate
            break
    if not match:
        return {
            "exchange_id": exchange_id, "resource_id": int(row["resource_id"]),
            "method": str(row["method"] or ""), "url": str(row["url"] or ""),
            "path": str(row["path"] or ""), "surface": surface, "secret_type": stype,
            "label": label, "masked_value": str(evidence.get("masked_value") or ""),
            "fingerprint": target_fp, "pattern": regex.pattern, "match_found": False,
        }
    start, end = match.span()
    before_line = body.rfind("\n", 0, start)
    line = body.count("\n", 0, start) + 1
    column = start - before_line if before_line >= 0 else start + 1
    context = _masked_secret_context(body, start, end)
    low_context = context.lower()
    context_hint = ""
    if stype == "google_api_key" and ("google.maps" in low_context or "maps.googleapis.com" in low_context):
        context_hint = "La coincidencia aparece junto a configuración/código de Google Maps JavaScript API; una key client-side puede ser pública por diseño y debe validarse por restricciones e impacto."
    return {
        "exchange_id": exchange_id, "resource_id": int(row["resource_id"]),
        "method": str(row["method"] or ""), "url": str(row["url"] or ""),
        "path": str(row["path"] or ""), "status_code": row["status_code"],
        "source": str(row["source"] or ""), "tool": str(row["tool"] or ""),
        "surface": surface, "secret_type": stype, "label": label,
        "masked_value": _mask_value(match.group(0)), "fingerprint": _secret_fingerprint(match.group(0)),
        "pattern": regex.pattern, "body_offset": start, "body_line": line, "body_column": column,
        "context_snippet": context, "context_hint": context_hint, "match_found": True,
    }

def _json_fields(value: Any, prefix: str = "$") -> list[tuple[str, str, Any]]:
    out: list[tuple[str, str, Any]] = []
    if isinstance(value, dict):
        for k, v in value.items():
            path = f"{prefix}.{k}"
            out.append((str(k), path, v))
            out.extend(_json_fields(v, path))
    elif isinstance(value, list):
        for idx, v in enumerate(value[:250]):
            out.extend(_json_fields(v, f"{prefix}[{idx}]"))
    return out


def _request_parameters(req_head: str, req_body: str, request_ct: str, query_json: str | None) -> list[dict[str, str]]:
    """Extract observed parameter names/values without mutating traffic."""
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(name: Any, value: Any, where: str) -> None:
        n = str(name or "").strip()
        if not n:
            return
        v = str(value if value is not None else "")
        key = (n.lower(), v[:1000], where)
        if key in seen:
            return
        seen.add(key)
        found.append({"name": n, "value": v[:4000], "location": where})

    # Request line query is authoritative even when the bridge query metadata is absent.
    first = req_head.splitlines()[0] if req_head else ""
    parts = first.split()
    if len(parts) >= 2:
        try:
            q = urllib.parse.urlsplit(parts[1]).query
            for k, vals in urllib.parse.parse_qs(q, keep_blank_values=True).items():
                for v in vals:
                    add(k, v, "query")
        except Exception:
            pass
    try:
        qmeta = json.loads(query_json or "null")
    except Exception:
        qmeta = None
    if isinstance(qmeta, dict):
        for k, v in qmeta.items():
            if isinstance(v, list):
                for item in v:
                    add(k, item, "query")
            else:
                add(k, v, "query")
    elif isinstance(qmeta, str):
        for k, vals in urllib.parse.parse_qs(qmeta, keep_blank_values=True).items():
            for v in vals:
                add(k, v, "query")

    ct = (request_ct or "").lower()
    body = req_body[:1_000_000]
    if body:
        if "application/json" in ct or body.lstrip().startswith(("{", "[")):
            try:
                obj = json.loads(body)
                for k, path, v in _json_fields(obj):
                    if not isinstance(v, (dict, list)):
                        add(k, v, f"json:{path}")
            except Exception:
                pass
        if "application/x-www-form-urlencoded" in ct:
            try:
                for k, vals in urllib.parse.parse_qs(body, keep_blank_values=True).items():
                    for v in vals:
                        add(k, v, "form")
            except Exception:
                pass
        if "multipart/form-data" in ct:
            for m in re.finditer(r'name="([^"]+)"\r?\n(?:[^\r\n]*\r?\n)*\r?\n([^\r\n]{0,2000})', body, re.I):
                add(m.group(1), m.group(2), "multipart")
    return found


def _signal_category(kind: str) -> str:
    k = str(kind or "").lower()
    if any(x in k for x in ("idor", "access", "authorization", "referer", "proxy_path")):
        return "access_control"
    if any(x in k for x in ("oauth", "oidc", "jwt", "auth", "session")):
        return "authentication"
    if "cors" in k:
        return "cors"
    if any(x in k for x in ("redirect", "url")):
        return "url_handling"
    if "ssrf" in k:
        return "ssrf"
    if any(x in k for x in ("secret", "api_key", "credential")):
        return "secrets"
    if any(x in k for x in ("business", "price", "coupon", "payment", "state")):
        return "business_logic"
    return k or "other"


def _upsert_signal_occurrence(conn, *, signal_key: str, kind: str, severity: str, title: str, message: str,
                              source: str, resource_id: int | None, operation_id: int | None,
                              exchange_id: int | None, data: dict[str, Any] | None) -> None:
    if not exchange_id:
        return
    now = now_iso()
    dedupe = f"{signal_key}:exchange:{int(exchange_id)}"
    row = conn.execute("SELECT id FROM signal_occurrences WHERE dedupe_key=?", (dedupe,)).fetchone()
    why = {"message": message, "rule_match": (data or {}).get("rule_match")}
    evidence = dict(data or {})
    if row:
        conn.execute(
            """UPDATE signal_occurrences SET occurrences=occurrences+1,last_seen_at=?,severity=?,title=?,why_json=?,evidence_json=?,
               reconsideration_needed=CASE WHEN COALESCE(human_decision,'new')='dismissed' THEN 1 ELSE reconsideration_needed END WHERE id=?""",
            (now, severity, title, json.dumps(why, ensure_ascii=False), json.dumps(evidence, ensure_ascii=False), int(row["id"])),
        )
    else:
        conn.execute(
            """INSERT INTO signal_occurrences(dedupe_key,exchange_id,operation_id,resource_id,kind,category,severity,title,why_json,evidence_json,source,first_seen_at,last_seen_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (dedupe, int(exchange_id), operation_id, resource_id, kind, _signal_category(kind), severity, title,
             json.dumps(why, ensure_ascii=False), json.dumps(evidence, ensure_ascii=False), source, now, now),
        )


def _persist_parameter_observations(conn, *, exchange_id: int, operation_id: int, resource_id: int, params: list[dict[str, str]]) -> None:
    now = now_iso()
    for item in params:
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        value = str(item.get("value") or "")
        location = str(item.get("location") or "unknown")[:120]
        normalized = re.sub(r"[^a-z0-9_]", "", name.lower().replace("-", "_"))[:160] or name.lower()[:160]
        sensitive = any(tok in normalized for tok in ("password", "passwd", "secret", "token", "authorization", "session", "cookie", "apikey", "api_key"))
        clean = value.replace("\r", " ").replace("\n", " ")
        preview = _mask_value(value) if sensitive else (clean if len(clean) <= 120 else clean[:117] + "…")
        value_hash = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()
        conn.execute(
            """INSERT INTO parameter_observations(exchange_id,operation_id,resource_id,name,normalized_name,location,value_hash,value_preview,value_raw,first_seen_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(exchange_id,normalized_name,location,value_hash)
               DO UPDATE SET value_preview=excluded.value_preview,value_raw=excluded.value_raw""",
            (int(exchange_id), int(operation_id), int(resource_id), name[:240], normalized, location, value_hash, preview, value, now),
        )


def _upsert_notification(conn, *, dedupe_key: str, kind: str, severity: str, title: str, message: str,
                         source: str, entity_type: str | None = None, entity_id: int | None = None,
                         resource_id: int | None = None, operation_id: int | None = None,
                         exchange_id: int | None = None, data: dict[str, Any] | None = None,
                         emit: bool = True, signal_kind: str | None = None) -> tuple[int | None, bool]:
    if not emit:
        return None, False
    _upsert_signal_occurrence(
        conn, signal_key=dedupe_key, kind=(signal_kind or kind), severity=severity, title=title, message=message,
        source=source, resource_id=resource_id, operation_id=operation_id, exchange_id=exchange_id, data=data,
    )
    now = now_iso()
    row = conn.execute("SELECT id FROM notifications WHERE dedupe_key=?", (dedupe_key,)).fetchone()
    payload = json.dumps(data or {}, ensure_ascii=False)
    if row:
        nid = int(row["id"])
        conn.execute(
            """UPDATE notifications SET severity=?,title=?,message=?,source=?,entity_type=?,entity_id=?,resource_id=?,operation_id=?,exchange_id=?,data_json=?,occurrences=occurrences+1,last_seen_at=? WHERE id=?""",
            (severity, title, message, source, entity_type, entity_id, resource_id, operation_id, exchange_id, payload, now, nid),
        )
        return nid, False
    cur = conn.execute(
        """INSERT INTO notifications(dedupe_key,kind,severity,title,message,source,entity_type,entity_id,resource_id,operation_id,exchange_id,data_json,occurrences,first_seen_at,last_seen_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)""",
        (dedupe_key, kind, severity, title, message, source, entity_type, entity_id, resource_id, operation_id, exchange_id, payload, now, now),
    )
    return int(cur.lastrowid), True


def _notification_href(resource_id: int | None = None, exchange_id: int | None = None) -> str | None:
    if not resource_id:
        return None
    suffix = f"#exchange-{exchange_id}" if exchange_id else ""
    return f"resource/{resource_id}{suffix}"


def _safe_url_evidence(value: str) -> str:
    """Keep redirect destination/provenance useful without persisting secret query values."""
    raw = str(value or "")[:4000]
    if not raw:
        return ""
    try:
        p = urllib.parse.urlsplit(raw)
        if not p.scheme and not p.netloc:
            return raw[:500]
        pairs = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
        safe_pairs = []
        for k, v in pairs[:40]:
            if k.lower() in QUERY_SECRET_KEYS or any(x in k.lower() for x in ("secret", "token", "password", "passwd", "pwd", "key", "code")):
                safe_pairs.append((k, "[masked]"))
            else:
                safe_pairs.append((k, v[:120]))
        q = urllib.parse.urlencode(safe_pairs, doseq=True)
        return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, q, ""))[:500]
    except Exception:
        return raw[:500]


def analyze_http_exchange(conn, exchange_id: int, domain: str, *, emit_notifications: bool = True) -> dict[str, Any]:
    """Correlate one captured HTTP exchange into high-signal, low-cost clues.

    This routine is intentionally passive: it never sends a request.  It only reads
    the request/response Burp already captured, masks sensitive values, persists
    provenance, and creates leads/notifications that still require manual validation.
    """
    init_schema(conn)
    row = conn.execute(
        """SELECT e.*,o.method,o.resource_id,o.authenticated_observed,o.request_content_type,o.response_content_type,
                  r.url,r.path,r.host_id,h.hostname
           FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id WHERE e.id=?""",
        (exchange_id,),
    ).fetchone()
    if not row:
        return {"exchange_id": exchange_id, "signals": [], "new_notifications": []}

    req_text = _safe_b64_text(row["request_b64"])
    resp_text = _safe_b64_text(row["response_b64"])
    req_head, req_body = _split_http_message(req_text)
    resp_head, resp_body = _split_http_message(resp_text)
    req_headers = _header_map(row["request_headers_json"])
    resp_headers = _header_map(row["response_headers_json"])
    request_ct = str(row["request_content_type"] or req_headers.get("content-type") or "")
    response_ct = str(row["response_content_type"] or resp_headers.get("content-type") or "")
    params = _request_parameters(req_head, req_body, request_ct, row["query_json"])
    # v0.22: response scalar fields also become parameter observations so Follow
    # Value can trace a business object from a response into later requests.
    try:
        import negro_parameters as parameter_tools
        params.extend(parameter_tools._path_parameters(req_head))
        response_params = parameter_tools._response_parameters(resp_body, response_ct)
    except Exception:
        response_params = []
    pmap: dict[str, list[dict[str, str]]] = {}
    for p in params:
        pmap.setdefault(p["name"].lower(), []).append(p)

    signals: list[dict[str, Any]] = []
    new_notifications: list[int] = []
    rid, oid, hid = int(row["resource_id"]), int(row["operation_id"]), int(row["host_id"])
    method, path, url = str(row["method"]), str(row["path"]), str(row["url"])
    _persist_parameter_observations(conn, exchange_id=exchange_id, operation_id=oid, resource_id=rid, params=params + response_params)

    def notify(*, kind: str, key: str, severity: str, title: str, message: str, data: dict[str, Any]) -> None:
        nid, created = _upsert_notification(
            conn, dedupe_key=key, kind=kind, severity=severity, title=title, message=message,
            source=str(row["source"] or "burp"), entity_type="resource", entity_id=rid,
            resource_id=rid, operation_id=oid, exchange_id=exchange_id,
            data={**data, "href": data.get("href") or _notification_href(rid, exchange_id)}, emit=emit_notifications,
        )
        signals.append({"kind": kind, "severity": severity, "title": title, **data})
        if created and nid:
            new_notifications.append(nid)

    def notify_new_lead(result: tuple[int, bool], *, lead_type: str, title: str, priority: str,
                        message: str, data: dict[str, Any] | None = None) -> None:
        """Compatibility shim: deterministic rules surface Signals, never user-facing hypotheses.

        Older code paths may still persist an internal leads_v2 row so existing workspaces
        remain readable, but Hunt no longer treats ENGINE rows as hypotheses.  The visible
        output of a rule match is only a Signal tied to the exact exchange.
        """
        _lead_id, _created = result
        severity = "high" if priority == "high" else "medium" if priority == "medium" else "low"
        payload = {
            "lead_type": lead_type,
            "href": _notification_href(rid, exchange_id),
            **(data or {}),
        }
        nid, made = _upsert_notification(
            conn,
            dedupe_key=f"signal:rule:{lead_type}:{exchange_id}",
            kind="signal",
            severity=severity,
            title=title,
            message=message,
            source="engine",
            entity_type="resource",
            entity_id=rid,
            resource_id=rid,
            operation_id=oid,
            exchange_id=exchange_id,
            data=payload,
            emit=emit_notifications,
            signal_kind=lead_type,
        )
        signals.append({"kind": lead_type, "severity": severity, "title": title, **payload})
        if made and nid:
            new_notifications.append(nid)

    # v0.19 rule helpers.  Every detector exposes the exact rules that created a
    # clue.  The same effective rule set is shown in Settings -> Detector.
    def _loc_base(value: str) -> str:
        raw = str(value or "").lower()
        return "json" if raw.startswith("json:") else raw

    def _norm_name(value: str) -> str:
        return re.sub(r"[^a-z0-9_]", "", str(value or "").lower().replace("-", "_"))

    def _compact(value: str) -> str:
        return re.sub(r"[^a-z0-9]", "", str(value or "").lower())

    def _allowed_parameter_names(detector_id: str, key_list: str, location_list: str = "locations") -> set[str]:
        cfg = detector_settings(detector_id, conn)
        keys = {_compact(x) for x in rulebook.rule_list(cfg, key_list)}
        locations = {x.lower() for x in rulebook.rule_list(cfg, location_list)}
        found: set[str] = set()
        for name, items in pmap.items():
            if _compact(name) not in keys:
                continue
            if not locations or any(_loc_base(item.get("location", "")) in locations for item in items):
                found.add(name)
        return found

    # 1) Redirect parameters observed in query/form/JSON from Burp.
    redirect_cfg = detector_settings("open_redirect", conn)
    redirect_names = _allowed_parameter_names("open_redirect", "parameter_keys") if redirect_cfg.get("enabled") else set()
    redirect_strong = {_compact(x) for x in rulebook.rule_list(redirect_cfg, "strong_parameter_keys")}
    nav_tokens = [x.lower() for x in rulebook.rule_list(redirect_cfg, "navigation_path_tokens")]
    navigation_route = any(tok in path.lower() for tok in nav_tokens)
    has_location_header = bool(resp_headers.get("location", ""))
    redirect_hits: list[str] = []
    for name in sorted(redirect_names):
        is_strong_name = _compact(name) in redirect_strong
        if rulebook.rule_bool(redirect_cfg, "require_context_for_ambiguous_keys", True) and not is_strong_name and not (navigation_route or has_location_header):
            continue
        redirect_hits.append(name)
    for name in redirect_hits:
        examples = pmap[name]
        locs = sorted({_loc_base(x["location"]) for x in examples})
        value = next((x["value"] for x in examples if x["value"]), "")
        value_host = ""
        try:
            if value.startswith(("http://", "https://", "//")):
                value_host = urllib.parse.urlsplit(value if not value.startswith("//") else "https:" + value).hostname or ""
        except Exception:
            pass
        response_location = resp_headers.get("location", "")
        external_location = False
        response_host = ""
        try:
            lp = urllib.parse.urlsplit(response_location)
            response_host = (lp.hostname or "").lower()
            external_location = bool(response_host and response_host != str(row["hostname"]).lower())
        except Exception:
            pass
        strong = bool(external_location and (not value_host or response_host == value_host.lower()))
        if rulebook.rule_bool(redirect_cfg, "require_external_location", False) and not strong:
            continue
        priority = "high" if strong else "medium"
        confidence = "high" if strong else "medium"
        ev = {"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,"parameter":name,"locations":locs,
              "value_example":_mask_value(value) if value else "(vacío)","response_location":_safe_url_evidence(response_location) if response_location else None,
              "rule_match":{"parameter_key":name,"external_location":strong}}
        upsert_lead(
            conn, lead_key=f"open_redirect_burp:{oid}:{name}", host_id=hid, resource_id=rid,
            lead_type="open_redirect", title=f"Posible Open Redirect · {name}", confidence=confidence, review_priority=priority,
            evidence=[ev],
            why=f"Burp observó el parámetro '{name}' en {', '.join(locs)} de {method} {path}. La regla editable de Open Redirect lo reconoce como posible controlador de navegación.",
            next_test=f"Abre el exchange #{exchange_id} en Repeater y cambia sólo '{name}' por una URL HTTPS controlada. Observa Location o navegación final y conserva el resto idéntico.",
            confirm_if="La aplicación termina redirigiendo/navegando a un dominio externo controlado sin una allowlist efectiva.",
            discard_if="El valor se limita a rutas internas, se ignora, se normaliza o existe una allowlist estricta.",
        )
        notify(kind="open_redirect", key=f"open_redirect:{oid}:{name}", severity="high" if strong else "medium",
               title=f"Parámetro de navegación observado · {name}",
               message=f"{method} {path} · regla '{name}' coincidió en {', '.join(locs)} · exchange #{exchange_id}", data=ev)

    # 2) URL-fetch / SSRF surfaces from actual parameters. Avoid duplicate redirect-only clues.
    ssrf_cfg = detector_settings("ssrf_surface", conn)
    ssrf_names = _allowed_parameter_names("ssrf_surface", "parameter_keys") if ssrf_cfg.get("enabled") else set()
    ssrf_names -= set(redirect_hits)
    ssrf_path_tokens = [x.lower() for x in rulebook.rule_list(ssrf_cfg, "server_fetch_path_tokens")]
    for name in sorted(ssrf_names):
        candidates = [x for x in pmap[name] if str(x["value"]).lower().startswith(("http://", "https://", "//"))]
        fallback = [x for x in pmap[name] if str(x.get("value") or "").strip()]
        if rulebook.rule_bool(ssrf_cfg, "require_absolute_url", True) and not candidates:
            continue
        if rulebook.rule_bool(ssrf_cfg, "require_server_fetch_path_token", False) and not any(tok in path.lower() for tok in ssrf_path_tokens):
            continue
        if not candidates and not fallback:
            continue
        sample = (candidates or fallback)[0]
        ev = {"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,"parameter":name,"location":_loc_base(sample["location"]),"value_example":_mask_value(sample["value"]),
              "rule_match":{"parameter_key":name,"absolute_url":bool(candidates)}}
        upsert_lead(conn, lead_key=f"ssrf_burp:{oid}:{name}", host_id=hid, resource_id=rid,
            lead_type="ssrf_surface", title=f"URL controlable observada · {name}", confidence="medium", review_priority="medium",
            evidence=[ev], why=f"Burp vio un valor URL-like controlado por el parámetro '{name}'. La regla sólo identifica superficie; falta demostrar que el servidor lo consume.",
            next_test=f"Revisa el flujo de {method} {path}. Si existe evidencia de fetch server-side y el scope lo permite, usa únicamente un endpoint propio como marcador benigno.",
            confirm_if="El servidor realiza una solicitud saliente hacia una URL controlada por el usuario.",
            discard_if="El valor sólo se usa client-side, se valida por allowlist o no provoca tráfico saliente.")
        notify(kind="url_fetch", key=f"url_fetch:{oid}:{name}", severity="medium", title=f"URL controlable en {method} {path}",
               message=f"La regla SSRF reconoció '{name}' en {_loc_base(sample['location'])}; revisa si existe consumo server-side.", data=ev)

    # 3) Secrets/config signatures in captured request/response. Never persist the raw secret.
    secret_cfg = detector_settings("secret_candidate", conn)
    enabled_secret_types = {x.lower() for x in rulebook.rule_list(secret_cfg, "secret_types")}
    text_surfaces: list[tuple[str, str]] = []
    if secret_cfg.get("enabled"):
        if rulebook.rule_bool(secret_cfg, "inspect_response", True):
            text_surfaces.append(("response", resp_body))
        if rulebook.rule_bool(secret_cfg, "inspect_request", True):
            text_surfaces.append(("request", req_body))
    for surface, text in text_surfaces:
        if not text:
            continue
        for stype, label, regex, severity in SECRET_PATTERNS:
            if enabled_secret_types and stype.lower() not in enabled_secret_types:
                continue
            for match in list(regex.finditer(text[:1_500_000]))[:8]:
                value = match.group(0)
                fp = _secret_fingerprint(value)
                start, end = match.span()
                before_line = text.rfind("\n", 0, start)
                line = text.count("\n", 0, start) + 1
                column = start - before_line if before_line >= 0 else start + 1
                context = _masked_secret_context(text, start, end)
                low_context = context.lower()
                context_hint = ""
                if stype == "google_api_key" and ("google.maps" in low_context or "maps.googleapis.com" in low_context):
                    context_hint = "La coincidencia aparece junto a configuración/código de Google Maps JavaScript API; una key client-side puede ser pública por diseño y debe validarse por restricciones e impacto."
                ev = {"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,"surface":surface,
                      "secret_type":stype,"masked_value":_mask_value(value),"fingerprint":fp,
                      "pattern":regex.pattern,"body_offset":start,"body_line":line,"body_column":column,
                      "context_snippet":context,"context_hint":context_hint,
                      "rule_match":{"secret_type":stype}}
                upsert_lead(conn, lead_key=f"burp_secret:{stype}:{fp}", host_id=hid, resource_id=rid,
                    lead_type="secret_or_client_config", title=f"{label} observada en tráfico HTTP", confidence="high", review_priority=severity,
                    evidence=[ev], why=f"Burp observó una señal de {label} en el {surface} de {method} {path}. La familia '{stype}' está habilitada en tu Knowledge Base.",
                    next_test="Valida el tipo de credencial/configuración de forma mínima, revisa restricciones de origen/API/rol y no ejecutes acciones destructivas.",
                    confirm_if="La credencial/configuración es activa y permite un uso no autorizado o expone capacidad no prevista.",
                    discard_if="Es configuración pública esperada, está correctamente restringida, es un fixture o no tiene impacto demostrable.")
                surface_label = "respuesta" if surface == "response" else "solicitud"
                notify(kind="secret_candidate", key=f"secret:{stype}:{fp}:host:{hid}", severity=severity,
                       title=f"{label} detectada en {surface_label}", message=f"{method} {path} · regla {stype} · exchange #{exchange_id} · valor {_mask_value(value)}", data=ev)

    # Parse JSON once.  Several detectors (sensitive response, mass assignment,
    # redirect body) reuse the same structured evidence even if one detector is disabled.
    response_obj: Any = None
    body_trim = resp_body.lstrip()
    if (body_trim.startswith(("{", "[")) or "json" in response_ct.lower()) and len(resp_body) <= 2_000_000:
        try:
            response_obj = json.loads(resp_body)
        except Exception:
            response_obj = None
    fields = _json_fields(response_obj) if response_obj is not None else []

    # 4) Structured credential-like fields returned by APIs.
    response_cfg = detector_settings("sensitive_response", conn)
    sensitive_keys = {_compact(x) for x in rulebook.rule_list(response_cfg, "sensitive_keys")}
    identity_keys = {_compact(x) for x in rulebook.rule_list(response_cfg, "identity_keys")}
    identity_present = any(_compact(k) in identity_keys and not isinstance(v, (dict, list)) and str(v or "").strip() for k, _, v in fields)
    if response_cfg.get("enabled") and (not rulebook.rule_bool(response_cfg, "require_identity_context", False) or identity_present):
        for key, jpath, value in fields:
            kl = _compact(key)
            if kl not in sensitive_keys:
                continue
            if isinstance(value, list):
                if value:
                    fp = _secret_fingerprint(json.dumps(value, sort_keys=True, default=str))
                    ev = {"source":"burp_response_json","exchange_id":exchange_id,"method":method,"url":url,"json_path":jpath,"field":key,
                          "masked_value":f"[{len(value)} valores enmascarados]","fingerprint":fp,"identity_context":identity_present,"rule_match":{"sensitive_key":key}}
                    upsert_lead(conn, lead_key=f"burp_response_secret:{rid}:{jpath}:{fp}", host_id=hid, resource_id=rid,
                        lead_type="sensitive_response", title=f"Campo sensible devuelto · {key}", confidence="high", review_priority="medium",
                        evidence=[ev], why=f"La respuesta de {method} {path} entrega '{key}', nombre incluido en tus reglas de campos sensibles. Negro no guardó los valores.",
                        next_test="Confirma si esos valores son reutilizables o si exponerlos al cliente amplía acceso. Trabaja sólo con tu propia cuenta/datos autorizados.",
                        confirm_if="Los valores permiten reutilizar una credencial/sesión o acceder a contexto que el cliente no debería recibir.",
                        discard_if="Son identificadores no sensibles, están rotados/ligados correctamente o su entrega al cliente es necesaria sin impacto adicional.")
                    notify(kind="sensitive_response", key=f"sensitive_response:{rid}:{jpath}:{fp}", severity="medium",
                           title=f"Campo sensible devuelto · {key}", message=f"{method} {path} · regla '{key}' · {jpath}", data=ev)
                continue
            if isinstance(value, dict) or not str(value or "").strip():
                continue
            value_s = str(value)
            if value_s.lower() in {"null", "none", "false", "true", "***", "*****", "redacted", "masked"} or len(value_s) < 4:
                continue
            high_keys = {"password","passwd","pwd","pass","clientsecret","privatekey","secretkey"}
            medium_keys = {"apikey","secret","accesskey","token","authtoken","sessiontoken","session","sessionid","authorization"}
            severity = "high" if kl in high_keys else "medium" if kl in medium_keys else "info"
            fp = _secret_fingerprint(value_s)
            ev = {"source":"burp_response_json","exchange_id":exchange_id,"method":method,"url":url,"json_path":jpath,"field":key,
                  "masked_value":_mask_value(value_s),"fingerprint":fp,"identity_context":identity_present,"rule_match":{"sensitive_key":key}}
            auth_path = any(x in path.lower() for x in ("oauth", "token", "login", "auth", "session"))
            if kl in {"accesstoken","refreshtoken"} and auth_path and severity == "info":
                continue
            title = "Posibles credenciales devueltas por la API" if identity_present and kl in high_keys else f"Campo sensible devuelto · {key}"
            upsert_lead(conn, lead_key=f"burp_response_secret:{rid}:{jpath}:{fp}", host_id=hid, resource_id=rid,
                lead_type="sensitive_response", title=title, confidence="high", review_priority=severity if severity in {"high","medium"} else "low",
                evidence=[ev], why=f"La respuesta de {method} {path} contiene el campo '{key}', que tu regla considera sensible. Negro guardó sólo una versión enmascarada.",
                next_test="Confirma si el valor pertenece al usuario actual, si era necesario devolverlo al cliente y si puede reutilizarse fuera de este flujo. Usa únicamente cuentas/datos autorizados.",
                confirm_if="La API devuelve una credencial/secreto reutilizable que el cliente no debería recibir o que permite acceso/capacidad adicional.",
                discard_if="El valor es público por diseño, está enmascarado/no reutilizable o su exposición es necesaria y no agrega capacidad.")
            notify(kind="sensitive_response", key=f"sensitive_response:{rid}:{jpath}:{fp}", severity=severity,
                   title=title, message=f"{method} {path} · regla '{key}' · {jpath} · exchange #{exchange_id}", data=ev)

    # Passwords/tokens in URL query are a distinct leak clue.
    url_cfg = detector_settings("sensitive_url", conn)
    sensitive_query_keys = {_compact(x) for x in rulebook.rule_list(url_cfg, "query_keys")}
    sensitive_url_names = {name for name in pmap if _compact(name) in sensitive_query_keys} if url_cfg.get("enabled") else set()
    for name in sorted(sensitive_url_names):
        for item in pmap[name]:
            if _loc_base(item["location"]) != "query":
                continue
            if rulebook.rule_bool(url_cfg, "require_nonempty_value", True) and not item["value"]:
                continue
            fp = _secret_fingerprint(item["value"])
            ev = {"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,"parameter":name,"location":"query","masked_value":_mask_value(item["value"]),"fingerprint":fp,"rule_match":{"query_key":name}}
            notify(kind="secret_in_url", key=f"secret_url:{oid}:{name}:{fp}", severity="high",
                   title=f"Dato sensible en la URL · {name}", message=f"{method} {path} incluye una regla sensible '{name}' en query.", data=ev)
            upsert_lead(conn, lead_key=f"secret_url:{oid}:{name}:{fp}", host_id=hid, resource_id=rid,
                lead_type="sensitive_url", title=f"Dato sensible en query · {name}", confidence="high", review_priority="high", evidence=[ev],
                why=f"'{name}' está incluido en tu Knowledge Base de secretos en URL. Si contiene una credencial real puede quedar expuesta en logs, historial, proxies y Referer.",
                next_test="Confirma el flujo y si el valor aparece en URLs/logs o se propaga a terceros. No reutilices credenciales ajenas.",
                confirm_if="El secreto real queda expuesto a componentes/personas que no deberían recibirlo.",
                discard_if="El parámetro no contiene un secreto real o el valor es un identificador público/no sensible.")
            break

    # 5) Passive CORS evidence already present in the captured exchange.
    cors_cfg = detector_settings("cors", conn)
    origin = req_headers.get("origin", "")
    acao = resp_headers.get("access-control-allow-origin", "")
    acac = resp_headers.get("access-control-allow-credentials", "").lower() == "true"
    reflection_ok = (acao == origin) if rulebook.rule_bool(cors_cfg, "require_exact_reflection", True) else bool(acao)
    if cors_cfg.get("enabled") and origin and acao and reflection_ok:
        try:
            origin_host = urllib.parse.urlsplit(origin).hostname or ""
        except Exception:
            origin_host = ""
        origin_host = origin_host.lower().rstrip(".")
        response_host = str(row["hostname"] or "").lower().rstrip(".")
        project_scopes = project_scopes_from_conn(conn, domain)
        cross_origin = bool(origin_host and origin_host != response_host)
        known_origin_host = bool(origin_host and conn.execute("SELECT 1 FROM hosts WHERE lower(hostname)=? LIMIT 1", (origin_host,)).fetchone())
        target_first_party = host_in_project_scope(origin_host, project_scopes)
        ignore_origins = {x.lower().rstrip("/") for x in rulebook.rule_list(cors_cfg, "ignore_origins")}
        trusted_suffixes = [x.lower().lstrip("*").lstrip(".") for x in rulebook.rule_list(cors_cfg, "trusted_origin_suffixes") if x.strip()]
        origin_normalized = origin.lower().rstrip("/")
        trusted_manual = origin_normalized in ignore_origins or any(origin_host == suf or origin_host.endswith("." + suf) for suf in trusted_suffixes)
        first_party = (known_origin_host or target_first_party) if rulebook.rule_bool(cors_cfg, "ignore_project_scopes", True) else False
        if cross_origin and (first_party or trusted_manual):
            stale_key=f"cors_burp:{rid}:{origin}"
            conn.execute(
                """UPDATE leads_v2 SET status='negative',result_notes=CASE WHEN COALESCE(result_notes,'')='' THEN ? ELSE result_notes END,updated_at=?
                   WHERE lead_key=? AND status IN ('candidate','testing','interesting','postponed')""",
                ("Origin reconocido como first-party/confiable por las reglas del proyecto; no se prioriza como CORS arbitrario.", now_iso(), stale_key),
            )
            conn.execute("UPDATE notifications SET read_at=COALESCE(read_at,?) WHERE dedupe_key=?", (now_iso(), f"cors_passive:{rid}:{origin}"))
        else:
            external_ok = cross_origin if rulebook.rule_bool(cors_cfg, "require_external_origin", True) else True
            creds_ok = acac if rulebook.rule_bool(cors_cfg, "require_credentials", False) else True
            auth_ok = bool(row["authenticated_observed"]) if rulebook.rule_bool(cors_cfg, "require_authenticated", False) else True
            if external_ok and creds_ok and auth_ok:
                ev = {"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,"origin":origin,"allow_origin":acao,"allow_credentials":acac,
                      "rule_match":{"external_origin":cross_origin,"exact_reflection":acao==origin,"credentials":acac,"authenticated":bool(row["authenticated_observed"])}}
                pri = "high" if acac and bool(row["authenticated_observed"]) else "medium"
                upsert_lead(conn, lead_key=f"cors_burp:{rid}:{origin}", host_id=hid, resource_id=rid,
                    lead_type="cors", title="CORS cross-origin observado en tráfico real", confidence="high", review_priority=pri,
                    evidence=[ev], why="La respuesta coincide con las condiciones CORS que configuraste. La señal NO demuestra explotación: falta probar si un origin no confiable puede leer datos sensibles en navegador.",
                    next_test="Repite con un Origin HTTPS controlado y verifica si el navegador puede leer una respuesta autenticada sensible.",
                    confirm_if="Un origen externo arbitrario puede leer una respuesta autenticada sensible.",
                    discard_if="El Origin está allowlisted de forma esperada, no hay credenciales/datos sensibles o un origen arbitrario es rechazado.")
                notify(kind="cors", key=f"cors_passive:{rid}:{origin}", severity=pri,
                       title="CORS cross-origin observado", message=f"{method} {path} cumplió tus reglas CORS · Origin {origin} · credentials={str(acac).lower()}", data=ev)

    # 6) High-signal exposed surfaces and verbose errors in actual responses.
    low_path = path.lower()
    status = int(row["status_code"] or 0)
    api_cfg = detector_settings("api_docs", conn)
    api_tokens = [x.lower() for x in rulebook.rule_list(api_cfg, "path_tokens")]
    api_status_ok = (status and status < 400) if rulebook.rule_bool(api_cfg, "require_success_status", True) else True
    if api_cfg.get("enabled") and api_status_ok and any(x in low_path for x in api_tokens):
        ev = {"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,"status":status,"rule_match":{"path_token":next((x for x in api_tokens if x in low_path),None)}}
        notify(kind="api_docs", key=f"api_docs:{rid}", severity="medium", title="Documentación API observada", message=f"{method} {path} respondió HTTP {status} y coincide con tus rutas API-docs.", data=ev)

    sm_cfg = detector_settings("source_map", conn)
    sm_suffixes = [x.lower() for x in rulebook.rule_list(sm_cfg, "path_suffixes")]
    sm_status_ok = (status and status < 400) if rulebook.rule_bool(sm_cfg, "require_success_status", True) else True
    if sm_cfg.get("enabled") and sm_status_ok and any(low_path.endswith(x) for x in sm_suffixes):
        ev = {"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,"status":status,"rule_match":{"suffix":next((x for x in sm_suffixes if low_path.endswith(x)),None)}}
        upsert_lead(conn, lead_key=f"sourcemap_burp:{rid}", host_id=hid, resource_id=rid, lead_type="source_map", title="Source map observado desde Burp", confidence="high", review_priority="medium", evidence=[ev],
            why="La URL coincide con una regla de source map. Un source map público puede revelar código original, rutas y configuración; la exposición sola no implica vulnerabilidad.", next_test="Ábrelo y analiza fuentes/configuración sin asumir que la exposición sola sea una vulnerabilidad.", confirm_if="El mapa revela secretos, rutas sensibles o una cadena de impacto adicional.", discard_if="Sólo contiene código público esperado sin información sensible ni impacto.")
        notify(kind="source_map", key=f"source_map:{rid}", severity="medium", title="Source map accesible", message=f"{method} {path} · HTTP {status}", data=ev)

    error_cfg = detector_settings("error_disclosure", conn)
    enabled_error_types = {x.lower() for x in rulebook.rule_list(error_cfg, "enabled_pattern_types")}
    error_patterns = [
        ("stack_trace", r"(?:Traceback \(most recent call last\)|\bException in thread\b|\bat [a-zA-Z0-9_.$]+\([^\n]+:\d+\)|System\.[A-Za-z.]+Exception)"),
        ("sql_error", r"(?:SQL syntax.*MySQL|ORA-\d{4,5}|PostgreSQL.*ERROR|SQLite(?:3)?::|Unclosed quotation mark after the character string)"),
        ("internal_path", r"(?:/home/[A-Za-z0-9_.-]+/|/var/www/|[A-Za-z]:\\\\(?:Users|inetpub|wwwroot)\\)"),
    ]
    custom_error_patterns = [("custom_regex", x) for x in rulebook.rule_list(error_cfg, "custom_regex")]
    if error_cfg.get("enabled"):
        for etype, pattern in error_patterns + custom_error_patterns:
            if etype != "custom_regex" and enabled_error_types and etype not in enabled_error_types:
                continue
            try:
                matched = bool(resp_body and re.search(pattern, resp_body[:700_000], re.I))
            except re.error:
                matched = False
            if matched:
                ev = {"source":"burp_response","exchange_id":exchange_id,"method":method,"url":url,"error_type":etype,"status":status,"rule_match":{"pattern_type":etype}}
                notify(kind="error_disclosure", key=f"error_disclosure:{etype}:{rid}:{hashlib.sha1(pattern.encode()).hexdigest()[:8]}", severity="medium", title="Detalle interno en respuesta", message=f"{method} {path} coincide con una regla de {etype.replace('_',' ')} · exchange #{exchange_id}", data=ev)

    # 7) Access Control Intelligence — explicit editable rules.
    object_cfg = detector_settings("access_object_reference", conn)
    object_key_compact = {_compact(x) for x in rulebook.rule_list(object_cfg, "identifier_keys")}
    object_suffixes = [_compact(x) for x in rulebook.rule_list(object_cfg, "identifier_suffixes") if _compact(x)]
    object_ignore = {_compact(x) for x in rulebook.rule_list(object_cfg, "ignore_keys")}
    identifier_prov=(object_cfg.get("provenance") or {}).get("identifier_keys") or {}
    object_ignore |= {_compact(x) for x in (identifier_prov.get("excluded_personal") or [])}
    object_ignore |= {_compact(x) for x in (identifier_prov.get("excluded_project") or [])}
    object_locations = {x.lower() for x in rulebook.rule_list(object_cfg, "locations")}
    object_hits: list[str] = []
    object_match_details: list[dict[str, Any]] = []
    if object_cfg.get("enabled"):
        for name, items in pmap.items():
            compact = _compact(name)
            if compact in object_ignore:
                continue
            locations=sorted({_loc_base(item.get("location", "")) for item in items})
            if object_locations and not any(loc in object_locations for loc in locations):
                continue
            reason=None
            if compact in object_key_compact:
                exact_value=next((x for x in rulebook.rule_list(object_cfg,"identifier_keys") if _compact(x)==compact),name)
                reason=f"exact:{exact_value}"
            else:
                matched_suffix=next((x for x in rulebook.rule_list(object_cfg,"identifier_suffixes") if _compact(x) and compact.endswith(_compact(x))),None)
                if matched_suffix:
                    reason=f"suffix:{matched_suffix}"
            if reason:
                object_hits.append(name)
                object_match_details.append({"name":name,"reason":reason,"locations":locations})
    numeric_path = bool(re.search(r"/(?:\d{1,18})(?:/|$|[?#])", path)) if rulebook.rule_bool(object_cfg, "detect_numeric_path", True) else False
    uuid_path = bool(re.search(r"/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?:/|$|[?#])", path, re.I)) if rulebook.rule_bool(object_cfg, "detect_uuid_path", True) else False
    path_has_object = numeric_path or uuid_path
    object_auth_ok = bool(row["authenticated_observed"]) if rulebook.rule_bool(object_cfg, "require_authenticated", True) else True
    if object_cfg.get("enabled") and (object_hits or path_has_object) and object_auth_ok:
        evidence = [{"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,
                     "object_parameters":sorted(object_hits)[:8],"path_identifier":path_has_object,
                     "rule_match":{"parameter_matches":object_match_details[:8],"numeric_path":numeric_path,"uuid_path":uuid_path}}]
        object_priority = "high" if method in {"PUT","PATCH","DELETE"} else "medium"
        lead_result = upsert_lead(conn, lead_key=f"access_object:{oid}", host_id=hid, resource_id=rid,
            lead_type="access_object_reference", title="Objeto referenciado por el cliente · revisar autorización horizontal",
            confidence="medium", review_priority=object_priority, evidence=evidence,
            why="La operación coincide con tus reglas de identificador de objeto. Eso no demuestra IDOR; indica dónde comparar ownership/tenant/rol entre identidades autorizadas.",
            next_test="Envía el exchange a Repeater y compara exactamente la misma operación con un objeto perteneciente a tu segunda cuenta de prueba. Mantén constante todo salvo identidad/ID y evita tocar datos de terceros.",
            confirm_if="Una identidad puede leer o modificar un objeto que pertenece a otra identidad sin autorización equivalente.",
            discard_if="El backend valida ownership/tenant/rol de forma consistente o el identificador sólo referencia datos públicos.")
        notify_new_lead(lead_result, lead_type="access_object_reference", title="Referencia de objeto controlada por el cliente",
                        priority=object_priority, message=f"{method} {path} coincidió con regla(s) de objeto: {', '.join(sorted(object_hits)[:5]) or 'ID en path'}.",
                        data={"object_parameters": sorted(object_hits)[:8]})

    # Mass assignment: configurable privileged vocabulary.
    response_field_names = {_norm_name(k) for k, _, _ in fields}
    compact_param_keys = {_compact(k) for k in pmap}
    mass_cfg = detector_settings("mass_assignment", conn)
    privileged_compact = {_compact(x) for x in rulebook.rule_list(mass_cfg, "privileged_keys")}
    ignored_mass = {_compact(x) for x in rulebook.rule_list(mass_cfg, "ignore_keys")}
    mass_methods = {x.upper() for x in rulebook.rule_list(mass_cfg, "methods")}
    hidden_privileged = sorted({
        k for k in response_field_names
        if _compact(k) in privileged_compact and _compact(k) not in ignored_mass
        and (not rulebook.rule_bool(mass_cfg, "require_response_only", True) or _compact(k) not in compact_param_keys)
    })
    mass_auth_ok = bool(row["authenticated_observed"]) if rulebook.rule_bool(mass_cfg, "require_authenticated", True) else True
    if mass_cfg.get("enabled") and method.upper() in mass_methods and hidden_privileged and mass_auth_ok:
        ev = {"source":"burp_access_control","exchange_id":exchange_id,"method":method,"url":url,
              "response_only_privileged_fields":hidden_privileged[:10],"rule_match":{"privileged_fields":hidden_privileged[:10]}}
        strong_fields={"role","roleid","isadmin","admin","permission","permissions","ownerid","privilege","privileges"}
        mass_priority = "high" if any(_compact(x) in strong_fields for x in hidden_privileged) else "medium"
        lead_result = upsert_lead(conn, lead_key=f"mass_assignment_fields:{oid}", host_id=hid, resource_id=rid,
            lead_type="mass_assignment", title="Campos privilegiados visibles pero no editados por la interfaz",
            confidence="medium", review_priority=mass_priority,
            evidence=[ev], why="La respuesta contiene campos que TU regla clasifica como privilegiados y que no aparecieron en el request observado. Eso es una pista de binder/model demasiado amplio, no una confirmación.",
            next_test=f"En Repeater, conserva el request original y prueba uno de estos campos observados: {', '.join(hidden_privileged[:6])}. Cambia sólo datos de tu propia cuenta/objeto y verifica el estado server-side después.",
            confirm_if="El backend acepta modificar un campo privilegiado que la identidad actual no debería controlar y el cambio produce capacidad adicional.",
            discard_if="El backend ignora/rechaza esos campos o revalida autorización antes de aplicar cambios sensibles.")
        notify_new_lead(lead_result, lead_type="mass_assignment", title="Campos privilegiados observados fuera del request",
                        priority=mass_priority, message=f"{method} {path} coincidió con campo(s) privilegiados configurados: {', '.join(hidden_privileged[:5])}.",
                        data={"fields": hidden_privileged[:10]})

    # Same resource observed with multiple verbs.
    method_cfg = detector_settings("method_access_control", conn)
    ignored_methods={x.upper() for x in rulebook.rule_list(method_cfg, "ignore_methods")}
    state_methods={x.upper() for x in rulebook.rule_list(method_cfg, "state_changing_methods")}
    sibling_methods = [str(x["method"]).upper() for x in conn.execute("SELECT method FROM resource_operations WHERE resource_id=? ORDER BY method", (rid,)).fetchall()]
    observed_methods={x for x in sibling_methods if x not in ignored_methods}
    method_trigger=len(observed_methods)>=2
    if rulebook.rule_bool(method_cfg, "require_state_changing", True):
        method_trigger = method_trigger and bool(observed_methods & state_methods)
    if rulebook.rule_bool(method_cfg, "require_authenticated", False):
        method_trigger = method_trigger and bool(row["authenticated_observed"])
    if rulebook.rule_bool(method_cfg, "require_two_successful_methods", False) and method_trigger:
        success_methods={str(x["method"]).upper() for x in conn.execute("SELECT DISTINCT o.method FROM resource_operations o JOIN http_exchanges e ON e.operation_id=o.id WHERE o.resource_id=? AND e.status_code BETWEEN 200 AND 399",(rid,)).fetchall() if str(x["method"]).upper() not in ignored_methods}
        method_trigger=len(success_methods)>=2 and (not rulebook.rule_bool(method_cfg, "require_state_changing", True) or bool(success_methods & state_methods))
    if method_cfg.get("enabled") and method_trigger:
        ev = {"source":"burp_http_model","exchange_id":exchange_id,"url":url,"methods":sorted(observed_methods),"rule_match":{"methods":sorted(observed_methods),"state_changing":sorted(observed_methods & state_methods)}}
        lead_result = upsert_lead(conn, lead_key=f"method_auth:{rid}", host_id=hid, resource_id=rid,
            lead_type="method_access_control", title="Mismo recurso observado con varios métodos HTTP",
            confidence="medium", review_priority="medium", evidence=[ev],
            why="El recurso cumple tus reglas de comparación por método. Distintas rutas de código/middleware pueden aplicar controles diferentes; todavía falta preservar la intención de negocio y validar autorización.",
            next_test="Compara la misma intención de negocio con los métodos observados. Si conviertes POST/JSON a GET, mueve los parámetros equivalentes al query string; cambiar sólo el verbo puede producir una petición incompleta y un falso negativo.",
            confirm_if="La misma acción/estado puede alcanzarse mediante un método con controles de autorización más débiles.",
            discard_if="Los métodos tienen semánticas distintas o todos aplican autorización equivalente.")
        notify_new_lead(lead_result, lead_type="method_access_control", title="Mismo recurso observado con varios métodos",
                        priority="medium", message=f"{path} coincidió con tus reglas de métodos: {', '.join(sorted(observed_methods))}.", data={"methods": sorted(observed_methods)})

    # Redirects are not authorization.
    red_cfg = detector_settings("redirect_body_access_control", conn)
    red_statuses={int(x) for x in rulebook.rule_list(red_cfg, "statuses") if str(x).isdigit()}
    if red_cfg.get("enabled") and status in red_statuses:
        stripped_body = resp_body.strip()
        body_field_names = {_norm_name(k) for k, _, _ in fields}
        interesting_keys={_compact(x) for x in rulebook.rule_list(red_cfg, "interesting_keys")}
        interesting_fields=sorted(k for k in body_field_names if _compact(k) in interesting_keys)
        min_chars=max(0, rulebook.rule_int(red_cfg, "minimum_body_chars", 120))
        data_like=bool(interesting_fields)
        trigger=len(stripped_body)>=min_chars and (data_like if rulebook.rule_bool(red_cfg, "require_interesting_field", False) else True)
        if trigger:
            ev = {"source":"burp_redirect","exchange_id":exchange_id,"method":method,"url":url,"status":status,
                  "location":_safe_url_evidence(resp_headers.get("location", "")),"response_size":len(resp_body),
                  "interesting_fields":interesting_fields[:10],"rule_match":{"status":status,"minimum_body_chars":min_chars,"interesting_fields":interesting_fields[:10]}}
            lead_result = upsert_lead(conn, lead_key=f"redirect_body:{rid}:{status}", host_id=hid, resource_id=rid,
                lead_type="redirect_body_access_control", title="Redirect con contenido que merece revisión",
                confidence="high" if data_like else "medium", review_priority="medium", evidence=[ev],
                why="El 3xx cumple las reglas de body que configuraste. Redirigir al navegador no evita una filtración si los datos ya salieron en la respuesta.",
                next_test=f"Abre el exchange #{exchange_id} sin seguir el redirect y revisa el body completo. Compara con tu propia identidad y no uses datos de terceros fuera del scope.",
                confirm_if="El body del 3xx contiene datos sensibles/privados que la identidad no estaba autorizada a recibir.",
                discard_if="El body sólo contiene una página genérica de redirect sin información adicional.")
            notify_new_lead(lead_result, lead_type="redirect_body_access_control", title="Redirect con body relevante",
                            priority="medium", message=f"{method} {path} respondió {status} y cumplió tus reglas de body 3xx.", data={"status": status, "response_size": len(resp_body)})

    # 403 layer fingerprint comparison.
    proxy_cfg = detector_settings("proxy_path_access_control", conn)
    blocked_statuses={int(x) for x in rulebook.rule_list(proxy_cfg, "blocked_statuses") if str(x).isdigit()}
    comparison_statuses={int(x) for x in rulebook.rule_list(proxy_cfg, "comparison_statuses") if str(x).isdigit()}
    if proxy_cfg.get("enabled") and status in blocked_statuses and comparison_statuses:
        placeholders=",".join("?" for _ in comparison_statuses)
        baseline = conn.execute(
            f"""SELECT e.id,e.response_size,e.response_headers_json,e.status_code,r.path
               FROM http_exchanges e JOIN resource_operations oo ON oo.id=e.operation_id
               JOIN resources r ON r.id=oo.resource_id
               WHERE r.host_id=? AND e.status_code IN ({placeholders}) AND e.id<>? ORDER BY e.last_seen_at DESC LIMIT 1""",
            (hid, *sorted(comparison_statuses), exchange_id),
        ).fetchone()
        if baseline:
            bh = _header_map(baseline["response_headers_json"])
            server_a, server_b = resp_headers.get("server", "").lower(), bh.get("server", "").lower()
            ctype_a, ctype_b = resp_headers.get("content-type", "").split(";",1)[0].lower(), bh.get("content-type", "").split(";",1)[0].lower()
            size_a, size_b = int(row["response_size"] or 0), int(baseline["response_size"] or 0)
            size_ratio = max(size_a, size_b, 1) / max(min(size_a or 1, size_b or 1), 1)
            strong_layer_diff=bool((server_a and server_b and server_a != server_b) or (ctype_a and ctype_b and ctype_a != ctype_b))
            layer_diff = strong_layer_diff if rulebook.rule_bool(proxy_cfg, "require_strong_difference", False) else bool(strong_layer_diff or size_ratio >= 3.0)
            if layer_diff:
                ev = {"source":"burp_fingerprint","exchange_id":exchange_id,"method":method,"url":url,"status":status,
                      "server":server_a or None,"content_type":ctype_a or None,"size":size_a,
                      "baseline_exchange":int(baseline["id"]),"baseline_status":int(baseline["status_code"]),"baseline_path":baseline["path"],"baseline_server":server_b or None,
                      "baseline_content_type":ctype_b or None,"baseline_size":size_b,"rule_match":{"strong_layer_difference":strong_layer_diff,"size_ratio":round(size_ratio,2)}}
                lead_result = upsert_lead(conn, lead_key=f"proxy_403:{rid}", host_id=hid, resource_id=rid,
                    lead_type="proxy_path_access_control", title=f"{status} con fingerprint distinto al backend observado",
                    confidence="medium", review_priority="medium", evidence=[ev],
                    why="La respuesta bloqueada coincide con tus reglas de discrepancia entre capas. Puede significar proxy/WAF/frontend distinto; no demuestra un bypass.",
                    next_test="Primero confirma qué capa responde. Si la arquitectura lo justifica, prueba manualmente discrepancias de routing/normalización; X-Original-URL y X-Rewrite-URL son quick checks, no una conclusión automática.",
                    confirm_if="Una representación permitida por la capa frontal termina ejecutando una ruta que directamente estaba bloqueada y el backend no revalida autorización.",
                    discard_if="Las respuestas provienen de la misma capa o el backend aplica autorización equivalente tras cualquier reescritura.")
                notify_new_lead(lead_result, lead_type="proxy_path_access_control", title="Respuesta bloqueada con fingerprint distinto",
                                priority="medium", message=f"{path} cumple tus reglas de fingerprint para capas distintas.", data={"status": status, "baseline_exchange": int(baseline["id"])})

    # Referer quick check.
    referer_cfg = detector_settings("referer_access_control", conn)
    referer_methods={x.upper() for x in rulebook.rule_list(referer_cfg, "methods")}
    referer_tokens=[x.lower() for x in rulebook.rule_list(referer_cfg, "sensitive_path_tokens")]
    referer_sensitive=any(tok in low_path for tok in referer_tokens)
    referer_trigger=bool(req_headers.get("referer") and method.upper() in referer_methods)
    if rulebook.rule_bool(referer_cfg, "require_sensitive_path", True):
        referer_trigger=referer_trigger and referer_sensitive
    if rulebook.rule_bool(referer_cfg, "require_authenticated", False):
        referer_trigger=referer_trigger and bool(row["authenticated_observed"])
    if referer_cfg.get("enabled") and referer_trigger:
        ev = {"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,"referer":_safe_url_evidence(req_headers.get("referer", "")),"rule_match":{"sensitive_path":referer_sensitive}}
        lead_result = upsert_lead(conn, lead_key=f"referer_access:{oid}", host_id=hid, resource_id=rid,
            lead_type="referer_access_control", title="Acción sensible observada con Referer",
            confidence="low", review_priority="low", evidence=[ev],
            why="La operación coincide con tus reglas de Referer. El header es controlable por el cliente y no debe ser la prueba de autorización; su presencia sólo merece un quick check.",
            next_test="Con tu propia cuenta de prueba, compara la request original contra la misma request sin Referer y con un Referer distinto. Si el resultado de autorización depende del header, investiga por qué.",
            confirm_if="Una identidad sin privilegios ejecuta la acción únicamente al presentar un Referer privilegiado/controlado.",
            discard_if="Referer sólo participa en CSRF/telemetría o la autorización depende correctamente de la identidad/rol server-side.")
        notify_new_lead(lead_result, lead_type="referer_access_control", title="Referer presente en acción sensible",
                        priority="low", message=f"{method} {path} coincidió con tus reglas de Referer.", data={})

    return {"exchange_id": exchange_id, "signals": signals, "new_notifications": new_notifications}


def retire_first_party_cors(conn, scopes: list[str]) -> int:
    """Retire stale CORS hypotheses that are now known first-party project scopes."""
    changed=0
    rows=conn.execute("SELECT id,resource_id,evidence_json,result_notes,status FROM leads_v2 WHERE lead_type='cors'").fetchall()
    for row in rows:
        try:
            evidence=json.loads(row["evidence_json"] or "[]")
        except Exception:
            evidence=[]
        origins=[]
        for ev in evidence if isinstance(evidence,list) else []:
            if isinstance(ev,dict) and ev.get("origin"):
                origins.append(str(ev.get("origin")))
        first_party=False
        for origin in origins:
            try: host=urllib.parse.urlsplit(origin).hostname or ""
            except Exception: host=""
            if host_in_project_scope(host,scopes):
                first_party=True; break
        if not first_party:
            continue
        if str(row["status"] or "") in {"candidate","testing","interesting","postponed"}:
            note=str(row["result_notes"] or "").strip() or "Origen first-party: ambos hosts pertenecen al mismo proyecto/scope. Negro deja de priorizarlo como CORS arbitrario."
            conn.execute("UPDATE leads_v2 SET status='negative',result_notes=?,updated_at=? WHERE id=?",(note,now_iso(),int(row["id"])))
            changed+=1
        for origin in origins:
            conn.execute("UPDATE notifications SET read_at=COALESCE(read_at,?) WHERE dedupe_key=?",(now_iso(),f"cors_passive:{int(row['resource_id'] or 0)}:{origin}"))
    return changed


def generate_leads(conn, domain: str, *, reprocess_all: bool = False) -> dict[str, Any]:
    init_schema(conn)
    generated_before = conn.execute("SELECT COUNT(*) c FROM leads_v2").fetchone()["c"]

    # Backfill deterministic Burp clues for workspaces captured before v0.16.0.
    # Notifications are disabled here to avoid flooding the user with historical toasts.
    exchange_sql = "SELECT id FROM http_exchanges ORDER BY id DESC" if reprocess_all else "SELECT id FROM http_exchanges ORDER BY id DESC LIMIT 5000"
    for _ex in conn.execute(exchange_sql).fetchall():
        try:
            analyze_http_exchange(conn, int(_ex["id"]), domain, emit_notifications=False)
        except Exception:
            pass

    js_by_host: dict[int, list[tuple[Any, dict[str, Any], dict[str, Any] | None]]] = {}
    for row, local, sm in _iter_js_analysis(conn):
        js_by_host.setdefault(int(row["host_id"]), []).append((row, local, sm))

        # Re-evaluate stored JavaScript routes using the CURRENT editable rules.
        # This is intentionally local-only: no bundle is downloaded again.
        if detector_enabled("js_sensitive_route", conn) and isinstance(local, dict):
            sensitive_tokens=tuple(x.lower() for x in detector_rule_list("js_sensitive_route", "path_tokens", conn))
            ignore_tokens=tuple(x.lower() for x in detector_rule_list("js_sensitive_route", "ignore_tokens", conn))
            only_new_routes=detector_rule_bool("js_sensitive_route", "only_new_routes", conn, False)
            stored_urls=[]
            resource_ids=[]
            sensitive_urls=[]
            for candidate in local.get("in_scope_urls", []) or []:
                candidate=str(candidate or "").strip()
                if not candidate:
                    continue
                try:
                    low_path=(urllib.parse.urlsplit(candidate).path or "/").lower()
                except Exception:
                    low_path=candidate.lower()
                if ignore_tokens and any(tok in low_path for tok in ignore_tokens):
                    continue
                rr=conn.execute("SELECT id FROM resources WHERE url=?", (candidate,)).fetchone()
                if rr:
                    rid=int(rr["id"]); resource_ids.append(rid)
                    if only_new_routes:
                        sources={str(x["source"]) for x in conn.execute("SELECT source FROM resource_sources WHERE resource_id=?",(rid,)).fetchall()}
                        if sources and sources != {"js_local"}:
                            continue
                elif only_new_routes:
                    continue
                stored_urls.append(candidate)
                if any(tok in low_path for tok in sensitive_tokens):
                    sensitive_urls.append(candidate)
            if sensitive_urls:
                sha=str(row["sha256"] or "stored")
                upsert_lead(conn,
                    lead_key=f"js_sensitive_routes:{row['id']}:{sha[:16]}", host_id=int(row["host_id"]), resource_id=None,
                    lead_type="javascript_surface", title="JavaScript revela rutas que merecen revisión", confidence="high", review_priority="medium",
                    evidence=[{"source":"javascript","asset_id":int(row["id"]),"url":row["url"],"routes":sensitive_urls[:30],
                               "node_ids":[f"js:{int(row['id'])}"]+[f"resource:{x}" for x in resource_ids[:30]],
                               "rule_match":{"path_tokens":[t for t in sensitive_tokens if any(t in (urllib.parse.urlsplit(u).path or '').lower() for u in sensitive_urls)][:20]}}],
                    why="El análisis JavaScript ya almacenado contiene rutas in-scope que coinciden con tus reglas actuales de superficie sensible. Recalcular no volvió a descargar el bundle.",
                    next_test="Abre las rutas descubiertas desde Resources/Mapa, identifica su método y contexto legítimo, y revisa control de acceso sin hacer fuzzing masivo.",
                    confirm_if="Una ruta revelada expone funcionalidad sensible con controles insuficientes o habilita una cadena adicional.",
                    discard_if="Las rutas son públicas/esperadas o aplican autenticación y autorización server-side de forma consistente.",
                    source="JS_LOCAL")

        # Source map lead.
        if detector_enabled("source_map", conn) and sm and int(sm.get("sources_count") or 0) > 0:
            sm_det = (sm.get("analysis") or {}).get("detections", []) if isinstance(sm.get("analysis"), dict) else []
            priority = "high" if any(d.get("category") == "potential_secret" for d in sm_det if isinstance(d, dict)) else "medium"
            upsert_lead(conn,
                lead_key=f"sourcemap:{row['id']}", host_id=int(row["host_id"]), resource_id=None,
                lead_type="source_map", title="Source map público con código recuperable", confidence="high", review_priority=priority,
                evidence=[{"source":"sourcemap","asset_id":row["id"],"url":sm.get("url"),"sources":sm.get("sources_count"),"application_sources":sm.get("application_sources_count")}],
                why="Un source map puede revelar código de aplicación, endpoints y configuración que el bundle minificado oculta. La exposición sola no implica vulnerabilidad; importa su contenido.",
                next_test="Revisar código de aplicación recuperado, detecciones de config/secrets y rutas que ya no aparecen en el frontend actual.",
                confirm_if="El mapa contiene información sensible o habilita una cadena de impacto demostrable.",
                discard_if="Sólo contiene código público/esperado sin secretos, rutas sensibles ni impacto adicional.")
        # Secrets/client config leads.
        merged: list[dict[str, Any]] = []
        merged.extend(local.get("detections", []) or [])
        if sm and isinstance(sm.get("analysis"), dict):
            merged.extend(sm["analysis"].get("detections", []) or [])
        configured_secret_types={x.lower() for x in detector_rule_list("secret_candidate","secret_types",conn)}
        for d in (merged if detector_enabled("secret_candidate", conn) else []):
            if not isinstance(d, dict):
                continue
            cat = d.get("category")
            dtype = str(d.get("type") or "config")
            if configured_secret_types and dtype.lower() not in configured_secret_types:
                continue
            if cat == "potential_secret":
                pri, conf = "high", str(d.get("confidence") or "medium")
            elif dtype == "google_api_key":
                pri, conf = "medium", "high"
            elif cat == "surface_config":
                pri, conf = "low", str(d.get("confidence") or "medium")
            else:
                pri, conf = "low", str(d.get("confidence") or "medium")
            upsert_lead(conn,
                lead_key=f"config:{row['id']}:{dtype}:{d.get('fingerprint')}", host_id=int(row["host_id"]), resource_id=None,
                lead_type="secret_or_client_config", title=f"{d.get('label','Config/secret candidate')}", confidence=conf, review_priority=pri,
                evidence=[{"source":"javascript/source_map","asset_id":row["id"],"category":cat,"masked_value":d.get("masked_value"),"context":d.get("context","")[:600]}],
                why="La señal merece contexto. Algunas claves de cliente son públicas por diseño; potential_secret requiere más cuidado.",
                next_test=str(d.get("validation_hint") or "Validar de forma mínima y no destructiva según el scope."),
                confirm_if="La configuración permite uso no autorizado o el secreto es real/activo y su exposición tiene impacto.",
                discard_if="Es configuración pública esperada, fixture, valor expirado o no existe impacto demostrable.")

    # URL/resource based leads.  Use the same editable vocabulary as live Burp analysis.
    redirect_rule_keys={str(x).lower() for x in detector_rule_list("open_redirect","parameter_keys",conn)}
    ssrf_rule_keys={str(x).lower() for x in detector_rule_list("ssrf_surface","parameter_keys",conn)}
    object_rule_nouns={str(x).lower() for x in detector_rule_list("access_object_reference","path_business_nouns",conn)}
    resources = conn.execute("SELECT r.*, h.hostname FROM resources r JOIN hosts h ON h.id=r.host_id").fetchall()
    for r in resources:
        query = urllib.parse.parse_qs(r["query"] or "", keep_blank_values=True)
        qkeys = {k.lower() for k in query}
        redirect_hits = sorted(qkeys & redirect_rule_keys)
        if redirect_hits and detector_enabled("open_redirect", conn):
            sink_evidence: list[str] = []
            for _, local, sm in js_by_host.get(int(r["host_id"]), []):
                contexts = list(local.get("contexts", []) or [])
                if sm and isinstance(sm.get("analysis"), dict):
                    contexts += list(sm["analysis"].get("contexts", []) or [])
                for ctx in contexts:
                    txt = str(ctx.get("context", "")).lower()
                    if any(x in txt for x in NAV_SINKS) and any(p in txt for p in redirect_hits):
                        sink_evidence.append(str(ctx.get("context", ""))[:700])
                        break
            conf = "high" if sink_evidence else "medium"
            pri = "high" if sink_evidence and any(x in r["path"].lower() for x in ("login", "auth", "oauth", "callback")) else "medium"
            upsert_lead(conn,
                lead_key=f"open_redirect:{r['id']}:{','.join(redirect_hits)}", host_id=int(r["host_id"]), resource_id=int(r["id"]),
                lead_type="open_redirect", title=f"Posible Open Redirect · {', '.join(redirect_hits)}", confidence=conf, review_priority=pri,
                evidence=[{"source":"resource","url":r["url"],"parameters":redirect_hits,"sources":[x[0] for x in conn.execute("SELECT source FROM resource_sources WHERE resource_id=?", (r["id"],)).fetchall()]}] + ([{"source":"javascript","navigation_sink":sink_evidence[0]}] if sink_evidence else []),
                why="Un parámetro de redirección controlable puede enviar al usuario fuera del dominio. Gana más interés si participa en login/OAuth.",
                next_test="Probar una única URL HTTPS controlada en el parámetro y observar Location/navegación sin usar phishing ni terceros.",
                confirm_if="La aplicación termina navegando/redirigiendo a un dominio externo controlado sin una allowlist efectiva.",
                discard_if="Normaliza a rutas internas, bloquea hosts externos o aplica una allowlist estricta.")
        ssrf_hits = sorted(qkeys & ssrf_rule_keys) if detector_enabled("ssrf_surface", conn) else []
        if ssrf_hits:
            upsert_lead(conn,
                lead_key=f"ssrf_surface:{r['id']}:{','.join(ssrf_hits)}", host_id=int(r["host_id"]), resource_id=int(r["id"]),
                lead_type="ssrf_surface", title=f"Superficie URL-fetch / SSRF candidata · {', '.join(ssrf_hits)}", confidence="low", review_priority="medium",
                evidence=[{"source":"resource","url":r["url"],"parameters":ssrf_hits}],
                why="Parámetros tipo URL/URI/proxy/import pueden acabar en consumo server-side, pero el nombre por sí solo no lo demuestra.",
                next_test="Revisar código/flujo y, sólo si hay evidencia server-side y el scope lo permite, usar un endpoint controlado propio como marcador benigno.",
                confirm_if="El servidor realiza una solicitud saliente hacia una URL controlada por el usuario.",
                discard_if="El valor sólo se usa client-side, se trata como dato o existe una allowlist/normalización que impide destinos arbitrarios.")
        segments = [x for x in (r["path"] or "").lower().split("/") if x]
        if any(x in object_rule_nouns for x in segments) and any(re.fullmatch(r"\d{2,}|[0-9a-f]{8}-[0-9a-f-]{20,}|[0-9a-f]{24,}", x, re.I) for x in segments):
            upsert_lead(conn,
                lead_key=f"bola_surface:{r['id']}", host_id=int(r["host_id"]), resource_id=int(r["id"]),
                lead_type="bola_surface", title="Object authorization / BOLA surface", confidence="low", review_priority="medium",
                evidence=[{"source":"resource","url":r["url"]}],
                why="La ruta contiene un identificador de objeto en un recurso de negocio. Es una buena superficie para probar autorización entre cuentas de prueba.",
                next_test="Con dos cuentas autorizadas de prueba, comparar acceso al mismo tipo de objeto cambiando únicamente el identificador.",
                confirm_if="Una cuenta puede leer/modificar un objeto que pertenece a otra sin autorización.",
                discard_if="El servidor aplica autorización por objeto y rechaza el acceso cruzado.")
        lowurl = (r["url"] or "").lower()
        if any(x in lowurl for x in (".s3.amazonaws.com", "storage.googleapis.com/", ".blob.core.windows.net/")):
            upsert_lead(conn,
                lead_key=f"cloud_storage:{r['id']}", host_id=int(r["host_id"]), resource_id=int(r["id"]),
                lead_type="cloud_storage", title="Cloud storage endpoint descubierto", confidence="high", review_priority="medium",
                evidence=[{"source":"resource","url":r["url"]}],
                why="El endpoint de storage amplía la superficie. La existencia del bucket/container no implica que sea público.",
                next_test="Validar únicamente acceso anónimo de lectura/listado permitido por scope, sin escribir ni modificar objetos.",
                confirm_if="Información no destinada a ser pública puede leerse/listarse sin autenticación.",
                discard_if="Sólo contiene activos públicos esperados o requiere autorización correctamente.")

    # Observations from web recon/crawl/CORS.
    obs = conn.execute("SELECT * FROM observations ORDER BY id DESC").fetchall()
    for o in obs:
        try:
            payload = json.loads(o["payload_json"] or "null")
        except Exception:
            payload = None
        if o["kind"] == "web_recon" and isinstance(payload, dict):
            hid = int(o["entity_id"]) if o["entity_type"] == "host" else None
            if payload.get("directory_listing"):
                upsert_lead(conn, lead_key=f"dir_listing:{hid}", host_id=hid, resource_id=None,
                    lead_type="directory_listing", title="Directory listing visible", confidence="high", review_priority="medium",
                    evidence=[{"source":"web_recon","url":payload.get("final_url")}],
                    why="Un índice de directorio puede exponer archivos no enlazados. El impacto depende del contenido.",
                    next_test="Revisar nombres y tipos de archivos visibles; no descargar en masa. Priorizar backups, configs y documentos internos.",
                    confirm_if="El índice expone archivos sensibles/no destinados a ser públicos.",
                    discard_if="Sólo lista activos públicos esperados sin información sensible.")
            oidc = (payload.get("well_known") or {}).get("/.well-known/openid-configuration")
            if isinstance(oidc, dict) and isinstance(oidc.get("json"), dict):
                data = oidc["json"]
                upsert_lead(conn, lead_key=f"oidc:{hid}:{hashlib.sha1(json.dumps(data,sort_keys=True).encode()).hexdigest()[:12]}", host_id=hid, resource_id=None,
                    lead_type="oauth_oidc_surface", title="Superficie OAuth/OIDC descubierta", confidence="high", review_priority="medium",
                    evidence=[{"source":"openid-configuration","issuer":data.get("issuer"),"authorization_endpoint":data.get("authorization_endpoint"),"token_endpoint":data.get("token_endpoint"),"jwks_uri":data.get("jwks_uri"),"response_types":data.get("response_types_supported"),"scopes":data.get("scopes_supported")}],
                    why="OIDC Discovery entrega un mapa fiable del flujo de identidad. Es una superficie para revisar redirect_uri, state, nonce y PKCE, no una vulnerabilidad por sí sola.",
                    next_test="Reconstruir el flujo con el cliente real y revisar validación de redirect_uri/state/nonce/PKCE usando cuentas de prueba autorizadas.",
                    confirm_if="Existe una validación insuficiente con impacto demostrable (p. ej. redirección/código/token hacia destino no autorizado).",
                    discard_if="Los endpoints y parámetros aplican las restricciones esperadas y no hay impacto.")
        elif o["kind"] == "crawl_result" and isinstance(payload, dict):
            hid = int(o["entity_id"]) if o["entity_type"] == "host" else None
            for p in payload.get("pages", []) or []:
                if isinstance(p, dict) and p.get("directory_listing"):
                    key = hashlib.sha1(str(p.get("url")).encode()).hexdigest()[:12]
                    upsert_lead(conn, lead_key=f"dir_listing:{hid}:{key}", host_id=hid, resource_id=None,
                        lead_type="directory_listing", title="Directory listing hallado durante crawling", confidence="high", review_priority="medium",
                        evidence=[{"source":"crawler","url":p.get("url"),"title":p.get("title")}],
                        why="El crawler confirmó un índice navegable; podría revelar archivos no enlazados.",
                        next_test="Revisar manualmente pocos nombres de alta señal y clasificar contenido sin descargar de forma masiva.",
                        confirm_if="Aparecen backups, configs, documentos internos u otro contenido sensible.",
                        discard_if="El índice sólo contiene activos públicos esperados.")
            # Form-derived redirect/SSRF candidates.
            for form in payload.get("forms", []) or []:
                fields = [str(x.get("name", "")).lower() for x in form.get("fields", []) if isinstance(x, dict)]
                rh = sorted(set(fields) & redirect_rule_keys)
                if rh:
                    key = hashlib.sha1((str(form.get("action"))+",".join(rh)).encode()).hexdigest()[:12]
                    upsert_lead(conn, lead_key=f"open_redirect_form:{hid}:{key}", host_id=hid, resource_id=None,
                        lead_type="open_redirect", title=f"Formulario con destino/redirección controlable · {', '.join(rh)}", confidence="medium", review_priority="medium",
                        evidence=[{"source":"crawler_form","page":form.get("page"),"action":form.get("action"),"method":form.get("method"),"fields":rh}],
                        why="Un form expone un campo de redirección. Requiere observar cómo lo consume la aplicación.",
                        next_test="Revisar JS/flujo y hacer una única validación con dominio HTTPS controlado si el campo realmente controla navegación.",
                        confirm_if="El valor termina en una redirección externa arbitraria.",
                        discard_if="El campo se ignora, se normaliza a rutas internas o usa allowlist.")
        elif o["kind"] == "cors_probe" and isinstance(payload, dict) and detector_enabled("cors", conn):
            hid = int(o["entity_id"]) if o["entity_type"] == "host" else None
            cors_cfg=detector_settings("cors",conn)
            ao = payload.get("allow_origin")
            origin_sent=str(payload.get("origin_sent") or "")
            creds = str(payload.get("allow_credentials") or "").lower() == "true"
            reflected = ao == origin_sent
            try: origin_host=(urllib.parse.urlsplit(origin_sent).hostname or '').lower().rstrip('.')
            except Exception: origin_host=''
            project_scopes=project_scopes_from_conn(conn,domain)
            first_party=host_in_project_scope(origin_host,project_scopes) if rulebook.rule_bool(cors_cfg,"ignore_project_scopes",True) else False
            ignore_origins={x.lower().rstrip('/') for x in rulebook.rule_list(cors_cfg,"ignore_origins")}
            trusted_suffixes=[x.lower().lstrip('*').lstrip('.') for x in rulebook.rule_list(cors_cfg,"trusted_origin_suffixes") if x.strip()]
            trusted_manual=origin_sent.lower().rstrip('/') in ignore_origins or any(origin_host == s or origin_host.endswith('.' + s) for s in trusted_suffixes)
            reflection_ok=reflected if rulebook.rule_bool(cors_cfg,"require_exact_reflection",True) else bool(ao)
            creds_ok=creds if rulebook.rule_bool(cors_cfg,"require_credentials",False) else True
            external_ok=(not first_party and not trusted_manual) if rulebook.rule_bool(cors_cfg,"require_external_origin",True) else True
            auth_ok=bool(payload.get('authenticated')) if rulebook.rule_bool(cors_cfg,"require_authenticated",False) else True
            if reflection_ok and creds_ok and external_ok and auth_ok:
                conf = "high" if reflected and creds else "medium"
                pri = "high" if reflected and creds else "low"
                upsert_lead(conn, lead_key=f"cors:{hid}:{hashlib.sha1(str(payload.get('url')).encode()).hexdigest()[:12]}", host_id=hid, resource_id=None,
                    lead_type="cors", title="CORS permisivo / Origin reflejado", confidence=conf, review_priority=pri,
                    evidence=[{"source":"cors_probe","url":payload.get("url"),"allow_origin":ao,"allow_credentials":payload.get("allow_credentials"),"status":payload.get("status"),"rule_match":{"external_origin":not first_party,"exact_reflection":reflected,"credentials":creds}}],
                    why="La prueba CORS cumplió exactamente las condiciones que configuraste. Eso sigue siendo una hipótesis hasta demostrar lectura cross-origin de datos relevantes.",
                    next_test="Con una cuenta propia de prueba, confirmar si el endpoint devuelve datos sensibles y el navegador permitiría leerlos desde el Origin externo controlado.",
                    confirm_if="Un origen externo arbitrario puede leer una respuesta autenticada sensible.",
                    discard_if="No se permiten credentials/datos sensibles, ACAO no refleja el origen o el navegador no permite lectura cross-origin.")

    # DNS takeover candidates from latest inspections.
    hosts = conn.execute("SELECT id,hostname FROM hosts").fetchall()
    for h in hosts:
        insp = conn.execute("SELECT payload_json FROM host_inspections WHERE host_id=? ORDER BY id DESC LIMIT 1", (h["id"],)).fetchone()
        if not insp:
            continue
        try:
            p = json.loads(insp["payload_json"])
        except Exception:
            continue
        cnames = (p.get("dns") or {}).get("cname", []) or []
        bodies = " ".join(str((p.get(k) or {}).get("error", "")) + " " + str((p.get(k) or {}).get("headers", "")) for k in ("http", "https")).lower()
        for cname in cnames:
            lowc = str(cname).lower()
            for provider, suffixes, fingerprints in TAKEOVER_PROVIDERS:
                if any(s in lowc for s in suffixes):
                    matched = any(f in bodies for f in fingerprints)
                    upsert_lead(conn, lead_key=f"takeover:{h['id']}:{provider}:{lowc}", host_id=int(h["id"]), resource_id=None,
                        lead_type="subdomain_takeover", title=f"Dangling DNS / takeover candidate · {provider}", confidence="high" if matched else "medium", review_priority="high" if matched else "medium",
                        evidence=[{"source":"dns_inspection","hostname":h["hostname"],"cname":cname,"provider":provider,"provider_error_fingerprint":matched}],
                        why="Un CNAME hacia un recurso de proveedor inexistente puede permitir subdomain takeover. Negro nunca reclama el recurso automáticamente.",
                        next_test="Confirmar de forma no destructiva que el recurso está sin asignar y revisar las reglas del programa antes de cualquier claim/PoC.",
                        confirm_if="El proveedor permite asociar el nombre/recurso abandonado y el programa autoriza la prueba necesaria.",
                        discard_if="El recurso existe, está reservado, no es reclamable o el proveedor no permite asociarlo.")
                    break

    # DOM XSS heuristics from code contexts.
    for row, local, sm in _iter_js_analysis(conn):
        contexts = list(local.get("contexts", []) or [])
        if sm and isinstance(sm.get("analysis"), dict):
            contexts += list(sm["analysis"].get("contexts", []) or [])
        for i, ctx in enumerate(contexts[:500]):
            txt = str(ctx.get("context", ""))
            low = txt.lower()
            sources = [s for s in DOM_SOURCES if s in low]
            sinks = [s for s in DOM_SINKS if s in low]
            if sources and sinks:
                upsert_lead(conn, lead_key=f"domxss:{row['id']}:{i}:{sources[0]}:{sinks[0]}", host_id=int(row["host_id"]), resource_id=None,
                    lead_type="dom_xss", title="DOM XSS source→sink candidate", confidence="medium", review_priority="high",
                    evidence=[{"source":"javascript/source_map","asset_id":row["id"],"sources":sources,"sinks":sinks,"context":txt[:900]}],
                    why="Un valor controlable por URL/message aparece cerca de un HTML/code sink. La proximidad no demuestra flujo de datos; requiere trazado y prueba benigna.",
                    next_test="Trazar transformaciones entre source y sink. Empezar con un marcador HTML inocuo; no usar payloads destructivos.",
                    confirm_if="Entrada controlada alcanza el sink sin neutralización adecuada y permite ejecución/HTML controlado según el contexto.",
                    discard_if="No existe flujo de datos, el valor se escapa/sanitiza o el sink recibe sólo datos constantes.")
                break

    count = conn.execute("SELECT COUNT(*) c FROM leads_v2").fetchone()["c"]
    return {"before": generated_before, "after": count, "new": max(0, count - generated_before), "generated_at": now_iso()}


def recalculate_intelligence(conn, domain: str) -> dict[str, Any]:
    """Reinterpret all STORED evidence with the current local detector rules.

    This function does not enumerate, crawl, fetch JavaScript or call AI. It only
    replays evidence already persisted in SQLite/local analyses. Deterministic
    hypotheses keep their human status/notes, while rule_active reflects whether
    they still match the current rules.
    """
    init_schema(conn)
    managed_sources=("ENGINE","JS_LOCAL")
    before_rows=conn.execute(
        "SELECT id,lead_key,rule_active,status FROM leads_v2 WHERE source IN (?,?)", managed_sources
    ).fetchall()
    before_all={str(r["lead_key"]):dict(r) for r in before_rows}
    before_active={k for k,v in before_all.items() if int(v.get("rule_active") or 0)==1}
    started=now_iso()

    # Invalidate first, then let current rules reactivate matching hypotheses.
    # The surrounding sqlite transaction makes this atomic on success.
    conn.execute(
        "UPDATE leads_v2 SET rule_active=0,last_rule_eval_at=? WHERE source IN (?,?)",
        (started,*managed_sources),
    )
    # Rebuild Investigation Memory from stored local evidence. Correlation
    # Signals are derived projections, so they can be safely reinterpreted when
    # the user explicitly asks for a local recalculation.
    correlation_summary = {"identifier_observations": 0, "signals": 0, "requirements_matched": 0}
    try:
        import negro_objects as object_tools
        object_tools.rebuild_identifier_index(conn)
        corr_ids = [int(r["id"]) for r in conn.execute("SELECT id FROM signal_occurrences WHERE source='correlation'").fetchall()]
        if corr_ids:
            marks = ",".join("?" for _ in corr_ids)
            conn.execute(
                f"""UPDATE hypothesis_requirements SET status='pending',matched_observation_id=NULL,matched_signal_id=NULL,updated_at=?
                    WHERE matched_signal_id IN ({marks})""", (started, *corr_ids)
            )
        conn.execute("DELETE FROM signal_occurrences WHERE source='correlation'")
        for ex in conn.execute("SELECT id FROM http_exchanges ORDER BY id").fetchall():
            r = evaluate_correlation_memory(conn, int(ex["id"]))
            correlation_summary["identifier_observations"] += int(r.get("identifier_observations") or 0)
            correlation_summary["signals"] += int(r.get("signals") or 0)
            correlation_summary["requirements_matched"] += int(r.get("requirements_matched") or 0)
    except Exception as exc:
        correlation_summary["error"] = str(exc)[:240]
    generated=generate_leads(conn, domain, reprocess_all=True)
    after_rows=conn.execute(
        "SELECT id,lead_key,rule_active,status FROM leads_v2 WHERE source IN (?,?)", managed_sources
    ).fetchall()
    after_all={str(r["lead_key"]):dict(r) for r in after_rows}
    after_active={k for k,v in after_all.items() if int(v.get("rule_active") or 0)==1}
    new_keys=after_active-set(before_all)
    reactivated=after_active-{k for k,v in before_all.items() if int(v.get("rule_active") or 0)==1}-new_keys
    retired=before_active-after_active

    retired_ids={int(after_all.get(k,before_all[k])["id"]) for k in retired if k in before_all}
    if retired_ids:
        # Old unread "new hypothesis" notifications should no longer demand action.
        for n in conn.execute("SELECT id,data_json FROM notifications WHERE kind='hypothesis' AND read_at IS NULL").fetchall():
            try: payload=json.loads(n["data_json"] or "{}")
            except Exception: payload={}
            if int(payload.get("lead_id") or 0) in retired_ids:
                conn.execute("UPDATE notifications SET read_at=? WHERE id=?", (started,int(n["id"])))

    summary={
        "evaluated_exchanges": int(conn.execute("SELECT COUNT(*) c FROM http_exchanges").fetchone()["c"] or 0),
        "stored_resources": int(conn.execute("SELECT COUNT(*) c FROM resources").fetchone()["c"] or 0),
        "stored_javascript": int(conn.execute("SELECT COUNT(*) c FROM js_assets WHERE local_analysis_json IS NOT NULL").fetchone()["c"] or 0),
        "active_before": len(before_active),
        "active_after": len(after_active),
        "new": len(new_keys),
        "reactivated": len(reactivated),
        "no_longer_matching": len(retired),
        "recalculated_at": started,
        "network_requests": 0,
        "ai_calls": 0,
        "correlation_memory": correlation_summary,
    }
    _upsert_notification(
        conn, dedupe_key=f"intelligence_recalc:{started}", kind="intelligence_recalc", severity="low",
        title="Inteligencia recalculada",
        message=f"{summary['active_after']} hipótesis vigentes · {summary['new']} nuevas · {summary['no_longer_matching']} dejaron de coincidir",
        source="rule_engine", entity_type="project", entity_id=0, data={**summary, "href":"hypotheses"}, emit=True,
    )
    return {**summary, "engine": generated}


def list_leads(conn, limit: int = 200) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT l.*, h.hostname, r.url AS resource_url FROM leads_v2 l
           LEFT JOIN hosts h ON h.id=l.host_id LEFT JOIN resources r ON r.id=l.resource_id
           WHERE COALESCE(l.rule_active,1)=1
           ORDER BY CASE l.review_priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                    CASE l.confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                    l.updated_at DESC LIMIT ?""", (limit,)
    ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        try:
            item["evidence"] = json.loads(item.pop("evidence_json") or "[]")
        except Exception:
            item["evidence"] = []
        try:
            item["test_plan"] = json.loads(item.get("test_plan_json") or "[]")
        except Exception:
            item["test_plan"] = []
        ai_meta = next((ev for ev in item["evidence"] if isinstance(ev, dict) and ev.get("source") == "ai_graph"), {})
        item["plain_language"] = str(ai_meta.get("plain_language") or "")
        item["investigation_priority"] = str(ai_meta.get("investigation_priority") or ("high" if item.get("review_priority")=="high" else "medium" if item.get("review_priority")=="medium" else "quick"))
        item["priority_reasons"] = [str(x) for x in (ai_meta.get("priority_reasons") or [])][:4]
        node_ids = [str(x) for x in (ai_meta.get("node_ids") or []) if isinstance(x, str)]
        item["node_ids"] = node_ids
        refs=[]; seen_refs=set(); primary_method=None; primary_exchange_id=None
        for nid in node_ids:
            if nid.startswith("operation:"):
                try: op_id=int(nid.split(":",1)[1])
                except Exception: continue
                rr=conn.execute("""SELECT o.id,o.method,o.last_status,r.id resource_id,r.path,r.query,r.url,h.hostname
                                  FROM resource_operations o JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id WHERE o.id=?""",(op_id,)).fetchone()
                if rr:
                    ex=conn.execute("SELECT id,status_code,source,tool FROM http_exchanges WHERE operation_id=? ORDER BY last_seen_at DESC LIMIT 1",(op_id,)).fetchone()
                    key=("operation",op_id)
                    if key not in seen_refs:
                        seen_refs.add(key); refs.append({"kind":"operation","id":op_id,"method":rr["method"],"resource_id":rr["resource_id"],"path":rr["path"],"query":rr["query"],"url":rr["url"],"host":rr["hostname"],"status":rr["last_status"],"exchange_id":int(ex["id"]) if ex else None,"exchange_status":ex["status_code"] if ex else None,"source":ex["source"] if ex else None,"tool":ex["tool"] if ex else None})
                    primary_method = primary_method or rr["method"]
                    primary_exchange_id = primary_exchange_id or (int(ex["id"]) if ex else None)
                    if not item.get("resource_id"): item["resource_id"]=int(rr["resource_id"]); item["resource_url"]=rr["url"]
            elif nid.startswith("resource:"):
                try: rid=int(nid.split(":",1)[1])
                except Exception: continue
                rr=conn.execute("SELECT r.id,r.path,r.query,r.url,h.hostname FROM resources r JOIN hosts h ON h.id=r.host_id WHERE r.id=?",(rid,)).fetchone()
                if rr and ("resource",rid) not in seen_refs:
                    seen_refs.add(("resource",rid)); refs.append({"kind":"resource","id":rid,"resource_id":rid,"path":rr["path"],"query":rr["query"],"url":rr["url"],"host":rr["hostname"]})
                    if not item.get("resource_id"): item["resource_id"]=rid; item["resource_url"]=rr["url"]
            elif nid.startswith("request:") or nid.startswith("exchange:"):
                try: exid=int(nid.split(":",1)[1])
                except Exception: continue
                ex=conn.execute("""SELECT e.id,e.status_code,e.source,e.tool,o.method,r.id resource_id,r.path,r.query,r.url,h.hostname
                                  FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id WHERE e.id=?""",(exid,)).fetchone()
                if ex and ("exchange",exid) not in seen_refs:
                    seen_refs.add(("exchange",exid)); refs.append({"kind":"exchange","id":exid,"exchange_id":exid,"method":ex["method"],"resource_id":ex["resource_id"],"path":ex["path"],"query":ex["query"],"url":ex["url"],"host":ex["hostname"],"status":ex["status_code"],"source":ex["source"],"tool":ex["tool"]})
                    primary_method = primary_method or ex["method"]; primary_exchange_id = primary_exchange_id or exid
                    if not item.get("resource_id"): item["resource_id"]=int(ex["resource_id"]); item["resource_url"]=ex["url"]
        item["evidence_refs"] = refs[:10]
        item["primary_method"] = primary_method
        item["primary_exchange_id"] = primary_exchange_id
        out.append(item)
    return out


def historical_intelligence(conn) -> dict[str, Any]:
    rows = conn.execute(
        """SELECT r.id,r.url,r.host_id,o.payload_json,o.value,o.observed_at
           FROM observations o JOIN resources r ON o.entity_type='resource' AND o.entity_id=r.id
           WHERE o.source='wayback_cdx' AND o.kind='wayback_capture'"""
    ).fetchall()
    by: dict[int, dict[str, Any]] = {}
    for row in rows:
        item = by.setdefault(int(row["id"]), {"resource_id":int(row["id"]),"url":row["url"],"host_id":int(row["host_id"]),"captures":0,"timestamps":[],"statuses":set(),"mimetypes":set()})
        item["captures"] += 1
        try:
            p = json.loads(row["payload_json"] or "{}")
        except Exception:
            p = {}
        ts = str(p.get("timestamp") or row["value"] or "")
        if ts:
            item["timestamps"].append(ts)
        if p.get("statuscode"):
            item["statuses"].add(str(p.get("statuscode")))
        if p.get("mimetype"):
            item["mimetypes"].add(str(p.get("mimetype")))
    result: list[dict[str, Any]] = []
    for item in by.values():
        ts = sorted(item.pop("timestamps"))
        item["first_seen"] = ts[0] if ts else None
        item["last_seen"] = ts[-1] if ts else None
        item["statuses"] = sorted(item["statuses"])
        item["mimetypes"] = sorted(item["mimetypes"])
        srcs = [r[0] for r in conn.execute("SELECT source FROM resource_sources WHERE resource_id=?", (item["resource_id"],)).fetchall()]
        item["sources"] = srcs
        item["historical_only"] = not any(s not in {"wayback_cdx", "gau_wayback"} for s in srcs)
        result.append(item)
    result.sort(key=lambda x: (not x["historical_only"], -(x["captures"] or 0), x["url"]))
    return {"resources": result[:1000], "historical_only_count": sum(1 for x in result if x["historical_only"]), "total": len(result), "generated_at": now_iso()}


def build_target_ai_payload(conn, domain: str, max_chars: int = 500_000) -> tuple[str, str]:
    leads = list_leads(conn, 80)
    fingerprints = []
    for o in conn.execute("SELECT payload_json FROM observations WHERE kind='web_recon' ORDER BY id DESC LIMIT 40").fetchall():
        try:
            p = json.loads(o["payload_json"] or "{}")
            fingerprints.extend(p.get("fingerprints", []) or [])
        except Exception:
            pass
    hist = historical_intelligence(conn)
    ct_rows: list[dict[str, Any]] = []
    seen_ct: set[str] = set()
    for o in conn.execute("SELECT payload_json FROM observations WHERE kind='ct_intelligence' ORDER BY id DESC LIMIT 500").fetchall():
        try:
            item = json.loads(o["payload_json"] or "{}")
        except Exception:
            continue
        host = str(item.get("hostname") or "") if isinstance(item, dict) else ""
        if host and host not in seen_ct:
            seen_ct.add(host)
            ct_rows.append(item)
    envelope = {
        "target": domain,
        "policy": policy_summary(conn),
        "leads": leads,
        "fingerprints": fingerprints[:100],
        "certificate_transparency": ct_rows[:100],
        "historical_summary": {"total":hist["total"],"historical_only_count":hist["historical_only_count"],"sample":hist["resources"][:80]},
    }
    payload = "NEGRO_TARGET_EVIDENCE\n" + json.dumps(envelope, ensure_ascii=False, indent=2)
    payload = intel.redact_sensitive_literals(payload)
    payload = payload[:max_chars]
    digest = hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()
    return payload, digest


def run_openai_target_analysis(payload: str, *, model: str, output_tokens: int) -> tuple[dict[str, Any], dict[str, Any]]:
    key = intel.load_secrets().get("OPENAI_API_KEY")
    if not key:
        raise RuntimeError(f"Falta OPENAI_API_KEY en {intel.SECRETS_PATH}")
    try:
        from openai import OpenAI  # type: ignore
    except Exception as exc:
        raise RuntimeError("El SDK de OpenAI no está disponible en el Python actual. Ejecuta ./install-web.sh") from exc
    system = """Eres el motor de triage técnico de Negro para un target de Bug Bounty autorizado.
Responde SIEMPRE en español, manteniendo términos técnicos útiles en inglés.
No eres un chatbot: transforma evidencia en decisiones accionables. Usa sólo la evidencia suministrada y no inventes endpoints, comportamiento, impacto ni vulnerabilidades.
Distingue LEAD de FINDING. Un lead es una hipótesis. No marques severidad CVSS.
Para cada lead prioritario explica: qué evidencia lo sostiene, por qué importa, UNA prueba manual de bajo impacto, qué resultado lo confirma y qué resultado lo descarta.
Da prioridad a correlaciones entre fuentes (current + historical + JS + OIDC + crawler), y penaliza señales aisladas como API keys client-side, CORS permisivo sin datos sensibles o source maps sin contenido sensible.
Return ONLY valid JSON con este schema:
{
  "summary":"...",
  "architecture":{"identity":[],"apis":[],"legacy":[],"storage":[],"technologies":[]},
  "top_leads":[
    {"lead_key":"...","title":"...","assessment":"...","why":"...","manual_test":"...","confirm_if":"...","discard_if":"..."}
  ],
  "next_actions":[{"priority":"high|medium|low","action":"...","reason":"...","estimated_requests":"..."}],
  "noise_or_low_value":[{"signal":"...","reason":"..."}]
}
No propongas credential brute force, DoS, phishing, mass scanning, resource claiming automático ni explotación destructiva."""
    client = OpenAI(api_key=key)
    response = client.responses.create(model=model, reasoning={"effort":"low"}, max_output_tokens=output_tokens, instructions=system, input=payload)
    text = response.output_text or ""
    result = _safe_json_object(text, {"summary":"La IA no devolvió JSON estructurado. Intenta de nuevo.","top_leads":[],"next_actions":[],"noise_or_low_value":[],"architecture":{}})
    usage = getattr(response, "usage", None)
    return result, {"input_tokens":getattr(usage,"input_tokens",None),"output_tokens":getattr(usage,"output_tokens",None),"total_tokens":getattr(usage,"total_tokens",None)}





def _ai_safe_json_preview(value: Any, depth: int = 0) -> Any:
    """Small, redacted-ish structural preview for AI hypothesis generation."""
    if depth > 3:
        return "…"
    sensitive = re.compile(r"pass(word)?|secret|token|cookie|authorization|api[_-]?key|session|jwt|credential", re.I)
    if isinstance(value, dict):
        out = {}
        for k, v in list(value.items())[:24]:
            key = str(k)[:80]
            out[key] = "[REDACTED]" if sensitive.search(key) else _ai_safe_json_preview(v, depth + 1)
        return out
    if isinstance(value, list):
        return [_ai_safe_json_preview(v, depth + 1) for v in value[:3]] + ([f"… {len(value)-3} more"] if len(value) > 3 else [])
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value
    text = str(value)
    if len(text) <= 80 and not re.search(r"[A-Za-z0-9+/=_-]{32,}", text):
        return text
    return f"<{type(value).__name__}:{len(text)} chars>"


def _decode_http_b64(value: str | None) -> str:
    if not value:
        return ""
    try:
        import base64
        return base64.b64decode(value, validate=False).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _http_body(text: str) -> str:
    if "\r\n\r\n" in text:
        return text.split("\r\n\r\n", 1)[1]
    if "\n\n" in text:
        return text.split("\n\n", 1)[1]
    return ""


def _json_preview_from_http(text: str) -> Any:
    body = _http_body(text).strip()
    if not body or len(body) > 400_000:
        return None
    try:
        return _ai_safe_json_preview(json.loads(body))
    except Exception:
        return None


def _graph_http_evidence(conn, relevant_resource_ids: set[int] | None = None, limit: int = 24) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT e.id AS exchange_id,e.source,e.tool,e.status_code,e.query_json,e.request_b64,e.response_b64,
                  o.id AS operation_id,o.method,o.authenticated_observed,r.id AS resource_id,r.url,r.path,h.hostname
           FROM http_exchanges e
           JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id
           JOIN hosts h ON h.id=r.host_id
           ORDER BY CASE WHEN r.id IN (%s) THEN 0 ELSE 1 END, e.last_seen_at DESC LIMIT ?""" % (
               ",".join("?" for _ in (relevant_resource_ids or {0}))
           ), tuple(relevant_resource_ids or {0}) + (limit,)
    ).fetchall()
    out=[]
    for row in rows:
        req=_decode_http_b64(row["request_b64"]); resp=_decode_http_b64(row["response_b64"])
        try: q=json.loads(row["query_json"] or "{}")
        except Exception: q={}
        first_req=(req.splitlines()[0][:220] if req else f"{row['method']} {row['path']}")
        first_resp=(resp.splitlines()[0][:120] if resp else None)
        item={
            "exchange_id": int(row["exchange_id"]), "resource_id": int(row["resource_id"]), "operation_id": int(row["operation_id"]),
            "host": row["hostname"], "url": row["url"], "method": row["method"], "status": row["status_code"],
            "source": row["source"], "tool": row["tool"], "authenticated": bool(row["authenticated_observed"]),
            "request_line": first_req, "response_line": first_resp,
            "query": _ai_safe_json_preview(q),
            "request_json": _json_preview_from_http(req), "response_json": _json_preview_from_http(resp),
        }
        out.append(item)
    return out


def _meaningful_object_type(name: Any) -> bool:
    text = str(name or "").strip()
    low = text.lower()
    return bool(text) and not text.isdigit() and low not in {
        "object", "objeto", "id", "uuid", "ref", "reference", "referencia",
        "item", "entity", "entidad", "unknown", "desconocido", "owner", "role",
    } and len(text) > 2


def build_hypothesis_context_pack(conn, *, selected_node_id: str | None = None) -> dict[str, Any]:
    """Build the bounded cross-feature context used by Hypothesis Engine 2.0.

    This is intentionally descriptive.  It gives the model the same structured
    concepts the investigator sees in Negro (Identity, Flow, Object, State,
    Signal and authorization outcomes) without claiming that any relationship is
    a vulnerability.
    """
    context: dict[str, Any] = {
        "identities": [], "flows": [], "business_objects": [], "signals": [],
        "pattern_anomalies": [], "authorization_outcomes": [], "selected_context": [],
    }

    # Identity contexts + endpoints actually observed under each session/account.
    try:
        identities = conn.execute(
            """SELECT i.id,i.name,i.kind,COUNT(DISTINCT ei.exchange_id) request_count
               FROM identities i LEFT JOIN exchange_identities ei ON ei.identity_id=i.id
               GROUP BY i.id ORDER BY request_count DESC,lower(i.name) LIMIT 18"""
        ).fetchall()
    except Exception:
        identities = []
    for ident in identities:
        rows = conn.execute(
            """SELECT e.id exchange_id,e.status_code,o.method,r.id resource_id,r.path,h.hostname,e.last_seen_at
               FROM exchange_identities ei JOIN http_exchanges e ON e.id=ei.exchange_id
               JOIN resource_operations o ON o.id=e.operation_id
               JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id
               WHERE ei.identity_id=? ORDER BY e.last_seen_at DESC,e.id DESC LIMIT 100""",
            (int(ident["id"]),),
        ).fetchall()
        by_resource: dict[int, dict[str, Any]] = {}
        for row in rows:
            rid = int(row["resource_id"])
            item = by_resource.setdefault(rid, {
                "id": f"resource:{rid}", "resource_id": rid, "path": row["path"], "host": row["hostname"],
                "methods": set(), "statuses": set(), "request_ids": [],
            })
            item["methods"].add(str(row["method"] or "?").upper())
            if row["status_code"] is not None: item["statuses"].add(int(row["status_code"]))
            if len(item["request_ids"]) < 8: item["request_ids"].append(f"exchange:{int(row['exchange_id'])}")
        endpoints = []
        for item in list(by_resource.values())[:36]:
            item["methods"] = sorted(item["methods"]); item["statuses"] = sorted(item["statuses"])
            endpoints.append(item)
        context["identities"].append({
            "id": f"identity:{int(ident['id'])}", "identity_id": int(ident["id"]), "name": ident["name"],
            "kind": ident["kind"], "request_count": int(ident["request_count"] or 0), "endpoints": endpoints,
        })

    # Shared endpoint outcomes across identities.  These are observations only;
    # same/different status codes are prompts for investigation, not conclusions.
    outcome_rows: list[Any] = []
    try:
        outcome_rows = conn.execute(
            """SELECT i.id identity_id,i.name identity_name,r.id resource_id,r.path,h.hostname,o.method,e.status_code,e.id exchange_id
               FROM exchange_identities ei JOIN identities i ON i.id=ei.identity_id
               JOIN http_exchanges e ON e.id=ei.exchange_id JOIN resource_operations o ON o.id=e.operation_id
               JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id
               ORDER BY e.last_seen_at DESC,e.id DESC LIMIT 2600"""
        ).fetchall()
    except Exception:
        outcome_rows = []
    outcome_map: dict[int, dict[str, Any]] = {}
    for row in outcome_rows:
        rid = int(row["resource_id"])
        bucket = outcome_map.setdefault(rid, {"id": f"resource:{rid}", "resource_id": rid, "path": row["path"], "host": row["hostname"], "identities": {}})
        iid = int(row["identity_id"])
        actor = bucket["identities"].setdefault(iid, {"id": f"identity:{iid}", "name": row["identity_name"], "methods": set(), "statuses": set(), "request_ids": []})
        actor["methods"].add(str(row["method"] or "?").upper())
        if row["status_code"] is not None: actor["statuses"].add(int(row["status_code"]))
        if len(actor["request_ids"]) < 6: actor["request_ids"].append(f"exchange:{int(row['exchange_id'])}")
    shared = []
    for bucket in outcome_map.values():
        if len(bucket["identities"]) < 2: continue
        identities_out = []
        status_shapes = set()
        for actor in bucket["identities"].values():
            actor["methods"] = sorted(actor["methods"]); actor["statuses"] = sorted(actor["statuses"])
            status_shapes.add(tuple(actor["statuses"])); identities_out.append(actor)
        bucket["identities"] = identities_out
        bucket["different_status_pattern"] = len(status_shapes) > 1
        shared.append(bucket)
    shared.sort(key=lambda x: (0 if x["different_status_pattern"] else 1, -len(x["identities"]), str(x["path"])))
    context["authorization_outcomes"] = shared[:70]

    # Flow sequence + actor + meaningful business objects.
    try:
        flow_rows = conn.execute(
            """SELECT f.id,f.name,f.description,f.identity_id,i.name identity_name,f.updated_at
               FROM flows f LEFT JOIN identities i ON i.id=f.identity_id
               ORDER BY f.updated_at DESC,f.id DESC LIMIT 20"""
        ).fetchall()
    except Exception:
        flow_rows = []
    for flow in flow_rows:
        steps = [dict(r) for r in conn.execute(
            """SELECT fs.position,e.id exchange_id,e.status_code,o.method,r.id resource_id,r.path,h.hostname
               FROM flow_steps fs JOIN http_exchanges e ON e.id=fs.exchange_id
               JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id
               JOIN hosts h ON h.id=r.host_id WHERE fs.flow_id=? AND fs.included=1
               ORDER BY fs.position,fs.id LIMIT 36""", (int(flow["id"]),)
        ).fetchall()]
        for st in steps:
            st["id"] = f"exchange:{int(st['exchange_id'])}"; st["resource_ref"] = f"resource:{int(st['resource_id'])}"
        try:
            objects = [dict(r) for r in conn.execute(
                """SELECT DISTINCT bo.id,bt.name object_type,COALESCE(bo.identifier_raw,bo.identifier_preview,'') identifier
                   FROM flow_steps fs JOIN business_object_observations boo ON boo.exchange_id=fs.exchange_id
                   JOIN business_objects bo ON bo.id=boo.business_object_id JOIN business_object_types bt ON bt.id=bo.object_type_id
                   WHERE fs.flow_id=? AND fs.included=1 ORDER BY bo.id LIMIT 24""", (int(flow["id"]),)
            ).fetchall()]
        except Exception:
            objects = []
        objects = [{"id": f"object:{int(o['id'])}", **o} for o in objects if _meaningful_object_type(o.get("object_type"))]
        context["flows"].append({
            "id": f"flow:{int(flow['id'])}", "flow_id": int(flow["id"]), "name": flow["name"],
            "description": str(flow["description"] or "")[:400],
            "identity": {"id": f"identity:{int(flow['identity_id'])}", "name": flow["identity_name"]} if flow["identity_id"] else None,
            "steps": steps, "objects": objects,
        })

    # Meaningful object instances + where/under whom/state they were observed.
    try:
        object_rows = conn.execute(
            """SELECT bo.id,bt.name object_type,COALESCE(bo.identifier_raw,bo.identifier_preview,'') identifier,bo.last_seen_at
               FROM business_objects bo JOIN business_object_types bt ON bt.id=bo.object_type_id
               ORDER BY bo.last_seen_at DESC,bo.id DESC LIMIT 120"""
        ).fetchall()
    except Exception:
        object_rows = []
    for obj in object_rows:
        if not _meaningful_object_type(obj["object_type"]): continue
        oid = int(obj["id"]); value = str(obj["identifier"] or "")
        observations = [dict(r) for r in conn.execute(
            """SELECT DISTINCT e.id exchange_id,o.method,r.id resource_id,r.path,h.hostname,i.id identity_id,i.name identity_name
               FROM business_object_observations boo JOIN http_exchanges e ON e.id=boo.exchange_id
               JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id
               JOIN hosts h ON h.id=r.host_id LEFT JOIN exchange_identities ei ON ei.exchange_id=e.id
               LEFT JOIN identities i ON i.id=ei.identity_id WHERE boo.business_object_id=?
               ORDER BY e.last_seen_at DESC,e.id DESC LIMIT 28""", (oid,)
        ).fetchall()]
        for ob in observations:
            ob["request_ref"] = f"exchange:{int(ob['exchange_id'])}"; ob["resource_ref"] = f"resource:{int(ob['resource_id'])}"
            if ob.get("identity_id"): ob["identity_ref"] = f"identity:{int(ob['identity_id'])}"
        states = []
        try:
            states = [dict(r) for r in conn.execute(
                """SELECT t.state_field,COALESCE(o.state_value_raw,o.state_value_preview,'') state_value,o.observed_at,o.exchange_id
                   FROM business_state_observations o JOIN business_state_tracks t ON t.id=o.track_id
                   WHERE lower(t.object_type)=lower(?) AND COALESCE(o.object_identifier_value_raw,o.object_identifier_value_preview,'')=?
                   ORDER BY o.observed_at,o.id LIMIT 30""", (obj["object_type"], value)
            ).fetchall()]
            for st in states: st["request_ref"] = f"exchange:{int(st['exchange_id'])}"
        except Exception:
            states = []
        context["business_objects"].append({
            "id": f"object:{oid}", "object_id": oid, "type": obj["object_type"], "identifier": value,
            "observations": observations, "states": states,
        })
        if len(context["business_objects"]) >= 42: break

    # Deterministic Signals, including Custom Signals and their exact reason.
    try:
        signal_rows = conn.execute(
            """SELECT s.id,s.exchange_id,s.resource_id,s.title,s.kind,s.category,s.severity,s.source,s.why_json,s.evidence_json,
                      o.method,r.path,h.hostname,i.id identity_id,i.name identity_name
               FROM signal_occurrences s LEFT JOIN http_exchanges e ON e.id=s.exchange_id
               LEFT JOIN resource_operations o ON o.id=e.operation_id LEFT JOIN resources r ON r.id=COALESCE(s.resource_id,o.resource_id)
               LEFT JOIN hosts h ON h.id=r.host_id LEFT JOIN exchange_identities ei ON ei.exchange_id=s.exchange_id
               LEFT JOIN identities i ON i.id=ei.identity_id
               WHERE s.dismissed_at IS NULL ORDER BY s.last_seen_at DESC,s.id DESC LIMIT 100"""
        ).fetchall()
    except Exception:
        signal_rows = []
    for row in signal_rows:
        try: why = json.loads(row["why_json"] or "{}")
        except Exception: why = {}
        try: evidence = json.loads(row["evidence_json"] or "{}")
        except Exception: evidence = {}
        context["signals"].append({
            "id": f"signal:{int(row['id'])}", "signal_id": int(row["id"]), "title": row["title"], "kind": row["kind"],
            "category": row["category"], "severity": row["severity"], "source": row["source"],
            "request_ref": f"exchange:{int(row['exchange_id'])}" if row["exchange_id"] else None,
            "resource_ref": f"resource:{int(row['resource_id'])}" if row["resource_id"] else None,
            "method": row["method"], "path": row["path"], "host": row["hostname"],
            "identity": {"id": f"identity:{int(row['identity_id'])}", "name": row["identity_name"]} if row["identity_id"] else None,
            "why": why, "evidence": evidence,
        })

    # Conservative pattern differences already calculated by Business Objects.
    try:
        import negro_objects as object_tools
        overview = object_tools.overview(conn, limit=80)
        for card in overview.get("anomaly_cards") or []:
            obj = card.get("object") or {}; oid = int(obj.get("id") or 0)
            for idx, anomaly in enumerate(card.get("items") or []):
                context["pattern_anomalies"].append({
                    "id": f"anomaly:{oid}:{idx}", "object_ref": f"object:{oid}",
                    "object": str(obj.get("display_label") or f"{obj.get('object_type','Object')} {obj.get('display_value','')}").strip(),
                    "kind": anomaly.get("kind"), "title": anomaly.get("title"), "message": anomaly.get("message"),
                    "baseline": anomaly.get("baseline") or anomaly.get("previous"), "current": anomaly.get("current"),
                })
                if len(context["pattern_anomalies"]) >= 40: break
            if len(context["pattern_anomalies"]) >= 40: break
    except Exception:
        pass

    # Bring the exact selected semantic item to the front of the AI context.
    if selected_node_id:
        selected = []
        for key in ("identities", "flows", "business_objects", "signals", "pattern_anomalies", "authorization_outcomes"):
            for item in context[key]:
                if str(item.get("id") or "") == str(selected_node_id):
                    selected.append({"kind": key, "item": item})
                elif key == "authorization_outcomes" and str(item.get("id") or "") == str(selected_node_id):
                    selected.append({"kind": key, "item": item})
        context["selected_context"] = selected[:4]

    context["summary"] = {
        "identities": len(context["identities"]), "flows": len(context["flows"]),
        "business_objects": len(context["business_objects"]), "signals": len(context["signals"]),
        "pattern_anomalies": len(context["pattern_anomalies"]), "shared_identity_endpoints": len(context["authorization_outcomes"]),
    }
    return context


def build_graph_ai_payload(conn, domain: str, graph_data: dict[str, Any], *, selected_node_id: str | None = None, max_chars: int = 220_000) -> tuple[str, str]:
    """Build compact structured graph context. Never dumps full HTTP bodies."""
    init_schema(conn)
    nodes = list(graph_data.get("nodes") or [])
    edges = list(graph_data.get("edges") or [])
    node_by_id = {str(n.get("id")): n for n in nodes}

    # If a node is selected, include its two-hop neighborhood first, then a concise global summary.
    relevant_ids: set[str] = set()
    if selected_node_id and selected_node_id in node_by_id:
        relevant_ids.add(selected_node_id)
        frontier = {selected_node_id}
        for _ in range(2):
            nxt: set[str] = set()
            for e in edges:
                a, b = str(e.get("source")), str(e.get("target"))
                if a in frontier and b not in relevant_ids:
                    relevant_ids.add(b); nxt.add(b)
                if b in frontier and a not in relevant_ids:
                    relevant_ids.add(a); nxt.add(a)
            frontier = nxt

    def compact_node(n: dict[str, Any]) -> dict[str, Any]:
        meta = dict(n.get("meta") or {})
        allowed = {k: meta.get(k) for k in (
            "id","url","host","method","status","seen_count","authenticated","source","tool",
            "review","classification","priority","type","why","next_test","severity","updated_at","last_seen_at","test_summary",
            "methods","method_count","identity","requests","objects","flows","object_type","identifier","identifier_field",
            "field","message","baseline","current","capture_status","signal_count","hypothesis_count"
        ) if meta.get(k) not in (None, "")}
        return {"id": n.get("id"), "type": n.get("type"), "label": n.get("label"), "state": n.get("state"), "meta": allowed}

    important_types = {"target","host","resource","operation","javascript","observation","lead","finding","source","identity","flow","object","request","state","anomaly"}
    global_nodes = [n for n in nodes if n.get("type") in important_types]
    global_nodes.sort(key=lambda n: (0 if n.get("state") in ("finding","interesting") else 1, str(n.get("type")), str(n.get("label"))))
    selected_nodes = [node_by_id[i] for i in relevant_ids if i in node_by_id]
    ordered_nodes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for n in selected_nodes + global_nodes:
        nid = str(n.get("id"))
        if nid and nid not in seen:
            seen.add(nid); ordered_nodes.append(compact_node(n))
        if len(ordered_nodes) >= 260:
            break

    kept_ids = {str(n["id"]) for n in ordered_nodes}
    compact_edges = [
        {"source": e.get("source"), "relation": e.get("relation"), "target": e.get("target"), "provenance": (e.get("meta") or {}).get("source")}
        for e in edges if str(e.get("source")) in kept_ids and str(e.get("target")) in kept_ids
    ][:420]

    existing = []
    for row in conn.execute("SELECT id,title,lead_type,status,why_interesting,next_test,source,updated_at FROM leads_v2 WHERE COALESCE(rule_active,1)=1 ORDER BY updated_at DESC LIMIT 120").fetchall():
        existing.append(dict(row))
    findings = [dict(r) for r in conn.execute("SELECT id,title,severity,status,updated_at FROM findings ORDER BY updated_at DESC LIMIT 80").fetchall()]
    # Test coverage is optional UX memory, not a synthetic task list for the AI.
    # Only send checks the investigator actually touched (or that an engine recorded).
    # Auto-generated untouched `pending/recommended` rows must not bias Give me ideas.
    testing_coverage = []
    for tr in conn.execute(
        """SELECT t.operation_id,t.test_key,t.label,t.category,t.status,t.notes,t.source,t.updated_at,o.method,r.id resource_id,r.path
           FROM operation_test_coverage t JOIN resource_operations o ON o.id=t.operation_id JOIN resources r ON r.id=o.resource_id
           WHERE NOT (t.status='pending' AND COALESCE(TRIM(t.notes),'')='' AND COALESCE(t.source,'recommended')='recommended')
           ORDER BY CASE t.status WHEN 'interesting' THEN 0 WHEN 'confirmed' THEN 1 WHEN 'testing' THEN 2 WHEN 'negative' THEN 3 WHEN 'not_applicable' THEN 4 ELSE 5 END, t.updated_at DESC LIMIT 320"""
    ).fetchall():
        item=dict(tr)
        item["notes"] = str(item.get("notes") or "")[:500]
        testing_coverage.append(item)
    relevant_resource_ids: set[int] = set()
    for n in ordered_nodes:
        if n.get("type") == "resource":
            try: relevant_resource_ids.add(int(str(n.get("id")).split(":",1)[1]))
            except Exception: pass
        elif n.get("type") == "operation":
            try:
                op_id = int(str(n.get("id")).split(":",1)[1])
                rr = conn.execute("SELECT resource_id FROM resource_operations WHERE id=?", (op_id,)).fetchone()
                if rr: relevant_resource_ids.add(int(rr["resource_id"]))
            except Exception: pass
    http_evidence = _graph_http_evidence(conn, relevant_resource_ids, limit=24)
    correlated_context = build_hypothesis_context_pack(conn, selected_node_id=selected_node_id)

    envelope = {
        "target": domain,
        "selected_node_id": selected_node_id,
        "graph_summary": graph_data.get("counts") or {},
        "nodes": ordered_nodes,
        "edges": compact_edges,
        "existing_hypotheses": existing,
        "confirmed_findings": findings,
        "test_coverage": testing_coverage,
        "http_evidence": http_evidence,
        "correlated_context": correlated_context,
        "instructions_context": {
            "prompt_version": GRAPH_AI_PROMPT_VERSION,
            "negative_is_knowledge": True,
            "do_not_repeat_negative_or_discarded": True,
            "full_http_bodies_included": False,
            "authorized_testing_only": True,
            "test_coverage_is_manual_memory": True,
            "untouched_recommended_checks_are_excluded": True,
            "negative_tests_should_not_repeat": True,
            "hypothesis_engine": "2.0",
            "context_fusion": ["identity", "flow", "business_object", "state", "signal", "pattern_anomaly", "authorization_outcome", "http"],
        },
    }
    payload = "NEGRO_GRAPH_EVIDENCE\n" + json.dumps(envelope, ensure_ascii=False, indent=2)
    payload = intel.redact_sensitive_literals(payload)[:max_chars]
    digest = hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()
    return payload, digest


def _graph_ideas_json_schema() -> dict[str, Any]:
    """Strict schema for Responses API Structured Outputs."""
    step_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "step": {"type": "integer"},
            "action": {"type": "string"},
            "what_to_watch": {"type": "string"},
        },
        "required": ["step", "action", "what_to_watch"],
    }
    needed_piece_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "key_pattern": {"type": "string"},
            "description": {"type": "string"},
            "identity_mode": {"type": "string", "enum": ["any", "specific", "different"]},
            "identity_id": {"type": ["integer", "null"]},
        },
        "required": ["key_pattern", "description", "identity_mode", "identity_id"],
    }
    hypothesis_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "title": {"type": "string"},
            "type": {"type": "string", "enum": ["authorization", "business_logic", "state_transition", "cors", "oauth", "javascript", "api", "feature_flag", "other"]},
            "strength": {"type": "string", "enum": ["strong", "medium", "exploratory"]},
            "investigation_priority": {"type": "string", "enum": ["high", "medium", "quick"]},
            "priority_reasons": {"type": "array", "items": {"type": "string"}},
            "plain_language": {"type": "string"},
            "facts": {"type": "array", "items": {"type": "string"}},
            "inference": {"type": "string"},
            "unknowns": {"type": "array", "items": {"type": "string"}},
            "why_interesting": {"type": "string"},
            "suggested_investigation": {"type": "string"},
            "steps": {"type": "array", "items": step_schema},
            "confirm_if": {"type": "string"},
            "discard_if": {"type": "string"},
            "node_ids": {"type": "array", "items": {"type": "string"}},
            "context_sources": {"type": "array", "items": {"type": "string", "enum": ["http", "identity", "flow", "business_object", "state", "signal", "pattern_anomaly", "authorization_outcome"]}},
            "needed_pieces": {"type": "array", "items": needed_piece_schema},
        },
        "required": ["title", "type", "strength", "investigation_priority", "priority_reasons", "plain_language", "facts", "inference", "unknowns", "why_interesting", "suggested_investigation", "steps", "confirm_if", "discard_if", "node_ids", "context_sources", "needed_pieces"],
    }
    unexplored_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"area": {"type": "string"}, "reason": {"type": "string"}},
        "required": ["area", "reason"],
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "summary": {"type": "string"},
            "hypotheses": {"type": "array", "items": hypothesis_schema},
            "unexplored_areas": {"type": "array", "items": unexplored_schema},
        },
        "required": ["summary", "hypotheses", "unexplored_areas"],
    }


def _safe_json_object(text: str, fallback: dict[str, Any]) -> dict[str, Any]:
    """Parse model JSON without ever surfacing a JSONDecodeError to the UI."""
    raw = (text or "").strip()
    candidates = [raw]
    if raw.startswith("```"):
        lines = raw.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        candidates.append("\n".join(lines).strip())
    a, b = raw.find("{"), raw.rfind("}")
    if a >= 0 and b > a:
        candidates.append(raw[a:b+1])
    last_error = None
    for candidate in candidates:
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception as exc:
            last_error = exc
    result = dict(fallback)
    result["parse_warning"] = f"La IA devolvió una respuesta no estructurada; no se guardaron hipótesis. {last_error}" if last_error else "La IA devolvió una respuesta vacía."
    return result


def graph_ai_result_is_cacheable(result: Any) -> bool:
    """Only reuse results that were actually parsed as structured output.

    A valid structured response may legitimately contain zero hypotheses. The key
    distinction is parse success, not hypothesis count.
    """
    if not isinstance(result, dict):
        return False
    if result.get("parse_warning"):
        return False
    if result.get("structured_ok") is False:
        return False
    if not isinstance(result.get("hypotheses"), list):
        return False
    if not isinstance(result.get("unexplored_areas"), list):
        return False
    return isinstance(result.get("summary"), str)


def _graph_ai_log(event: str, **fields: Any) -> None:
    """Safe diagnostics for Graph AI. Never log prompts, bodies, cookies or model text."""
    clean = []
    for key, value in fields.items():
        if value is None:
            continue
        text = str(value).replace("\n", " ")[:240]
        clean.append(f"{key}={text}")
    suffix = " · " + " · ".join(clean) if clean else ""
    print(f"[AI graph] {event}{suffix}", file=sys.stderr, flush=True)


def _response_usage_dict(response: Any) -> dict[str, Any]:
    usage = getattr(response, "usage", None)
    details = getattr(usage, "output_tokens_details", None) if usage else None
    return {
        "input_tokens": getattr(usage, "input_tokens", None),
        "output_tokens": getattr(usage, "output_tokens", None),
        "reasoning_tokens": getattr(details, "reasoning_tokens", None),
        "total_tokens": getattr(usage, "total_tokens", None),
    }


def _response_refusal_text(response: Any) -> str | None:
    try:
        for item in list(getattr(response, "output", None) or []):
            for content in list(getattr(item, "content", None) or []):
                if getattr(content, "type", None) == "refusal":
                    value = getattr(content, "refusal", None)
                    if value:
                        return str(value)[:800]
    except Exception:
        return None
    return None


def _graph_ai_failure(summary: str, *, error_type: str, retryable: bool, diagnostics: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "summary": summary,
        "hypotheses": [],
        "unexplored_areas": [],
        "structured_ok": False,
        "error_type": error_type,
        "retryable": retryable,
        "diagnostics": diagnostics or {},
    }


def run_openai_graph_ideas(payload: str, *, model: str, output_tokens: int, exploratory_retry: bool = False, retry_output_tokens: int | None = None, reasoning_effort: str = "low") -> tuple[dict[str, Any], dict[str, Any]]:
    key = intel.load_secrets().get("OPENAI_API_KEY")
    if not key:
        raise RuntimeError(f"Falta OPENAI_API_KEY en {intel.SECRETS_PATH}")
    try:
        from openai import OpenAI  # type: ignore
    except Exception as exc:
        raise RuntimeError("El SDK de OpenAI no está disponible. Ejecuta ./install-web.sh") from exc
    system = """Eres la mano derecha de un pentester durante una investigación AUTORIZADA. Responde SIEMPRE en español claro, concreto, ofensivo y didáctico.
No eres un chatbot genérico: no listes OWASP por rutina, no inventes endpoints/roles/respuestas y no declares una vulnerabilidad sin evidencia.
Tu salida debe permitir ejecutar la SIGUIENTE PRUEBA MANUAL con Burp/Navegador sin tener que adivinar tu intención.

MODELO DE NEGRO:
- RULE = conocimiento determinístico configurable.
- SIGNAL = hecho observado por una Rule en tráfico/evidencia real.
- HYPOTHESIS = inferencia tuya, generada sólo porque el humano pidió este análisis.
- INVESTIGATION = trabajo que el humano decide promover; tú NO creas findings ni cierras investigaciones.

Para CADA hipótesis separa explícitamente:
1. facts: hechos observados y verificables en la evidencia.
2. inference: qué relación o explicación propones.
3. unknowns: qué todavía NO sabemos y evita afirmar.
4. suggested_investigation/steps: la prueba manual mínima que resolvería esas incógnitas.
Una Rule/Signal aislada no debe convertirse automáticamente en una hipótesis si no aporta una pregunta de investigación de valor.

Usa exclusivamente el grafo, el historial y el resumen HTTP sanitizado suministrados. El bloque http_evidence puede incluir línea de request, query y preview JSON limitada; úsalo para nombrar requests, parámetros, campos y respuestas REALES.

HYPOTHESIS ENGINE 2.0 — CONTEXTO CORRELACIONADO:
- correlated_context.identities contiene cuentas/sesiones reales y los endpoints/status observados bajo cada una. No asumas nombres de rol.
- correlated_context.authorization_outcomes muestra endpoints vistos bajo 2+ identidades. 200/200, 200/403 o cualquier diferencia es sólo una observación; razona sobre el patrón antes de proponer una prueba.
- correlated_context.flows contiene secuencias reales. Úsalo para detectar pasos ausentes, caminos alternativos o la misma operación bajo distinto actor.
- correlated_context.business_objects contiene objetos con significado y dónde/por quién aparecieron. No eleves IDs genéricos sin contexto.
- correlated_context.signals son coincidencias determinísticas, incluidas Custom Signals del investigador. Un Signal NO prueba una vulnerabilidad; úsalo como evidencia que puede reforzar una pregunta.
- correlated_context.pattern_anomalies son diferencias conservadoras ya observadas; no las conviertas directamente en findings.
- Correlaciona varias fuentes cuando aporte valor. Prefiere una hipótesis respaldada por Identity + endpoint + Object/Flow/Signal frente a una idea genérica basada sólo en el nombre de una ruta.
- node_ids puede citar IDs REALES de cualquiera de estos bloques: resource:, operation:, exchange:, identity:, flow:, object:, signal:, anomaly:.
- context_sources debe decir qué tipos de contexto sostienen realmente la hipótesis. No marques una fuente que no hayas usado.
- needed_pieces representa piezas concretas que faltan para poder continuar la investigación, especialmente identificadores/objetos. Úsalo sólo cuando la hipótesis esté realmente bloqueada por algo observable que Negro pueda encontrar después.
- En needed_pieces.key_pattern usa una key real observada o una variante simple/glob, por ejemplo order_id, cardId o *_id. No inventes nombres.
- identity_mode: any si sirve cualquier contexto; specific si necesitas el valor bajo una identidad concreta; different si necesitas observarlo bajo una identidad distinta de la indicada. identity_id debe ser un ID REAL de correlated_context.identities o null.
- Si no falta ninguna pieza que Negro pueda reconocer posteriormente, devuelve needed_pieces=[].

NEGATIVE/discarded son conocimiento: no repitas la misma prueba salvo evidencia nueva. Una señal interesting no equivale a finding.
El bloque test_coverage contiene ÚNICAMENTE memoria de pruebas que el investigador o un motor realmente tocó. No es una checklist obligatoria ni una fuente de ideas por sí sola. Respeta sus estados: negative/not_applicable no se repiten sin evidencia nueva; testing no se propone como si estuviera pendiente; interesting/confirmed sirven como contexto. Los checks recomendados que nunca fueron tocados se excluyen deliberadamente.

ORDEN DE PRIORIDAD OFENSIVA:
1. Superficie nueva controlada por cliente, autorización server-side desconocida, cross-role/cross-account, objetos/IDs, estados terminales, métodos alternativos, parámetros que gobiernan operaciones sensibles, endpoints/rutas nuevas desde JS o feature flags.
2. Lógica de negocio donde exista una OPERACIÓN SENSIBLE relacionada: aplicar/canjear promoción, pagar, refund, crédito, wallet, crear/modificar/borrar, invitaciones, límites, cambios de estado. No te quedes en comprobar si la UI “se ve coherente”: pregunta qué operación consume esa condición y dónde la valida el backend.
3. Comprobaciones simples y probablemente públicas (por ejemplo quitar cookies a un catálogo) sólo como investigation_priority=quick, con una prueba corta y criterio de descarte inmediato. No les des el mismo protagonismo que a una superficie ofensiva nueva.

REGLAS ESPECÍFICAS:
- Feature flags/config cliente: si una respuesta contiene active/enabled/flag, propone interceptar ESA RESPONSE, cambiar UNA bandera a la vez, recargar, observar nuevas rutas/controles/requests y luego probar directamente el endpoint nuevo para verificar autorización server-side. Mostrar una función oculta no es vulnerabilidad por sí solo.
- Business logic: identifica la condición de negocio y la operación sensible que depende de ella. Ejemplo: si ves state/until/regional/limit, busca dónde se aplica/canjea/ejecuta y verifica si el servidor vuelve a validar la condición.
- Authorization: cuando existan dos contextos/identidades o una operación con object id, explica exactamente qué request comparar y qué debe permanecer constante.
- Cambios de estado: pueden ser necesarios para validar una hipótesis. Hazlos únicamente sobre cuentas/datos autorizados por el investigador y minimiza impacto. No impongas una prohibición genérica a POST/PUT/DELETE.
- No sugieras brute force de credenciales, phishing, DoS, mass scanning, acciones destructivas ni fuera de scope.
- No incluyas secretos ni pidas exfiltrar datos de terceros.

Para cada hipótesis:
- investigation_priority: high si puede abrir superficie ofensiva nueva o probar enforcement crítico; medium si es una relación prometedora pero faltan piezas; quick si es una comprobación corta de descarte.
- priority_reasons: 1-4 etiquetas cortas basadas en evidencia, por ejemplo “client-controlled behavior”, “backend enforcement unknown”, “cross-role”, “state not tested”, “new attack surface possible”. No uses probabilidades.
- title: di QUÉ intentar, no una frase abstracta.
- plain_language: explica qué estamos intentando conseguir y por qué, como para alguien que conoce Burp pero no adivina tu intención.
- steps: 2 a 5 pasos ejecutables y concisos. Cuando aplique, di literalmente qué request mandar a Repeater/Proxy, qué header/query/campo cambiar, si debes interceptar REQUEST o RESPONSE, y qué comparar.
- what_to_watch: breve y observable.
- suggested_investigation: una sola frase con el objetivo ofensivo, no “revisar comportamiento”.
- confirm_if y discard_if observables y concretos.
- node_ids: sólo IDs REALES del contexto, incluyendo identity:/flow:/object:/signal:/anomaly: cuando sean parte de la correlación.
- context_sources: enumera únicamente las capas realmente usadas para razonar esa hipótesis.
- needed_pieces: 0-4 piezas concretas y verificables que impedirían ejecutar la siguiente prueba hoy. No conviertas cada unknown en una pieza pendiente.
- Sé conciso: cada hipótesis debe caber cómodamente en una tarjeta; evita repetir la misma explicación en varias secciones.

Devuelve únicamente JSON válido que cumpla el schema suministrado.
"""
    if exploratory_retry:
        system += """

SEGUNDO INTENTO EXPLORATORIO:
El primer análisis estructurado no encontró hipótesis. Busca ahora 3-5 oportunidades ACOTADAS que sigan ancladas en evidencia real, priorizando diferencias de sesión observables, métodos alternativos, client-side trust/feature flags, parámetros reales, rutas/JS observados, cambios de estado y lógica de negocio con una operación sensible. Usa test_coverage sólo como memoria para no repetir lo ya probado; no conviertas checks automáticos en tareas.
No inventes vulnerabilidades ni endpoints. Si una comprobación es débil pero barata, márcala quick. Si aun así no hay nada defendible, devuelve hypotheses=[] y explica en unexplored_areas qué evidencia falta para avanzar.
"""
    client = OpenAI(api_key=key)
    schema_format = {
        "type": "json_schema",
        "name": "negro_graph_hypotheses",
        "description": "Hipótesis accionables basadas únicamente en la evidencia estructurada de Negro.",
        "schema": _graph_ideas_json_schema(),
        "strict": True,
    }
    budgets = [max(1200, int(output_tokens))]
    if retry_output_tokens is not None and int(retry_output_tokens) > budgets[0]:
        budgets.append(int(retry_output_tokens))
    total_usage = {"input_tokens":0,"output_tokens":0,"reasoning_tokens":0,"total_tokens":0,"api_attempts":0}
    diagnostics: list[dict[str, Any]] = []
    for attempt, budget in enumerate(budgets, start=1):
        _graph_ai_log("request", model=model, attempt=attempt, exploratory=exploratory_retry, budget=budget, reasoning=reasoning_effort, payload_chars=len(payload))
        try:
            response = client.responses.create(
                model=model,
                reasoning={"effort":reasoning_effort},
                max_output_tokens=budget,
                instructions=system,
                input=payload,
                text={"format": schema_format},
            )
        except TypeError as exc:
            raise RuntimeError(
                "El SDK de OpenAI instalado no soporta Structured Outputs para Responses API. "
                "Ejecuta ./install-web.sh para actualizar dependencias y vuelve a intentar."
            ) from exc
        except Exception as exc:
            _graph_ai_log("api_error", model=model, attempt=attempt, error=type(exc).__name__, message=str(exc)[:180])
            return _graph_ai_failure(
                "La llamada a OpenAI falló antes de completar la respuesta. Puedes reintentar.",
                error_type="api_error", retryable=True, diagnostics={"exception":type(exc).__name__}
            ), total_usage

        status = str(getattr(response, "status", "unknown") or "unknown")
        incomplete = getattr(response, "incomplete_details", None)
        incomplete_reason = getattr(incomplete, "reason", None) if incomplete else None
        error_obj = getattr(response, "error", None)
        error_code = getattr(error_obj, "code", None) if error_obj else None
        refusal = _response_refusal_text(response)
        attempt_usage = _response_usage_dict(response)
        total_usage["api_attempts"] += 1
        for key_name in ("input_tokens","output_tokens","reasoning_tokens","total_tokens"):
            value = attempt_usage.get(key_name)
            if isinstance(value, int):
                total_usage[key_name] = int(total_usage.get(key_name) or 0) + value
        diag = {
            "attempt": attempt, "status": status, "budget": budget,
            "incomplete_reason": incomplete_reason, "error_code": error_code,
            "output_chars": len(getattr(response, "output_text", "") or ""),
            **attempt_usage,
        }
        diagnostics.append(diag)
        _graph_ai_log("response", model=model, **diag)

        if refusal:
            _graph_ai_log("refusal", model=model, attempt=attempt)
            result = _graph_ai_failure(
                "El modelo rechazó generar hipótesis para esta solicitud. No se guardó ni cacheó el resultado.",
                error_type="refusal", retryable=False, diagnostics={"attempts":diagnostics}
            )
            result["refusal"] = refusal
            total_usage["response_status"] = status
            total_usage["diagnostics"] = diagnostics
            return result, total_usage

        if status == "incomplete":
            max_token_reason = str(incomplete_reason or "").lower() in {"max_tokens","max_output_tokens"}
            if max_token_reason and attempt < len(budgets):
                _graph_ai_log("retry_larger_budget", model=model, from_budget=budget, to_budget=budgets[attempt])
                continue
            summary = (
                f"La respuesta quedó incompleta por límite de salida ({incomplete_reason or 'desconocido'}). "
                "No se guardó ni cacheó; puedes reintentar."
                if max_token_reason else
                f"OpenAI devolvió una respuesta incompleta ({incomplete_reason or 'razón no informada'}). No se guardó ni cacheó."
            )
            result = _graph_ai_failure(summary, error_type="incomplete", retryable=True, diagnostics={"attempts":diagnostics})
            total_usage["response_status"] = status
            total_usage["incomplete_reason"] = incomplete_reason
            total_usage["diagnostics"] = diagnostics
            return result, total_usage

        if status not in {"completed","unknown"}:
            result = _graph_ai_failure(
                f"OpenAI terminó la generación con estado {status}. No se guardó ni cacheó el resultado.",
                error_type=status or "response_error", retryable=status in {"failed","cancelled"}, diagnostics={"attempts":diagnostics}
            )
            total_usage["response_status"] = status
            total_usage["diagnostics"] = diagnostics
            return result, total_usage

        text = getattr(response, "output_text", "") or ""
        if not text.strip():
            result = _graph_ai_failure(
                "OpenAI marcó la respuesta como completada pero no devolvió contenido estructurado. No se guardó ni cacheó.",
                error_type="empty_output", retryable=True, diagnostics={"attempts":diagnostics}
            )
            total_usage["response_status"] = status
            total_usage["diagnostics"] = diagnostics
            return result, total_usage

        result = _safe_json_object(text, {"summary":"La respuesta completó pero no pudo validarse como JSON estructurado. No se guardó ni cacheó; intenta de nuevo.","hypotheses":[],"unexplored_areas":[]})
        result["structured_ok"] = not bool(result.get("parse_warning"))
        if not result["structured_ok"]:
            result["error_type"] = "invalid_structured_output"
            result["retryable"] = True
            result["diagnostics"] = {"attempts":diagnostics}
            _graph_ai_log("parse_invalid", model=model, attempt=attempt, output_chars=len(text))
        if not isinstance(result.get("hypotheses"), list):
            result["hypotheses"] = []
        result["hypotheses"] = result["hypotheses"][:5]
        total_usage["response_status"] = status
        total_usage["diagnostics"] = diagnostics
        return result, total_usage

    result = _graph_ai_failure("No fue posible completar una respuesta estructurada.", error_type="incomplete", retryable=True, diagnostics={"attempts":diagnostics})
    total_usage["diagnostics"] = diagnostics
    return result, total_usage

def hypothesis_refs_from_nodes(conn, node_ids: list[str]) -> dict[str, Any]:
    """Resolve graph/context refs into human-actionable HTTP/resource references."""
    # Hypothesis Engine 2.0 may cite semantic context refs that are not HTTP
    # nodes themselves. Expand them to a bounded set of Requests so Hunt still
    # lands on evidence the investigator can open in Burp/Negro.
    expanded = list(node_ids or [])
    for nid in list(node_ids or [])[:24]:
        try:
            if str(nid).startswith("signal:"):
                sid = int(str(nid).split(":", 1)[1])
                row = conn.execute("SELECT exchange_id,resource_id FROM signal_occurrences WHERE id=?", (sid,)).fetchone()
                if row and row["exchange_id"]:
                    expanded.append(f"exchange:{int(row['exchange_id'])}")
                elif row and row["resource_id"]:
                    expanded.append(f"resource:{int(row['resource_id'])}")
            elif str(nid).startswith("flow:"):
                fid = int(str(nid).split(":", 1)[1])
                steps = conn.execute("SELECT exchange_id FROM flow_steps WHERE flow_id=? AND included=1 ORDER BY position,id LIMIT 3", (fid,)).fetchall()
                for row in steps:
                    expanded.append(f"exchange:{int(row['exchange_id'])}")
            elif str(nid).startswith("object:"):
                oid = int(str(nid).split(":", 1)[1])
                rows = conn.execute("SELECT DISTINCT exchange_id FROM business_object_observations WHERE business_object_id=? ORDER BY observed_at DESC,id DESC LIMIT 3", (oid,)).fetchall()
                for row in rows:
                    expanded.append(f"exchange:{int(row['exchange_id'])}")
        except Exception:
            continue
    node_ids = list(dict.fromkeys(str(x) for x in expanded if str(x)))[:40]
    refs: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    resource_id = None
    primary_method = None
    primary_exchange_id = None
    for nid in node_ids[:24]:
        if nid.startswith("operation:"):
            try: op_id = int(nid.split(":", 1)[1])
            except Exception: continue
            rr = conn.execute("""SELECT o.id,o.method,o.last_status,r.id resource_id,r.path,r.query,r.url,h.hostname
                                 FROM resource_operations o JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id WHERE o.id=?""", (op_id,)).fetchone()
            if not rr: continue
            ex = conn.execute("SELECT id,status_code,source,tool FROM http_exchanges WHERE operation_id=? ORDER BY last_seen_at DESC LIMIT 1", (op_id,)).fetchone()
            key=("operation",op_id)
            if key not in seen:
                seen.add(key); refs.append({"kind":"operation","id":op_id,"method":rr["method"],"resource_id":int(rr["resource_id"]),"path":rr["path"],"query":rr["query"],"url":rr["url"],"host":rr["hostname"],"status":rr["last_status"],"exchange_id":int(ex["id"]) if ex else None,"exchange_status":ex["status_code"] if ex else None,"source":ex["source"] if ex else None,"tool":ex["tool"] if ex else None})
            resource_id = resource_id or int(rr["resource_id"]); primary_method = primary_method or rr["method"]; primary_exchange_id = primary_exchange_id or (int(ex["id"]) if ex else None)
        elif nid.startswith("resource:"):
            try: rid = int(nid.split(":", 1)[1])
            except Exception: continue
            rr = conn.execute("SELECT r.id,r.path,r.query,r.url,h.hostname FROM resources r JOIN hosts h ON h.id=r.host_id WHERE r.id=?", (rid,)).fetchone()
            if rr and ("resource",rid) not in seen:
                seen.add(("resource",rid)); refs.append({"kind":"resource","id":rid,"resource_id":rid,"path":rr["path"],"query":rr["query"],"url":rr["url"],"host":rr["hostname"]})
                resource_id = resource_id or rid
        elif nid.startswith("request:") or nid.startswith("exchange:"):
            try: exid = int(nid.split(":", 1)[1])
            except Exception: continue
            ex = conn.execute("""SELECT e.id,e.status_code,e.source,e.tool,o.method,r.id resource_id,r.path,r.query,r.url,h.hostname
                                 FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id WHERE e.id=?""", (exid,)).fetchone()
            if ex and ("exchange",exid) not in seen:
                seen.add(("exchange",exid)); refs.append({"kind":"exchange","id":exid,"exchange_id":exid,"method":ex["method"],"resource_id":int(ex["resource_id"]),"path":ex["path"],"query":ex["query"],"url":ex["url"],"host":ex["hostname"],"status":ex["status_code"],"source":ex["source"],"tool":ex["tool"]})
                resource_id = resource_id or int(ex["resource_id"]); primary_method = primary_method or ex["method"]; primary_exchange_id = primary_exchange_id or exid
    # If only a resource is known, pick its most recently observed operation to make Repeater actionable.
    if resource_id and not primary_method:
        op = conn.execute("SELECT id,method FROM resource_operations WHERE resource_id=? ORDER BY last_seen_at DESC LIMIT 1", (resource_id,)).fetchone()
        if op:
            primary_method = op["method"]
            ex = conn.execute("SELECT id FROM http_exchanges WHERE operation_id=? ORDER BY last_seen_at DESC LIMIT 1", (op["id"],)).fetchone()
            primary_exchange_id = int(ex["id"]) if ex else None
    return {"evidence_refs": refs[:10], "resource_id": resource_id, "primary_method": primary_method, "primary_exchange_id": primary_exchange_id}


def persist_graph_ai_hypotheses(conn, result: dict[str, Any], *, evidence_hash: str, selected_node_id: str | None = None) -> list[dict[str, Any]]:
    """Persist explicit, human-requested AI hypotheses. ENGINE rows are not hypotheses in Hunt."""
    init_schema(conn)
    persisted: list[dict[str, Any]] = []
    for idx, item in enumerate((result.get("hypotheses") or [])[:5]):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "Hipótesis sin título").strip()[:240]
        typ = str(item.get("type") or "other").strip()[:80]
        fingerprint = hashlib.sha256(f"{typ}|{title.lower()}".encode("utf-8", errors="ignore")).hexdigest()[:20]
        node_ids = [str(x) for x in (item.get("node_ids") or []) if isinstance(x, str)][:20]
        host_id = resource_id = None
        for nid in node_ids:
            if nid.startswith("resource:") and resource_id is None:
                try: resource_id = int(nid.split(":",1)[1])
                except Exception: pass
            if nid.startswith("host:") and host_id is None:
                try: host_id = int(nid.split(":",1)[1])
                except Exception: pass
        refs = hypothesis_refs_from_nodes(conn, node_ids) if node_ids else {"evidence_refs": [], "resource_id": None, "primary_method": None, "primary_exchange_id": None}
        if resource_id is None and refs.get("resource_id"):
            resource_id = int(refs["resource_id"])
        if resource_id and host_id is None:
            row = conn.execute("SELECT host_id FROM resources WHERE id=?", (resource_id,)).fetchone()
            host_id = int(row["host_id"]) if row else None
        strength = str(item.get("strength") or "medium").lower()
        investigation_priority = str(item.get("investigation_priority") or ("high" if strength == "strong" else "medium" if strength == "medium" else "quick")).lower()
        priority = "high" if investigation_priority == "high" else "medium" if investigation_priority == "medium" else "low"
        confidence = "high" if strength == "strong" else "medium" if strength == "medium" else "low"
        priority_reasons = [str(x).strip()[:120] for x in (item.get("priority_reasons") or []) if str(x).strip()][:4]
        context_sources = [str(x).strip() for x in (item.get("context_sources") or []) if str(x).strip()][:8]
        evidence = [{"source":"ai_graph","node_ids":node_ids,"evidence_hash":evidence_hash,"selected_node_id":selected_node_id,"plain_language":str(item.get("plain_language") or "").strip(),"investigation_priority":investigation_priority,"priority_reasons":priority_reasons,"facts":[str(x).strip()[:300] for x in (item.get("facts") or []) if str(x).strip()][:8],"inference":str(item.get("inference") or "").strip()[:1200],"unknowns":[str(x).strip()[:300] for x in (item.get("unknowns") or []) if str(x).strip()][:8],"context_sources":context_sources}]
        upsert_lead(
            conn, lead_key=f"ai_graph:{fingerprint}", host_id=host_id, resource_id=resource_id,
            lead_type=typ, title=title, confidence=confidence, review_priority=priority,
            evidence=evidence, why=str(item.get("why_interesting") or "").strip(),
            next_test=str(item.get("suggested_investigation") or "").strip(),
            confirm_if=str(item.get("confirm_if") or "").strip(), discard_if=str(item.get("discard_if") or "").strip(),
            source="AI",
        )
        conn.execute("UPDATE leads_v2 SET test_plan_json=? WHERE lead_key=?", (json.dumps(item.get("steps") or [], ensure_ascii=False), f"ai_graph:{fingerprint}"))
        row = conn.execute("SELECT id,status FROM leads_v2 WHERE lead_key=?", (f"ai_graph:{fingerprint}",)).fetchone()
        if row:
            lead_id = int(row["id"])
            for needed in (item.get("needed_pieces") or [])[:4]:
                if not isinstance(needed, dict):
                    continue
                try:
                    add_hypothesis_requirement(
                        conn, lead_id,
                        key_pattern=str(needed.get("key_pattern") or ""),
                        description=str(needed.get("description") or ""),
                        identity_mode=str(needed.get("identity_mode") or "any"),
                        identity_id=int(needed["identity_id"]) if needed.get("identity_id") is not None else None,
                    )
                except Exception:
                    # A hypothesis remains useful even if one model-proposed
                    # requirement is malformed or references a stale identity.
                    pass
            persisted.append({**item, **refs, "lead_id": lead_id, "status": row["status"], "node_ids": node_ids})
    return persisted

def promote_ai_hypothesis_to_investigation(conn, lead_id: int) -> dict[str, Any]:
    """Create a human-owned Investigation from an existing Hypothesis. Never automatic.

    The historical function name is kept for compatibility, but manual Hypotheses
    are valid origins too. Investigation is a workspace around a question, not a
    different state that an AI-only Hypothesis is converted into.
    """
    init_schema(conn)
    row = conn.execute("SELECT * FROM leads_v2 WHERE id=?", (int(lead_id),)).fetchone()
    if not row:
        raise ValueError("Hipótesis no encontrada")
    existing = conn.execute("SELECT * FROM investigations WHERE source_hypothesis_id=?", (int(lead_id),)).fetchone()
    if existing:
        return dict(existing)
    now = now_iso()
    investigation_id = create_investigation(
        conn, title=str(row["title"]), category=str(row["lead_type"] or "other"),
        summary=str(row["why_interesting"] or ""), source_hypothesis_id=int(lead_id),
    )
    try:
        evidence = json.loads(row["evidence_json"] or "[]")
    except Exception:
        evidence = []
    node_ids: list[str] = []
    for ev in evidence if isinstance(evidence, list) else []:
        if isinstance(ev, dict):
            node_ids.extend(str(x) for x in (ev.get("node_ids") or []) if isinstance(x, str))
            if ev.get("exchange_id"):
                node_ids.append(f"exchange:{ev.get('exchange_id')}")
    refs = hypothesis_refs_from_nodes(conn, list(dict.fromkeys(node_ids))) if node_ids else {"evidence_refs": []}
    for ref in refs.get("evidence_refs") or []:
        if ref.get("exchange_id"):
            link_investigation_entity(conn, investigation_id, "exchange", int(ref["exchange_id"]), "evidence")
        if ref.get("resource_id"):
            link_investigation_entity(conn, investigation_id, "resource", int(ref["resource_id"]), "surface")
    # Attach Signals that directly support the referenced exchanges/resources.
    exchange_ids = {int(r["exchange_id"]) for r in (refs.get("evidence_refs") or []) if r.get("exchange_id")}
    resource_ids = {int(r["resource_id"]) for r in (refs.get("evidence_refs") or []) if r.get("resource_id")}
    signal_rows = []
    if exchange_ids:
        q = ",".join("?" for _ in exchange_ids)
        signal_rows.extend(conn.execute(f"SELECT id FROM signal_occurrences WHERE exchange_id IN ({q}) LIMIT 80", tuple(exchange_ids)).fetchall())
    if resource_ids:
        q = ",".join("?" for _ in resource_ids)
        signal_rows.extend(conn.execute(f"SELECT id FROM signal_occurrences WHERE resource_id IN ({q}) LIMIT 80", tuple(resource_ids)).fetchall())
    for sr in signal_rows:
        link_investigation_entity(conn, investigation_id, "signal", int(sr["id"]), "supports")
    conn.execute("UPDATE leads_v2 SET promoted_investigation_id=?,updated_at=? WHERE id=?", (investigation_id, now, int(lead_id)))
    out = conn.execute("SELECT * FROM investigations WHERE id=?", (investigation_id,)).fetchone()
    return dict(out)


def update_investigation(conn, investigation_id: int, *, status: str | None = None, notes: str | None = None) -> dict[str, Any]:
    init_schema(conn)
    row = conn.execute("SELECT * FROM investigations WHERE id=?", (int(investigation_id),)).fetchone()
    if not row:
        raise ValueError("Investigación no encontrada")
    next_status = status or str(row["status"] or "active")
    if next_status not in {"active", "paused", "closed"}:
        raise ValueError("Estado de investigación inválido")
    next_notes = str(row["notes"] or "") if notes is None else str(notes)
    conn.execute("UPDATE investigations SET status=?,notes=?,updated_at=? WHERE id=?", (next_status, next_notes, now_iso(), int(investigation_id)))
    return dict(conn.execute("SELECT * FROM investigations WHERE id=?", (int(investigation_id),)).fetchone())


# ---------------------------------------------------------------------------
# v0.40 · Human decisions, Investigation workspace and persistent AI Ideas
# ---------------------------------------------------------------------------

AI_IDEA_STATES = {"new", "saved", "investigating", "dismissed", "postponed", "converted_to_hypothesis"}
SIGNAL_DECISIONS = {"new", "interesting", "investigating", "dismissed"}


def set_signal_decision(conn, signal_id: int, *, decision: str, reason: str = "") -> dict[str, Any]:
    """Record a human decision without deleting machine evidence.

    Dismissal is memory, not deletion. `dismissed_at` is retained as a backwards-
    compatible projection for older views, while `human_decision` is authoritative.
    """
    init_schema(conn)
    decision = str(decision or "new").strip().lower()
    if decision not in SIGNAL_DECISIONS:
        raise ValueError("Decisión de Señal inválida")
    row = conn.execute("SELECT * FROM signal_occurrences WHERE id=?", (int(signal_id),)).fetchone()
    if not row:
        raise ValueError("Señal no encontrada")
    now = now_iso()
    dismissed_at = now if decision == "dismissed" else None
    reviewed_at = None if decision == "new" else (row["reviewed_at"] or now)
    conn.execute(
        """UPDATE signal_occurrences
           SET human_decision=?,decision_reason=?,decision_at=?,decision_occurrences=occurrences,
               reconsideration_needed=0,reviewed_at=?,dismissed_at=?
           WHERE id=?""",
        (decision, str(reason or "").strip()[:2000], now, reviewed_at, dismissed_at, int(signal_id)),
    )
    return dict(conn.execute("SELECT * FROM signal_occurrences WHERE id=?", (int(signal_id),)).fetchone())


def create_manual_signal(conn, exchange_id: int, *, title: str, note: str = "", category: str = "manual") -> int:
    """Deprecated compatibility guard. Signals are emitted exclusively by Rules."""
    raise ValueError("Las Señales sólo nacen de Reglas. Crea una Regla para observar esta condición.")


def create_manual_hypothesis(conn, exchange_id: int, *, title: str, why: str = "", next_test: str = "") -> int:
    """Create a human-owned Hypothesis from an existing Request without a parallel model."""
    init_schema(conn)
    ex = conn.execute(
        """SELECT e.id,e.operation_id,o.resource_id,o.method,r.path,r.host_id,h.hostname,e.status_code
           FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
           JOIN resources r ON r.id=o.resource_id JOIN hosts h ON h.id=r.host_id WHERE e.id=?""",
        (int(exchange_id),),
    ).fetchone()
    if not ex:
        raise ValueError("Request no encontrada")
    clean_title = str(title or "").strip()[:240]
    if not clean_title:
        raise ValueError("Título de Hipótesis requerido")
    import hashlib
    key = hashlib.sha256(f"manual:{exchange_id}:{clean_title.lower()}".encode()).hexdigest()[:22]
    evidence = [{
        "source": "manual_request", "exchange_id": int(exchange_id),
        "node_ids": [f"exchange:{int(exchange_id)}", f"resource:{int(ex['resource_id'])}"],
        "method": ex["method"], "path": ex["path"], "host": ex["hostname"], "status": ex["status_code"],
    }]
    hid, _ = upsert_lead(
        conn, lead_key=f"manual:{key}", host_id=int(ex["host_id"]), resource_id=int(ex["resource_id"]),
        lead_type="manual", title=clean_title, confidence="medium", review_priority="medium",
        evidence=evidence, why=str(why or "").strip()[:4000], next_test=str(next_test or "").strip()[:4000],
        confirm_if="", discard_if="", source="MANUAL",
    )
    return int(hid)


def create_investigation(conn, *, title: str, category: str = "other", summary: str = "", notes: str = "",
                         source_hypothesis_id: int | None = None) -> int:
    init_schema(conn)
    clean = str(title or "").strip()[:240]
    if not clean:
        raise ValueError("Título de Investigación requerido")
    if source_hypothesis_id:
        row = conn.execute("SELECT id FROM investigations WHERE source_hypothesis_id=?", (int(source_hypothesis_id),)).fetchone()
        if row:
            return int(row["id"])
    now = now_iso()
    cur = conn.execute(
        "INSERT INTO investigations(title,category,status,summary,notes,source_hypothesis_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
        (clean, str(category or "other")[:80], "active", str(summary or "")[:5000], str(notes or "")[:10000], source_hypothesis_id, now, now),
    )
    iid = int(cur.lastrowid)
    if source_hypothesis_id:
        link_investigation_entity(conn, iid, "hypothesis", int(source_hypothesis_id), "pursuing")
        conn.execute("UPDATE leads_v2 SET promoted_investigation_id=?,updated_at=? WHERE id=?", (iid, now, int(source_hypothesis_id)))
    return iid


def link_investigation_entity(conn, investigation_id: int, entity_type: str, entity_id: int, relation: str = "context") -> int:
    """Attach an existing first-class entity to an Investigation.

    `investigation_links` is the canonical many-to-many membership graph. Legacy
    single-Investigation pointers are intentionally not removed; callers that need
    one primary/origin Investigation can keep writing them for compatibility.
    """
    init_schema(conn)
    iid = int(investigation_id)
    if not conn.execute("SELECT id FROM investigations WHERE id=?", (iid,)).fetchone():
        raise ValueError("Investigación no encontrada")
    et, _ = _assert_investigation_entity(conn, entity_type, int(entity_id))
    rel = str(relation or "context").strip()[:80] or "context"
    now = now_iso()
    conn.execute(
        "INSERT OR IGNORE INTO investigation_links(investigation_id,entity_type,entity_id,relation,created_at) VALUES(?,?,?,?,?)",
        (iid, et, int(entity_id), rel, now),
    )
    row = conn.execute(
        "SELECT id FROM investigation_links WHERE investigation_id=? AND entity_type=? AND entity_id=? AND relation=?",
        (iid, et, int(entity_id), rel),
    ).fetchone()
    conn.execute("UPDATE investigations SET updated_at=? WHERE id=?", (now, iid))
    return int(row["id"]) if row else 0


def unlink_investigation_entity(conn, investigation_id: int, entity_type: str, entity_id: int, relation: str | None = None) -> int:
    """Remove only the Investigation membership edge; never delete source evidence."""
    init_schema(conn)
    iid = int(investigation_id)
    if not conn.execute("SELECT id FROM investigations WHERE id=?", (iid,)).fetchone():
        raise ValueError("Investigación no encontrada")
    et = str(entity_type or "").strip().lower()
    if et not in INVESTIGATION_ENTITY_TABLES:
        raise ValueError("Tipo de contexto no soportado")
    params: list[Any] = [iid, et, int(entity_id)]
    sql = "DELETE FROM investigation_links WHERE investigation_id=? AND entity_type=? AND entity_id=?"
    if relation is not None:
        sql += " AND relation=?"
        params.append(str(relation).strip()[:80])
    cur = conn.execute(sql, tuple(params))
    if cur.rowcount:
        conn.execute("UPDATE investigations SET updated_at=? WHERE id=?", (now_iso(), iid))
    return int(cur.rowcount or 0)


def list_investigation_links(conn, investigation_id: int, *, entity_type: str | None = None) -> list[dict[str, Any]]:
    """Return canonical Investigation edges without copying the linked entities."""
    init_schema(conn)
    params: list[Any] = [int(investigation_id)]
    sql = "SELECT * FROM investigation_links WHERE investigation_id=?"
    if entity_type:
        et = str(entity_type).strip().lower()
        if et not in INVESTIGATION_ENTITY_TABLES:
            raise ValueError("Tipo de contexto no soportado")
        sql += " AND entity_type=?"
        params.append(et)
    sql += " ORDER BY id"
    return [dict(r) for r in conn.execute(sql, tuple(params)).fetchall()]


def _ai_idea_dict_from_row(row) -> dict[str, Any]:
    item = dict(row)
    for src, dst, default in (("facts_json","facts",[]),("unknowns_json","unknowns",[]),("runner_json","runner",None)):
        try: item[dst] = json.loads(item.get(src) or ("[]" if default == [] else "null"))
        except Exception: item[dst] = default
    return item


def persist_flow_ai_batch(conn, *, flow_id: int, model: str, evidence_hash: str, result: dict[str, Any],
                          context_snapshot: str, investigation_id: int | None = None) -> dict[str, Any]:
    """Persist an AI exploration as first-class memory; identical evidence reuses its batch."""
    init_schema(conn)
    # If this Flow already belongs to exactly one active Investigation, keep that origin
    # on the generation. With multiple Investigations we keep it Flow-scoped to avoid
    # inventing ownership; the workspace can still surface it through the Flow link.
    if investigation_id is None:
        linked = conn.execute(
            """SELECT DISTINCT i.id FROM investigations i JOIN investigation_links l ON l.investigation_id=i.id
               WHERE l.entity_type='flow' AND l.entity_id=? AND i.status!='closed' ORDER BY i.updated_at DESC LIMIT 2""",
            (int(flow_id),),
        ).fetchall()
        if len(linked) == 1:
            investigation_id = int(linked[0]["id"])
    existing = conn.execute(
        """SELECT * FROM ai_idea_batches WHERE origin_type='flow' AND flow_id=? AND
           ((investigation_id IS NULL AND ? IS NULL) OR investigation_id=?) AND model=? AND evidence_hash=?""",
        (int(flow_id), investigation_id, investigation_id, str(model), str(evidence_hash)),
    ).fetchone()
    if existing:
        return {"batch_id": int(existing["id"]), "reused": True}
    now = now_iso()
    cur = conn.execute(
        """INSERT INTO ai_idea_batches(origin_type,flow_id,investigation_id,model,evidence_hash,summary,context_snapshot_json,created_at)
           VALUES('flow',?,?,?,?,?,?,?)""",
        (int(flow_id), investigation_id, str(model), str(evidence_hash), str(result.get("summary") or "")[:8000], str(context_snapshot or ""), now),
    )
    batch_id = int(cur.lastrowid)
    for idea in result.get("ideas") or []:
        if not isinstance(idea, dict):
            continue
        question = str(idea.get("question") or idea.get("alias") or "Pregunta de lógica").strip()[:1000]
        prior = conn.execute(
            """SELECT ai.id FROM ai_ideas ai JOIN ai_idea_batches b ON b.id=ai.batch_id
               WHERE ai.flow_id=? AND ai.status='dismissed' AND lower(trim(ai.question))=lower(trim(?))
               ORDER BY ai.id DESC LIMIT 1""",
            (int(flow_id), question),
        ).fetchone()
        conn.execute(
            """INSERT INTO ai_ideas(batch_id,flow_id,investigation_id,question,alias,category,priority,rationale,facts_json,unknowns_json,
               test_goal,confirm_if,discard_if,runner_json,status,reconsidered_from_idea_id,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'new',?,?,?)""",
            (batch_id, int(flow_id), investigation_id, question, str(idea.get("alias") or "")[:240], str(idea.get("category") or "other")[:80],
             str(idea.get("priority") or "medium")[:20], str(idea.get("rationale") or "")[:8000],
             json.dumps(idea.get("facts") or [], ensure_ascii=False), json.dumps(idea.get("unknowns") or [], ensure_ascii=False),
             str(idea.get("test_goal") or "")[:8000], str(idea.get("confirm_if") or "")[:4000], str(idea.get("discard_if") or "")[:4000],
             json.dumps(idea.get("runner"), ensure_ascii=False) if idea.get("runner") is not None else None,
             int(prior["id"]) if prior else None, now, now),
        )
    return {"batch_id": batch_id, "reused": False}


def list_ai_idea_batches(conn, *, flow_id: int | None = None, investigation_id: int | None = None, limit: int = 30) -> list[dict[str, Any]]:
    init_schema(conn)
    where=[]; params=[]
    if flow_id is not None:
        where.append("b.flow_id=?"); params.append(int(flow_id))
    if investigation_id is not None:
        where.append("(b.investigation_id=? OR EXISTS(SELECT 1 FROM investigation_links il WHERE il.investigation_id=? AND il.entity_type='flow' AND il.entity_id=b.flow_id))")
        params.extend([int(investigation_id), int(investigation_id)])
    where_sql=(" WHERE " + " AND ".join(where) if where else "")
    total=int(conn.execute("SELECT COUNT(*) c FROM ai_idea_batches b"+where_sql,tuple(params)).fetchone()["c"] or 0)
    sql = "SELECT b.* FROM ai_idea_batches b" + where_sql + " ORDER BY b.id DESC LIMIT ?"
    batches=[]
    for idx,row in enumerate(conn.execute(sql, tuple(params+[max(1,min(int(limit),100))])).fetchall()):
        b=dict(row)
        b["generation_number"]=max(1,total-idx)
        b["ideas"]=[_ai_idea_dict_from_row(x) for x in conn.execute("SELECT * FROM ai_ideas WHERE batch_id=? ORDER BY id", (int(row["id"]),)).fetchall()]
        batches.append(b)
    return batches


def get_ai_idea(conn, idea_id: int) -> dict[str, Any] | None:
    init_schema(conn)
    row = conn.execute("SELECT * FROM ai_ideas WHERE id=?", (int(idea_id),)).fetchone()
    return _ai_idea_dict_from_row(row) if row else None


def update_ai_idea_state(conn, idea_id: int, *, status: str, reason: str = "") -> dict[str, Any]:
    init_schema(conn)
    state = str(status or "new").strip().lower()
    if state not in AI_IDEA_STATES:
        raise ValueError("Estado de idea IA inválido")
    row = conn.execute("SELECT id FROM ai_ideas WHERE id=?", (int(idea_id),)).fetchone()
    if not row:
        raise ValueError("Idea IA no encontrada")
    conn.execute("UPDATE ai_ideas SET status=?,decision_reason=?,updated_at=? WHERE id=?",
                 (state, str(reason or "").strip()[:3000], now_iso(), int(idea_id)))
    return get_ai_idea(conn, int(idea_id)) or {}

def actual_ai_cost(usage: dict[str, Any], model: str, usd_cop_rate: float) -> dict[str, Any]:
    prices = intel.OPENAI_PRICING.get(model)
    if not prices:
        return {}
    inp = int(usage.get("input_tokens") or 0)
    out = int(usage.get("output_tokens") or 0)
    long_context = inp > intel.LONG_CONTEXT_THRESHOLD
    in_rate = prices["long_input"] if long_context else prices["input"]
    out_rate = prices["long_output"] if long_context else prices["output"]
    usd = (inp/1_000_000)*in_rate + (out/1_000_000)*out_rate
    return {"actual_cost_usd":usd,"actual_cost_cop":usd*usd_cop_rate,"usd_cop_rate":usd_cop_rate,"input_rate_per_m":in_rate,"output_rate_per_m":out_rate}

# ---------------------------------------------------------------------------
# v0.39 · Flow Intelligence / Runner ideas
# ---------------------------------------------------------------------------

def _flow_logic_schema() -> dict[str, Any]:
    action_schema = {
        "type":"object","additionalProperties":False,
        "properties":{
            "position":{"type":"integer"},
            "action":{"type":"string","enum":["keep","omit","repeat"]},
            "repeat_count":{"type":"integer"},
            "notes":{"type":"string"},
        },
        "required":["position","action","repeat_count","notes"],
    }
    variable_schema = {
        "type":"object","additionalProperties":False,
        "properties":{
            "target_position":{"type":"integer"},
            "target_name":{"type":"string"},
            "target_value":{"type":"string"},
            "mode":{"type":"string","enum":["values","response_key","response_regex"]},
            "values":{"type":"array","items":{"type":"string"}},
            "source_position":{"type":["integer","null"]},
            "source_name":{"type":"string"},
            "regex_pattern":{"type":"string"},
            "why":{"type":"string"},
        },
        "required":["target_position","target_name","target_value","mode","values","source_position","source_name","regex_pattern","why"],
    }
    runner_schema = {
        "type":"object","additionalProperties":False,
        "properties":{
            "description":{"type":"string"},
            "step_actions":{"type":"array","items":action_schema},
            "variables":{"type":"array","items":variable_schema},
            "review_before_run":{"type":"array","items":{"type":"string"}},
        },
        "required":["description","step_actions","variables","review_before_run"],
    }
    idea_schema = {
        "type":"object","additionalProperties":False,
        "properties":{
            "question":{"type":"string"},
            "alias":{"type":"string"},
            "category":{"type":"string","enum":["step_order","step_omission","replay","state","client_value","stale_reference","cross_identity","race_candidate","other"]},
            "priority":{"type":"string","enum":["high","medium","quick"]},
            "rationale":{"type":"string"},
            "facts":{"type":"array","items":{"type":"string"}},
            "unknowns":{"type":"array","items":{"type":"string"}},
            "test_goal":{"type":"string"},
            "confirm_if":{"type":"string"},
            "discard_if":{"type":"string"},
            "runner":{"type":["object","null"],"additionalProperties":False,
                      "properties":runner_schema["properties"],"required":runner_schema["required"]},
        },
        "required":["question","alias","category","priority","rationale","facts","unknowns","test_goal","confirm_if","discard_if","runner"],
    }
    return {
        "type":"object","additionalProperties":False,
        "properties":{
            "summary":{"type":"string"},
            "ideas":{"type":"array","items":idea_schema},
            "already_covered":{"type":"array","items":{"type":"string"}},
            "context_gaps":{"type":"array","items":{"type":"string"}},
        },
        "required":["summary","ideas","already_covered","context_gaps"],
    }


def _redact_http_for_flow_ai(raw: str, *, max_chars: int) -> str:
    text=str(raw or "")
    if not text:
        return ""
    lines=text.replace("\r\n","\n").split("\n")
    out=[]
    for line in lines:
        if ":" in line:
            name=line.split(":",1)[0].strip().lower()
            if name in {"authorization","cookie","set-cookie","proxy-authorization"}:
                out.append(line.split(":",1)[0]+": <redacted>")
                continue
        out.append(line)
    result="\n".join(out)
    return result[:max(2000,int(max_chars))]


def build_flow_logic_payload(conn, domain: str, flow_id: int, *, max_chars: int = 240_000) -> tuple[str,str]:
    """Build a flow-centric AI context including prior Runner outcomes.

    Unlike Graph AI, this is intentionally centered on one observed business
    process. It includes bounded HTTP text so the model can reason about the
    actual parameters and responses while auth headers/cookies are redacted.
    """
    import negro_flows as flow_tools
    import negro_runners as runner_tools
    init_schema(conn); runner_tools.init_schema(conn)
    flow=flow_tools.get_flow(conn,int(flow_id))
    if not flow:
        raise ValueError("Flujo no encontrado")
    f=flow["flow"]
    context: dict[str,Any]={
        "target":domain,
        "flow":{"id":int(f["id"]),"name":f["name"],"description":f.get("description") or "","identity":f.get("identity_name")},
        "steps":[],
        "objects":flow.get("meaningful_business_objects") or [],
        "state_timelines":flow.get("state_timelines") or [],
        "signals":[],
        "previous_runners":[],
        "previous_hypotheses":[],
        "previous_ai_ideas":[],
        "instructions":{
            "goal":"Proponer preguntas de lógica de negocio nuevas y comprobables sobre este Flujo.",
            "do_not_repeat":"Evita ideas ya descartadas o cubiertas por pruebas VÁLIDAS. Un Run con transport_error/timeout/dns_error/tls_error/proxy_error/runner_error NO cuenta como prueba y la pregunta sigue pendiente.",
            "dismissed_memory":"Las ideas descartadas siguen siendo memoria. No repitas exactamente la misma propuesta salvo que nueva evidencia concreta justifique reconsiderarla; si la reconsideras, explica la evidencia nueva.",
            "execution":"La IA sólo propone borradores. El humano revisa y ejecuta manualmente cada Runner.",
        }
    }
    step_exchange_ids=[]
    for s in flow.get("included_steps") or []:
        exid=int(s["exchange_id"]); step_exchange_ids.append(exid)
        row=conn.execute("SELECT request_b64,response_b64 FROM http_exchanges WHERE id=?",(exid,)).fetchone()
        req=resp=""
        if row:
            req=_decode_http_b64(row["request_b64"]); resp=_decode_http_b64(row["response_b64"])
        params=[]
        try:
            params=[dict(r) for r in conn.execute(
                """SELECT name,normalized_name,location,COALESCE(value_raw,value_preview,'') value
                   FROM parameter_observations WHERE exchange_id=? ORDER BY id LIMIT 80""",(exid,)).fetchall()]
        except Exception:
            params=[]
        context["steps"].append({
            "position":int(s["position"]),"flow_step_id":int(s["id"]),"exchange_id":exid,
            "method":s.get("method"),"host":s.get("hostname"),"path":s.get("path"),"status":s.get("status_code"),
            "identity":s.get("identity_name"),"label":s.get("label") or "","notes":s.get("notes") or "",
            "parameters":params[:60],
            "request":_redact_http_for_flow_ai(req,max_chars=12_000),
            "response":_redact_http_for_flow_ai(resp,max_chars=18_000),
        })
    if step_exchange_ids:
        marks=",".join("?" for _ in step_exchange_ids)
        try:
            for row in conn.execute(
                f"SELECT id,title,kind,category,signal_level,source,exchange_id,why_json,evidence_json,human_decision,decision_reason,decision_at,occurrences,decision_occurrences FROM signal_occurrences WHERE exchange_id IN ({marks}) ORDER BY id DESC LIMIT 80",
                tuple(step_exchange_ids)).fetchall():
                item=dict(row)
                item["why"]=_load_json_for_flow_ai(item.pop("why_json",None),{})
                item["evidence"]=_load_json_for_flow_ai(item.pop("evidence_json",None),{})
                context["signals"].append(item)
        except Exception:
            pass
    # Prior Runners and outcomes are first-class context. This is what stops the
    # assistant from suggesting the same business-logic question every session.
    for runner_index, rr in enumerate(runner_tools.list_runners(conn,flow_id=int(flow_id),limit=30)):
        detail=runner_tools.get_runner(conn,int(rr["id"]))
        if not detail: continue
        runner_memory={
            "id":int(rr["id"]),"alias":rr["alias"],"description":rr.get("description") or "",
            "hypothesis":rr.get("hypothesis_title"),"status":rr.get("status"),
            "steps":[{"position":int(s["position"]),"method":s["method"],"path":s["path"],"action":s["action"],"repeat_count":int(s["repeat_count"])} for s in detail["steps"]],
            "runs":[],
        }
        # Recent Runner evidence is intentionally first-class context. A negative
        # experiment can still teach the assistant something from the actual
        # Request/Response behavior. Keep this bounded: only recent runners/runs
        # and short sanitized HTTP previews are included.
        for run_index, run in enumerate(detail["runs"][:12]):
            run_memory={"id":int(run["id"]),"status":run["status"],"execution_class":run.get("execution_class") or "pending",
                        "counts_as_test":bool(run.get("counts_as_test")),"outcome":run["outcome"] if bool(run.get("counts_as_test")) else "not_counted",
                        "summary":run.get("summary") or {},"error":run.get("error"),"evidence":[]}
            if runner_index < 6 and run_index < 2:
                try:
                    evidence_rows=conn.execute(
                        """SELECT rrr.repeat_index,rrr.elapsed_ms,rrr.status_code,rrr.error,rrr.exchange_id,rrr.execution_class,
                                  COALESCE(o.method,rrr.method) method,r.path,h.hostname,COALESCE(e.request_b64,rrr.request_b64) request_b64,
                                  COALESCE(e.response_b64,rrr.response_b64) response_b64,rrr.url
                           FROM runner_run_requests rrr
                           LEFT JOIN http_exchanges e ON e.id=rrr.exchange_id
                           LEFT JOIN resource_operations o ON o.id=e.operation_id
                           LEFT JOIN resources r ON r.id=o.resource_id
                           LEFT JOIN hosts h ON h.id=r.host_id
                           WHERE rrr.run_id=? ORDER BY rrr.id LIMIT 5""",
                        (int(run["id"]),),
                    ).fetchall()
                    for erow in evidence_rows:
                        req=_decode_http_b64(erow["request_b64"]) if erow["request_b64"] else ""
                        resp=_decode_http_b64(erow["response_b64"]) if erow["response_b64"] else ""
                        run_memory["evidence"].append({
                            "exchange_id":int(erow["exchange_id"]) if erow["exchange_id"] else None,
                            "repeat_index":int(erow["repeat_index"] or 1),
                            "method":erow["method"],"host":erow["hostname"] or (urllib.parse.urlsplit(str(erow["url"] or "")).hostname or ""),
                            "path":erow["path"] or (urllib.parse.urlsplit(str(erow["url"] or "")).path or "/"),
                            "status":erow["status_code"],"execution_class":erow["execution_class"],"elapsed_ms":erow["elapsed_ms"],"error":erow["error"],
                            "request":_redact_http_for_flow_ai(req,max_chars=1200),
                            "response":_redact_http_for_flow_ai(resp,max_chars=1800),
                        })
                except Exception:
                    pass
            runner_memory["runs"].append(run_memory)
        context["previous_runners"].append(runner_memory)
    # Existing AI hypotheses that explicitly cite this flow are useful negative/
    # positive memory even if they never became a Runner.
    flow_ref=f"flow:{int(flow_id)}"
    for row in conn.execute("SELECT id,title,status,why_interesting,next_test,result_notes,evidence_json FROM leads_v2 WHERE upper(COALESCE(source,''))='AI' ORDER BY updated_at DESC,id DESC LIMIT 200").fetchall():
        ev=str(row["evidence_json"] or "")
        if flow_ref not in ev:
            continue
        context["previous_hypotheses"].append({k:row[k] for k in ("id","title","status","why_interesting","next_test","result_notes")})
        if len(context["previous_hypotheses"])>=30: break
    # Persistent AI Ideas are memory even before/without becoming Hypotheses.
    # Dismissed/postponed proposals are included so future generations do not
    # blindly repeat them; a model may reconsider only when current evidence changed.
    try:
        for idea in conn.execute(
            """SELECT ai.id,ai.question,ai.alias,ai.category,ai.priority,ai.status,ai.decision_reason,ai.created_at,ai.updated_at,
                      b.evidence_hash,b.created_at batch_created_at
               FROM ai_ideas ai JOIN ai_idea_batches b ON b.id=ai.batch_id
               WHERE ai.flow_id=? ORDER BY ai.id DESC LIMIT 120""", (int(flow_id),)).fetchall():
            context["previous_ai_ideas"].append(dict(idea))
    except Exception:
        pass
    raw=json.dumps(context,ensure_ascii=False,separators=(",",":"))
    if len(raw)>max_chars:
        # Preserve structure and prior-test memory; trim HTTP previews first.
        for step in context["steps"]:
            step["request"]=str(step.get("request") or "")[:5000]
            step["response"]=str(step.get("response") or "")[:7000]
            step["parameters"]=(step.get("parameters") or [])[:30]
        raw=json.dumps(context,ensure_ascii=False,separators=(",",":"))
    if len(raw)>max_chars:
        context["previous_runners"]=context["previous_runners"][:15]
        context["signals"]=context["signals"][:40]
        raw=json.dumps(context,ensure_ascii=False,separators=(",",":"))[:max_chars]
    evidence_hash=hashlib.sha256(raw.encode("utf-8",errors="ignore")).hexdigest()
    return raw,evidence_hash


def _load_json_for_flow_ai(value: Any, default: Any) -> Any:
    try: return json.loads(value or "")
    except Exception: return default


def flow_logic_result_is_cacheable(result: Any) -> bool:
    return isinstance(result,dict) and isinstance(result.get("ideas"),list) and isinstance(result.get("summary"),str) and not result.get("parse_warning")


def run_openai_flow_logic_ideas(payload: str, *, model: str, output_tokens: int = 6500, reasoning_effort: str = "medium") -> tuple[dict[str,Any],dict[str,Any]]:
    key=intel.load_secrets().get("OPENAI_API_KEY")
    if not key:
        raise RuntimeError(f"Falta OPENAI_API_KEY en {intel.SECRETS_PATH}")
    try:
        from openai import OpenAI  # type: ignore
    except Exception as exc:
        raise RuntimeError("El SDK de OpenAI no está disponible. Ejecuta ./install-web.sh") from exc
    system="""Eres el copiloto de lógica de negocio de un pentester durante una investigación AUTORIZADA. Responde SIEMPRE en español claro.
Tu trabajo NO es declarar vulnerabilidades ni ejecutar nada. Debes ayudar al humano a formular preguntas nuevas y de alto valor sobre UN Flujo real observado por Negro.

Recibes: secuencia del Flujo, Requests/Responses sanitizadas, parámetros, Identity, objetos/estados, Signals, Hypotheses previas y Runners ya ejecutados con sus resultados.

OBJETIVO:
- Proponer preguntas de lógica de negocio específicas a ESTE proceso, no una lista OWASP genérica.
- Prioriza: pasos omitibles/reordenables/repetibles, valores controlados por cliente, estados que podrían saltarse, referencias reutilizables/stale, replay, cambios después de validación, operaciones que podrían ejecutarse varias veces y cruces de identidad cuando la evidencia lo justifique.
- USA la memoria completa. NO cuentes como prueba un Run cuyo execution_class no sea application_response o counts_as_test=false. Un 504/proxy error/timeout/dns/tls sólo significa que la prueba no llegó válidamente al aplicativo.
- No repitas un Runner/Hypothesis que terminó negative en una prueba válida, ni una AI Idea descartada, salvo que exista NUEVA evidencia concreta que justifique reconsiderarla; si lo haces, explica exactamente qué cambió.
- Usa parámetros/rutas/status reales. No inventes endpoints, roles, campos, cupones, IDs o Responses.
- Si una idea requiere una pieza que no existe, dilo en unknowns/review_before_run; no inventes valores.

RUNNER DRAFT:
- Cada idea puede incluir un Runner borrador si puede expresarse con el Flujo observado.
- step_actions usa posiciones REALES del Flujo. keep conserva, omit salta, repeat repite; repeat_count 1..20.
- variables sólo si el parámetro/valor aparece realmente en la evidencia. mode=values sirve para una lista manual; response_key toma una key JSON de una Response anterior; response_regex sólo cuando el texto real hace razonable ese patrón.
- El Runner nunca se ejecuta automáticamente. review_before_run debe recordar al humano cualquier punto que deba revisar antes.
- Alias corto y profesional, por ejemplo “Checkout · sin Payment”, “Cupón · reutilización”, “Quantity · cambio tardío”.

Para cada idea separa hechos de inferencias. Una pregunta útil debe poder probarse y descartarse con evidencia observable.
Devuelve únicamente JSON válido que cumpla el schema."""
    client=OpenAI(api_key=key)
    fmt={"type":"json_schema","name":"negro_flow_logic_ideas","description":"Preguntas de lógica de negocio y borradores de Runner basados en un Flujo real.","schema":_flow_logic_schema(),"strict":True}
    response=client.responses.create(model=model,reasoning={"effort":reasoning_effort},max_output_tokens=max(2500,int(output_tokens)),instructions=system,input=payload,text={"format":fmt})
    usage=_response_usage_dict(response)
    refusal=_response_refusal_text(response)
    if refusal:
        return {"summary":"El modelo rechazó este análisis.","ideas":[],"already_covered":[],"context_gaps":[],"structured_ok":False,"refusal":refusal},usage
    text=getattr(response,"output_text","") or ""
    result=_safe_json_object(text,{"summary":"No pude validar la respuesta estructurada.","ideas":[],"already_covered":[],"context_gaps":[]})
    result["structured_ok"]=not bool(result.get("parse_warning"))
    if not isinstance(result.get("ideas"),list): result["ideas"]=[]
    result["ideas"]=result["ideas"][:7]
    return result,usage
