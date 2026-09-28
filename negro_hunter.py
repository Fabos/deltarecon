#!/usr/bin/env python3
"""Negro Recon v0.9 hunter intelligence layer.

Low-impact, policy-aware reconnaissance helpers plus deterministic lead generation.
This module deliberately avoids exploitation, credential use, state-changing requests,
form submission, resource claiming, and mass brute force defaults.
"""
from __future__ import annotations

import base64
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

GRAPH_AI_PROMPT_VERSION = "0.16.0-burp-signals-v1"

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

    query_keys: set[str] = set()
    ex = conn.execute("SELECT query_json FROM http_exchanges WHERE operation_id=? ORDER BY last_seen_at DESC LIMIT 1", (operation_id,)).fetchone()
    if ex:
        try:
            q = json.loads(ex["query_json"] or "{}")
            if isinstance(q, dict):
                query_keys = {str(k).lower() for k in q}
        except Exception:
            pass
    if query_keys & (REDIRECT_PARAMS | URLISH_PARAMS):
        keys.append("url_handling")
    if any(k in query_keys for k in ("id", "user_id", "userid", "account_id", "order_id", "document_id", "profile_id")) or re.search(r"/(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27,})\b", path):
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
        CREATE INDEX IF NOT EXISTS idx_operation_test_coverage ON operation_test_coverage(operation_id,status,test_key);
        CREATE INDEX IF NOT EXISTS idx_leads_v2_priority ON leads_v2(review_priority, confidence, updated_at);
        CREATE INDEX IF NOT EXISTS idx_relationships_src ON relationships(src_type, src_id, relation);
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

    row = conn.execute("SELECT value FROM meta WHERE key='policy_profile'").fetchone()
    if not row:
        conn.execute("INSERT INTO meta(key,value) VALUES('policy_profile',?)", (DEFAULT_POLICY,))


def relationship(conn, src_type: str, src_id: int | None, relation: str, dst_type: str, dst_value: str, source: str, evidence: Any = None) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO relationships(src_type,src_id,relation,dst_type,dst_value,source,evidence_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (src_type, src_id, relation, dst_type, dst_value, source, json.dumps(evidence, ensure_ascii=False) if evidence is not None else None, now_iso()),
    )


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


def upsert_lead(conn, *, lead_key: str, host_id: int | None, resource_id: int | None, lead_type: str, title: str, confidence: str, review_priority: str, evidence: list[dict[str, Any]], why: str, next_test: str, confirm_if: str, discard_if: str, source: str = "ENGINE", parent_lead_id: int | None = None) -> None:
    now = now_iso()
    existing = conn.execute("SELECT id,confidence,review_priority,status FROM leads_v2 WHERE lead_key=?", (lead_key,)).fetchone()
    if existing:
        # Never downgrade confidence/priority automatically and preserve human status.
        confidence = max([existing["confidence"], confidence], key=_confidence_rank)
        review_priority = max([existing["review_priority"], review_priority], key=_priority_rank)
        conn.execute(
            "UPDATE leads_v2 SET host_id=?,resource_id=?,lead_type=?,title=?,confidence=?,review_priority=?,evidence_json=?,why_interesting=?,next_test=?,confirm_if=?,discard_if=?,source=COALESCE(source,?),parent_lead_id=COALESCE(parent_lead_id,?),updated_at=? WHERE lead_key=?",
            (host_id, resource_id, lead_type, title, confidence, review_priority, json.dumps(evidence, ensure_ascii=False), why, next_test, confirm_if, discard_if, source, parent_lead_id, now, lead_key),
        )
    else:
        conn.execute(
            "INSERT INTO leads_v2(lead_key,host_id,resource_id,lead_type,title,confidence,review_priority,status,evidence_json,why_interesting,next_test,confirm_if,discard_if,created_at,updated_at,source,parent_lead_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (lead_key, host_id, resource_id, lead_type, title, confidence, review_priority, "candidate", json.dumps(evidence, ensure_ascii=False), why, next_test, confirm_if, discard_if, now, now, source, parent_lead_id),
        )


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


def _upsert_notification(conn, *, dedupe_key: str, kind: str, severity: str, title: str, message: str,
                         source: str, entity_type: str | None = None, entity_id: int | None = None,
                         resource_id: int | None = None, operation_id: int | None = None,
                         exchange_id: int | None = None, data: dict[str, Any] | None = None,
                         emit: bool = True) -> tuple[int | None, bool]:
    if not emit:
        return None, False
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
    pmap: dict[str, list[dict[str, str]]] = {}
    for p in params:
        pmap.setdefault(p["name"].lower(), []).append(p)

    signals: list[dict[str, Any]] = []
    new_notifications: list[int] = []
    rid, oid, hid = int(row["resource_id"]), int(row["operation_id"]), int(row["host_id"])
    method, path, url = str(row["method"]), str(row["path"]), str(row["url"])

    def notify(*, kind: str, key: str, severity: str, title: str, message: str, data: dict[str, Any]) -> None:
        nid, created = _upsert_notification(
            conn, dedupe_key=key, kind=kind, severity=severity, title=title, message=message,
            source=str(row["source"] or "burp"), entity_type="resource", entity_id=rid,
            resource_id=rid, operation_id=oid, exchange_id=exchange_id, data={**data, "href": _notification_href(rid, exchange_id)}, emit=emit_notifications,
        )
        signals.append({"kind": kind, "severity": severity, "title": title, **data})
        if created and nid:
            new_notifications.append(nid)

    # 1) Redirect parameters observed in query/form/JSON from Burp.
    all_redirect_names = set(pmap) & REDIRECT_PARAMS
    navigation_route = any(tok in path.lower() for tok in ("login", "signin", "sign-in", "logout", "auth", "oauth", "sso", "callback", "redirect", "continue", "checkout"))
    has_location_header = bool(resp_headers.get("location", ""))
    redirect_hits = sorted(
        name for name in all_redirect_names
        if name in STRONG_REDIRECT_PARAMS or navigation_route or has_location_header
    )
    for name in redirect_hits:
        examples = pmap[name]
        locs = sorted({x["location"] for x in examples})
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
        priority = "high" if strong else "medium"
        confidence = "high" if strong else "medium"
        ev = {"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,"parameter":name,"locations":locs,
              "value_example":_mask_value(value) if value else "(vacío)","response_location":_safe_url_evidence(response_location) if response_location else None}
        upsert_lead(
            conn, lead_key=f"open_redirect_burp:{oid}:{name}", host_id=hid, resource_id=rid,
            lead_type="open_redirect", title=f"Posible Open Redirect · {name}", confidence=confidence, review_priority=priority,
            evidence=[ev],
            why=f"Burp observó el parámetro '{name}' en {', '.join(locs)} de {method} {path}. Ese valor podría controlar el destino de navegación.",
            next_test=f"Abre el exchange #{exchange_id} en Repeater y cambia sólo '{name}' por una URL HTTPS controlada. Observa Location o navegación final y conserva el resto idéntico.",
            confirm_if="La aplicación termina redirigiendo/navegando a un dominio externo controlado sin una allowlist efectiva.",
            discard_if="El valor se limita a rutas internas, se ignora, se normaliza o existe una allowlist estricta.",
        )
        notify(kind="open_redirect", key=f"open_redirect:{oid}:{name}", severity="high" if strong else "medium",
               title=f"Posible Open Redirect · {name}",
               message=f"{method} {path} · detectado en {', '.join(locs)} · exchange #{exchange_id}", data=ev)

    # 2) URL-fetch / SSRF surfaces from actual parameters. Avoid duplicate redirect-only clues.
    for name in sorted((set(pmap) & URLISH_PARAMS) - set(redirect_hits)):
        candidates = [x for x in pmap[name] if str(x["value"]).lower().startswith(("http://", "https://", "//"))]
        if not candidates:
            continue
        sample = candidates[0]
        ev = {"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,"parameter":name,"location":sample["location"],"value_example":_mask_value(sample["value"])}
        upsert_lead(conn, lead_key=f"ssrf_burp:{oid}:{name}", host_id=hid, resource_id=rid,
            lead_type="ssrf_surface", title=f"URL controlable observada · {name}", confidence="medium", review_priority="medium",
            evidence=[ev], why=f"Burp vio una URL completa controlada por el parámetro '{name}'. Falta determinar si la consume el servidor o sólo el cliente.",
            next_test=f"Revisa el flujo de {method} {path}. Si existe evidencia de fetch server-side y el scope lo permite, usa únicamente un endpoint propio como marcador benigno.",
            confirm_if="El servidor realiza una solicitud saliente hacia una URL controlada por el usuario.",
            discard_if="El valor sólo se usa client-side, se valida por allowlist o no provoca tráfico saliente.")
        notify(kind="url_fetch", key=f"url_fetch:{oid}:{name}", severity="medium", title=f"URL controlable en {method} {path}",
               message=f"Parámetro '{name}' observado en {sample['location']} · revisa si existe consumo server-side.", data=ev)

    # 3) Secrets/config signatures in captured request/response. Never persist the raw secret.
    text_surfaces = [("response", resp_body), ("request", req_body)]
    for surface, text in text_surfaces:
        if not text:
            continue
        for stype, label, regex, severity in SECRET_PATTERNS:
            for match in list(regex.finditer(text[:1_500_000]))[:8]:
                value = match.group(0)
                fp = _secret_fingerprint(value)
                ev = {"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,"surface":surface,
                      "secret_type":stype,"masked_value":_mask_value(value),"fingerprint":fp}
                upsert_lead(conn, lead_key=f"burp_secret:{stype}:{fp}", host_id=hid, resource_id=rid,
                    lead_type="secret_or_client_config", title=f"{label} observada en tráfico HTTP", confidence="high", review_priority=severity,
                    evidence=[ev], why=f"Burp observó una señal de {label} en el {surface} de {method} {path}. Algunas claves de cliente (por ejemplo Google API keys) pueden ser públicas por diseño; hay que validar restricciones e impacto.",
                    next_test="Valida el tipo de credencial/configuración de forma mínima, revisa restricciones de origen/API/rol y no ejecutes acciones destructivas.",
                    confirm_if="La credencial/configuración es activa y permite un uso no autorizado o expone capacidad no prevista.",
                    discard_if="Es configuración pública esperada, está correctamente restringida, es un fixture o no tiene impacto demostrable.")
                surface_label = "respuesta" if surface == "response" else "solicitud"
                notify(kind="secret_candidate", key=f"secret:{stype}:{fp}:host:{hid}", severity=severity,
                       title=f"{label} detectada en {surface_label}", message=f"{method} {path} · exchange #{exchange_id} · valor enmascarado {_mask_value(value)}", data=ev)

    # 4) Structured credential-like fields returned by APIs.
    response_obj: Any = None
    body_trim = resp_body.lstrip()
    if (body_trim.startswith(("{", "[")) or "json" in response_ct.lower()) and len(resp_body) <= 2_000_000:
        try:
            response_obj = json.loads(resp_body)
        except Exception:
            response_obj = None
    fields = _json_fields(response_obj) if response_obj is not None else []
    identity_present = any(k.lower() in IDENTITY_KEYS and not isinstance(v, (dict, list)) and str(v or "").strip() for k, _, v in fields)
    for key, jpath, value in fields:
        kl = key.lower().replace("-", "_")
        normalized = kl.replace("_", "")
        if kl not in SENSITIVE_RESPONSE_KEYS and normalized not in {x.replace("_", "").replace("-", "") for x in SENSITIVE_RESPONSE_KEYS}:
            continue
        # Session/token arrays paired with an identity are worth a clue, but never
        # persist the raw entries. Containers unrelated to sensitive keys are skipped.
        if isinstance(value, list):
            if kl in {"sessions", "session", "tokens"} and identity_present and value:
                fp = _secret_fingerprint(json.dumps(value, sort_keys=True, default=str))
                ev = {"source":"burp_response_json","exchange_id":exchange_id,"method":method,"url":url,"json_path":jpath,"field":key,
                      "masked_value":f"[{len(value)} valores enmascarados]","fingerprint":fp,"identity_context":True}
                upsert_lead(conn, lead_key=f"burp_response_secret:{rid}:{jpath}:{fp}", host_id=hid, resource_id=rid,
                    lead_type="sensitive_response", title=f"Sesiones/tokens devueltos junto a identidad · {key}", confidence="high", review_priority="medium",
                    evidence=[ev], why=f"La respuesta de {method} {path} entrega '{key}' junto a datos de identidad. Negro no guardó los valores.",
                    next_test="Confirma si esos valores son reutilizables o si exponerlos al cliente amplía acceso. Trabaja sólo con tu propia cuenta/datos autorizados.",
                    confirm_if="Los valores permiten reutilizar una sesión/token o acceder a contexto que el cliente no debería recibir.",
                    discard_if="Son identificadores no sensibles, están rotados/ligados correctamente o su entrega al cliente es necesaria sin impacto adicional.")
                notify(kind="sensitive_response", key=f"sensitive_response:{rid}:{jpath}:{fp}", severity="medium",
                       title=f"Sesiones/tokens devueltos · {key}", message=f"{method} {path} · {jpath} · exchange #{exchange_id}", data=ev)
            continue
        if isinstance(value, dict) or not str(value or "").strip():
            continue
        value_s = str(value)
        if value_s.lower() in {"null", "none", "false", "true", "***", "*****", "redacted", "masked"}:
            continue
        if len(value_s) < 4:
            continue
        high_keys = {"password","passwd","pwd","pass","client_secret","private_key","secret_key"}
        severity = "high" if kl in high_keys else "medium" if kl in {"api_key","apikey","api-key","secret","access_key"} else "info"
        if identity_present and kl in high_keys:
            severity = "high"
        elif identity_present and kl in {"token","auth_token","session_token","session","session_id","sessionid","authorization"}:
            severity = "medium"
        fp = _secret_fingerprint(value_s)
        ev = {"source":"burp_response_json","exchange_id":exchange_id,"method":method,"url":url,"json_path":jpath,"field":key,
              "masked_value":_mask_value(value_s),"fingerprint":fp,"identity_context":identity_present}
        # access/refresh tokens are normal on token endpoints; retain as low-noise intel, no hypothesis unless unusual.
        auth_path = any(x in path.lower() for x in ("oauth", "token", "login", "auth", "session"))
        if kl in {"access_token","refresh_token"} and auth_path:
            if severity == "info":
                continue
        title = "Posibles credenciales devueltas por la API" if identity_present and kl in high_keys else f"Campo sensible devuelto · {key}"
        upsert_lead(conn, lead_key=f"burp_response_secret:{rid}:{jpath}:{fp}", host_id=hid, resource_id=rid,
            lead_type="sensitive_response", title=title, confidence="high", review_priority=severity if severity in {"high","medium"} else "low",
            evidence=[ev], why=f"La respuesta de {method} {path} contiene el campo '{key}' con un valor no vacío. Negro guardó sólo una versión enmascarada.",
            next_test="Confirma si el valor pertenece al usuario actual, si era necesario devolverlo al cliente y si puede reutilizarse fuera de este flujo. Usa únicamente cuentas/datos autorizados.",
            confirm_if="La API devuelve una credencial/secreto reutilizable que el cliente no debería recibir o que permite acceso/capacidad adicional.",
            discard_if="El valor es público por diseño, está enmascarado/no reutilizable o su exposición es necesaria y no agrega capacidad.")
        notify(kind="sensitive_response", key=f"sensitive_response:{rid}:{jpath}:{fp}", severity=severity,
               title=title, message=f"{method} {path} · {jpath} · exchange #{exchange_id}", data=ev)

    # Passwords/tokens in URL query are a distinct high-value leak clue.
    for name in sorted(set(pmap) & QUERY_SECRET_KEYS):
        for item in pmap[name]:
            if item["location"] != "query" or not item["value"]:
                continue
            fp = _secret_fingerprint(item["value"])
            ev = {"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,"parameter":name,"location":"query","masked_value":_mask_value(item["value"]),"fingerprint":fp}
            notify(kind="secret_in_url", key=f"secret_url:{oid}:{name}:{fp}", severity="high",
                   title=f"Dato sensible en la URL · {name}", message=f"{method} {path} incluye '{name}' en query; puede terminar en logs, historial o Referer.", data=ev)
            upsert_lead(conn, lead_key=f"secret_url:{oid}:{name}:{fp}", host_id=hid, resource_id=rid,
                lead_type="sensitive_url", title=f"Dato sensible en query · {name}", confidence="high", review_priority="high", evidence=[ev],
                why="Credenciales/tokens en la URL pueden quedar expuestos en logs, historial, proxies y encabezados Referer.",
                next_test="Confirma el flujo y si el valor aparece en URLs/logs o se propaga a terceros. No reutilices credenciales ajenas.",
                confirm_if="El secreto real queda expuesto a componentes/personas que no deberían recibirlo.",
                discard_if="El parámetro no contiene un secreto real o el valor es un identificador público/no sensible.")
            break

    # 5) Passive CORS evidence already present in the captured exchange.
    origin = req_headers.get("origin", "")
    acao = resp_headers.get("access-control-allow-origin", "")
    acac = resp_headers.get("access-control-allow-credentials", "").lower() == "true"
    if origin and acao and acao == origin:
        try:
            origin_host = urllib.parse.urlsplit(origin).hostname or ""
        except Exception:
            origin_host = ""
        cross_origin = bool(origin_host and origin_host.lower() != str(row["hostname"]).lower())
        if cross_origin:
            ev = {"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,"origin":origin,"allow_origin":acao,"allow_credentials":acac}
            pri = "high" if acac and bool(row["authenticated_observed"]) else "medium"
            upsert_lead(conn, lead_key=f"cors_burp:{rid}:{origin}", host_id=hid, resource_id=rid,
                lead_type="cors", title="CORS cross-origin observado en tráfico real", confidence="high", review_priority=pri,
                evidence=[ev], why="Burp observó que el servidor reflejó exactamente un Origin de otro host. Con credenciales/datos sensibles puede ser relevante.",
                next_test="Repite con un Origin HTTPS controlado y verifica si el navegador puede leer una respuesta autenticada sensible.",
                confirm_if="Un origen externo arbitrario puede leer una respuesta autenticada sensible.",
                discard_if="El Origin está allowlisted de forma esperada, no hay credenciales/datos sensibles o un origen arbitrario es rechazado.")
            notify(kind="cors", key=f"cors_passive:{rid}:{origin}", severity=pri,
                   title="CORS cross-origin observado", message=f"{method} {path} reflejó Origin {origin} · credentials={str(acac).lower()}", data=ev)

    # 6) High-signal exposed surfaces and verbose errors in actual responses.
    low_path = path.lower()
    status = int(row["status_code"] or 0)
    if status and status < 400 and any(x in low_path for x in ("/swagger", "/openapi", "/v3/api-docs", "/api-docs")):
        ev = {"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,"status":status}
        notify(kind="api_docs", key=f"api_docs:{rid}", severity="medium", title="Documentación API observada", message=f"{method} {path} respondió HTTP {status}.", data=ev)
    if status and status < 400 and low_path.endswith(".map"):
        ev = {"source":"burp_http","exchange_id":exchange_id,"method":method,"url":url,"status":status}
        upsert_lead(conn, lead_key=f"sourcemap_burp:{rid}", host_id=hid, resource_id=rid, lead_type="source_map", title="Source map observado desde Burp", confidence="high", review_priority="medium", evidence=[ev],
            why="Un source map público puede revelar código original, rutas y configuración.", next_test="Ábrelo y analiza fuentes/configuración sin asumir que la exposición sola sea una vulnerabilidad.", confirm_if="El mapa revela secretos, rutas sensibles o una cadena de impacto adicional.", discard_if="Sólo contiene código público esperado sin información sensible ni impacto.")
        notify(kind="source_map", key=f"source_map:{rid}", severity="medium", title="Source map accesible", message=f"{method} {path} · HTTP {status}", data=ev)

    error_patterns = [
        ("stack_trace", r"(?:Traceback \(most recent call last\)|\bException in thread\b|\bat [a-zA-Z0-9_.$]+\([^\n]+:\d+\)|System\.[A-Za-z.]+Exception)"),
        ("sql_error", r"(?:SQL syntax.*MySQL|ORA-\d{4,5}|PostgreSQL.*ERROR|SQLite(?:3)?::|Unclosed quotation mark after the character string)"),
        ("internal_path", r"(?:/home/[A-Za-z0-9_.-]+/|/var/www/|[A-Za-z]:\\\\(?:Users|inetpub|wwwroot)\\)"),
    ]
    for etype, pattern in error_patterns:
        if resp_body and re.search(pattern, resp_body[:700_000], re.I):
            ev = {"source":"burp_response","exchange_id":exchange_id,"method":method,"url":url,"error_type":etype,"status":status}
            notify(kind="error_disclosure", key=f"error_disclosure:{etype}:{rid}", severity="medium", title="Detalle interno en respuesta", message=f"{method} {path} muestra una señal de {etype.replace('_',' ')} · exchange #{exchange_id}", data=ev)

    return {"exchange_id": exchange_id, "signals": signals, "new_notifications": new_notifications}


def generate_leads(conn, domain: str) -> dict[str, Any]:
    init_schema(conn)
    generated_before = conn.execute("SELECT COUNT(*) c FROM leads_v2").fetchone()["c"]

    # Backfill deterministic Burp clues for workspaces captured before v0.16.0.
    # Notifications are disabled here to avoid flooding the user with historical toasts.
    for _ex in conn.execute("SELECT id FROM http_exchanges ORDER BY id DESC LIMIT 5000").fetchall():
        try:
            analyze_http_exchange(conn, int(_ex["id"]), domain, emit_notifications=False)
        except Exception:
            pass

    js_by_host: dict[int, list[tuple[Any, dict[str, Any], dict[str, Any] | None]]] = {}
    for row, local, sm in _iter_js_analysis(conn):
        js_by_host.setdefault(int(row["host_id"]), []).append((row, local, sm))
        # Source map lead.
        if sm and int(sm.get("sources_count") or 0) > 0:
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
        for d in merged:
            if not isinstance(d, dict):
                continue
            cat = d.get("category")
            dtype = str(d.get("type") or "config")
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

    # URL/resource based leads.
    resources = conn.execute("SELECT r.*, h.hostname FROM resources r JOIN hosts h ON h.id=r.host_id").fetchall()
    for r in resources:
        query = urllib.parse.parse_qs(r["query"] or "", keep_blank_values=True)
        qkeys = {k.lower() for k in query}
        redirect_hits = sorted(qkeys & REDIRECT_PARAMS)
        if redirect_hits:
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
        ssrf_hits = sorted(qkeys & URLISH_PARAMS)
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
        if any(x in OBJECT_NOUNS for x in segments) and any(re.fullmatch(r"\d{2,}|[0-9a-f]{8}-[0-9a-f-]{20,}|[0-9a-f]{24,}", x, re.I) for x in segments):
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
                rh = sorted(set(fields) & REDIRECT_PARAMS)
                if rh:
                    key = hashlib.sha1((str(form.get("action"))+",".join(rh)).encode()).hexdigest()[:12]
                    upsert_lead(conn, lead_key=f"open_redirect_form:{hid}:{key}", host_id=hid, resource_id=None,
                        lead_type="open_redirect", title=f"Formulario con destino/redirección controlable · {', '.join(rh)}", confidence="medium", review_priority="medium",
                        evidence=[{"source":"crawler_form","page":form.get("page"),"action":form.get("action"),"method":form.get("method"),"fields":rh}],
                        why="Un form expone un campo de redirección. Requiere observar cómo lo consume la aplicación.",
                        next_test="Revisar JS/flujo y hacer una única validación con dominio HTTPS controlado si el campo realmente controla navegación.",
                        confirm_if="El valor termina en una redirección externa arbitraria.",
                        discard_if="El campo se ignora, se normaliza a rutas internas o usa allowlist.")
        elif o["kind"] == "cors_probe" and isinstance(payload, dict):
            hid = int(o["entity_id"]) if o["entity_type"] == "host" else None
            ao = payload.get("allow_origin")
            creds = str(payload.get("allow_credentials") or "").lower() == "true"
            reflected = ao == payload.get("origin_sent")
            if reflected or ao == "*":
                conf = "high" if reflected and creds else "medium"
                pri = "high" if reflected and creds else "low"
                upsert_lead(conn, lead_key=f"cors:{hid}:{hashlib.sha1(str(payload.get('url')).encode()).hexdigest()[:12]}", host_id=hid, resource_id=None,
                    lead_type="cors", title="CORS permisivo / Origin reflejado", confidence=conf, review_priority=pri,
                    evidence=[{"source":"cors_probe","url":payload.get("url"),"allow_origin":ao,"allow_credentials":payload.get("allow_credentials"),"status":payload.get("status")}],
                    why="Aceptar un Origin arbitrario puede ser relevante si una respuesta autenticada sensible es legible cross-origin. Sin datos sensibles/credentials puede ser inocuo.",
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


def list_leads(conn, limit: int = 200) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT l.*, h.hostname, r.url AS resource_url FROM leads_v2 l
           LEFT JOIN hosts h ON h.id=l.host_id LEFT JOIN resources r ON r.id=l.resource_id
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
            "review","classification","priority","type","why","next_test","severity","updated_at","last_seen_at","test_summary"
        ) if meta.get(k) not in (None, "")}
        return {"id": n.get("id"), "type": n.get("type"), "label": n.get("label"), "state": n.get("state"), "meta": allowed}

    important_types = {"target","host","resource","operation","javascript","observation","lead","finding","source"}
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
    for row in conn.execute("SELECT id,title,lead_type,status,why_interesting,next_test,source,updated_at FROM leads_v2 ORDER BY updated_at DESC LIMIT 120").fetchall():
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
        "instructions_context": {
            "prompt_version": GRAPH_AI_PROMPT_VERSION,
            "negative_is_knowledge": True,
            "do_not_repeat_negative_or_discarded": True,
            "full_http_bodies_included": False,
            "authorized_testing_only": True,
            "test_coverage_is_manual_memory": True,
            "untouched_recommended_checks_are_excluded": True,
            "negative_tests_should_not_repeat": True,
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
            "why_interesting": {"type": "string"},
            "suggested_investigation": {"type": "string"},
            "steps": {"type": "array", "items": step_schema},
            "confirm_if": {"type": "string"},
            "discard_if": {"type": "string"},
            "node_ids": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["title", "type", "strength", "investigation_priority", "priority_reasons", "plain_language", "why_interesting", "suggested_investigation", "steps", "confirm_if", "discard_if", "node_ids"],
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

Usa exclusivamente el grafo, el historial y el resumen HTTP sanitizado suministrados. El bloque http_evidence puede incluir línea de request, query y preview JSON limitada; úsalo para nombrar requests, parámetros, campos y respuestas REALES.
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
- node_ids: sólo IDs REALES del contexto.
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
    """Resolve internal graph ids into human-actionable HTTP/resource references."""
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
    """Persist AI ideas into leads_v2, preserving human lifecycle status."""
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
        if resource_id and host_id is None:
            row = conn.execute("SELECT host_id FROM resources WHERE id=?", (resource_id,)).fetchone()
            host_id = int(row["host_id"]) if row else None
        strength = str(item.get("strength") or "medium").lower()
        investigation_priority = str(item.get("investigation_priority") or ("high" if strength == "strong" else "medium" if strength == "medium" else "quick")).lower()
        priority = "high" if investigation_priority == "high" else "medium" if investigation_priority == "medium" else "low"
        confidence = "high" if strength == "strong" else "medium" if strength == "medium" else "low"
        priority_reasons = [str(x).strip()[:120] for x in (item.get("priority_reasons") or []) if str(x).strip()][:4]
        evidence = [{"source":"ai_graph","node_ids":node_ids,"evidence_hash":evidence_hash,"selected_node_id":selected_node_id,"plain_language":str(item.get("plain_language") or "").strip(),"investigation_priority":investigation_priority,"priority_reasons":priority_reasons}]
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
            refs = hypothesis_refs_from_nodes(conn, node_ids)
            persisted.append({**item, **refs, "lead_id": int(row["id"]), "status": row["status"], "node_ids": node_ids})
    return persisted

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
