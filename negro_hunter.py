#!/usr/bin/env python3
"""Negro Recon v0.9 hunter intelligence layer.

Low-impact, policy-aware reconnaissance helpers plus deterministic lead generation.
This module deliberately avoids exploitation, credential use, state-changing requests,
form submission, resource claiming, and mass brute force defaults.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import random
import re
import socket
import string
import time
import urllib.parse
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable

import negro_intel as intel

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
URLISH_PARAMS = {"url", "uri", "target", "endpoint", "webhook", "feed", "proxy", "fetch", "import", "image", "file", "src", "source"}
OBJECT_NOUNS = {"order", "orders", "user", "users", "account", "accounts", "document", "documents", "invoice", "invoices", "customer", "customers", "profile", "profiles"}
DOM_SOURCES = ["location.search", "location.hash", "document.url", "document.documenturi", "window.name", "postmessage", "event.data"]
DOM_SINKS = ["innerhtml", "outerhtml", "insertadjacenthtml", "document.write", "eval(", "settimeout(", "setinterval("]
NAV_SINKS = ["window.location", "location.href", "location.assign", "location.replace", "document.location"]

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
        CREATE INDEX IF NOT EXISTS idx_leads_v2_priority ON leads_v2(review_priority, confidence, updated_at);
        CREATE INDEX IF NOT EXISTS idx_relationships_src ON relationships(src_type, src_id, relation);
        """
    )
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


def upsert_lead(conn, *, lead_key: str, host_id: int | None, resource_id: int | None, lead_type: str, title: str, confidence: str, review_priority: str, evidence: list[dict[str, Any]], why: str, next_test: str, confirm_if: str, discard_if: str) -> None:
    now = now_iso()
    existing = conn.execute("SELECT id,confidence,review_priority,status FROM leads_v2 WHERE lead_key=?", (lead_key,)).fetchone()
    if existing:
        # Never downgrade confidence/priority automatically and preserve human status.
        confidence = max([existing["confidence"], confidence], key=_confidence_rank)
        review_priority = max([existing["review_priority"], review_priority], key=_priority_rank)
        conn.execute(
            "UPDATE leads_v2 SET host_id=?,resource_id=?,lead_type=?,title=?,confidence=?,review_priority=?,evidence_json=?,why_interesting=?,next_test=?,confirm_if=?,discard_if=?,updated_at=? WHERE lead_key=?",
            (host_id, resource_id, lead_type, title, confidence, review_priority, json.dumps(evidence, ensure_ascii=False), why, next_test, confirm_if, discard_if, now, lead_key),
        )
    else:
        conn.execute(
            "INSERT INTO leads_v2(lead_key,host_id,resource_id,lead_type,title,confidence,review_priority,status,evidence_json,why_interesting,next_test,confirm_if,discard_if,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (lead_key, host_id, resource_id, lead_type, title, confidence, review_priority, "candidate", json.dumps(evidence, ensure_ascii=False), why, next_test, confirm_if, discard_if, now, now),
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


def generate_leads(conn, domain: str) -> dict[str, Any]:
    init_schema(conn)
    generated_before = conn.execute("SELECT COUNT(*) c FROM leads_v2").fetchone()["c"]

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
    try:
        result = json.loads(text)
    except Exception:
        a, b = text.find("{"), text.rfind("}")
        result = json.loads(text[a:b+1]) if a >= 0 and b > a else {"summary":"No se pudo parsear la salida de IA","raw":text[:10000],"top_leads":[],"next_actions":[]}
    usage = getattr(response, "usage", None)
    return result, {"input_tokens":getattr(usage,"input_tokens",None),"output_tokens":getattr(usage,"output_tokens",None),"total_tokens":getattr(usage,"total_tokens",None)}


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
