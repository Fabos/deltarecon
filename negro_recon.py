from __future__ import annotations

import json
import os
import re
import sqlite3
import shutil
import subprocess
import uuid
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit

ENV_PATTERNS = (
    ("DEV", re.compile(r"(?:^|[._-])(dev|development|sandbox|lab)(?:$|[._-])", re.I)),
    ("QA", re.compile(r"(?:^|[._-])(qa|test|testing)(?:$|[._-])", re.I)),
    ("STAGING", re.compile(r"(?:^|[._-])(stage|staging|uat|preprod)(?:$|[._-])", re.I)),
    ("PROD", re.compile(r"(?:^|[._-])(prod|prd|production)(?:$|[._-])", re.I)),
)

ENV_TOKENS = {
    "dev", "development", "sandbox", "lab", "qa", "test", "testing",
    "stage", "staging", "uat", "preprod", "prod", "prd", "production",
}
ROLE_TOKENS = {
    "api", "apis", "www", "web", "app", "apps", "cloud", "cloudapps",
    "sso", "auth", "login", "cdn", "static", "frontend", "backend", "portal", "admin", "mobile",
}

# Small, high-signal baseline for the *explicit* active discovery phase.
# The goal is not to spray huge dictionaries by default; hunters can point
# NEGRO_DNS_WORDLIST at a larger authorized wordlist when that is useful.
DEFAULT_DNS_WORDS = (
    "www", "api", "apis", "app", "apps", "web", "portal", "admin",
    "auth", "login", "sso", "oauth", "idp", "gateway", "gw", "backend",
    "frontend", "mobile", "cdn", "static", "assets", "files", "download",
    "dev", "development", "qa", "test", "testing", "uat", "stage",
    "staging", "preprod", "prod", "prd", "production", "sandbox", "lab",
    "old", "legacy", "new", "beta", "alpha", "demo", "internal", "intranet",
    "vpn", "remote", "jenkins", "gitlab", "github", "grafana", "kibana",
    "monitor", "status", "docs", "swagger", "openapi", "graphql", "ws",
    "socket", "mail", "smtp", "autodiscover", "ftp", "sftp", "mta",
)

PROVIDER_TECH = {
    "amazon web services": ("Amazon Web Services", "HOSTED_ON", "cloud"),
    "amazon s3": ("Amazon Web Services", "HOSTED_ON", "cloud"),
    "amazon alb": ("Amazon Web Services", "HOSTED_ON", "cloud"),
    "amazon cloudfront": ("Amazon CloudFront", "PROXIED_BY", "cdn"),
    "google cloud": ("Google Cloud", "HOSTED_ON", "cloud"),
    "google cloud cdn": ("Google Cloud CDN", "PROXIED_BY", "cdn"),
    "platform.sh": ("Platform.sh", "HOSTED_ON", "platform"),
    "salesforce": ("Salesforce", "USES_PLATFORM", "saas"),
    "salesforce service cloud": ("Salesforce Service Cloud", "USES_PLATFORM", "saas"),
}

# Conservative signatures for *unprovisioned-service* responses.  These are
# deliberately treated as fingerprints, not proof that the resource can be
# claimed.  Claimability changes over time and must remain a manual validation.
TAKEOVER_FINGERPRINTS = (
    ("github-pages", "GitHub Pages", ("github.io",), ("there isn't a github pages site here",)),
    ("heroku", "Heroku", ("herokudns.com", "herokuapp.com"), ("no such app",)),
    ("aws-s3", "Amazon S3", ("s3.amazonaws.com", "s3-website", "amazonaws.com"), ("nosuchbucket", "the specified bucket does not exist")),
    ("azure-webapps", "Azure App Service", ("azurewebsites.net",), ("404 web site not found", "web app - unavailable")),
    ("fastly", "Fastly", ("fastly.net",), ("fastly error: unknown domain",)),
    ("pantheon", "Pantheon", ("pantheonsite.io",), ("the gods are wise, but do not know of the site which you seek",)),
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS recon_import_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            filename TEXT,
            status TEXT NOT NULL DEFAULT 'done',
            record_count INTEGER NOT NULL DEFAULT 0,
            error_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS recon_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_type TEXT NOT NULL,
            asset_key TEXT NOT NULL,
            label TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            UNIQUE(asset_type, asset_key)
        );
        CREATE TABLE IF NOT EXISTS recon_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            source TEXT NOT NULL,
            kind TEXT NOT NULL,
            value TEXT,
            raw_json TEXT,
            observed_at TEXT NOT NULL,
            FOREIGN KEY(asset_id) REFERENCES recon_assets(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS recon_relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_asset_id INTEGER NOT NULL,
            relation TEXT NOT NULL,
            dst_asset_id INTEGER NOT NULL,
            source TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 1.0,
            confidence_type TEXT NOT NULL DEFAULT 'observed',
            evidence_id INTEGER,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            UNIQUE(src_asset_id, relation, dst_asset_id, source),
            FOREIGN KEY(src_asset_id) REFERENCES recon_assets(id) ON DELETE CASCADE,
            FOREIGN KEY(dst_asset_id) REFERENCES recon_assets(id) ON DELETE CASCADE,
            FOREIGN KEY(evidence_id) REFERENCES recon_evidence(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_recon_assets_type ON recon_assets(asset_type);
        CREATE INDEX IF NOT EXISTS idx_recon_evidence_asset ON recon_evidence(asset_id, observed_at);
        CREATE INDEX IF NOT EXISTS idx_recon_rel_src ON recon_relationships(src_asset_id, relation);
        CREATE INDEX IF NOT EXISTS idx_recon_rel_dst ON recon_relationships(dst_asset_id, relation);
        CREATE TABLE IF NOT EXISTS recon_tool_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phase TEXT NOT NULL,
            tool TEXT NOT NULL,
            root_domain TEXT,
            run_group TEXT,
            command_json TEXT NOT NULL,
            status TEXT NOT NULL,
            return_code INTEGER,
            record_count INTEGER NOT NULL DEFAULT 0,
            stdout_path TEXT,
            stderr_path TEXT,
            error TEXT,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_recon_tool_runs_phase ON recon_tool_runs(phase, id DESC);
        CREATE TABLE IF NOT EXISTS recon_baseline_batches (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            root_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS recon_baseline_jobs (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            batch_id TEXT NOT NULL,
            root_domain TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            current_phase TEXT,
            step_index INTEGER NOT NULL DEFAULT 0,
            step_total INTEGER NOT NULL DEFAULT 8,
            completed_json TEXT NOT NULL DEFAULT '[]',
            skipped_json TEXT NOT NULL DEFAULT '[]',
            error TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(batch_id) REFERENCES recon_baseline_batches(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_recon_baseline_jobs_batch ON recon_baseline_jobs(batch_id, seq);
        CREATE INDEX IF NOT EXISTS idx_recon_baseline_jobs_root ON recon_baseline_jobs(root_domain, seq DESC);
        """
    )
    # Lightweight migrations for projects created before guided multi-root recon.
    cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(recon_tool_runs)").fetchall()}
    if "root_domain" not in cols:
        conn.execute("ALTER TABLE recon_tool_runs ADD COLUMN root_domain TEXT")
    if "run_group" not in cols:
        conn.execute("ALTER TABLE recon_tool_runs ADD COLUMN run_group TEXT")


def _loads(raw: str | None) -> dict:
    try:
        value = json.loads(raw or "{}")
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _merge_meta(old: dict, new: dict) -> dict:
    out = dict(old)
    for key, value in new.items():
        if value is None or value == "" or value == []:
            continue
        if key in {"sources", "tech", "ips", "cnames", "statuses", "urls"}:
            before = out.get(key, [])
            if not isinstance(before, list):
                before = [before]
            incoming = value if isinstance(value, list) else [value]
            out[key] = list(dict.fromkeys([str(x) for x in before + incoming if x not in (None, "")]))
        else:
            out[key] = value
    return out


def upsert_asset(conn: sqlite3.Connection, asset_type: str, asset_key: str, label: str | None = None, metadata: dict | None = None) -> int:
    now = _now()
    key = str(asset_key or "").strip().lower()
    if not key:
        raise ValueError("asset_key vacío")
    row = conn.execute("SELECT id,metadata_json FROM recon_assets WHERE asset_type=? AND asset_key=?", (asset_type, key)).fetchone()
    if row:
        meta = _merge_meta(_loads(row["metadata_json"]), metadata or {})
        conn.execute("UPDATE recon_assets SET label=?,metadata_json=?,last_seen_at=? WHERE id=?", (label or asset_key, json.dumps(meta, ensure_ascii=False), now, row["id"]))
        return int(row["id"])
    cur = conn.execute(
        "INSERT INTO recon_assets(asset_type,asset_key,label,metadata_json,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?)",
        (asset_type, key, label or asset_key, json.dumps(metadata or {}, ensure_ascii=False), now, now),
    )
    return int(cur.lastrowid)


def add_evidence(conn: sqlite3.Connection, asset_id: int, source: str, kind: str, value: str | None = None, raw: dict | list | str | None = None) -> int:
    raw_json = raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False) if raw is not None else None
    cur = conn.execute(
        "INSERT INTO recon_evidence(asset_id,source,kind,value,raw_json,observed_at) VALUES(?,?,?,?,?,?)",
        (asset_id, source, kind, value, raw_json, _now()),
    )
    return int(cur.lastrowid)


def link(conn: sqlite3.Connection, src_id: int, relation: str, dst_id: int, source: str, *, confidence: float = 1.0, confidence_type: str = "observed", evidence_id: int | None = None) -> None:
    now = _now()
    conn.execute(
        """INSERT INTO recon_relationships(src_asset_id,relation,dst_asset_id,source,confidence,confidence_type,evidence_id,first_seen_at,last_seen_at)
           VALUES(?,?,?,?,?,?,?,?,?)
           ON CONFLICT(src_asset_id,relation,dst_asset_id,source) DO UPDATE SET
             confidence=excluded.confidence, confidence_type=excluded.confidence_type,
             evidence_id=COALESCE(excluded.evidence_id,recon_relationships.evidence_id), last_seen_at=excluded.last_seen_at""",
        (src_id, relation, dst_id, source, float(confidence), confidence_type, evidence_id, now, now),
    )


def detect_environment(hostname: str) -> tuple[str, float]:
    local = hostname.split(".")[0].lower()
    whole = hostname.lower()
    for env, pattern in ENV_PATTERNS:
        if pattern.search(local) or pattern.search(whole):
            return env, 0.98

    env_aliases = {
        "DEV": ("development", "sandbox", "lab", "dev"),
        "QA": ("testing", "test", "qa"),
        "STAGING": ("staging", "stage", "preprod", "uat"),
        "PROD": ("production", "prod", "prd"),
    }
    strong_roles = ("apis", "api", "www", "sso", "auth", "login", "cdn", "static")
    # Compact forms are intentionally conservative: avoid treating a semantic
    # word such as ``devops`` as the DEV environment.
    for env, aliases in env_aliases.items():
        for role in strong_roles:
            if local.startswith(role):
                remainder = local[len(role):]
                if any(remainder.startswith(alias) and len(remainder) > len(alias) + 2 for alias in aliases):
                    return env, 0.82
        for alias in aliases:
            if local.endswith(alias) and len(local) >= len(alias) + 2:
                return env, 0.78
            if local.startswith(alias):
                remainder = local[len(alias):]
                if any(remainder.startswith(role) for role in ROLE_TOKENS) and len(remainder) >= 3:
                    return env, 0.72
    return "UNKNOWN", 0.0


def _strip_compact_role_env(label: str) -> str:
    """Normalize compact environment naming without organization-specific rules.

    We intentionally prefer precision over recall. Generic role prefixes are
    stripped only when an environment token immediately follows them, so a
    product name such as ``webpayments`` is not reduced to ``payments``.
    """
    value = label.lower().strip("-_")
    if not value:
        return value
    envs = sorted(ENV_TOKENS, key=len, reverse=True)
    strong_roles = ("apis", "api", "www", "sso", "auth", "login", "cdn", "static")
    role_stripped = False
    for role in strong_roles:
        if value.startswith(role):
            remainder = value[len(role):].lstrip("-_")
            if any(remainder.startswith(env) and len(remainder) > len(env) + 2 for env in envs):
                value = remainder
                role_stripped = True
                break
    for env in envs:
        if value.startswith(env) and len(value) > len(env) + 2:
            remainder = value[len(env):].lstrip("-_")
            if role_stripped or any(remainder.startswith(role) for role in ROLE_TOKENS):
                value = remainder
            break
    for env in envs:
        if value.endswith(env) and len(value) >= len(env) + 2:
            value = value[:-len(env)].rstrip("-_")
            break
    return value


def _family_stem(hostname: str, root_domain: str) -> str:
    h = hostname.lower().rstrip(".")
    root = root_domain.lower().rstrip(".")
    rel = h[:-len(root)].rstrip(".") if h == root or h.endswith("." + root) else h
    labels = [x for x in rel.split(".") if x]
    if not labels:
        return root

    candidates: list[str] = []
    fallback_roles: list[str] = []
    for label in labels:
        parts = [p for p in re.split(r"[-_]", label) if p]
        for part in parts:
            if part in ENV_TOKENS:
                continue
            if part in ROLE_TOKENS:
                fallback_roles.append(part)
                continue
            normalized = _strip_compact_role_env(part)
            if normalized and normalized not in ENV_TOKENS:
                candidates.append(normalized)
        if len(parts) == 1 and not candidates:
            compact = _strip_compact_role_env(label)
            if compact and compact not in ENV_TOKENS and compact not in ROLE_TOKENS:
                candidates.append(compact)

    if not candidates and fallback_roles:
        candidates.append(fallback_roles[0])

    # Parent semantic labels are often more useful than generic role labels:
    # auth.customer.example -> customer. This remains a low-confidence heuristic.
    return (candidates[0] if candidates else labels[0]).strip("-_") or labels[0]


def _longest_common_prefix(values: list[str]) -> str:
    if not values:
        return ""
    prefix = min(values, key=len)
    for value in values:
        while prefix and not value.startswith(prefix):
            prefix = prefix[:-1]
    return prefix.rstrip("-_")


def rebuild_family_heuristics(conn: sqlite3.Connection, root_domain: str) -> None:
    """Rebuild reusable family candidates without target-specific vocabulary.

    Pass 1 groups exact normalized stems. Pass 2 can merge sibling stems by a
    strong common prefix (>=5 chars) when at least two siblings support it.
    These are always heuristic edges and stay visually distinct from facts.
    """
    init_schema(conn)
    conn.execute("DELETE FROM recon_relationships WHERE source LIKE 'heuristic:family%'")
    rows = conn.execute("SELECT id,asset_key,metadata_json FROM recon_assets WHERE asset_type='hostname'").fetchall()
    first_party = []
    for row in rows:
        host = str(row["asset_key"]).lower()
        if host == root_domain.lower() or host.endswith("." + root_domain.lower()):
            first_party.append((int(row["id"]), host, _family_stem(host, root_domain)))
    stems = sorted(set(stem for _,_,stem in first_party if stem))
    merge_to = {stem: stem for stem in stems}
    for stem in stems:
        peers = [other for other in stems if other != stem and (other.startswith(stem) or stem.startswith(other))]
        if peers:
            shortest = min([stem] + peers, key=len)
            if len(shortest) >= 5:
                for x in [stem] + peers:
                    merge_to[x] = shortest
    # Also catch opaque sibling names sharing a meaningful prefix, e.g.
    # productalpha/productbeta. Kept deliberately low confidence.
    for i, stem in enumerate(stems):
        peers = [x for x in stems[i+1:] if len(_longest_common_prefix([stem,x])) >= 5]
        for peer in peers:
            prefix = _longest_common_prefix([stem, peer])
            if len(prefix) >= 5 and min(len(stem)-len(prefix), len(peer)-len(prefix)) >= 2:
                merge_to[stem] = prefix
                merge_to[peer] = prefix
    for host_id, hostname, stem in first_party:
        family = merge_to.get(stem, stem) or "other"
        fid = upsert_asset(conn, "family", family, family, {"heuristic": "generic_hostname_normalization"})
        confidence = 0.72 if family == stem else 0.56
        link(conn, host_id, "POSSIBLE_FAMILY", fid, "heuristic:family:naming", confidence=confidence, confidence_type="heuristic")
        row = conn.execute("SELECT metadata_json FROM recon_assets WHERE id=?", (host_id,)).fetchone()
        meta = _merge_meta(_loads(row["metadata_json"] if row else "{}"), {"family": family, "family_confidence": confidence})
        conn.execute("UPDATE recon_assets SET metadata_json=? WHERE id=?", (json.dumps(meta, ensure_ascii=False), host_id))
    conn.execute("DELETE FROM recon_assets WHERE asset_type='family' AND id NOT IN (SELECT dst_asset_id FROM recon_relationships WHERE relation='POSSIBLE_FAMILY')")


def _link_family(conn: sqlite3.Connection, host_id: int, hostname: str, root_domain: str) -> None:
    # Kept as a cheap per-record hint. Full cross-host family inference is
    # rebuilt after each ingestion by rebuild_family_heuristics().
    family = _family_stem(hostname, root_domain)
    if not family:
        return
    fid = upsert_asset(conn, "family", family, family, {"heuristic": "generic_hostname_normalization"})
    link(conn, host_id, "POSSIBLE_FAMILY", fid, "heuristic:family:initial", confidence=0.60, confidence_type="heuristic")


def _provider_label(raw: str) -> str:
    value = str(raw or "").strip().lower()
    mapping = {"cloudflare": "Cloudflare", "fastly": "Fastly", "cloudfront": "Amazon CloudFront", "aws": "Amazon Web Services", "azure": "Microsoft Azure", "office365": "Microsoft 365"}
    return mapping.get(value, str(raw or "").strip())


def _tech_key(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).lower()


def import_subfinder_text(conn: sqlite3.Connection, text: str, root_domain: str, filename: str = "") -> dict:
    init_schema(conn)
    count = errors = 0
    for line in text.splitlines():
        host = line.strip().lower().rstrip(".")
        if not host or " " in host:
            continue
        try:
            env, env_conf = detect_environment(host)
            prior = conn.execute("SELECT metadata_json FROM recon_assets WHERE asset_type='hostname' AND asset_key=?", (host,)).fetchone()
            prior_state = (_loads(prior["metadata_json"]).get("dns_state") if prior else None)
            dns_state = prior_state if prior_state in {"RESOLVED","NODATA","NXDOMAIN"} else "DISCOVERED"
            hid = upsert_asset(conn, "hostname", host, host, {"sources": ["subfinder"], "environment": env, "environment_confidence": env_conf, "family": _family_stem(host, root_domain), "dns_state": dns_state})
            _link_family(conn, hid, host, root_domain)
            add_evidence(conn, hid, "subfinder", "discovered_hostname", host, {"hostname": host})
            count += 1
        except Exception:
            errors += 1
    rebuild_family_heuristics(conn, root_domain)
    conn.execute("INSERT INTO recon_import_runs(source,filename,record_count,error_count,created_at) VALUES(?,?,?,?,?)", ("subfinder", filename, count, errors, _now()))
    conn.commit()
    return {"source": "subfinder", "records": count, "errors": errors}


def import_discovered_hosts(conn: sqlite3.Connection, hosts: list[str], root_domain: str, source: str, filename: str = "") -> dict:
    """Persist hostname candidates from any passive discovery source.

    Discovery sources are intentionally treated as candidate evidence only;
    DNS validation decides whether the names currently resolve.
    """
    init_schema(conn)
    count = errors = 0
    root = root_domain.lower().rstrip(".")
    for raw in hosts:
        host = str(raw or "").strip().lower().rstrip(".").lstrip("*.")
        if not host or " " in host or not (host == root or host.endswith("." + root)):
            continue
        try:
            env, env_conf = detect_environment(host)
            prior = conn.execute("SELECT metadata_json FROM recon_assets WHERE asset_type='hostname' AND asset_key=?", (host,)).fetchone()
            prior_state = (_loads(prior["metadata_json"]).get("dns_state") if prior else None)
            dns_state = prior_state if prior_state in {"RESOLVED","NODATA","NXDOMAIN"} else "DISCOVERED"
            hid = upsert_asset(conn, "hostname", host, host, {
                "sources": [source], "environment": env, "environment_confidence": env_conf,
                "family": _family_stem(host, root_domain), "dns_state": dns_state,
            })
            _link_family(conn, hid, host, root_domain)
            add_evidence(conn, hid, source, "discovered_hostname", host, {"hostname": host, "source": source})
            count += 1
        except Exception:
            errors += 1
    rebuild_family_heuristics(conn, root_domain)
    conn.execute(
        "INSERT INTO recon_import_runs(source,filename,record_count,error_count,created_at) VALUES(?,?,?,?,?)",
        (source, filename, count, errors, _now()),
    )
    conn.commit()
    return {"source": source, "records": count, "errors": errors}


_DNSX_RE = re.compile(r"^(?P<host>\S+)\s+\[(?P<rtype>A|AAAA|CNAME)\]\s+\[(?P<value>.+?)\]\s*$", re.I)


def import_dnsx_text(conn: sqlite3.Connection, text: str, root_domain: str, filename: str = "") -> dict:
    init_schema(conn)
    count = errors = 0
    for line in text.splitlines():
        m = _DNSX_RE.match(line.strip())
        if not m:
            continue
        try:
            host = m.group("host").lower().rstrip(".")
            rtype = m.group("rtype").upper()
            value = m.group("value").strip().rstrip(".")
            env, env_conf = detect_environment(host)
            hid = upsert_asset(conn, "hostname", host, host, {"sources": ["dnsx"], "environment": env, "environment_confidence": env_conf, "family": _family_stem(host, root_domain), "dns_state": "RESOLVED"})
            _link_family(conn, hid, host, root_domain)
            evid = add_evidence(conn, hid, "dnsx", f"dns_{rtype.lower()}", value, {"host": host, "type": rtype, "value": value})
            if rtype in {"A", "AAAA"}:
                did = upsert_asset(conn, "ip", value, value, {"ip_version": 6 if rtype == "AAAA" else 4, "sources": ["dnsx"]})
                link(conn, hid, "RESOLVES_TO", did, "dnsx", evidence_id=evid)
            else:
                did = upsert_asset(conn, "hostname", value, value, {"sources": ["dnsx"], "external": not value.endswith(root_domain.lower().rstrip("."))})
                link(conn, hid, "CNAME_TO", did, "dnsx", evidence_id=evid)
            count += 1
        except Exception:
            errors += 1
    rebuild_family_heuristics(conn, root_domain)
    conn.execute("INSERT INTO recon_import_runs(source,filename,record_count,error_count,created_at) VALUES(?,?,?,?,?)", ("dnsx", filename, count, errors, _now()))
    conn.commit()
    return {"source": "dnsx", "records": count, "errors": errors}


def import_httpx_jsonl(conn: sqlite3.Connection, text: str, root_domain: str, filename: str = "") -> dict:
    init_schema(conn)
    count = errors = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                continue
            host = str(row.get("host") or row.get("input") or "").lower().rstrip(".")
            if not host:
                continue
            env, env_conf = detect_environment(host)
            tech = [str(x) for x in (row.get("tech") or []) if x]
            cnames = [str(x).rstrip(".") for x in (row.get("cname") or []) if x]
            ips = [str(x) for x in (row.get("a") or []) + (row.get("aaaa") or []) if x]
            if row.get("host_ip"):
                ips.append(str(row.get("host_ip")))
            ips = list(dict.fromkeys(ips))
            status = row.get("status_code")
            meta = {
                "sources": ["httpx"], "environment": env, "environment_confidence": env_conf,
                "family": _family_stem(host, root_domain), "http_state": "ALIVE" if status else "UNKNOWN",
                "status_code": status, "statuses": [status] if status is not None else [], "title": row.get("title"),
                "url": row.get("url"), "urls": [row.get("url")] if row.get("url") else [], "scheme": row.get("scheme"),
                "port": row.get("port"), "webserver": row.get("webserver"), "content_type": row.get("content_type"),
                "location": row.get("location"), "cdn": bool(row.get("cdn")), "cdn_name": _provider_label(row.get("cdn_name")) if row.get("cdn_name") else None,
                "cdn_type": row.get("cdn_type"), "tech": tech, "ips": ips, "cnames": cnames, "failed": bool(row.get("failed")),
                "response_time": row.get("time"), "content_length": row.get("content_length"),
            }
            hid = upsert_asset(conn, "hostname", host, host, meta)
            _link_family(conn, hid, host, root_domain)
            evid = add_evidence(conn, hid, "httpx", "http_probe", str(status) if status is not None else None, row)
            for ip in ips:
                iid = upsert_asset(conn, "ip", ip, ip, {"sources": ["httpx"], "serving_ip": True})
                link(conn, hid, "OBSERVED_IP", iid, "httpx", confidence=1.0, evidence_id=evid)
            for cname in cnames:
                cid = upsert_asset(conn, "hostname", cname, cname, {"sources": ["httpx"], "external": not cname.lower().endswith(root_domain.lower().rstrip("."))})
                link(conn, hid, "CNAME_TO", cid, "httpx", confidence=1.0, evidence_id=evid)
            provider = _provider_label(row.get("cdn_name")) if row.get("cdn_name") else ""
            if provider:
                pid = upsert_asset(conn, "provider", provider, provider, {"provider_type": row.get("cdn_type"), "sources": ["httpx"]})
                link(conn, hid, "PROXIED_BY", pid, "httpx", confidence=0.98, evidence_id=evid)
            if row.get("webserver"):
                server = str(row.get("webserver")).strip()
                sid = upsert_asset(conn, "server", server, server, {"sources": ["httpx"]})
                link(conn, hid, "SERVED_BY", sid, "httpx", confidence=0.85, confidence_type="fingerprint", evidence_id=evid)
            for technology in tech:
                tid = upsert_asset(conn, "technology", _tech_key(technology), technology, {"sources": ["httpx"]})
                link(conn, hid, "USES", tid, "httpx", confidence=0.82, confidence_type="fingerprint", evidence_id=evid)
                provider_hint = PROVIDER_TECH.get(_tech_key(technology))
                if provider_hint:
                    provider_name, relation, provider_type = provider_hint
                    pid = upsert_asset(conn, "provider", provider_name, provider_name, {"provider_type": provider_type, "sources": ["httpx"]})
                    link(conn, hid, relation, pid, "httpx", confidence=0.80, confidence_type="fingerprint", evidence_id=evid)
            if row.get("location"):
                target = urlsplit(str(row.get("location"))).hostname
                if target:
                    rid = upsert_asset(conn, "hostname", target, target, {"sources": ["httpx"], "external": not target.lower().endswith(root_domain.lower().rstrip("."))})
                    link(conn, hid, "REDIRECTS_TO", rid, "httpx", confidence=1.0, evidence_id=evid)
            count += 1
        except Exception:
            errors += 1
    rebuild_family_heuristics(conn, root_domain)
    conn.execute("INSERT INTO recon_import_runs(source,filename,record_count,error_count,created_at) VALUES(?,?,?,?,?)", ("httpx", filename, count, errors, _now()))
    conn.commit()
    return {"source": "httpx", "records": count, "errors": errors}


def import_text(conn: sqlite3.Connection, source: str, text: str, root_domain: str, filename: str = "") -> dict:
    source = (source or "").lower().strip()
    if source == "auto":
        if any(line.lstrip().startswith("{") and '"status_code"' in line for line in text.splitlines()[:20]):
            source = "httpx"
        elif any(re.search(r"\[(A|AAAA|CNAME)\]", line) for line in text.splitlines()[:30]):
            source = "dnsx"
        else:
            source = "subfinder"
    if source == "httpx":
        return import_httpx_jsonl(conn, text, root_domain, filename)
    if source == "dnsx":
        return import_dnsx_text(conn, text, root_domain, filename)
    if source == "subfinder":
        return import_subfinder_text(conn, text, root_domain, filename)
    raise ValueError(f"Fuente no soportada: {source}")




def _tool_path(name: str) -> str | None:
    if name == "amass":
        kali_real = Path("/usr/lib/amass/amass")
        if kali_real.exists() and kali_real.is_file():
            return str(kali_real)
    preferred = Path.home() / "go" / "bin" / name
    if preferred.exists() and preferred.is_file():
        return str(preferred)
    return shutil.which(name)


def tool_inventory() -> dict[str, dict]:
    out = {}
    for name in ("whois", "dig", "openssl", "curl", "subfinder", "amass", "gau", "alterx", "dnsx", "httpx", "nmap"):
        path = _tool_path(name)
        out[name] = {"available": bool(path), "path": path or ""}
    return out


def _record_tool_run(conn: sqlite3.Connection, phase: str, tool: str, command: list[str], status: str, return_code: int | None,
                     record_count: int, stdout_path: str, stderr_path: str, error: str, started_at: str, finished_at: str,
                     *, root_domain: str = "", run_group: str = "") -> int:
    cur = conn.execute(
        """INSERT INTO recon_tool_runs(phase,tool,root_domain,run_group,command_json,status,return_code,record_count,stdout_path,stderr_path,error,started_at,finished_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (phase, tool, root_domain, run_group, json.dumps(command, ensure_ascii=False), status, return_code, record_count, stdout_path, stderr_path, error, started_at, finished_at),
    )
    return int(cur.lastrowid)


def _run_tool(conn: sqlite3.Connection, paths: dict, phase: str, tool: str, command: list[str], *, timeout: int = 180,
              input_text: str | None = None, root_domain: str = "", run_group: str = "") -> dict:
    init_schema(conn)
    started = _now()
    run_dir = Path(paths["raw"]) / "surface-runs"
    run_dir.mkdir(parents=True, exist_ok=True)
    stamp = re.sub(r"[^0-9]", "", started)[:14]
    base = f"{stamp}-{phase}-{tool}"
    stdout_path = run_dir / f"{base}.stdout.txt"
    stderr_path = run_dir / f"{base}.stderr.txt"
    try:
        proc = subprocess.run(command, input=input_text, capture_output=True, text=True, timeout=timeout, check=False)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        stdout_path.write_text(stdout, encoding="utf-8")
        stderr_path.write_text(stderr, encoding="utf-8")
        status = "ok" if proc.returncode == 0 else "error"
        error = "" if proc.returncode == 0 else (stderr.strip() or f"{tool} rc={proc.returncode}")[:1200]
        # Remote passive sources can be temporarily unavailable.  That is not
        # equivalent to a scanner failure nor to a successful zero-result query.
        # Preserve the raw curl error but expose a semantically distinct state.
        if tool == "crt.sh" and proc.returncode != 0:
            transient = re.search(r"(?:HTTP[^\n]*\b(?:429|500|502|503|504)\b|returned error:\s*(?:429|500|502|503|504)|timed?\s*out|timeout|temporar(?:y|ily))", stderr, re.I)
            if transient:
                status = "unavailable"
                detail = (stderr.strip() or f"crt.sh rc={proc.returncode}")[:700]
                error = f"Certificate Transparency no estuvo disponible temporalmente. {detail}"
        run_id = _record_tool_run(conn, phase, tool, command, status, proc.returncode, len([x for x in stdout.splitlines() if x.strip()]), str(stdout_path), str(stderr_path), error, started, _now(), root_domain=root_domain, run_group=run_group)
        return {"id": run_id, "status": status, "return_code": proc.returncode, "stdout": stdout, "stderr": stderr, "command": command, "error": error}
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""; stderr = exc.stderr or ""
        if isinstance(stdout, bytes): stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes): stderr = stderr.decode("utf-8", errors="replace")
        stdout_path.write_text(stdout, encoding="utf-8"); stderr_path.write_text(stderr, encoding="utf-8")
        record_count = len([x for x in stdout.splitlines() if x.strip()])
        status = "partial" if record_count else "timeout"
        error = (
            f"{tool} alcanzó el timeout de {timeout}s; se conservaron {record_count} líneas parciales"
            if record_count else f"{tool} alcanzó el timeout de {timeout}s sin stdout utilizable"
        )
        run_id = _record_tool_run(conn, phase, tool, command, status, None, record_count, str(stdout_path), str(stderr_path), error, started, _now(), root_domain=root_domain, run_group=run_group)
        return {"id": run_id, "status": status, "return_code": None, "stdout": stdout, "stderr": stderr, "command": command, "error": error, "timed_out": True}



def add_manual_hostnames(conn: sqlite3.Connection, root_domain: str, hostnames: list[str], note: str = "") -> dict:
    """Add hunter-known hostnames as first-class discovery evidence.

    Manual knowledge is intentionally preserved as a distinct source instead of
    pretending a scanner discovered it.  Entries remain DISCOVERED until the DNS
    phase validates them, so they naturally flow into the same guided pipeline.
    """
    init_schema(conn)
    root = str(root_domain or "").strip().lower().rstrip(".")
    clean: list[str] = []
    rejected: list[str] = []
    for raw in hostnames or []:
        host = str(raw or "").strip().lower().rstrip(".")
        if not host:
            continue
        if host == root or host.endswith("." + root):
            if host not in clean:
                clean.append(host)
        else:
            rejected.append(host)
    added = 0
    for host in clean:
        env, env_conf = detect_environment(host)
        hid = upsert_asset(
            conn,
            "hostname",
            host,
            host,
            {
                "sources": ["manual"],
                "environment": env,
                "environment_confidence": env_conf,
                "family": _family_stem(host, root),
                "dns_state": "DISCOVERED",
            },
        )
        add_evidence(
            conn,
            hid,
            "manual",
            "discovered_hostname",
            host,
            {"hostname": host, "recon_root": root, "note": str(note or "").strip()},
        )
        added += 1
    conn.commit()
    return {"added": added, "hostnames": clean, "rejected": rejected}


def manual_hostname_entries(conn: sqlite3.Connection, root_domain: str) -> list[dict]:
    """Latest manual discovery note per hostname for the active recon root."""
    root = str(root_domain or "").strip().lower().rstrip(".")
    rows = conn.execute(
        """SELECT a.asset_key hostname,e.raw_json,e.observed_at,e.id
           FROM recon_evidence e JOIN recon_assets a ON a.id=e.asset_id
           WHERE e.source='manual' AND e.kind='discovered_hostname'
             AND a.asset_type='hostname' AND (a.asset_key=? OR a.asset_key LIKE ?)
           ORDER BY e.id DESC""",
        (root, "%." + root),
    ).fetchall()
    out=[]; seen=set()
    for row in rows:
        host=str(row["hostname"] or "")
        if host in seen:
            continue
        seen.add(host)
        raw=_loads(row["raw_json"])
        out.append({"hostname":host,"note":str(raw.get("note") or ""),"observed_at":row["observed_at"]})
    return out

def _first_party_hostnames(conn: sqlite3.Connection, root_domain: str, *, resolved_only: bool = False) -> list[str]:
    values = []
    for row in conn.execute("SELECT asset_key,metadata_json FROM recon_assets WHERE asset_type='hostname' ORDER BY asset_key").fetchall():
        host = str(row["asset_key"]).lower()
        if host != root_domain.lower() and not host.endswith("." + root_domain.lower()):
            continue
        meta = _loads(row["metadata_json"])
        if resolved_only and meta.get("dns_state") != "RESOLVED":
            continue
        values.append(host)
    return sorted(set(values))


def run_root_phase(conn: sqlite3.Connection, root_domain: str, paths: dict, timeout: int = 30, run_group: str = "") -> dict:
    init_schema(conn)
    root = root_domain.lower().rstrip(".")
    hid = upsert_asset(conn, "hostname", root, root, {"sources": ["root_recon"]})
    results = []
    dig = _tool_path("dig")
    if dig:
        for rtype in ("NS", "A", "AAAA", "MX", "TXT", "CAA"):
            run = _run_tool(conn, paths, "root", "dig", [dig, root, rtype, "+short"], timeout=timeout, root_domain=root, run_group=run_group)
            results.append(run)
            if run["status"] == "ok":
                values = [x.strip().rstrip(".") for x in run["stdout"].splitlines() if x.strip()]
                add_evidence(conn, hid, "root_recon", f"dns_{rtype.lower()}", "\n".join(values), {"type": rtype, "values": values})
                if rtype in {"A", "AAAA"}:
                    if values:
                        row = conn.execute("SELECT metadata_json FROM recon_assets WHERE id=?", (hid,)).fetchone()
                        meta = _merge_meta(_loads(row["metadata_json"]), {"dns_state": "RESOLVED"})
                        conn.execute("UPDATE recon_assets SET metadata_json=? WHERE id=?", (json.dumps(meta, ensure_ascii=False), hid))
                    for ip in values:
                        iid = upsert_asset(conn, "ip", ip, ip, {"sources": ["root_recon"]})
                        link(conn, hid, "RESOLVES_TO", iid, "root_recon")
    whois = _tool_path("whois")
    if whois:
        run = _run_tool(conn, paths, "root", "whois", [whois, root], timeout=max(timeout, 45), root_domain=root, run_group=run_group)
        results.append(run)
        if run["stdout"].strip(): add_evidence(conn, hid, "root_recon", "whois", None, run["stdout"][:200000])
    curl = _tool_path("curl")
    if curl:
        for scheme in ("https", "http"):
            cmd = [curl, "-skD", "-", "-o", "/dev/null", "--max-time", str(timeout), f"{scheme}://{root}/"] if scheme == "https" else [curl, "-sD", "-", "-o", "/dev/null", "--max-time", str(timeout), f"{scheme}://{root}/"]
            run = _run_tool(conn, paths, "root", "curl", cmd, timeout=timeout+5, root_domain=root, run_group=run_group)
            results.append(run)
            if run["stdout"].strip(): add_evidence(conn, hid, "root_recon", f"http_{scheme}_headers", None, run["stdout"][:50000])
    rebuild_family_heuristics(conn, root_domain)
    conn.commit()
    ok = sum(1 for x in results if x["status"] == "ok")
    return {"phase": "root", "status": "ok" if ok else "error", "tools_ok": ok, "tools_total": len(results)}


def _historical_hosts_from_text(text: str, root_domain: str) -> list[str]:
    """Extract first-party hostnames from URL-oriented historical output.

    GAU and similar tools primarily return URLs.  Discovery only imports the
    hostname portion here; paths stay raw evidence for the later historical /
    content-correlation phase.
    """
    root = root_domain.lower().rstrip(".")
    out: set[str] = set()
    for raw in (text or "").splitlines():
        value = raw.strip()
        if not value:
            continue
        host = ""
        try:
            parsed = urlsplit(value if "://" in value else "//" + value)
            host = (parsed.hostname or "").lower().rstrip(".")
        except Exception:
            host = ""
        if host and host != root and host.endswith("." + root):
            out.add(host)
    return sorted(out)


def _discovery_source_counts(conn: sqlite3.Connection, root_domain: str) -> dict[str, int]:
    root = root_domain.lower().rstrip(".")
    rows = conn.execute(
        """SELECT e.source, COUNT(DISTINCT e.asset_id) c
           FROM recon_evidence e JOIN recon_assets a ON a.id=e.asset_id
           WHERE e.kind='discovered_hostname' AND a.asset_type='hostname'
             AND a.asset_key!=? AND a.asset_key LIKE ?
           GROUP BY e.source""",
        (root, "%." + root),
    ).fetchall()
    return {str(r["source"]): int(r["c"] or 0) for r in rows}


def run_discovery_phase(conn: sqlite3.Connection, root_domain: str, paths: dict, timeout: int = 300, run_group: str = "") -> dict:
    """Composite hostname discovery.

    One source returning zero names never means the domain has no additional
    surface. The default pass runs the fast/base sources (Subfinder, CT and
    historical URLs); Amass remains optional enrichment because it may add no
    names while taking several minutes. Every command is persisted separately
    so the audit page can show exactly what each source returned.
    """
    root = root_domain.lower().rstrip(".")
    successes = 0
    attempted = 0
    source_results: list[dict] = []

    subfinder = _tool_path("subfinder")
    if subfinder:
        attempted += 1
        cmd = [subfinder, "-d", root, "-all", "-silent"]
        run = _run_tool(conn, paths, "discovery", "subfinder", cmd, timeout=timeout, root_domain=root, run_group=run_group)
        if run["status"] == "ok":
            result = import_subfinder_text(conn, run["stdout"], root, "surface-run:subfinder")
            successes += 1
            source_results.append({"source":"subfinder", **result})

    curl = _tool_path("curl")
    if curl:
        attempted += 1
        query = f"https://crt.sh/?q=%25.{root}&output=json"
        cmd = [curl, "-fsSL", "--retry", "3", "--retry-delay", "2", "--retry-max-time", "75", "--max-time", str(min(timeout, 180)), query]
        run = _run_tool(conn, paths, "discovery", "crt.sh", cmd, timeout=min(timeout, 190), root_domain=root, run_group=run_group)
        if run["status"] == "ok":
            hosts = [h for h in _crtsh_hosts(run["stdout"], root) if h != root]
            result = import_discovered_hosts(conn, hosts, root, "crtsh", "surface-run:crtsh")
            successes += 1
            source_results.append({"source":"crtsh", **result})

    # Amass v5 passive enumeration is intentionally optional in the default
    # composite run. In real targets it can take minutes while adding zero new
    # names; the phase detail exposes an explicit per-source button when the
    # hunter wants that extra coverage.

    gau = _tool_path("gau")
    if gau:
        attempted += 1
        cmd = [gau, "--subs", root]
        run = _run_tool(conn, paths, "discovery", "gau", cmd, timeout=max(timeout, 300), root_domain=root, run_group=run_group)
        if run["status"] == "ok":
            hosts = _historical_hosts_from_text(run["stdout"], root)
            result = import_discovered_hosts(conn, hosts, root, "gau_historical", "surface-run:gau")
            successes += 1
            source_results.append({"source":"gau_historical", **result})

    if attempted == 0:
        raise RuntimeError("No hay fuentes de discovery disponibles. Instala Subfinder, Amass o GAU, o habilita curl para consultar Certificate Transparency.")
    if successes == 0:
        raise RuntimeError("Las fuentes disponibles se ejecutaron, pero ninguna terminó correctamente. Revisa stdout/stderr en el detalle del paso.")

    unique_candidates = len(_first_party_hostnames(conn, root))
    if root in _first_party_hostnames(conn, root):
        unique_candidates = max(0, unique_candidates - 1)
    return {
        "phase": "discovery", "records": unique_candidates, "sources_ok": successes,
        "sources_attempted": attempted, "source_results": source_results,
    }


def _crtsh_hosts(raw: str, root_domain: str) -> list[str]:
    try:
        data = json.loads(raw or "[]")
    except Exception:
        return []
    root = root_domain.lower().rstrip(".")
    out: set[str] = set()
    if not isinstance(data, list):
        return []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        for field in ("name_value", "common_name"):
            value = entry.get(field)
            if not isinstance(value, str):
                continue
            for item in value.splitlines():
                host = item.strip().lower().rstrip(".").lstrip("*.")
                if host and (host == root or host.endswith("." + root)):
                    out.add(host)
    return sorted(out)



def run_discovery_source(conn: sqlite3.Connection, root_domain: str, paths: dict, source: str, timeout: int = 300, run_group: str = "") -> dict:
    """Run exactly one discovery source without repeating the whole phase.

    This is primarily useful for transient remote failures (crt.sh) or expensive
    enrichment sources (Amass).  Evidence is merged into the same inventory and
    can be attached to the latest discovery run group for a coherent audit view.
    """
    root = root_domain.lower().rstrip(".")
    src = (source or "").strip().lower()
    if src in {"crtsh", "ct", "certificate_transparency"}:
        src = "crt.sh"
    if src in {"gau_historical", "historical"}:
        src = "gau"

    if src == "subfinder":
        tool = _tool_path("subfinder")
        if not tool:
            raise RuntimeError("Subfinder no está disponible localmente")
        cmd = [tool, "-d", root, "-all", "-silent"]
        run = _run_tool(conn, paths, "discovery", "subfinder", cmd, timeout=timeout, root_domain=root, run_group=run_group)
        if run["status"] == "ok":
            result = import_subfinder_text(conn, run["stdout"], root, "surface-rerun:subfinder")
        else:
            result = {"records": 0, "errors": 0}
        return {"source":"subfinder", "status":run["status"], "records":int(result.get("records") or 0), "run":run}

    if src == "crt.sh":
        curl = _tool_path("curl")
        if not curl:
            raise RuntimeError("curl no está disponible para consultar Certificate Transparency")
        query = f"https://crt.sh/?q=%25.{root}&output=json"
        cmd = [curl, "-fsSL", "--retry", "3", "--retry-delay", "2", "--retry-max-time", "75", "--max-time", str(min(timeout, 180)), query]
        run = _run_tool(conn, paths, "discovery", "crt.sh", cmd, timeout=min(timeout, 190), root_domain=root, run_group=run_group)
        hosts: list[str] = []
        if run["status"] == "ok":
            hosts = [h for h in _crtsh_hosts(run["stdout"], root) if h != root]
            import_discovered_hosts(conn, hosts, root, "crtsh", "surface-rerun:crtsh")
        return {"source":"crtsh", "status":run["status"], "records":len(set(hosts)), "run":run}

    if src == "amass":
        tool = _tool_path("amass")
        if not tool:
            raise RuntimeError("Amass no está disponible localmente")
        cmd = [tool, "enum", "-d", root, "-nocolor", "-timeout", str(int(os.environ.get("NEGRO_AMASS_STALL_MINUTES", "10") or 10))]
        amass_timeout = max(timeout, int(os.environ.get("NEGRO_AMASS_TIMEOUT", "2400") or 2400))
        run = _run_tool(conn, paths, "discovery", "amass", cmd, timeout=amass_timeout, root_domain=root, run_group=run_group)
        hosts = [x.strip() for x in run["stdout"].splitlines() if x.strip()] if run["status"] in {"ok", "partial"} else []
        if hosts:
            import_discovered_hosts(conn, hosts, root, "amass", "surface-rerun:amass")
        return {"source":"amass", "status":run["status"], "records":len(set(hosts)), "run":run}

    if src == "gau":
        tool = _tool_path("gau")
        if not tool:
            raise RuntimeError("GAU no está disponible localmente")
        cmd = [tool, "--subs", root]
        run = _run_tool(conn, paths, "discovery", "gau", cmd, timeout=max(timeout, 300), root_domain=root, run_group=run_group)
        hosts = _historical_hosts_from_text(run["stdout"], root) if run["status"] == "ok" else []
        if hosts:
            import_discovered_hosts(conn, hosts, root, "gau_historical", "surface-rerun:gau")
        return {"source":"gau_historical", "status":run["status"], "records":len(set(hosts)), "run":run}

    raise ValueError(f"Fuente de discovery no soportada: {source}")

def run_expand_discovery_phase(conn: sqlite3.Connection, root_domain: str, paths: dict, timeout: int = 300, run_group: str = "") -> dict:
    """Backward-compatible alias for pre-v0.84 discovery enrichment actions."""
    return run_discovery_phase(conn, root_domain, paths, timeout=timeout, run_group=run_group)


_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _first_party_hosts_from_lines(text: str, root_domain: str) -> list[str]:
    """Extract clean first-party hostnames from line-oriented tool output."""
    root = str(root_domain or "").strip().lower().rstrip(".")
    out: set[str] = set()
    for raw in (text or "").splitlines():
        value = _ANSI_RE.sub("", raw).strip()
        if not value:
            continue
        token = value.split()[0].strip().lower().rstrip(".")
        if "://" in token:
            try:
                token = (urlsplit(token).hostname or "").lower().rstrip(".")
            except Exception:
                token = ""
        if token and token != root and token.endswith("." + root):
            out.add(token)
    return sorted(out)


def _discovery_source_hosts(conn: sqlite3.Connection, root_domain: str, source: str) -> list[str]:
    root = str(root_domain or "").strip().lower().rstrip(".")
    rows = conn.execute(
        """SELECT DISTINCT a.asset_key hostname
           FROM recon_evidence e JOIN recon_assets a ON a.id=e.asset_id
           WHERE e.kind='discovered_hostname' AND e.source=?
             AND a.asset_type='hostname' AND a.asset_key!=? AND a.asset_key LIKE ?
           ORDER BY a.asset_key COLLATE NOCASE""",
        (source, root, "%." + root),
    ).fetchall()
    return [str(r["hostname"]) for r in rows]


def _active_wordlist(paths: dict) -> tuple[Path, str]:
    configured = str(os.environ.get("NEGRO_DNS_WORDLIST", "") or "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.exists() and candidate.is_file():
            return candidate, "externa"
    out_dir = Path(paths["raw"]) / "surface-runs"
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "negro-active-dns-baseline.txt"
    target.write_text("\n".join(DEFAULT_DNS_WORDS) + "\n", encoding="utf-8")
    return target, "baseline Negro"


def run_active_discovery_phase(conn: sqlite3.Connection, root_domain: str, paths: dict, timeout: int = 420, run_group: str = "") -> dict:
    """Explicit active hostname discovery before broad DNS/HTTP fingerprinting.

    AlterX, when installed, proposes naming-pattern permutations from already
    observed first-party hosts and dnsx validates those candidates. A compact
    DNS wordlist is then brute-forced with wildcard filtering. Only names that
    resolve are imported, avoiding thousands of speculative graph nodes.
    """
    root = str(root_domain or "").strip().lower().rstrip(".")
    dnsx = _tool_path("dnsx")
    if not dnsx:
        raise RuntimeError("dnsx no está instalado. El discovery activo necesita resolver candidatos y filtrar wildcard DNS.")

    existing = [h for h in _first_party_hostnames(conn, root) if h != root]
    source_results: list[dict] = []
    new_hosts: set[str] = set()
    runs_ok = 0

    alterx = _tool_path("alterx")
    if alterx and existing:
        seeds = _write_target_list(paths, "active-alterx-seeds", existing)
        limit = max(100, int(os.environ.get("NEGRO_ALTERX_LIMIT", "5000") or 5000))
        alter_cmd = [alterx, "-l", str(seeds), "-silent", "-limit", str(limit)]
        alter_run = _run_tool(conn, paths, "active_discovery", "alterx", alter_cmd, timeout=min(timeout, 300), root_domain=root, run_group=run_group)
        if alter_run["status"] == "ok":
            runs_ok += 1
            existing_set = set(existing)
            candidates = [h for h in _first_party_hosts_from_lines(alter_run["stdout"], root) if h not in existing_set]
            if candidates:
                candidate_file = _write_target_list(paths, "active-alterx-candidates", candidates)
                resolve_cmd = [dnsx, "-l", str(candidate_file), "-silent", "-nc", "-auto-wildcard"]
                resolve_run = _run_tool(conn, paths, "active_discovery", "dnsx-permutations", resolve_cmd, timeout=timeout, root_domain=root, run_group=run_group)
                if resolve_run["status"] == "ok":
                    runs_ok += 1
                    hosts = _first_party_hosts_from_lines(resolve_run["stdout"], root)
                    if hosts:
                        import_discovered_hosts(conn, hosts, root, "active_permutation", "surface-run:alterx+dnsx")
                        new_hosts.update(hosts)
                    source_results.append({"source":"active_permutation", "records":len(hosts), "candidates":len(candidates)})
            else:
                source_results.append({"source":"active_permutation", "records":0, "candidates":0})

    wordlist, wordlist_kind = _active_wordlist(paths)
    brute_cmd = [dnsx, "-d", root, "-w", str(wordlist), "-silent", "-nc", "-auto-wildcard"]
    brute_run = _run_tool(conn, paths, "active_discovery", "dnsx-bruteforce", brute_cmd, timeout=timeout, root_domain=root, run_group=run_group)
    if brute_run["status"] == "ok":
        runs_ok += 1
        brute_hosts = _first_party_hosts_from_lines(brute_run["stdout"], root)
        if brute_hosts:
            import_discovered_hosts(conn, brute_hosts, root, "active_bruteforce", f"surface-run:dnsx:{wordlist_kind}")
            new_hosts.update(brute_hosts)
        source_results.append({"source":"active_bruteforce", "records":len(brute_hosts), "wordlist":str(wordlist), "wordlist_kind":wordlist_kind})

    if runs_ok == 0:
        raise RuntimeError("El discovery activo no pudo completar ninguna ejecución. Revisa stdout/stderr del paso.")
    return {
        "phase":"active_discovery", "records":len(new_hosts), "new_hosts":sorted(new_hosts),
        "source_results":source_results, "wordlist":str(wordlist), "wordlist_kind":wordlist_kind,
    }


def _parse_tls_bundle(text: str, root_domain: str) -> list[dict]:
    root = str(root_domain or "").strip().lower().rstrip(".")
    records: list[dict] = []
    current: dict | None = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line.startswith("===HOST ") and line.endswith("==="):
            if current:
                records.append(current)
            host = line[len("===HOST "):-3].strip().lower().rstrip(".")
            current = {"hostname":host, "sans":[]}
            continue
        if line == "===END===":
            if current:
                records.append(current)
                current = None
            continue
        if current is None or not line:
            continue
        lower = line.lower()
        if lower.startswith("subject="):
            current["subject"] = line.split("=",1)[1].strip()
        elif lower.startswith("issuer="):
            current["issuer"] = line.split("=",1)[1].strip()
        elif lower.startswith("notbefore="):
            current["not_before"] = line.split("=",1)[1].strip()
        elif lower.startswith("notafter="):
            current["not_after"] = line.split("=",1)[1].strip()
        elif "fingerprint=" in lower:
            current["fingerprint"] = line.split("=",1)[1].replace(":","").strip().lower()
        elif "DNS:" in line:
            for name in re.findall(r"DNS:([^,\s]+)", line, re.I):
                san = name.strip().lower().rstrip(".")
                if san and san not in current["sans"]:
                    current["sans"].append(san)
    if current:
        records.append(current)
    for rec in records:
        rec["first_party_sans"] = sorted({x.lstrip("*.") for x in rec.get("sans",[]) if x.lstrip("*.") == root or x.lstrip("*.").endswith("." + root)})
    return records


def run_tls_phase(conn: sqlite3.Connection, root_domain: str, paths: dict, timeout: int = 600, run_group: str = "") -> dict:
    openssl = _tool_path("openssl")
    if not openssl:
        raise RuntimeError("openssl no está disponible localmente")
    hosts = _first_party_hostnames(conn, root_domain, resolved_only=True)
    if not hosts:
        raise RuntimeError("No hay hosts DNS_RESOLVED. Ejecuta primero Validación DNS.")
    target_file = _write_target_list(paths, "tls", hosts)
    bash = shutil.which("bash") or "/bin/bash"
    timeout_bin = shutil.which("timeout") or "timeout"
    script = '''while IFS= read -r host; do
  [ -z "$host" ] && continue
  echo "===HOST $host==="
  cert="$({timeout} 8 {openssl} s_client -connect "${{host}}:443" -servername "$host" -showcerts </dev/null 2>/dev/null | {openssl} x509 -noout -subject -issuer -dates -fingerprint -sha256 -ext subjectAltName 2>/dev/null)"
  if [ -n "$cert" ]; then printf '%s\\n' "$cert"; fi
  echo "===END==="
done < "$1"'''.format(timeout=timeout_bin, openssl=openssl)
    cmd = [bash, "-lc", script, "negro-tls", str(target_file)]
    run = _run_tool(conn, paths, "tls", "openssl", cmd, timeout=timeout, root_domain=root_domain, run_group=run_group)
    if run["status"] not in {"ok", "partial"}:
        raise RuntimeError(run["error"] or "openssl TLS discovery falló")
    records = _parse_tls_bundle(run["stdout"], root_domain)
    san_candidates: set[str] = set()
    certificates = 0
    root = root_domain.lower().rstrip(".")
    for rec in records:
        host = str(rec.get("hostname") or "").lower().rstrip(".")
        if not host:
            continue
        hid = upsert_asset(conn, "hostname", host, host, {"sources":["openssl"]})
        add_evidence(conn, hid, "openssl", "tls_certificate", rec.get("fingerprint") or "", rec)
        fp = str(rec.get("fingerprint") or "").strip().lower()
        if fp:
            cid = upsert_asset(conn, "certificate", fp, fp[:16], {"issuer":rec.get("issuer"), "subject":rec.get("subject"), "not_before":rec.get("not_before"), "not_after":rec.get("not_after"), "sans":rec.get("sans") or []})
            link(conn, hid, "PRESENTS_CERTIFICATE", cid, "openssl", confidence=1.0, confidence_type="observed")
            certificates += 1
            for san_raw in rec.get("sans") or []:
                san = str(san_raw).lower().rstrip(".").lstrip("*.")
                if not san or not (san == root or san.endswith("." + root)):
                    continue
                sid = upsert_asset(conn, "hostname", san, san, {"sources":["tls_san"]})
                link(conn, cid, "NAMES", sid, "openssl", confidence=1.0, confidence_type="observed")
                if san != root:
                    san_candidates.add(san)
    if san_candidates:
        import_discovered_hosts(conn, sorted(san_candidates), root, "tls_san", "surface-run:openssl-san")
    conn.commit()
    return {"phase":"tls", "records":certificates, "targets":len(hosts), "san_hosts":sorted(san_candidates), "run_status":run["status"]}


def _write_target_list(paths: dict, phase: str, hosts: list[str]) -> Path:
    out_dir = Path(paths["raw"]) / "surface-runs"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"targets-{phase}.txt"
    path.write_text("\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8")
    return path


def run_dns_phase(conn: sqlite3.Connection, root_domain: str, paths: dict, timeout: int = 300, run_group: str = "") -> dict:
    binary = _tool_path("dnsx")
    if not binary:
        raise RuntimeError("dnsx no está instalado. Instálalo con ProjectDiscovery y verifica que esté en PATH.")
    hosts = _first_party_hostnames(conn, root_domain)
    if not hosts:
        raise RuntimeError("No hay hostnames descubiertos. Ejecuta primero Descubrimiento pasivo.")

    target_file = _write_target_list(paths, "dns", hosts)
    cmd = [binary, "-l", str(target_file), "-a", "-aaaa", "-cname", "-resp", "-silent"]
    run = _run_tool(conn, paths, "dns", "dnsx", cmd, timeout=timeout, root_domain=root_domain, run_group=run_group)
    if run["status"] != "ok":
        raise RuntimeError(run["error"] or "dnsx falló")

    dnsx_result = import_dnsx_text(conn, run["stdout"], root_domain, "surface-run:dnsx")
    resolved_hosts: set[str] = set()
    for line in run["stdout"].splitlines():
        m = _DNSX_RE.match(line.strip())
        if m:
            resolved_hosts.add(m.group("host").lower().rstrip("."))

    # Evidence-first fallback: a dnsx output/parser mismatch must never make a
    # live host look like NODATA. Verify every host not normalized from dnsx with
    # dig A/AAAA/CNAME, import those answers using the same canonical model, and
    # only then classify names with no answer as NXDOMAIN/NODATA.
    dig = _tool_path("dig")
    bash = shutil.which("bash")
    unresolved = sorted(set(hosts) - resolved_hosts)
    fallback_records = 0

    if unresolved and dig and bash:
        unresolved_file = _write_target_list(
            paths,
            f"dns-unresolved-{re.sub(r'[^a-zA-Z0-9]+','-',root_domain)}",
            unresolved,
        )
        record_script = (
            'while IFS= read -r host; do '
            'for t in A AAAA CNAME; do '
            'dig "$host" "$t" +time=3 +tries=1 +noall +answer | '
            'awk -v h="$host" -v want="$t" \'$4==want {v=$5; sub(/\\.$/,"",v); printf "%s [%s] [%s]\\n",h,want,v}\'; '
            'done; '
            'done < "$1"'
        )
        records_cmd = [bash, "-lc", record_script, "negro-dns-records", str(unresolved_file)]
        records_run = _run_tool(
            conn,
            paths,
            "dns",
            "dig-records",
            records_cmd,
            timeout=max(timeout, 300),
            root_domain=root_domain,
            run_group=run_group,
        )
        if records_run["status"] == "ok" and records_run["stdout"].strip():
            fallback_result = import_dnsx_text(
                conn,
                records_run["stdout"],
                root_domain,
                "surface-run:dig-records",
            )
            fallback_records = int(fallback_result.get("records", 0))
            for line in records_run["stdout"].splitlines():
                m = _DNSX_RE.match(line.strip())
                if m:
                    resolved_hosts.add(m.group("host").lower().rstrip("."))

    unresolved = sorted(set(hosts) - resolved_hosts)
    status_counts = {"NXDOMAIN": 0, "NODATA": 0, "UNKNOWN": 0}

    if unresolved and dig and bash:
        unresolved_file = _write_target_list(
            paths,
            f"dns-status-{re.sub(r'[^a-zA-Z0-9]+','-',root_domain)}",
            unresolved,
        )
        status_script = (
            'while IFS= read -r host; do '
            's=$(dig "$host" A +time=3 +tries=1 +noall +comments | '
            'grep -o "status: [A-Z]*" | head -1 | awk "{print \\$2}"); '
            'printf "%s\\t%s\\n" "$host" "${s:-UNKNOWN}"; '
            'done < "$1"'
        )
        status_cmd = [bash, "-lc", status_script, "negro-dns-status", str(unresolved_file)]
        status_run = _run_tool(
            conn,
            paths,
            "dns",
            "dig-status",
            status_cmd,
            timeout=max(timeout, 300),
            root_domain=root_domain,
            run_group=run_group,
        )
        if status_run["status"] == "ok":
            for line in status_run["stdout"].splitlines():
                parts = line.split("\t", 1)
                if len(parts) != 2:
                    continue
                host, status = parts[0].strip().lower().rstrip("."), parts[1].strip().upper()
                row = conn.execute(
                    "SELECT id,metadata_json FROM recon_assets WHERE asset_type='hostname' AND asset_key=?",
                    (host,),
                ).fetchone()
                if not row:
                    continue
                if status == "NXDOMAIN":
                    state = "NXDOMAIN"
                    status_counts["NXDOMAIN"] += 1
                elif status == "NOERROR":
                    state = "NODATA"
                    status_counts["NODATA"] += 1
                else:
                    state = "DISCOVERED"
                    status_counts["UNKNOWN"] += 1
                meta = _merge_meta(_loads(row["metadata_json"]), {"dns_state": state})
                conn.execute(
                    "UPDATE recon_assets SET metadata_json=?,last_seen_at=? WHERE id=?",
                    (json.dumps(meta, ensure_ascii=False), _now(), row["id"]),
                )
                add_evidence(
                    conn,
                    int(row["id"]),
                    "dig-status",
                    "dns_status",
                    status,
                    {"hostname": host, "status": status},
                )
            conn.commit()

    dnsx_records = int(dnsx_result.get("records", 0))
    total_records = dnsx_records + fallback_records
    return {
        "phase": "dns",
        "source": "dnsx+dig",
        "records": total_records,
        "errors": int(dnsx_result.get("errors", 0)),
        "dnsx_records": dnsx_records,
        "dig_fallback_records": fallback_records,
        "targets": len(hosts),
        "command": cmd,
        "resolved_hosts": len(resolved_hosts),
        "unresolved": len(unresolved),
        "status_counts": status_counts,
    }

def run_http_phase(conn: sqlite3.Connection, root_domain: str, paths: dict, timeout: int = 420, run_group: str = "") -> dict:
    binary = _tool_path("httpx")
    if not binary: raise RuntimeError("httpx de ProjectDiscovery no está instalado o no está en PATH.")
    hosts = _first_party_hostnames(conn, root_domain, resolved_only=True)
    if not hosts: raise RuntimeError("No hay hosts DNS_RESOLVED. Ejecuta primero Validación DNS.")
    target_file = _write_target_list(paths, "http", hosts)
    cmd = [binary, "-l", str(target_file), "-status-code", "-title", "-tech-detect", "-server", "-ip", "-cname", "-cdn", "-location", "-json", "-silent"]
    run = _run_tool(conn, paths, "http", "httpx", cmd, timeout=timeout, root_domain=root_domain, run_group=run_group)
    if run["status"] != "ok": raise RuntimeError(run["error"] or "httpx falló")
    result = import_httpx_jsonl(conn, run["stdout"], root_domain, "surface-run:httpx")
    return {"phase": "http", **result, "targets": len(hosts), "command": cmd}


def _external_cname_pairs(conn: sqlite3.Connection, root_domain: str) -> list[tuple[str, str]]:
    """Return observed first-party -> external CNAME edges for one recon root."""
    root = str(root_domain or "").strip().lower().rstrip(".")
    rows = conn.execute(
        """SELECT DISTINCT src.asset_key host,dst.asset_key target
           FROM recon_relationships r
           JOIN recon_assets src ON src.id=r.src_asset_id
           JOIN recon_assets dst ON dst.id=r.dst_asset_id
           WHERE r.relation='CNAME_TO'
             AND src.asset_type='hostname' AND dst.asset_type='hostname'
             AND (src.asset_key=? OR src.asset_key LIKE ?)
           ORDER BY src.asset_key,dst.asset_key""",
        (root, "%." + root),
    ).fetchall()
    out=[]
    for row in rows:
        host=str(row["host"] or "").lower().rstrip(".")
        target=str(row["target"] or "").lower().rstrip(".")
        if not host or not target:
            continue
        if target == root or target.endswith("." + root):
            continue
        out.append((host,target))
    return out


def _takeover_fingerprint(target: str, body: str) -> dict | None:
    target_l=str(target or "").lower().rstrip(".")
    body_l=str(body or "").lower()
    for key,label,suffixes,phrases in TAKEOVER_FINGERPRINTS:
        target_match=any(s in target_l for s in suffixes)
        phrase=next((p for p in phrases if p in body_l), None)
        if target_match and phrase:
            return {"key":key,"provider":label,"phrase":phrase}
    return None


def _parse_takeover_dns(text: str) -> dict[tuple[str,str], dict]:
    out: dict[tuple[str,str], dict] = {}
    for raw in (text or "").splitlines():
        parts=raw.split("\t",3)
        if len(parts) < 3:
            continue
        host=parts[0].strip().lower().rstrip(".")
        target=parts[1].strip().lower().rstrip(".")
        status=parts[2].strip().upper() or "UNKNOWN"
        answers=[]
        if len(parts) > 3 and parts[3].strip():
            answers=[x.strip().rstrip(".") for x in parts[3].split(",") if x.strip()]
        out[(host,target)]={"status":status,"answers":answers}
    return out


def _parse_takeover_http(text: str) -> dict[tuple[str,str], dict]:
    out: dict[tuple[str,str], dict] = {}
    current: tuple[str,str] | None = None
    chunks: list[str] = []
    for raw in (text or "").splitlines():
        if raw.startswith("===TAKEOVER ") and raw.endswith("==="):
            if current:
                out[current]={"body":"\n".join(chunks)}
            payload=raw[len("===TAKEOVER "):-3]
            if "\t" in payload:
                host,target=payload.split("\t",1)
                current=(host.strip().lower().rstrip("."),target.strip().lower().rstrip("."))
            else:
                current=None
            chunks=[]
            continue
        if raw == "===END TAKEOVER===":
            if current:
                out[current]={"body":"\n".join(chunks)}
            current=None; chunks=[]
            continue
        if current:
            chunks.append(raw)
    if current:
        out[current]={"body":"\n".join(chunks)}
    return out


def takeover_findings(conn: sqlite3.Connection, root_domain: str) -> list[dict]:
    """Latest takeover-analysis observation per first-party host/CNAME target."""
    root=str(root_domain or "").strip().lower().rstrip(".")
    rows=conn.execute(
        """SELECT a.asset_key hostname,e.raw_json,e.observed_at,e.id
           FROM recon_evidence e JOIN recon_assets a ON a.id=e.asset_id
           WHERE e.source='takeover_analysis' AND e.kind='takeover_observation'
             AND a.asset_type='hostname' AND (a.asset_key=? OR a.asset_key LIKE ?)
           ORDER BY e.id DESC""", (root,"%."+root)
    ).fetchall()
    out=[]; seen=set()
    for row in rows:
        payload=_loads(row["raw_json"])
        key=(str(row["hostname"]),str(payload.get("cname_target") or ""))
        if key in seen:
            continue
        seen.add(key)
        payload.update({"hostname":row["hostname"],"observed_at":row["observed_at"]})
        out.append(payload)
    rank={"HIGH":0,"MEDIUM":1,"LOW":2,"INFO":3}
    return sorted(out,key=lambda x:(0 if x.get("candidate") else 1,rank.get(str(x.get("confidence") or "INFO"),9),str(x.get("hostname") or "")))


def run_takeover_analysis(conn: sqlite3.Connection, root_domain: str, paths: dict, timeout: int = 240, run_group: str = "") -> dict:
    """Analyze stored CNAME evidence without rerunning the recon pipeline.

    Only external CNAME destinations already observed by DNS/httpx are checked.
    `dig` verifies whether the upstream target still exists and a small `curl`
    probe to the authorized first-party hostname looks for conservative
    unprovisioned-service fingerprints.  Nothing is claimed or registered.
    """
    init_schema(conn)
    root=str(root_domain or "").strip().lower().rstrip(".")
    pairs=_external_cname_pairs(conn,root)
    if not pairs:
        return {"phase":"takeover","records":0,"candidates":0,"observations":0,"message":"No hay CNAME externos observados para analizar."}

    limit=max(1,int(os.environ.get("NEGRO_TAKEOVER_LIMIT","100") or 100))
    pairs=pairs[:limit]
    run_dir=Path(paths["raw"])/"surface-runs"
    run_dir.mkdir(parents=True,exist_ok=True)
    pair_file=run_dir/f"takeover-cnames-{re.sub(r'[^a-zA-Z0-9]+','-',root)}.tsv"
    pair_file.write_text("\n".join(f"{h}\t{t}" for h,t in pairs)+"\n",encoding="utf-8")

    dig=_tool_path("dig")
    bash=shutil.which("bash") or "/bin/bash"
    dns_data={}
    if dig:
        dns_script=r'''while IFS=$'\t' read -r host target; do
  [ -z "$target" ] && continue
  status=$({dig} "$target" A +time=3 +tries=1 +noall +comments 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)
  answers=$(for t in A AAAA CNAME; do {dig} "$target" "$t" +time=3 +tries=1 +short 2>/dev/null; done | sed 's/\.$//' | paste -sd, -)
  printf '%s\t%s\t%s\t%s\n' "$host" "$target" "${{status:-UNKNOWN}}" "$answers"
done < "$1"'''.format(dig=dig)
        dns_run=_run_tool(conn,paths,"takeover","dig-upstream",[bash,"-lc",dns_script,"negro-takeover-dns",str(pair_file)],timeout=timeout,root_domain=root,run_group=run_group)
        if dns_run["status"] in {"ok","partial"}:
            dns_data=_parse_takeover_dns(dns_run["stdout"])

    curl=_tool_path("curl")
    http_data={}
    if curl:
        http_script=r'''while IFS=$'\t' read -r host target; do
  [ -z "$host" ] && continue
  printf '===TAKEOVER %s\t%s===\n' "$host" "$target"
  out=$({curl} -ksSL --connect-timeout 4 --max-time 10 --max-redirs 3 --range 0-65535 "https://$host/" 2>&1)
  rc=$?
  if [ $rc -ne 0 ] || [ -z "$out" ]; then
    out=$({curl} -sSL --connect-timeout 4 --max-time 10 --max-redirs 3 --range 0-65535 "http://$host/" 2>&1)
  fi
  printf '%s\n' "$out" | head -c 65536
  printf '\n===END TAKEOVER===\n'
done < "$1"'''.format(curl=curl)
        http_run=_run_tool(conn,paths,"takeover","curl-fingerprint",[bash,"-lc",http_script,"negro-takeover-http",str(pair_file)],timeout=max(timeout,300),root_domain=root,run_group=run_group)
        if http_run["status"] in {"ok","partial"}:
            http_data=_parse_takeover_http(http_run["stdout"])

    observations=[]; candidates=0
    for host,target in pairs:
        dns=dns_data.get((host,target),{})
        status=str(dns.get("status") or "UNKNOWN").upper()
        answers=list(dns.get("answers") or [])
        body=str((http_data.get((host,target)) or {}).get("body") or "")
        fingerprint=_takeover_fingerprint(target,body)
        reasons=[]
        confidence="INFO"
        candidate=False
        if status == "NXDOMAIN":
            candidate=True; confidence="MEDIUM"
            reasons.append("El CNAME externo observado apunta a un destino que actualmente responde NXDOMAIN.")
        elif status == "NOERROR" and not answers:
            candidate=True; confidence="LOW"
            reasons.append("El destino del CNAME responde NOERROR pero no devolvió A/AAAA/CNAME (NODATA).")
        if fingerprint:
            candidate=True; confidence="HIGH"
            reasons.append(f"Respuesta compatible con recurso no aprovisionado de {fingerprint['provider']}.")
        if not reasons:
            reasons.append("CNAME externo observado; el destino sigue resolviendo y no coincidió con fingerprints conservadores.")

        row=conn.execute("SELECT id,metadata_json FROM recon_assets WHERE asset_type='hostname' AND asset_key=?",(host,)).fetchone()
        if not row:
            continue
        payload={
            "candidate":candidate,"confidence":confidence,"state":"CANDIDATE" if candidate else "OBSERVED_EXTERNAL_CNAME",
            "cname_target":target,"upstream_dns_status":status,"upstream_answers":answers,
            "fingerprint":fingerprint or {},"reasons":reasons,
            "claimability":"NOT_VALIDATED","confirmed":False,
        }
        add_evidence(conn,int(row["id"]),"takeover_analysis","takeover_observation",target,payload)
        meta=_merge_meta(_loads(row["metadata_json"]),{
            "takeover_state":payload["state"],"takeover_confidence":confidence if candidate else "",
            "takeover_target":target if candidate else "",
        })
        conn.execute("UPDATE recon_assets SET metadata_json=?,last_seen_at=? WHERE id=?",(json.dumps(meta,ensure_ascii=False),_now(),row["id"]))
        observations.append({"hostname":host,**payload})
        if candidate:
            candidates += 1
    conn.commit()
    return {"phase":"takeover","records":len(observations),"candidates":candidates,"observations":len(observations),"items":observations}



BASELINE_STEPS = (
    ("root", "Root / contexto"),
    ("discovery", "Discovery pasivo"),
    ("active_discovery", "Discovery activo ligero"),
    ("dns", "Validación DNS"),
    ("tls", "TLS / certificados"),
    ("dns_refresh", "DNS de SANs nuevos"),
    ("takeover", "Señales de takeover"),
    ("http", "HTTP / tecnologías"),
)


def create_baseline_batch(conn: sqlite3.Connection, roots: list[str]) -> dict:
    """Persist a project-wide baseline batch before background workers start.

    Persistence is intentional: the UI can recover progress after a browser
    refresh and a failed root can be retried without repeating completed roots.
    Actual execution is scheduled by the web layer, which already owns the
    local background-job concurrency controls.
    """
    init_schema(conn)
    normalized = []
    for raw in roots or []:
        root = str(raw or "").strip().lower().rstrip(".")
        if root and root not in normalized:
            normalized.append(root)
    if not normalized:
        raise ValueError("No hay roots de recon para ejecutar")
    batch_id = uuid.uuid4().hex
    now = _now()
    conn.execute(
        "INSERT INTO recon_baseline_batches(id,root_count,created_at) VALUES(?,?,?)",
        (batch_id, len(normalized), now),
    )
    jobs = []
    for root in normalized:
        job_id = uuid.uuid4().hex
        conn.execute(
            """INSERT INTO recon_baseline_jobs(
                   id,batch_id,root_domain,status,current_phase,step_index,step_total,
                   completed_json,skipped_json,error,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (job_id, batch_id, root, "queued", "", 0, len(BASELINE_STEPS), "[]", "[]", "", now, now),
        )
        jobs.append({"id": job_id, "root_domain": root, "status": "queued"})
    conn.commit()
    return {"batch_id": batch_id, "jobs": jobs, "roots": normalized}


def _baseline_update_job(conn: sqlite3.Connection, job_id: str, **values) -> None:
    allowed = {
        "status", "current_phase", "step_index", "step_total", "completed_json",
        "skipped_json", "error", "started_at", "finished_at", "updated_at",
    }
    payload = {k: v for k, v in values.items() if k in allowed}
    payload["updated_at"] = _now()
    if not payload:
        return
    fields = ",".join(f"{k}=?" for k in payload)
    conn.execute(f"UPDATE recon_baseline_jobs SET {fields} WHERE id=?", (*payload.values(), job_id))
    conn.commit()


def _baseline_pending_dns(conn: sqlite3.Connection, root_domain: str) -> int:
    count = 0
    root = root_domain.lower().rstrip(".")
    for row in conn.execute("SELECT asset_key,metadata_json FROM recon_assets WHERE asset_type='hostname'").fetchall():
        host = str(row["asset_key"] or "").lower().rstrip(".")
        if host != root and not host.endswith("." + root):
            continue
        state = str(_loads(row["metadata_json"]).get("dns_state") or "DISCOVERED").upper()
        if state not in {"RESOLVED", "NXDOMAIN", "NODATA"}:
            count += 1
    return count


def _baseline_pending_http(conn: sqlite3.Connection, root_domain: str) -> int:
    count = 0
    root = root_domain.lower().rstrip(".")
    for row in conn.execute("SELECT asset_key,metadata_json FROM recon_assets WHERE asset_type='hostname'").fetchall():
        host = str(row["asset_key"] or "").lower().rstrip(".")
        if host != root and not host.endswith("." + root):
            continue
        meta = _loads(row["metadata_json"])
        if meta.get("dns_state") == "RESOLVED" and meta.get("status_code") is None:
            count += 1
    return count


def run_project_baseline_root(conn: sqlite3.Connection, root_domain: str, paths: dict, job_id: str, *, force: bool = False) -> dict:
    """Build the breadth-first attack-surface baseline for one recon root.

    The baseline deliberately stops after HTTP/technology fingerprinting. It
    skips already-valid work where possible, re-runs DNS when new discovery or
    TLS SANs require it, and never includes Amass or deep endpoint crawling.
    """
    init_schema(conn)
    root = str(root_domain or "").strip().lower().rstrip(".")
    row = conn.execute("SELECT id FROM recon_baseline_jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        raise ValueError("Job baseline inexistente")
    started = _now()
    _baseline_update_job(conn, job_id, status="running", started_at=started, error="")
    completed: list[str] = []
    skipped: list[str] = []
    changed_surface = False
    dns_ran = False

    def mark(step_key: str, index: int, *, state: str = "running") -> None:
        _baseline_update_job(
            conn, job_id,
            status=state,
            current_phase=step_key,
            step_index=index,
            completed_json=json.dumps(completed, ensure_ascii=False),
            skipped_json=json.dumps(skipped, ensure_ascii=False),
        )

    try:
        for index, (step, _label) in enumerate(BASELINE_STEPS, start=1):
            mark(step, index)
            if step == "root":
                if not force and _phase_run_bundle(conn, "root", root).get("done"):
                    skipped.append(step)
                else:
                    run_root_phase(conn, root, paths, run_group=uuid.uuid4().hex)
                    completed.append(step)
                continue

            if step == "discovery":
                if not force and _phase_run_bundle(conn, "discovery", root).get("done"):
                    skipped.append(step)
                else:
                    run_discovery_phase(conn, root, paths, run_group=uuid.uuid4().hex)
                    completed.append(step); changed_surface = True
                continue

            if step == "active_discovery":
                if not force and _phase_run_bundle(conn, "active_discovery", root).get("done"):
                    skipped.append(step)
                else:
                    run_active_discovery_phase(conn, root, paths, run_group=uuid.uuid4().hex)
                    completed.append(step); changed_surface = True
                continue

            if step == "dns":
                should_run = force or changed_surface or _baseline_pending_dns(conn, root) > 0 or not _phase_run_bundle(conn, "dns", root).get("done")
                if should_run:
                    run_dns_phase(conn, root, paths, run_group=uuid.uuid4().hex)
                    completed.append(step); dns_ran = True; changed_surface = False
                else:
                    skipped.append(step)
                continue

            if step == "tls":
                should_run = force or dns_ran or not _phase_run_bundle(conn, "tls", root).get("done")
                if should_run:
                    run_tls_phase(conn, root, paths, run_group=uuid.uuid4().hex)
                    completed.append(step)
                else:
                    skipped.append(step)
                continue

            if step == "dns_refresh":
                if _baseline_pending_dns(conn, root) > 0:
                    run_dns_phase(conn, root, paths, run_group=uuid.uuid4().hex)
                    completed.append(step); dns_ran = True
                else:
                    skipped.append(step)
                continue

            if step == "takeover":
                pairs = _external_cname_pairs(conn, root)
                should_run = bool(pairs) and (force or dns_ran or not _phase_run_bundle(conn, "takeover", root).get("done"))
                if should_run:
                    run_takeover_analysis(conn, root, paths, run_group=uuid.uuid4().hex)
                    completed.append(step)
                else:
                    skipped.append(step)
                continue

            if step == "http":
                should_run = force or dns_ran or _baseline_pending_http(conn, root) > 0 or not _phase_run_bundle(conn, "http", root).get("done")
                if should_run:
                    run_http_phase(conn, root, paths, run_group=uuid.uuid4().hex)
                    completed.append(step)
                else:
                    skipped.append(step)
                continue

        _baseline_update_job(
            conn, job_id,
            status="done", current_phase="complete", step_index=len(BASELINE_STEPS),
            completed_json=json.dumps(completed, ensure_ascii=False),
            skipped_json=json.dumps(skipped, ensure_ascii=False),
            finished_at=_now(), error="",
        )
        return {"root_domain": root, "status": "done", "completed": completed, "skipped": skipped}
    except Exception as exc:
        _baseline_update_job(
            conn, job_id,
            status="failed", error=str(exc)[:1200], finished_at=_now(),
            completed_json=json.dumps(completed, ensure_ascii=False),
            skipped_json=json.dumps(skipped, ensure_ascii=False),
        )
        raise


def _baseline_job_dict(row: sqlite3.Row | dict) -> dict:
    item = dict(row)
    for key in ("completed_json", "skipped_json"):
        try:
            item[key[:-5]] = json.loads(item.get(key) or "[]")
        except Exception:
            item[key[:-5]] = []
    total = max(1, int(item.get("step_total") or len(BASELINE_STEPS)))
    index = max(0, int(item.get("step_index") or 0))
    item["percent"] = min(100, int(round(index / total * 100)))
    return item


def project_baseline_data(conn: sqlite3.Connection, roots: list[str]) -> dict:
    init_schema(conn)
    root_values = [str(x).lower().rstrip(".") for x in roots or [] if str(x).strip()]
    latest_batch = conn.execute("SELECT * FROM recon_baseline_batches ORDER BY seq DESC LIMIT 1").fetchone()
    batch = dict(latest_batch) if latest_batch else None
    jobs: list[dict] = []
    if batch:
        rows = conn.execute("SELECT * FROM recon_baseline_jobs WHERE batch_id=? ORDER BY seq", (batch["id"],)).fetchall()
        jobs = [_baseline_job_dict(r) for r in rows]
    latest_by_root: dict[str, dict] = {}
    for root in root_values:
        row = conn.execute("SELECT * FROM recon_baseline_jobs WHERE root_domain=? ORDER BY seq DESC LIMIT 1", (root,)).fetchone()
        if row:
            latest_by_root[root] = _baseline_job_dict(row)
    counts = {"queued":0,"running":0,"done":0,"failed":0}
    for job in jobs:
        status = str(job.get("status") or "queued")
        counts[status] = counts.get(status, 0) + 1
    active = any(str(j.get("status")) in {"queued","running"} for j in jobs)
    failed_roots = [str(j.get("root_domain")) for j in jobs if str(j.get("status")) == "failed"]
    return {
        "batch": batch,
        "jobs": jobs,
        "latest_by_root": latest_by_root,
        "counts": counts,
        "active": active,
        "failed_roots": failed_roots,
        "has_history": bool(latest_by_root),
    }


def recover_interrupted_baseline_jobs(conn: sqlite3.Connection) -> int:
    """Mark persisted queue/running rows as retryable after the local worker vanished."""
    init_schema(conn)
    rows=conn.execute("SELECT id FROM recon_baseline_jobs WHERE status IN ('queued','running')").fetchall()
    if not rows:
        return 0
    now=_now()
    for row in rows:
        conn.execute(
            "UPDATE recon_baseline_jobs SET status='failed',error=?,finished_at=?,updated_at=? WHERE id=?",
            ("Proceso local interrumpido antes de completar el baseline. Usa Reintentar fallidos.",now,now,row["id"]),
        )
    conn.commit()
    return len(rows)


def failed_baseline_roots(conn: sqlite3.Connection) -> list[str]:
    init_schema(conn)
    latest = conn.execute("SELECT id FROM recon_baseline_batches ORDER BY seq DESC LIMIT 1").fetchone()
    if not latest:
        return []
    rows = conn.execute(
        "SELECT root_domain FROM recon_baseline_jobs WHERE batch_id=? AND status='failed' ORDER BY seq",
        (latest["id"],),
    ).fetchall()
    return [str(r["root_domain"]) for r in rows]

def run_phase(conn: sqlite3.Connection, root_domain: str, paths: dict, phase: str) -> dict:
    phase = (phase or "").strip().lower()
    run_group = uuid.uuid4().hex
    if phase == "root": return run_root_phase(conn, root_domain, paths, run_group=run_group)
    if phase == "discovery": return run_discovery_phase(conn, root_domain, paths, run_group=run_group)
    if phase == "discovery_expand": return run_expand_discovery_phase(conn, root_domain, paths, run_group=run_group)
    if phase == "active_discovery": return run_active_discovery_phase(conn, root_domain, paths, run_group=run_group)
    if phase == "dns": return run_dns_phase(conn, root_domain, paths, run_group=run_group)
    if phase == "tls": return run_tls_phase(conn, root_domain, paths, run_group=run_group)
    if phase == "http": return run_http_phase(conn, root_domain, paths, run_group=run_group)
    raise ValueError(f"Fase no soportada: {phase}")


def _read_run_preview(path_value: str | None, *, max_lines: int = 120, max_chars: int = 32000) -> str:
    if not path_value:
        return ""
    try:
        path = Path(path_value)
        if not path.exists() or not path.is_file():
            return ""
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    lines = text.splitlines()
    clipped = "\n".join(lines[:max_lines])
    if len(clipped) > max_chars:
        clipped = clipped[:max_chars]
    if len(lines) > max_lines or len(text) > len(clipped):
        clipped += f"\n… salida truncada ({len(lines)} líneas totales)"
    return clipped


def attach_legacy_runs(conn: sqlite3.Connection, primary_root: str) -> None:
    """Attach pre-v0.73 tool runs to the project's original root once.

    v0.72 had no root_domain column because a project effectively exposed only
    one recon root. Backfilling against the primary project domain avoids
    accidentally assigning historical runs to a newly-added secondary root.
    """
    init_schema(conn)
    conn.execute(
        "UPDATE recon_tool_runs SET root_domain=? WHERE COALESCE(root_domain,'')=''",
        (primary_root.lower().rstrip("."),),
    )
    conn.commit()


def _phase_run_bundle(conn: sqlite3.Connection, phase: str, root_domain: str) -> dict:
    root = root_domain.lower().rstrip(".")
    latest = conn.execute(
        "SELECT * FROM recon_tool_runs WHERE phase=? AND COALESCE(root_domain,'')=? ORDER BY id DESC LIMIT 1",
        (phase, root),
    ).fetchone()
    if not latest:
        return {"count": 0, "latest": None, "runs": [], "done": False}
    latest = dict(latest)
    group = str(latest.get("run_group") or "")
    if group:
        rows = conn.execute(
            "SELECT * FROM recon_tool_runs WHERE phase=? AND COALESCE(root_domain,'')=? AND run_group=? ORDER BY id",
            (phase, root, group),
        ).fetchall()
    else:
        rows = [latest]
    runs = []
    for row in rows:
        item = dict(row)
        try:
            cmd = json.loads(item.get("command_json") or "[]")
        except Exception:
            cmd = []
        item["command"] = " ".join(str(x) for x in cmd)
        item["stdout_preview"] = _read_run_preview(item.get("stdout_path"))
        item["stderr_preview"] = _read_run_preview(item.get("stderr_path"), max_lines=60, max_chars=16000)
        runs.append(item)
    total_count = conn.execute(
        "SELECT COUNT(*) c FROM recon_tool_runs WHERE phase=? AND COALESCE(root_domain,'')=?",
        (phase, root),
    ).fetchone()["c"]
    return {
        "count": int(total_count),
        "latest": latest,
        "runs": runs,
        "done": bool(runs and any(str(r.get("status")) == "ok" for r in runs)),
    }


def phase_progress(conn: sqlite3.Connection, root_domain: str) -> list[dict]:
    """Return the guided recon sequence for a root.

    Discovery is intentionally split into passive and explicit active phases.
    TLS sits before HTTP because SANs can add hostnames which then flow back to
    DNS validation before the technology fingerprinting step.
    """
    init_schema(conn)
    root = root_domain.lower().rstrip(".")
    hosts = _asset_rows(conn, "hostname")
    first = [h for h in hosts if h["asset_key"] == root or h["asset_key"].endswith("." + root)]
    discovered = max(0, len(first) - 1 if any(h["asset_key"] == root for h in first) else len(first))
    resolved = sum(1 for h in first if (h.get("metadata") or {}).get("dns_state") == "RESOLVED")
    nodata = sum(1 for h in first if (h.get("metadata") or {}).get("dns_state") == "NODATA")
    nxdomain = sum(1 for h in first if (h.get("metadata") or {}).get("dns_state") == "NXDOMAIN")
    http = sum(1 for h in first if (h.get("metadata") or {}).get("status_code") is not None)
    takeover_candidates = sum(1 for x in takeover_findings(conn, root) if x.get("candidate"))
    discovery_counts = _discovery_source_counts(conn, root)
    discovery_sources_with_evidence = sum(1 for key in ("subfinder","crtsh","amass","gau_historical","manual") if discovery_counts.get(key, 0) > 0)
    active_count = int(discovery_counts.get("active_permutation", 0)) + int(discovery_counts.get("active_bruteforce", 0))
    tls_certs = int(conn.execute(
        """SELECT COUNT(*) c FROM recon_evidence e JOIN recon_assets a ON a.id=e.asset_id
           WHERE e.source='openssl' AND e.kind='tls_certificate' AND a.asset_type='hostname'
             AND (a.asset_key=? OR a.asset_key LIKE ?)""", (root, "%." + root)
    ).fetchone()["c"] or 0)
    root_ev = int(conn.execute(
        """SELECT COUNT(*) c FROM recon_evidence e JOIN recon_assets a ON a.id=e.asset_id
           WHERE e.source='root_recon' AND a.asset_type='hostname' AND a.asset_key=?""",
        (root,),
    ).fetchone()["c"] or 0)
    tooling = tool_inventory()
    phase_keys = ("root","discovery","discovery_expand","active_discovery","dns","tls","http","web","historical","infra","deep","services")
    bundles = {key: _phase_run_bundle(conn, key, root) for key in phase_keys}

    # Base passive discovery is intentionally fast: Subfinder + CT + GAU.
    # Amass remains visible as optional enrichment and can be run independently.
    discovery_available = sum(1 for name in ("subfinder","curl","gau") if tooling.get(name,{}).get("available"))
    discovery_latest_runs = list(bundles["discovery"].get("runs") or [])
    discovery_last_tools = {str(r.get("tool")) for r in discovery_latest_runs}
    discovery_executed = sum(1 for tool in ("subfinder","crt.sh","gau") if tool in discovery_last_tools)
    discovery_success = sum(1 for r in discovery_latest_runs if str(r.get("tool")) in {"subfinder","crt.sh","gau"} and str(r.get("status")) in {"ok","partial"})

    specs = [
        {"key":"root","title":"Dominio raíz","subtitle":"WHOIS · DNS · HTTP inicial","count":root_ev,"count_label":"evidencias","implemented":True,"tool_ok":all(tooling[x]["available"] for x in ("dig","curl")),"tool_names":["whois","dig","curl"],"purpose":"Crear la línea base del dominio raíz antes de descubrir nombres."},
        {"key":"discovery","title":"Discovery pasivo de hosts","subtitle":"Subfinder · CT · históricos · Amass opcional","count":discovered,"count_label":"hosts únicos candidatos","implemented":True,"tool_ok":bool(discovery_available),"tool_names":["subfinder","curl","gau"],"optional_tool_names":["amass"],"purpose":"Cruzar fuentes pasivas e históricas antes de generar tráfico DNS activo. Amass es enriquecimiento opcional y no bloquea el flujo.","secondary_counts":{"fuentes con evidencia":discovery_sources_with_evidence,"Subfinder":discovery_counts.get("subfinder",0),"CT":discovery_counts.get("crtsh",0),"Históricos":discovery_counts.get("gau_historical",0),"Amass opcional":discovery_counts.get("amass",0),"Manual":discovery_counts.get("manual",0)},"coverage":{"success":discovery_success,"executed":discovery_executed,"available":discovery_available,"total":3}},
        {"key":"active_discovery","title":"Discovery activo de hosts","subtitle":"AlterX · DNS wordlist · wildcard filtering","count":active_count,"count_label":"hosts activos añadidos","implemented":True,"tool_ok":bool(tooling["dnsx"]["available"]),"tool_names":["dnsx"],"optional_tool_names":["alterx"],"purpose":"Generar candidatos plausibles a partir de patrones reales y una wordlist corta; incorporar únicamente nombres que resuelven.","secondary_counts":{"Permutaciones":discovery_counts.get("active_permutation",0),"DNS brute force":discovery_counts.get("active_bruteforce",0)}},
        {"key":"dns","title":"Validar DNS","subtitle":"dnsx · A / AAAA / CNAME + estado DNS","count":resolved,"count_label":"DNS resueltos","implemented":True,"tool_ok":tooling["dnsx"]["available"],"tool_names":["dnsx","dig"],"purpose":"Separar nombres actuales de NXDOMAIN/NODATA, relacionar CNAME/IP y permitir análisis de dangling DNS para takeover.","secondary_counts":{"NODATA":nodata,"NXDOMAIN":nxdomain,"Takeover candidatos":takeover_candidates}},
        {"key":"tls","title":"TLS y certificados","subtitle":"SAN · issuer · fechas · certificados compartidos","count":tls_certs,"count_label":"certificados observados","implemented":True,"tool_ok":tooling["openssl"]["available"],"tool_names":["openssl"],"purpose":"Extraer SANs y relaciones de certificados; cualquier hostname nuevo vuelve a DNS antes de HTTP.","secondary_counts":{"SAN hosts":discovery_counts.get("tls_san",0)}},
        {"key":"http","title":"Descubrir HTTP y tecnologías","subtitle":"httpx · status / title / tech / CDN / redirects","count":http,"count_label":"HTTP observados","implemented":True,"tool_ok":tooling["httpx"]["available"],"tool_names":["httpx"],"purpose":"Convertir hosts DNS en aplicaciones observables y fingerprint técnico estructurado."},
        {"key":"web","title":"Descubrimiento web","subtitle":"robots · sitemap · crawler · JavaScript","count":0,"count_label":"artefactos web","implemented":False,"tool_ok":True,"tool_names":["curl"],"purpose":"Profundizar hosts HTTP vivos y permitir que robots, sitemap, crawling y JavaScript retroalimenten nuevos hostnames."},
        {"key":"historical","title":"Históricos y contenido","subtitle":"rutas antiguas · endpoints · parámetros · correlación","count":0,"count_label":"artefactos históricos","implemented":False,"tool_ok":bool(tooling["gau"]["available"] or tooling["curl"]["available"]),"tool_names":["gau","curl"],"purpose":"Reutilizar las URLs históricas ya recolectadas para rutas, endpoints, parámetros y contexto temporal; nuevos hosts vuelven a DNS."},
        {"key":"infra","title":"Clasificar infraestructura","subtitle":"edge / SaaS / origin candidato / IP directa","count":0,"count_label":"candidatos directos","implemented":False,"tool_ok":True,"tool_names":[],"purpose":"Decidir qué IP es edge compartido, SaaS o candidata real a infraestructura directa."},
        {"key":"deep","title":"Enumeración profunda","subtitle":"rama elegida · señales de alto valor","count":0,"count_label":"ramas priorizadas","implemented":False,"tool_ok":True,"tool_names":[],"purpose":"Profundizar únicamente ramas priorizadas usando el contexto acumulado, sin barrer toda la superficie a ciegas."},
        {"key":"services","title":"Servicios / Nmap","subtitle":"sólo infraestructura directa validada","count":0,"count_label":"candidatos Nmap","implemented":False,"tool_ok":tooling["nmap"]["available"],"tool_names":["nmap"],"purpose":"Enumerar puertos únicamente después de confirmar que el objetivo no es un CDN/SaaS compartido."},
    ]

    out=[]
    previous_complete = True
    for index, spec in enumerate(specs, start=1):
        key=spec["key"]
        bundle=bundles[key]
        own_done=bool(bundle["done"])
        effective_done=bool(own_done and previous_complete)
        ready=bool(previous_complete and spec["implemented"])
        prior_evidence=bool(own_done and not previous_complete)
        if effective_done:
            state="done"; state_label="COMPLETADO"
        elif ready and spec["tool_ok"]:
            state="ready"; state_label="SIGUIENTE"
        elif ready and not spec["tool_ok"]:
            state="missing_tool"; state_label="FALTA HERRAMIENTA"
        elif prior_evidence:
            state="evidence"; state_label="EVIDENCIA PREVIA"
        elif not spec["implemented"] and previous_complete:
            state="planned"; state_label="PENDIENTE"
        else:
            state="blocked"; state_label="BLOQUEADO"
        tool_info=[]
        for name in spec.get("tool_names",[]):
            info=dict(tooling.get(name) or {"available":False,"path":""})
            info["name"]=name
            tool_info.append(info)
        optional_tool_info=[]
        for name in spec.get("optional_tool_names",[]):
            info=dict(tooling.get(name) or {"available":False,"path":""})
            info["name"]=name
            optional_tool_info.append(info)
        out.append({
            **spec,
            "number": index,
            "ready": ready,
            "done": effective_done,
            "own_done": own_done,
            "prior_evidence": prior_evidence,
            "state": state,
            "state_label": state_label,
            "tool_info": tool_info,
            "optional_tool_info": optional_tool_info,
            "run_count": bundle["count"],
            "last_status": (bundle["latest"].get("status") if bundle["latest"] else None),
            "last_started_at": (bundle["latest"].get("started_at") if bundle["latest"] else None),
            "latest_runs": bundle["runs"],
            "question": spec.get("purpose") or spec["subtitle"],
            "tool": ", ".join(spec.get("tool_names") or []),
            "checks": [spec["count_label"]],
            "success": spec["count_label"],
        })
        previous_complete = effective_done
    return out

def _read_run_text(path_value: str | None, *, max_chars: int = 240000) -> str:
    if not path_value:
        return ""
    try:
        path=Path(path_value)
        if not path.exists() or not path.is_file():
            return ""
        text=path.read_text(encoding="utf-8",errors="replace")
    except Exception:
        return ""
    if len(text) > max_chars:
        return text[:max_chars] + f"\n… salida truncada en UI ({len(text)} caracteres totales)"
    return text


def _compact_audit_stderr(tool: str, text: str) -> str:
    """Hide progress/terminal noise inline while preserving raw stderr on disk.

    Amass can emit hundreds of kilobytes of carriage-return progress frames.
    Those frames are useful only for low-level audit and make the phase detail
    unreadable.  The raw file is never modified; this function only creates the
    compact UI representation.
    """
    raw = text or ""
    if str(tool).lower() != "amass":
        return raw

    # Remove ANSI control sequences / backspaces first.
    cleaned = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw).replace("\b", "")

    # Progress frames may be separated by CR, LF, or concatenated into one very
    # long line after capture.  Remove the complete `done / total [bar] pct p/s`
    # frame globally rather than relying only on line boundaries.
    frame = re.compile(
        r"\d+\s*/\s*\d+\s*\[[^\]]{10,2000}\]\s*"
        r"\d+(?:\.\d+)?%\s*(?:\??\s*)?(?:\d+(?:\.\d+)?\s*)?p/s?",
        re.I,
    )
    cleaned = frame.sub("\n", cleaned)
    # Some builds print the p/s counter before the next frame.
    cleaned = re.sub(r"\b\d+(?:\.\d+)?\s+p/s(?=\d+\s*/\s*\d+)", "\n", cleaned, flags=re.I)

    kept: list[str] = []
    for part in re.split(r"[\r\n]+", cleaned):
        line = part.strip()
        if not line:
            continue
        # Defensive catch for malformed/truncated progress frames.
        if "p/s" in line.lower() and (line.count("-") + line.count("_") > 18 or "%" in line):
            continue
        if line.count("-") + line.count("_") > 60:
            continue
        kept.append(line)
    return "\n".join(kept[-80:])


def phase_detail_data(conn: sqlite3.Connection, root_domain: str, phase_key: str) -> dict | None:
    """Full auditable detail for one guided recon phase."""
    phases=phase_progress(conn, root_domain)
    phase=next((p for p in phases if p["key"]==phase_key),None)
    if not phase:
        return None
    runs=[]
    run_items=list(phase.get("latest_runs") or [])
    if phase_key=="discovery" and len(run_items) <= 1:
        legacy = list(_phase_run_bundle(conn, "discovery_expand", root_domain).get("runs") or [])
        seen = {int(x.get("id") or 0) for x in run_items}
        run_items += [x for x in legacy if int(x.get("id") or 0) not in seen]
    for item in run_items:
        run=dict(item)
        run["stdout_full"]=_read_run_text(run.get("stdout_path"))
        run["stderr_full"]=_read_run_text(run.get("stderr_path"))
        run["stderr_display"]=_compact_audit_stderr(str(run.get("tool") or ""), run.get("stderr_full") or "")
        raw = run.get("stdout_full") or ""
        tool = str(run.get("tool") or "")
        root = root_domain.lower().rstrip(".")
        if phase_key == "discovery":
            if tool == "subfinder":
                run["normalized_count"] = len(_first_party_hosts_from_lines(raw, root))
            elif tool == "crt.sh":
                run["normalized_count"] = len([h for h in _crtsh_hosts(raw, root) if h != root])
            elif tool == "amass":
                run["normalized_count"] = len(_first_party_hosts_from_lines(raw, root))
            elif tool == "gau":
                run["normalized_count"] = len(_historical_hosts_from_text(raw, root))
        elif phase_key == "active_discovery":
            if tool == "alterx":
                run["normalized_count"] = len(_first_party_hosts_from_lines(raw, root))
                run["normalized_label"] = "candidatos generados"
            elif tool in {"dnsx-permutations", "dnsx-bruteforce"}:
                run["normalized_count"] = len(_first_party_hosts_from_lines(raw, root))
                run["normalized_label"] = "hosts que resolvieron"
        elif phase_key == "tls" and tool == "openssl":
            tls_rows = _parse_tls_bundle(raw, root)
            run["normalized_count"] = len([x for x in tls_rows if x.get("fingerprint")])
            run["normalized_label"] = "certificados parseados"
        runs.append(run)

    normalized=[]
    root=root_domain.lower().rstrip(".")
    if phase_key in {"discovery","discovery_expand","active_discovery","dns","http"}:
        data=surface_data(conn, root_domain)
        for h in data.get("hosts",[]):
            sources=set(h.get("sources") or [])
            if phase_key=="discovery" and not ({"subfinder","crtsh","amass","gau_historical","manual"} & sources):
                continue
            if phase_key=="discovery_expand" and not ({"crtsh","amass"} & sources):
                continue
            if phase_key=="active_discovery" and not ({"active_permutation","active_bruteforce"} & sources):
                continue
            if phase_key=="dns" and h.get("dns_state") in {None,"DISCOVERED"}:
                continue
            if phase_key=="http" and h.get("status_code") is None:
                continue
            normalized.append(h)
    elif phase_key=="tls":
        rows=conn.execute(
            """SELECT a.asset_key hostname,e.raw_json,e.observed_at FROM recon_evidence e
               JOIN recon_assets a ON a.id=e.asset_id
               WHERE e.source='openssl' AND e.kind='tls_certificate' AND a.asset_type='hostname'
                 AND (a.asset_key=? OR a.asset_key LIKE ?)
               ORDER BY e.id""", (root, "%."+root)).fetchall()
        for row in rows:
            raw=_loads(row["raw_json"])
            normalized.append({"hostname":row["hostname"],"tls":raw,"observed_at":row["observed_at"],"dns_state":"TLS"})
    elif phase_key=="root":
        rows=conn.execute(
            """SELECT e.kind,e.value,e.raw_json,e.observed_at FROM recon_evidence e
               JOIN recon_assets a ON a.id=e.asset_id
               WHERE e.source='root_recon' AND a.asset_type='hostname' AND a.asset_key=?
               ORDER BY e.id""",(root,)).fetchall()
        for row in rows:
            normalized.append({"kind":row["kind"],"value":row["value"],"payload":_loads(row["raw_json"]),"observed_at":row["observed_at"]})

    source_summary=[]
    inventory=tool_inventory()
    latest_by_tool={str(r.get("tool")):r for r in runs}
    if phase_key=="discovery":
        counts=_discovery_source_counts(conn, root)
        definitions=[
            ("subfinder","Subfinder","subfinder",bool(inventory.get("subfinder",{}).get("available")),"nombres crudos",False),
            ("crtsh","Certificate Transparency · crt.sh","crt.sh",bool(inventory.get("curl",{}).get("available")),"respuestas crudas",False),
            ("gau_historical","Históricos · GAU","gau",bool(inventory.get("gau",{}).get("available")),"URLs históricas",False),
            ("amass","Amass · enriquecimiento opcional","amass",bool(inventory.get("amass",{}).get("available")),"líneas crudas",True),
            ("manual","Añadidos manualmente","manual",True,"entradas manuales",True),
        ]
        for source,label,tool,available,raw_label,optional in definitions:
            run=latest_by_tool.get(tool)
            hosts=_discovery_source_hosts(conn, root, source)
            source_summary.append({
                "source":source,"label":label,"tool":tool,"available":available,
                "executed":bool(run) or source=="manual","status":str(run.get("status")) if run else ("ok" if hosts and source=="manual" else ""),
                "raw_count":int(run.get("record_count") or 0) if run else len(hosts),
                "raw_label":raw_label,"optional":optional,"hosts":hosts,
                "normalized_count":len(hosts) if hosts else int(counts.get(source,0)),
                "rerunnable":source != "manual",
            })
    elif phase_key=="active_discovery":
        definitions=[
            ("active_permutation","Permutaciones validadas · AlterX + dnsx","dnsx-permutations",bool(inventory.get("dnsx",{}).get("available"))),
            ("active_bruteforce","DNS wordlist · dnsx","dnsx-bruteforce",bool(inventory.get("dnsx",{}).get("available"))),
        ]
        for source,label,tool,available in definitions:
            run=latest_by_tool.get(tool)
            hosts=_discovery_source_hosts(conn, root, source)
            source_summary.append({
                "source":source,"label":label,"tool":tool,"available":available,
                "executed":bool(run),"status":str(run.get("status")) if run else "",
                "raw_count":int(run.get("record_count") or 0) if run else 0,
                "raw_label":"hosts que resolvieron","optional":False,"hosts":hosts,
                "normalized_count":len(hosts),"rerunnable":False,
            })
    elif phase_key=="tls":
        san_hosts=_discovery_source_hosts(conn, root, "tls_san")
        source_summary.append({
            "source":"tls_san","label":"Hostnames descubiertos en SAN","tool":"openssl","available":bool(inventory.get("openssl",{}).get("available")),
            "executed":bool(runs),"status":str(runs[-1].get("status")) if runs else "",
            "raw_count":0,"raw_label":"SANs","optional":False,"hosts":san_hosts,
            "normalized_count":len(san_hosts),"rerunnable":False,
        })
    takeover={}
    if phase_key in {"dns","http"}:
        takeover_runs=list(_phase_run_bundle(conn,"takeover",root).get("runs") or [])
        takeover={
            "findings":takeover_findings(conn,root),
            "runs":takeover_runs,
            "executed":bool(takeover_runs),
            "external_cnames":len(_external_cname_pairs(conn,root)),
            "tool_ok":bool(inventory.get("dig",{}).get("available") or inventory.get("curl",{}).get("available")),
        }
        takeover["candidates"]=sum(1 for x in takeover["findings"] if x.get("candidate"))
    return {"phase":phase,"runs":runs,"normalized":normalized,"root_domain":root_domain,"source_summary":source_summary,"takeover":takeover}

def _asset_rows(conn: sqlite3.Connection, asset_type: str) -> list[dict]:
    out = []
    for row in conn.execute("SELECT * FROM recon_assets WHERE asset_type=? ORDER BY label COLLATE NOCASE", (asset_type,)).fetchall():
        item = dict(row)
        item["metadata"] = _loads(item.pop("metadata_json", "{}"))
        out.append(item)
    return out



def _host_interest(host: dict) -> dict:
    """Deterministic triage, never a vulnerability score."""
    score = 0
    reasons: list[str] = []
    env = str(host.get("environment") or "UNKNOWN").upper()
    hostname = str(host.get("hostname") or "").lower()
    tokens = set(re.split(r"[._-]+", hostname))
    status = host.get("status_code")
    sources = {str(x).lower() for x in (host.get("sources") or [])}

    if str(host.get("takeover_state") or "") == "CANDIDATE":
        score += 6; reasons.append("takeover candidate")
    if env in {"DEV", "QA", "STAGING"}:
        score += 3; reasons.append(f"ambiente {env}")
    if tokens & {"api", "apis", "graphql", "gateway", "gw", "ws", "socket"}:
        score += 2; reasons.append("superficie API")
    if tokens & {"auth", "login", "sso", "oauth", "idp"}:
        score += 2; reasons.append("autenticación / identidad")
    try:
        sc = int(status) if status is not None else None
    except Exception:
        sc = None
    if sc is not None and sc >= 500:
        score += 2; reasons.append(f"HTTP {sc}")
    elif sc in {401, 403}:
        score += 1; reasons.append(f"HTTP {sc}")
    if sources & {"active_permutation", "active_bruteforce", "tls_san", "gau_historical"}:
        score += 1; reasons.append("descubierto por pivote")

    if score >= 6:
        level = "HIGH"
    elif score >= 3:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = ""
    return {"interest_score": score, "interest_level": level, "interest_reasons": reasons}

def surface_data(conn: sqlite3.Connection, root_domain: str, scopes: list[str] | None = None) -> dict:
    init_schema(conn)
    roots = list(dict.fromkeys([root_domain.lower().rstrip('.')] + [str(x).lower().rstrip('.') for x in (scopes or []) if x]))
    for recon_root in roots:
        rebuild_family_heuristics(conn, recon_root)
    conn.commit()

    hosts = _asset_rows(conn, "hostname")
    rels = [dict(r) for r in conn.execute("SELECT * FROM recon_relationships ORDER BY id").fetchall()]
    assets_by_id = {int(r["id"]): r for typ in ("ip", "provider", "technology", "server", "hostname") for r in _asset_rows(conn, typ)}
    by_src: dict[int, list[dict]] = {}
    for r in rels:
        by_src.setdefault(int(r["src_asset_id"]), []).append(r)

    # A hostname belongs to the most specific recon root that contains it. This
    # keeps multiple roots in the same project map without duplicating nested
    # hostnames if a user intentionally adds a more specific root later.
    sorted_roots = sorted(roots, key=len, reverse=True)
    def host_root(hostname: str) -> str | None:
        key = str(hostname or '').lower().rstrip('.')
        for rr in sorted_roots:
            if key == rr or key.endswith('.' + rr):
                return rr
        return None

    def enrich_host(host: dict, assigned_root: str) -> dict:
        m = dict(host["metadata"])
        related = by_src.get(int(host["id"]), [])
        techs=[]; providers=[]; servers=[]; ips=[]; cnames=[]; redirects=[]; sources=set(m.get("sources") or [])
        for rel in related:
            dst = assets_by_id.get(int(rel["dst_asset_id"]))
            if not dst:
                continue
            rel_source = str(rel.get("source") or "")
            if rel_source and not rel_source.startswith("heuristic:"):
                sources.add(rel_source)
            if rel["relation"] == "USES" and dst["asset_type"] == "technology": techs.append(dst["label"])
            elif rel["relation"] in {"PROXIED_BY", "HOSTED_ON", "USES_PLATFORM"}: providers.append(dst["label"])
            elif rel["relation"] == "SERVED_BY": servers.append(dst["label"])
            elif rel["relation"] in {"RESOLVES_TO","OBSERVED_IP"} and dst["asset_type"] == "ip": ips.append(dst["label"])
            elif rel["relation"] == "CNAME_TO": cnames.append(dst["label"])
            elif rel["relation"] == "REDIRECTS_TO": redirects.append(dst["label"])
        family = m.get("family") or _family_stem(host["label"], assigned_root)
        item = {
            "id": host["id"], "hostname": host["label"], "root_domain": assigned_root,
            "environment": m.get("environment") or "UNKNOWN", "family": family or "other",
            "status_code": m.get("status_code"), "title": m.get("title"), "url": m.get("url"), "scheme": m.get("scheme"), "port": m.get("port"),
            "http_state": m.get("http_state") or "UNKNOWN", "dns_state": m.get("dns_state") or ("RESOLVED" if ips or cnames else "DISCOVERED"),
            "takeover_state": m.get("takeover_state") or "", "takeover_confidence": m.get("takeover_confidence") or "", "takeover_target": m.get("takeover_target") or "",
            "webserver": m.get("webserver"), "location": m.get("location"), "cdn": bool(m.get("cdn")), "cdn_name": m.get("cdn_name"),
            "technologies": list(dict.fromkeys(techs or m.get("tech") or [])), "providers": list(dict.fromkeys(providers)), "servers": list(dict.fromkeys(servers)),
            "ips": list(dict.fromkeys(ips)), "cnames": list(dict.fromkeys(cnames)), "redirects": list(dict.fromkeys(redirects)),
            "sources": sorted(x for x in sources if x), "last_seen_at": host["last_seen_at"],
        }
        item.update(_host_interest(item))
        return item

    project_hosts=[]
    for host in hosts:
        rr = host_root(host["asset_key"])
        if rr:
            project_hosts.append(enrich_host(host, rr))
    enriched=[h for h in project_hosts if h["root_domain"] == root_domain.lower().rstrip('.')]

    def uniq(field, rows=None):
        rows = project_hosts if rows is None else rows
        vals=[]
        for h in rows:
            v=h.get(field)
            vals.extend(v if isinstance(v,list) else [v] if v not in (None,"") else [])
        return sorted(set(str(x) for x in vals if str(x)))

    status = sorted(set(str(h["status_code"]) for h in project_hosts if h.get("status_code") is not None))
    family_counts: dict[str, int] = {}
    for h in project_hosts:
        # Families are root-local. Prefix with root for counting so two unrelated
        # roots that happen to use "api" do not become one family.
        key=f'{h.get("root_domain")}::{h.get("family") or "other"}'
        family_counts[key] = family_counts.get(key, 0) + 1
    grouped_families = [f for f, count in family_counts.items() if count > 1]
    phases = phase_progress(conn, root_domain)
    done_count = sum(1 for p in phases if p.get("state") == "done")
    total_count = len(phases)
    next_phase = next((p for p in phases if p.get("state") in {"ready", "planned", "missing_tool"}), None)
    baseline = project_baseline_data(conn, roots)
    non_prod = sum(1 for h in project_hosts if str(h.get("environment") or "").upper() in {"DEV","QA","STAGING"})
    takeover_count = sum(1 for h in project_hosts if str(h.get("takeover_state") or "") == "CANDIDATE")
    api_like = sum(1 for h in project_hosts if "superficie API" in (h.get("interest_reasons") or []))
    auth_like = sum(1 for h in project_hosts if "autenticación / identidad" in (h.get("interest_reasons") or []))
    server_errors = sum(1 for h in project_hosts if isinstance(h.get("status_code"), int) and int(h.get("status_code")) >= 500)
    resolved_project = sum(1 for h in project_hosts if h.get("dns_state") == "RESOLVED")
    top_interest = sorted(
        [h for h in project_hosts if int(h.get("interest_score") or 0) > 0],
        key=lambda h: (-int(h.get("interest_score") or 0), str(h.get("hostname") or "")),
    )[:12]
    root_overview=[]
    for rr in roots:
        rows=[h for h in project_hosts if h.get("root_domain")==rr]
        latest=baseline.get("latest_by_root",{}).get(rr) or {}
        root_overview.append({
            "root_domain":rr, "hosts":len(rows),
            "resolved":sum(1 for h in rows if h.get("dns_state")=="RESOLVED"),
            "http_alive":sum(1 for h in rows if h.get("status_code") is not None),
            "non_prod":sum(1 for h in rows if str(h.get("environment") or "").upper() in {"DEV","QA","STAGING"}),
            "takeover_candidates":sum(1 for h in rows if str(h.get("takeover_state") or "")=="CANDIDATE"),
            "baseline_status":str(latest.get("status") or "not_run"),
            "baseline_phase":str(latest.get("current_phase") or ""),
            "baseline_percent":int(latest.get("percent") or 0),
            "baseline_error":str(latest.get("error") or ""),
        })
    return {
        "root_domain": root_domain,
        "roots": roots,
        "hosts": enriched,
        "project_hosts": project_hosts,
        "filters": {
            "roots": roots,
            "technologies": uniq("technologies"), "providers": uniq("providers"), "servers": uniq("servers"),
            "environments": uniq("environment"), "families": uniq("family"), "sources": uniq("sources"), "statuses": status,
        },
        "summary": {"hosts": len(enriched), "http_alive": sum(1 for h in enriched if h.get("status_code") is not None), "technologies": len(uniq("technologies", enriched)), "providers": len(uniq("providers", enriched)), "families": len([k for k,v in family_counts.items() if k.startswith(root_domain.lower().rstrip('.')+'::') and v>1])},
        "project_summary": {"roots": len(roots), "hosts": len(project_hosts), "resolved": resolved_project, "http_alive": sum(1 for h in project_hosts if h.get("status_code") is not None), "technologies": len(uniq("technologies")), "providers": len(uniq("providers")), "families": len(grouped_families), "non_prod": non_prod, "api_like": api_like, "auth_like": auth_like, "takeover_candidates": takeover_count, "server_errors": server_errors},
        "baseline": baseline,
        "root_overview": root_overview,
        "top_interest": top_interest,
        "imports": [dict(r) for r in conn.execute("SELECT * FROM recon_import_runs ORDER BY id DESC LIMIT 20").fetchall()],
        "tool_runs": [dict(r) for r in conn.execute("SELECT * FROM recon_tool_runs WHERE COALESCE(root_domain,'')=? ORDER BY id DESC LIMIT 30", (root_domain.lower().rstrip('.'),)).fetchall()],
        "phases": phases,
        "phase_summary": {"done": done_count, "total": total_count, "percent": int(round((done_count / total_count) * 100)) if total_count else 0, "next": next_phase},
        "tooling": tool_inventory(),
        "manual_hosts": manual_hostname_entries(conn, root_domain),
    }
