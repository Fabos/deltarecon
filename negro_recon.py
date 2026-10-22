from __future__ import annotations

import json
import re
import sqlite3
import shutil
import subprocess
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
        """
    )


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
            hid = upsert_asset(conn, "hostname", host, host, {"sources": ["subfinder"], "environment": env, "environment_confidence": env_conf, "family": _family_stem(host, root_domain), "dns_state": "DISCOVERED"})
            _link_family(conn, hid, host, root_domain)
            add_evidence(conn, hid, "subfinder", "discovered_hostname", host, {"hostname": host})
            count += 1
        except Exception:
            errors += 1
    rebuild_family_heuristics(conn, root_domain)
    conn.execute("INSERT INTO recon_import_runs(source,filename,record_count,error_count,created_at) VALUES(?,?,?,?,?)", ("subfinder", filename, count, errors, _now()))
    conn.commit()
    return {"source": "subfinder", "records": count, "errors": errors}


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
    preferred = Path.home() / "go" / "bin" / name
    if preferred.exists() and preferred.is_file():
        return str(preferred)
    return shutil.which(name)


def tool_inventory() -> dict[str, dict]:
    out = {}
    for name in ("whois", "dig", "openssl", "curl", "subfinder", "dnsx", "httpx", "nmap"):
        path = _tool_path(name)
        out[name] = {"available": bool(path), "path": path or ""}
    return out


def _record_tool_run(conn: sqlite3.Connection, phase: str, tool: str, command: list[str], status: str, return_code: int | None,
                     record_count: int, stdout_path: str, stderr_path: str, error: str, started_at: str, finished_at: str) -> int:
    cur = conn.execute(
        """INSERT INTO recon_tool_runs(phase,tool,command_json,status,return_code,record_count,stdout_path,stderr_path,error,started_at,finished_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (phase, tool, json.dumps(command, ensure_ascii=False), status, return_code, record_count, stdout_path, stderr_path, error, started_at, finished_at),
    )
    return int(cur.lastrowid)


def _run_tool(conn: sqlite3.Connection, paths: dict, phase: str, tool: str, command: list[str], *, timeout: int = 180, input_text: str | None = None) -> dict:
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
        _record_tool_run(conn, phase, tool, command, status, proc.returncode, len([x for x in stdout.splitlines() if x.strip()]), str(stdout_path), str(stderr_path), error, started, _now())
        return {"status": status, "return_code": proc.returncode, "stdout": stdout, "stderr": stderr, "command": command, "error": error}
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""; stderr = exc.stderr or ""
        if isinstance(stdout, bytes): stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes): stderr = stderr.decode("utf-8", errors="replace")
        stdout_path.write_text(stdout, encoding="utf-8"); stderr_path.write_text(stderr, encoding="utf-8")
        error = f"{tool} timeout después de {timeout}s"
        _record_tool_run(conn, phase, tool, command, "error", None, 0, str(stdout_path), str(stderr_path), error, started, _now())
        return {"status": "error", "return_code": None, "stdout": stdout, "stderr": stderr, "command": command, "error": error}


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


def run_root_phase(conn: sqlite3.Connection, root_domain: str, paths: dict, timeout: int = 30) -> dict:
    init_schema(conn)
    root = root_domain.lower().rstrip(".")
    hid = upsert_asset(conn, "hostname", root, root, {"sources": ["root_recon"]})
    results = []
    dig = _tool_path("dig")
    if dig:
        for rtype in ("NS", "A", "AAAA", "MX", "TXT", "CAA"):
            run = _run_tool(conn, paths, "root", "dig", [dig, root, rtype, "+short"], timeout=timeout)
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
        run = _run_tool(conn, paths, "root", "whois", [whois, root], timeout=max(timeout, 45))
        results.append(run)
        if run["stdout"].strip(): add_evidence(conn, hid, "root_recon", "whois", None, run["stdout"][:200000])
    curl = _tool_path("curl")
    if curl:
        for scheme in ("https", "http"):
            cmd = [curl, "-skD", "-", "-o", "/dev/null", "--max-time", str(timeout), f"{scheme}://{root}/"] if scheme == "https" else [curl, "-sD", "-", "-o", "/dev/null", "--max-time", str(timeout), f"{scheme}://{root}/"]
            run = _run_tool(conn, paths, "root", "curl", cmd, timeout=timeout+5)
            results.append(run)
            if run["stdout"].strip(): add_evidence(conn, hid, "root_recon", f"http_{scheme}_headers", None, run["stdout"][:50000])
    rebuild_family_heuristics(conn, root_domain)
    conn.commit()
    ok = sum(1 for x in results if x["status"] == "ok")
    return {"phase": "root", "status": "ok" if ok else "error", "tools_ok": ok, "tools_total": len(results)}


def run_discovery_phase(conn: sqlite3.Connection, root_domain: str, paths: dict, timeout: int = 240) -> dict:
    binary = _tool_path("subfinder")
    if not binary:
        raise RuntimeError("Subfinder no está instalado o no está disponible en PATH.")
    cmd = [binary, "-d", root_domain, "-all", "-silent"]
    run = _run_tool(conn, paths, "discovery", "subfinder", cmd, timeout=timeout)
    if run["status"] != "ok": raise RuntimeError(run["error"] or "Subfinder falló")
    result = import_subfinder_text(conn, run["stdout"], root_domain, "surface-run:subfinder")
    return {"phase": "discovery", **result, "command": cmd}


def _write_target_list(paths: dict, phase: str, hosts: list[str]) -> Path:
    out_dir = Path(paths["raw"]) / "surface-runs"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"targets-{phase}.txt"
    path.write_text("\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8")
    return path


def run_dns_phase(conn: sqlite3.Connection, root_domain: str, paths: dict, timeout: int = 300) -> dict:
    binary = _tool_path("dnsx")
    if not binary: raise RuntimeError("dnsx no está instalado. Instálalo con ProjectDiscovery y verifica que esté en PATH.")
    hosts = _first_party_hostnames(conn, root_domain)
    if not hosts: raise RuntimeError("No hay hostnames descubiertos. Ejecuta primero Descubrimiento pasivo.")
    target_file = _write_target_list(paths, "dns", hosts)
    cmd = [binary, "-l", str(target_file), "-a", "-aaaa", "-cname", "-resp", "-silent"]
    run = _run_tool(conn, paths, "dns", "dnsx", cmd, timeout=timeout)
    if run["status"] != "ok": raise RuntimeError(run["error"] or "dnsx falló")
    result = import_dnsx_text(conn, run["stdout"], root_domain, "surface-run:dnsx")
    # Anything discovered but absent from dnsx remains DISCOVERED rather than being falsely marked dead.
    return {"phase": "dns", **result, "targets": len(hosts), "command": cmd}


def run_http_phase(conn: sqlite3.Connection, root_domain: str, paths: dict, timeout: int = 420) -> dict:
    binary = _tool_path("httpx")
    if not binary: raise RuntimeError("httpx de ProjectDiscovery no está instalado o no está en PATH.")
    hosts = _first_party_hostnames(conn, root_domain, resolved_only=True)
    if not hosts: raise RuntimeError("No hay hosts DNS_RESOLVED. Ejecuta primero Validación DNS.")
    target_file = _write_target_list(paths, "http", hosts)
    cmd = [binary, "-l", str(target_file), "-status-code", "-title", "-tech-detect", "-server", "-ip", "-cname", "-cdn", "-location", "-json", "-silent"]
    run = _run_tool(conn, paths, "http", "httpx", cmd, timeout=timeout)
    if run["status"] != "ok": raise RuntimeError(run["error"] or "httpx falló")
    result = import_httpx_jsonl(conn, run["stdout"], root_domain, "surface-run:httpx")
    return {"phase": "http", **result, "targets": len(hosts), "command": cmd}


def run_phase(conn: sqlite3.Connection, root_domain: str, paths: dict, phase: str) -> dict:
    phase = (phase or "").strip().lower()
    if phase == "root": return run_root_phase(conn, root_domain, paths)
    if phase == "discovery": return run_discovery_phase(conn, root_domain, paths)
    if phase == "dns": return run_dns_phase(conn, root_domain, paths)
    if phase == "http": return run_http_phase(conn, root_domain, paths)
    raise ValueError(f"Fase no soportada: {phase}")


def phase_progress(conn: sqlite3.Connection, root_domain: str) -> list[dict]:
    init_schema(conn)
    hosts = _asset_rows(conn, "hostname")
    first = [h for h in hosts if h["asset_key"] == root_domain.lower() or h["asset_key"].endswith("." + root_domain.lower())]
    discovered = len(first)
    resolved = sum(1 for h in first if (h.get("metadata") or {}).get("dns_state") == "RESOLVED")
    http = sum(1 for h in first if (h.get("metadata") or {}).get("status_code") is not None)
    root_ev = conn.execute("SELECT COUNT(*) c FROM recon_evidence WHERE source='root_recon'").fetchone()["c"]
    tooling = tool_inventory()
    phase_help = {
        "root": {
            "question": "¿Qué publica el dominio raíz y qué intermediarios aparecen antes de la aplicación?",
            "tool": "dig · whois · curl",
            "checks": ["WHOIS / registrador", "NS y DNS raíz", "A / AAAA", "MX / TXT / CAA", "Headers HTTP/HTTPS"],
            "success": "Identificar la postura inicial del dominio sin confundir edge/CDN con origin.",
        },
        "discovery": {
            "question": "¿Qué nombres conoce la superficie pública del target?",
            "tool": "subfinder",
            "checks": ["Enumerar hostnames candidatos", "Conservar fuente/evidencia", "No asumir que un nombre descubierto sigue activo"],
            "success": "Construir el inventario candidato que después será validado por DNS.",
        },
        "dns": {
            "question": "¿Cuáles nombres existen hoy y a qué infraestructura observable apuntan?",
            "tool": "dnsx",
            "checks": ["A / AAAA", "CNAME", "Separar resolved de discovered", "Conservar IP observada sin llamarla origin"],
            "success": "Reducir el inventario a nombres DNS útiles y relaciones de red observables.",
        },
        "http": {
            "question": "¿Qué hosts exponen HTTP y qué tecnologías, redirects o edge/CDN podemos observar?",
            "tool": "httpx",
            "checks": ["Status HTTP", "Title", "Servidor", "Tecnologías", "CDN / cloud", "Redirects"],
            "success": "Convertir el mapa DNS en un mapa tecnológico y operativo.",
        },
        "services": {
            "question": "¿Qué infraestructura directa merece enumeración de puertos y servicios?",
            "tool": "nmap",
            "checks": ["Excluir CDN/edge compartido", "Excluir SaaS/terceros fuera de scope", "Validar candidatos directos", "Enumerar servicios sólo con contexto"],
            "success": "Enumerar servicios sin escanear indiscriminadamente infraestructura compartida.",
        },
    }
    specs = [
        ("root", "Dominio raíz", "WHOIS · DNS · HTTP inicial", int(root_ev), True, all(tooling[x]["available"] for x in ("dig","curl"))),
        ("discovery", "Descubrimiento", "Subfinder · nombres candidatos", discovered, bool(root_ev), tooling["subfinder"]["available"]),
        ("dns", "Validar DNS", "dnsx · A / AAAA / CNAME", resolved, discovered > 0, tooling["dnsx"]["available"]),
        ("http", "Descubrir HTTP", "httpx · status / tech / CDN", http, resolved > 0, tooling["httpx"]["available"]),
        ("services", "Servicios", "Nmap · sólo candidatos directos", 0, http > 0, tooling["nmap"]["available"]),
    ]
    out=[]
    for key,title,subtitle,count,ready,tool_ok in specs:
        complete = count > 0
        state = "done" if complete else "ready" if ready and tool_ok and key != "services" else "blocked" if not ready else "planned" if key=="services" else "missing_tool"
        latest = conn.execute("SELECT * FROM recon_tool_runs WHERE phase=? ORDER BY id DESC LIMIT 1", (key,)).fetchone()
        runs = conn.execute("SELECT COUNT(*) c FROM recon_tool_runs WHERE phase=?", (key,)).fetchone()["c"]
        help_data = phase_help[key]
        out.append({
            "key":key,"title":title,"subtitle":subtitle,"count":int(count),"state":state,
            "ready":bool(ready),"tool_available":bool(tool_ok),"implemented":key!="services",
            "question": help_data["question"], "tool": help_data["tool"], "checks": help_data["checks"],
            "success": help_data["success"], "run_count": int(runs),
            "last_status": (dict(latest).get("status") if latest else None),
            "last_started_at": (dict(latest).get("started_at") if latest else None),
        })
    return out

def _asset_rows(conn: sqlite3.Connection, asset_type: str) -> list[dict]:
    out = []
    for row in conn.execute("SELECT * FROM recon_assets WHERE asset_type=? ORDER BY label COLLATE NOCASE", (asset_type,)).fetchall():
        item = dict(row)
        item["metadata"] = _loads(item.pop("metadata_json", "{}"))
        out.append(item)
    return out


def surface_data(conn: sqlite3.Connection, root_domain: str) -> dict:
    init_schema(conn)
    rebuild_family_heuristics(conn, root_domain)
    conn.commit()
    hosts = _asset_rows(conn, "hostname")
    first_party = [h for h in hosts if h["asset_key"] == root_domain.lower() or h["asset_key"].endswith("." + root_domain.lower())]
    rels = [dict(r) for r in conn.execute("SELECT * FROM recon_relationships ORDER BY id").fetchall()]
    assets_by_id = {int(r["id"]): r for typ in ("ip", "provider", "technology", "server", "hostname") for r in _asset_rows(conn, typ)}
    by_src: dict[int, list[dict]] = {}
    for r in rels:
        by_src.setdefault(int(r["src_asset_id"]), []).append(r)
    enriched = []
    for host in first_party:
        m = dict(host["metadata"])
        related = by_src.get(int(host["id"]), [])
        techs=[]; providers=[]; servers=[]; ips=[]; cnames=[]; redirects=[]; sources=set(m.get("sources") or [])
        for rel in related:
            dst = assets_by_id.get(int(rel["dst_asset_id"]))
            if not dst: continue
            rel_source = str(rel.get("source") or "")
            if rel_source and not rel_source.startswith("heuristic:"):
                sources.add(rel_source)
            if rel["relation"] == "USES" and dst["asset_type"] == "technology": techs.append(dst["label"])
            elif rel["relation"] in {"PROXIED_BY", "HOSTED_ON", "USES_PLATFORM"}: providers.append(dst["label"])
            elif rel["relation"] == "SERVED_BY": servers.append(dst["label"])
            elif rel["relation"] in {"RESOLVES_TO","OBSERVED_IP"} and dst["asset_type"] == "ip": ips.append(dst["label"])
            elif rel["relation"] == "CNAME_TO": cnames.append(dst["label"])
            elif rel["relation"] == "REDIRECTS_TO": redirects.append(dst["label"])
        item={
            "id": host["id"], "hostname": host["label"], "environment": m.get("environment") or "UNKNOWN", "family": m.get("family") or "other",
            "status_code": m.get("status_code"), "title": m.get("title"), "url": m.get("url"), "scheme": m.get("scheme"), "port": m.get("port"),
            "http_state": m.get("http_state") or "UNKNOWN", "dns_state": m.get("dns_state") or ("RESOLVED" if ips or cnames else "DISCOVERED"),
            "webserver": m.get("webserver"), "location": m.get("location"), "cdn": bool(m.get("cdn")), "cdn_name": m.get("cdn_name"),
            "technologies": list(dict.fromkeys(techs or m.get("tech") or [])), "providers": list(dict.fromkeys(providers)), "servers": list(dict.fromkeys(servers)),
            "ips": list(dict.fromkeys(ips)), "cnames": list(dict.fromkeys(cnames)), "redirects": list(dict.fromkeys(redirects)),
            "sources": sorted(x for x in sources if x), "last_seen_at": host["last_seen_at"],
        }
        enriched.append(item)
    def uniq(field):
        vals=[]
        for h in enriched:
            v=h.get(field)
            vals.extend(v if isinstance(v,list) else [v] if v not in (None,"") else [])
        return sorted(set(str(x) for x in vals if str(x)))
    status = sorted(set(str(h["status_code"]) for h in enriched if h.get("status_code") is not None))
    family_counts: dict[str, int] = {}
    for h in enriched:
        fam = str(h.get("family") or "other")
        family_counts[fam] = family_counts.get(fam, 0) + 1
    grouped_families = sorted(f for f, count in family_counts.items() if count > 1)
    phases = phase_progress(conn, root_domain)
    done_count = sum(1 for p in phases if p.get("state") == "done")
    total_count = len(phases)
    next_phase = next((p for p in phases if p.get("state") in {"ready", "planned", "missing_tool"}), None)
    return {
        "root_domain": root_domain,
        "hosts": enriched,
        "filters": {"technologies": uniq("technologies"), "providers": uniq("providers"), "servers": uniq("servers"), "environments": uniq("environment"), "families": uniq("family"), "sources": uniq("sources"), "statuses": status},
        "summary": {"hosts": len(enriched), "http_alive": sum(1 for h in enriched if h.get("status_code") is not None), "technologies": len(uniq("technologies")), "providers": len(uniq("providers")), "families": len(grouped_families)},
        "imports": [dict(r) for r in conn.execute("SELECT * FROM recon_import_runs ORDER BY id DESC LIMIT 20").fetchall()],
        "tool_runs": [dict(r) for r in conn.execute("SELECT * FROM recon_tool_runs ORDER BY id DESC LIMIT 30").fetchall()],
        "phases": phases,
        "phase_summary": {"done": done_count, "total": total_count, "percent": int(round((done_count / total_count) * 100)) if total_count else 0, "next": next_phase},
        "tooling": tool_inventory(),
    }
