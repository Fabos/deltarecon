#!/usr/bin/env python3
"""
Negro Recon v0.8.1
"Olfatea donde otros no miran."

Passive-first Bug Bounty reconnaissance organizer.

Automated discovery sources:
  - crt.sh
  - Subfinder
  - Amass passive (v5-friendly workflow)
  - GAU providers: OTX, URLScan, Wayback, Common Crawl

Core model:
  SOURCE -> RAW -> NORMALIZED -> DELTA -> INVENTORY -> SQLITE GRAPH
  HOST -> BASIC TRIAGE -> REVIEW/CLASSIFICATION

Negro does NOT perform port scanning, brute force, directory fuzzing,
vulnerability scanning, exploitation, or credential attacks.
Basic host inspection is single-host and low-impact: DNS, TLS and one HTTP/HTTPS request.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

VERSION = "0.8.1"
CONFIG_PATH = Path.home() / ".config" / "negro" / "config.json"
TARGETS_PATH = Path.home() / ".config" / "negro" / "targets.json"

HOST_SOURCE_ORDER = [
    "crtsh",
    "subfinder",
    "amass",
    "gau_otx",
    "gau_urlscan",
    "gau_wayback",
    "gau_commoncrawl",
    "wayback_cdx",
    "urlscan_direct",
    "securitytrails",
    "tls_san",
    "github_code",
    "js_discovery",
    "js_local",
    "sourcemap",
]

GAU_PROVIDERS = {
    "otx": "gau_otx",
    "urlscan": "gau_urlscan",
    "wayback": "gau_wayback",
    "commoncrawl": "gau_commoncrawl",
}

CLASSIFICATIONS = ["unknown", "informational", "lead", "discarded", "finding"]
REVIEW_STATES = ["pending", "in_progress", "reviewed"]
PRIORITIES = ["none", "low", "medium", "high"]

SOURCE_INFO = {
    "crtsh": ("AUTOMATIZADA", "Certificate Transparency", "Nombres observados en certificados TLS públicos."),
    "subfinder": ("AUTOMATIZADA", "Subfinder passive", "Agregador rápido de múltiples fuentes pasivas."),
    "amass": ("AUTOMATIZADA", "Amass passive", "Correlación OSINT/asset graph; en Kali v5 se usa el binario real."),
    "gau_otx": ("AUTOMATIZADA", "GAU / OTX", "URLs históricas/observadas por AlienVault OTX."),
    "gau_urlscan": ("AUTOMATIZADA", "GAU / URLScan", "URLs observadas en navegaciones públicas de URLScan."),
    "gau_wayback": ("AUTOMATIZADA", "GAU / Wayback", "URLs históricas de Internet Archive; puede sufrir timeouts."),
    "gau_commoncrawl": ("AUTOMATIZADA", "GAU / Common Crawl", "URLs históricas de Common Crawl; puede sufrir timeouts."),
    "wayback_cdx": ("AUTOMATIZADA", "Wayback CDX direct", "Capturas históricas con timestamp/status/MIME, independiente de GAU."),
    "urlscan_direct": ("AUTOMATIZADA", "URLScan direct", "Scans históricos y requests observados públicamente."),
    "securitytrails": ("OPCIONAL", "SecurityTrails passive DNS", "Subdominios y DNS histórico; requiere API key."),
    "tls_san": ("AUTOMATIZADA", "TLS SAN pivot", "Importa SANs in-scope del certificado de un host seleccionado."),
    "github_code": ("OPCIONAL", "GitHub public code search", "Fragmentos públicos que referencian el dominio; requiere token."),
    "js_discovery": ("DIRIGIDA", "JavaScript discovery", "Scripts cargados por un host seleccionado."),
    "js_local": ("DIRIGIDA", "JavaScript local analysis", "Endpoints, URLs, source maps y señales extraídas localmente."),
    "sourcemap": ("DIRIGIDA", "Source maps", "Sources/sourcesContent públicos y endpoints derivados."),
    "ai_js": ("OPCIONAL", "AI JavaScript analysis", "Analiza sólo evidencia/chunks relevantes; requiere OPENAI_API_KEY."),
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def banner() -> None:
    print(r"""
 _   _
| \ | | ___  __ _ _ __ ___
|  \| |/ _ \/ _` | '__/ _ \
| |\  |  __/ (_| | | | (_) |
|_| \_|\___|\__, |_|  \___/
            |___/
""")
    print(f"Negro Recon v{VERSION} — olfatea donde otros no miran.\n")


def normalize_host(host: str, domain: str) -> str | None:
    host = host.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    domain = domain.strip().lower().rstrip(".")
    if host == domain or host.endswith("." + domain):
        return host
    return None


def normalize_hosts(hosts: Iterable[str], domain: str) -> list[str]:
    values = set()
    for host in hosts:
        value = normalize_host(host, domain)
        if value:
            values.add(value)
    return sorted(values)


def write_lines(path: Path, lines: Iterable[str]) -> None:
    values = sorted(set(x for x in lines if x))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(("\n".join(values) + "\n") if values else "", encoding="utf-8")


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [x.strip() for x in path.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]


def workspace_paths(workspace: Path) -> dict[str, Path]:
    return {
        "root": workspace,
        "raw": workspace / "raw",
        "normalized": workspace / "normalized",
        "delta": workspace / "delta",
        "inventory": workspace / "inventory",
        "notes": workspace / "notes",
        "inventory_file": workspace / "inventory" / "all-hosts.txt",
        "provenance_file": workspace / "inventory" / "provenance.json",
        "state_file": workspace / "inventory" / "state.json",
        "db_file": workspace / "inventory" / "negro.db",
    }


def db_connect(paths: dict[str, Path]) -> sqlite3.Connection:
    conn = sqlite3.connect(paths["db_file"])
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(paths: dict[str, Path], domain: str) -> None:
    with db_connect(paths) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL UNIQUE,
                review_state TEXT NOT NULL DEFAULT 'pending',
                classification TEXT NOT NULL DEFAULT 'unknown',
                priority TEXT NOT NULL DEFAULT 'none',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS host_sources (
                host_id INTEGER NOT NULL,
                source TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                PRIMARY KEY (host_id, source),
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS resources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                url TEXT NOT NULL UNIQUE,
                scheme TEXT,
                path TEXT NOT NULL,
                query TEXT,
                review_state TEXT NOT NULL DEFAULT 'pending',
                classification TEXT NOT NULL DEFAULT 'unknown',
                priority TEXT NOT NULL DEFAULT 'none',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS resource_sources (
                resource_id INTEGER NOT NULL,
                source TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                PRIMARY KEY (resource_id, source),
                FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type TEXT NOT NULL,
                entity_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                status TEXT NOT NULL,
                result_count INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS host_inspections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                observed_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type TEXT NOT NULL,
                entity_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type TEXT NOT NULL,
                entity_id INTEGER NOT NULL,
                source TEXT NOT NULL,
                kind TEXT NOT NULL,
                value TEXT,
                payload_json TEXT,
                observed_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS js_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                url TEXT NOT NULL UNIQUE,
                source TEXT NOT NULL,
                size_bytes INTEGER,
                sha256 TEXT,
                local_path TEXT,
                sourcemap_url TEXT,
                local_analysis_json TEXT,
                sourcemap_analysis_json TEXT,
                sourcemap_path TEXT,
                sourcemap_analyzed_at TEXT,
                discovered_at TEXT NOT NULL,
                analyzed_at TEXT,
                FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS ai_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                js_asset_id INTEGER NOT NULL,
                model TEXT NOT NULL,
                status TEXT NOT NULL,
                estimate_json TEXT,
                usage_json TEXT,
                result_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(js_asset_id) REFERENCES js_assets(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_events_entity ON events(entity_type, entity_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_inspections_host ON host_inspections(host_id, observed_at);
            CREATE INDEX IF NOT EXISTS idx_resources_host ON resources(host_id);
            CREATE INDEX IF NOT EXISTS idx_hosts_review ON hosts(review_state, classification);
            CREATE INDEX IF NOT EXISTS idx_resources_review ON resources(review_state, classification);
            CREATE INDEX IF NOT EXISTS idx_observations_entity ON observations(entity_type, entity_id, observed_at);
            CREATE INDEX IF NOT EXISTS idx_js_assets_host ON js_assets(host_id, discovered_at);
            CREATE INDEX IF NOT EXISTS idx_ai_asset ON ai_analyses(js_asset_id, created_at);
            """
        )
        # Conservative schema migration for workspaces created by v0.3/v0.4.
        host_cols = {row["name"] for row in conn.execute("PRAGMA table_info(hosts)")}
        resource_cols = {row["name"] for row in conn.execute("PRAGMA table_info(resources)")}
        if "priority" not in host_cols:
            conn.execute("ALTER TABLE hosts ADD COLUMN priority TEXT NOT NULL DEFAULT 'none'")
        if "priority" not in resource_cols:
            conn.execute("ALTER TABLE resources ADD COLUMN priority TEXT NOT NULL DEFAULT 'none'")
        js_cols = {row["name"] for row in conn.execute("PRAGMA table_info(js_assets)")}
        if "sourcemap_analysis_json" not in js_cols:
            conn.execute("ALTER TABLE js_assets ADD COLUMN sourcemap_analysis_json TEXT")
        if "sourcemap_path" not in js_cols:
            conn.execute("ALTER TABLE js_assets ADD COLUMN sourcemap_path TEXT")
        if "sourcemap_analyzed_at" not in js_cols:
            conn.execute("ALTER TABLE js_assets ADD COLUMN sourcemap_analyzed_at TEXT")

        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('domain', ?)", (domain,))
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('version', ?)", (VERSION,))


def ensure_workspace(workspace: Path, domain: str) -> dict[str, Path]:
    paths = workspace_paths(workspace)
    for key in ("raw", "normalized", "delta", "inventory", "notes"):
        paths[key].mkdir(parents=True, exist_ok=True)

    if paths["state_file"].exists():
        state = json.loads(paths["state_file"].read_text(encoding="utf-8"))
        existing_domain = state.get("domain")
        if existing_domain and existing_domain != domain:
            raise RuntimeError(f"Este workspace pertenece a {existing_domain}, no a {domain}")
    else:
        state = {"domain": domain, "version": VERSION}

    state["version"] = VERSION
    paths["state_file"].write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

    if not paths["inventory_file"].exists():
        paths["inventory_file"].write_text("", encoding="utf-8")
    if not paths["provenance_file"].exists():
        paths["provenance_file"].write_text("{}\n", encoding="utf-8")

    init_db(paths, domain)
    migrate_existing_workspace(paths, domain)
    return paths


def source_host_file(paths: dict[str, Path], source: str) -> Path:
    if source.startswith("gau_"):
        return paths["normalized"] / f"{source}-hosts.txt"
    return paths["normalized"] / f"{source}.txt"


def source_url_file(paths: dict[str, Path], source: str) -> Path:
    return paths["normalized"] / f"{source}-urls.txt"


def upsert_host(conn: sqlite3.Connection, hostname: str, source: str) -> tuple[int, bool]:
    ts = now_iso()
    cur = conn.execute(
        "INSERT OR IGNORE INTO hosts(hostname, created_at, updated_at) VALUES(?, ?, ?)",
        (hostname, ts, ts),
    )
    created = cur.rowcount == 1
    row = conn.execute("SELECT id FROM hosts WHERE hostname = ?", (hostname,)).fetchone()
    host_id = int(row["id"])
    conn.execute(
        "INSERT OR IGNORE INTO host_sources(host_id, source, first_seen_at) VALUES(?, ?, ?)",
        (host_id, source, ts),
    )
    return host_id, created


def canonicalize_url(raw_url: str, domain: str) -> tuple[str, str, str, str, str] | None:
    raw_url = raw_url.strip()
    if not raw_url:
        return None
    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except ValueError:
        return None
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return None
    host = normalize_host(parsed.hostname, domain)
    if not host:
        return None
    scheme = parsed.scheme.lower()
    netloc = host
    if parsed.port:
        netloc = f"{host}:{parsed.port}"
    path = parsed.path or "/"
    query = parsed.query or ""
    canonical = urllib.parse.urlunsplit((scheme, netloc, path, query, ""))
    return canonical, host, scheme, path, query


def upsert_resource(conn: sqlite3.Connection, raw_url: str, source: str, domain: str) -> tuple[bool, bool]:
    normalized = canonicalize_url(raw_url, domain)
    if not normalized:
        return False, False
    url, host, scheme, path, query = normalized
    host_id, host_created = upsert_host(conn, host, source)
    ts = now_iso()
    cur = conn.execute(
        """
        INSERT OR IGNORE INTO resources(host_id, url, scheme, path, query, created_at, updated_at)
        VALUES(?, ?, ?, ?, ?, ?, ?)
        """,
        (host_id, url, scheme, path, query, ts, ts),
    )
    resource_created = cur.rowcount == 1
    row = conn.execute("SELECT id FROM resources WHERE url = ?", (url,)).fetchone()
    resource_id = int(row["id"])
    conn.execute(
        "INSERT OR IGNORE INTO resource_sources(resource_id, source, first_seen_at) VALUES(?, ?, ?)",
        (resource_id, source, ts),
    )
    return host_created, resource_created


def migrate_existing_workspace(paths: dict[str, Path], domain: str) -> None:
    """Importa inventarios v0.2 sin borrar ni alterar estados/notas existentes."""
    imported = set()
    with db_connect(paths) as conn:
        for source in HOST_SOURCE_ORDER:
            path = source_host_file(paths, source)
            if path.exists():
                for host in normalize_hosts(read_lines(path), domain):
                    upsert_host(conn, host, source)
                    imported.add(host)

            if source.startswith("gau_") or source in {"wayback_cdx", "urlscan_direct", "github_code", "js_local", "sourcemap"}:
                url_path = source_url_file(paths, source)
                if url_path.exists():
                    for url in read_lines(url_path):
                        upsert_resource(conn, url, source, domain)

        for host in normalize_hosts(read_lines(paths["inventory_file"]), domain):
            if host not in imported:
                upsert_host(conn, host, "legacy_inventory")


def rebuild_inventory(paths: dict[str, Path], domain: str) -> tuple[int, dict[str, int]]:
    source_sets: dict[str, set[str]] = {}
    for source in HOST_SOURCE_ORDER:
        source_sets[source] = set(normalize_hosts(read_lines(source_host_file(paths, source)), domain))

    seen: set[str] = set()
    counts: dict[str, int] = {}
    provenance: dict[str, dict] = {}

    for source in HOST_SOURCE_ORDER:
        current = source_sets[source]
        new_hosts = sorted(current - seen)
        write_lines(paths["delta"] / f"{source}-new.txt", new_hosts)
        counts[source] = len(new_hosts)
        seen |= current

    # Preserve legacy hosts that do not have a source-specific file yet.
    legacy = set(normalize_hosts(read_lines(paths["inventory_file"]), domain))
    seen |= legacy

    db_source_map: dict[str, set[str]] = {}
    with db_connect(paths) as conn:
        db_hosts = {row["hostname"] for row in conn.execute("SELECT hostname FROM hosts")}
        for row in conn.execute("SELECT h.hostname, hs.source FROM host_sources hs JOIN hosts h ON h.id=hs.host_id"):
            db_source_map.setdefault(row["hostname"], set()).add(row["source"])
    seen |= db_hosts

    for host in sorted(seen):
        sources = {source for source in HOST_SOURCE_ORDER if host in source_sets[source]}
        sources |= db_source_map.get(host, set())
        provenance[host] = {"sources": sorted(sources)}

    write_lines(paths["inventory_file"], seen)
    paths["provenance_file"].write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return len(seen), counts


def log_run(paths: dict[str, Path], source: str, status: str, count: int, error: str | None, started: str) -> None:
    with db_connect(paths) as conn:
        conn.execute(
            "INSERT INTO runs(source, status, result_count, error, started_at, finished_at) VALUES(?, ?, ?, ?, ?, ?)",
            (source, status, count, error, started, now_iso()),
        )


def fetch_crtsh(domain: str, paths: dict[str, Path], timeout: int) -> list[str]:
    query = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={query}&output=json"
    request = urllib.request.Request(url, headers={"User-Agent": f"Negro-Recon/{VERSION}"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
    (paths["raw"] / "crtsh.json").write_bytes(raw)
    data = json.loads(raw.decode("utf-8"))
    hosts: list[str] = []
    for entry in data:
        for field in ("name_value", "common_name"):
            value = entry.get(field)
            if isinstance(value, str):
                hosts.extend(value.splitlines())
    return normalize_hosts(hosts, domain)


def run_subfinder(domain: str, paths: dict[str, Path], timeout: int) -> list[str]:
    binary = shutil.which("subfinder")
    if not binary:
        raise RuntimeError("Subfinder no está instalado o no está disponible en PATH.")
    result = subprocess.run(
        [binary, "-d", domain, "-silent", "-all"],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    (paths["raw"] / "subfinder.txt").write_text(result.stdout, encoding="utf-8")
    (paths["raw"] / "subfinder.stderr.txt").write_text(result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(f"Subfinder terminó con código {result.returncode}.")
    return normalize_hosts(result.stdout.splitlines(), domain)


def find_amass() -> str | None:
    # Kali 2026 ships /usr/bin/amass as a wrapper that may fail on libpostal_data.
    real = Path("/usr/lib/amass/amass")
    if real.exists() and real.is_file():
        return str(real)
    return shutil.which("amass")


def run_amass(domain: str, paths: dict[str, Path], timeout: int) -> list[str]:
    binary = find_amass()
    if not binary:
        raise RuntimeError("OWASP Amass no está instalado.")

    enum = subprocess.run(
        [binary, "enum", "-passive", "-d", domain],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    (paths["raw"] / "amass-enum.txt").write_text(enum.stdout, encoding="utf-8")
    (paths["raw"] / "amass-enum.stderr.txt").write_text(enum.stderr, encoding="utf-8")
    if enum.returncode != 0:
        raise RuntimeError(f"Amass enum terminó con código {enum.returncode}.")

    subs = subprocess.run(
        [binary, "subs", "-d", domain, "-names"],
        capture_output=True,
        text=True,
        timeout=min(timeout, 600) if timeout else None,
        check=False,
    )
    (paths["raw"] / "amass-subs.txt").write_text(subs.stdout, encoding="utf-8")
    (paths["raw"] / "amass-subs.stderr.txt").write_text(subs.stderr, encoding="utf-8")

    candidates = subs.stdout.splitlines() if subs.returncode == 0 and subs.stdout.strip() else enum.stdout.splitlines()
    return normalize_hosts(candidates, domain)


def find_gau() -> str | None:
    preferred = Path.home() / "go" / "bin" / "gau"
    if preferred.exists() and preferred.is_file():
        return str(preferred)
    binary = shutil.which("gau")
    if binary:
        return binary
    # Kali package fallback. Modern ~/go/bin/gau is preferred because Kali's
    # getallurls package can be old and provider APIs may have changed.
    return shutil.which("getallurls")


def run_gau(domain: str, provider: str, paths: dict[str, Path], timeout: int) -> tuple[list[str], str, str | None]:
    binary = find_gau()
    if not binary:
        raise RuntimeError("GAU no está instalado. Instala github.com/lc/gau/v2/cmd/gau@latest.")

    modern = Path(binary).name == "gau"
    if modern:
        command = [binary, "--subs", "--providers", provider, domain]
    else:
        command = [binary, "-subs", "-providers", provider, domain]

    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    source = GAU_PROVIDERS[provider]
    (paths["raw"] / f"{source}.txt").write_text(result.stdout, encoding="utf-8")
    (paths["raw"] / f"{source}.stderr.txt").write_text(result.stderr, encoding="utf-8")

    urls = sorted(set(x.strip() for x in result.stdout.splitlines() if x.strip().startswith(("http://", "https://"))))
    stderr_lower = result.stderr.lower()
    errorish = any(token in stderr_lower for token in ("timeout", "failed to fetch", "error instantiating", "connection refused", "tls handshake"))

    if result.returncode != 0:
        return urls, "error", f"GAU terminó con código {result.returncode}: {result.stderr.strip()[:500]}"
    if not urls and errorish:
        return [], "error", result.stderr.strip()[:500]
    if not urls:
        return [], "empty", None
    return urls, "ok", None


def persist_host_source(source: str, hosts: list[str], domain: str, paths: dict[str, Path]) -> tuple[int, int]:
    write_lines(source_host_file(paths, source), hosts)
    new_db = 0
    with db_connect(paths) as conn:
        for host in hosts:
            _, created = upsert_host(conn, host, source)
            new_db += int(created)
    total, counts = rebuild_inventory(paths, domain)
    return total, counts.get(source, 0)


def collect_source(source: str, domain: str, paths: dict[str, Path], timeout: int) -> None:
    started = now_iso()
    try:
        if source == "crtsh":
            print("[*] Consultando crt.sh...")
            hosts = fetch_crtsh(domain, paths, timeout)
        elif source == "subfinder":
            print("[*] Ejecutando Subfinder passive...")
            hosts = run_subfinder(domain, paths, timeout)
        elif source == "amass":
            print("[*] Ejecutando Amass passive. Puede tardar bastante...")
            hosts = run_amass(domain, paths, timeout)
        elif source.startswith("gau_"):
            provider = source.removeprefix("gau_")
            collect_gau_provider(provider, domain, paths, timeout)
            return
        else:
            raise RuntimeError(f"Fuente no soportada: {source}")

        total, delta_count = persist_host_source(source, hosts, domain, paths)
        log_run(paths, source, "ok" if hosts else "empty", len(hosts), None, started)
        print(f"[+] {source}: {len(hosts)} hosts normalizados")
        print(f"[+] Delta lógico {source}: {delta_count}")
        print(f"[+] Inventario total: {total}")
    except Exception as exc:
        log_run(paths, source, "error", 0, str(exc), started)
        raise


def collect_gau_provider(provider: str, domain: str, paths: dict[str, Path], timeout: int) -> None:
    if provider not in GAU_PROVIDERS:
        raise RuntimeError(f"Provider GAU inválido: {provider}")
    source = GAU_PROVIDERS[provider]
    started = now_iso()
    print(f"[*] Ejecutando GAU provider={provider}...")
    try:
        urls, status, error = run_gau(domain, provider, paths, timeout)
        if status == "error":
            log_run(paths, source, status, 0, error, started)
            print(f"[!] {source}: ERROR — {error}")
            return

        normalized_urls: list[str] = []
        hosts: set[str] = set()
        new_resources = 0
        new_hosts = 0
        with db_connect(paths) as conn:
            for raw_url in urls:
                parsed = canonicalize_url(raw_url, domain)
                if not parsed:
                    continue
                canonical, host, _, _, _ = parsed
                normalized_urls.append(canonical)
                host_created, resource_created = upsert_resource(conn, canonical, source, domain)
                hosts.add(host)
                new_hosts += int(host_created)
                new_resources += int(resource_created)

        write_lines(source_url_file(paths, source), normalized_urls)
        write_lines(source_host_file(paths, source), hosts)
        total, counts = rebuild_inventory(paths, domain)
        log_run(paths, source, status, len(normalized_urls), error, started)

        print(f"[+] {source}: {len(normalized_urls)} URLs normalizadas")
        print(f"[+] Hosts extraídos: {len(hosts)}")
        print(f"[+] Hosts nuevos en DB en esta ejecución: {new_hosts}")
        print(f"[+] Recursos nuevos en DB: {new_resources}")
        print(f"[+] Delta lógico de hosts: {counts.get(source, 0)}")
        print(f"[+] Inventario total: {total}")
    except Exception as exc:
        log_run(paths, source, "error", 0, str(exc), started)
        raise


def command_exists(name: str) -> str | None:
    return shutil.which(name)


def run_capture(command: list[str], timeout: int, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def inspect_dns(hostname: str, timeout: int = 15) -> dict:
    dig = command_exists("dig")
    if not dig:
        return {"error": "dig no está instalado o no está en PATH"}

    result: dict[str, object] = {}
    for record in ("A", "AAAA", "CNAME"):
        try:
            proc = run_capture([dig, "+short", hostname, record], timeout)
            values = []
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    value = line.strip()
                    if value:
                        values.append(value.rstrip(".") if record == "CNAME" else value)
            result[record.lower()] = sorted(set(values))
            if proc.returncode != 0:
                result[f"{record.lower()}_error"] = proc.stderr.strip() or f"dig rc={proc.returncode}"
        except subprocess.TimeoutExpired:
            result[f"{record.lower()}_error"] = "timeout"
    return result


def inspect_tls(hostname: str, timeout: int = 20) -> dict:
    openssl = command_exists("openssl")
    if not openssl:
        return {"status": "error", "error": "openssl no está instalado o no está en PATH"}

    try:
        proc = run_capture(
            [openssl, "s_client", "-connect", f"{hostname}:443", "-servername", hostname, "-showcerts"],
            timeout,
            input_text="",
        )
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "TLS timeout"}

    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if "BEGIN CERTIFICATE" not in proc.stdout:
        compact = " ".join(x.strip() for x in combined.splitlines() if x.strip())
        return {
            "status": "error",
            "error": compact[:1200] or f"openssl s_client rc={proc.returncode}",
        }

    try:
        cert = run_capture(
            [openssl, "x509", "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"],
            timeout,
            input_text=proc.stdout,
        )
    except subprocess.TimeoutExpired:
        return {"status": "partial", "error": "x509 parse timeout"}

    fields: dict[str, object] = {"status": "ok" if cert.returncode == 0 else "partial"}
    sans: list[str] = []
    for line in cert.stdout.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith("subject="):
            fields["subject"] = stripped.split("=", 1)[1].strip()
        elif lower.startswith("issuer="):
            fields["issuer"] = stripped.split("=", 1)[1].strip()
        elif lower.startswith("notbefore="):
            fields["not_before"] = stripped.split("=", 1)[1].strip()
        elif lower.startswith("notafter="):
            fields["not_after"] = stripped.split("=", 1)[1].strip()
        elif "DNS:" in stripped:
            for part in stripped.split(","):
                part = part.strip()
                if part.startswith("DNS:"):
                    sans.append(part[4:].strip())
    fields["sans"] = sans
    if cert.returncode != 0:
        fields["error"] = cert.stderr.strip()[:1000]
    return fields


def parse_curl_headers(raw: str) -> dict:
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in raw.replace("\r\n", "\n").split("\n"):
        if line.startswith("HTTP/"):
            if current:
                blocks.append(current)
            current = [line]
        elif current:
            if line == "":
                blocks.append(current)
                current = []
            else:
                current.append(line)
    if current:
        blocks.append(current)

    if not blocks:
        return {}

    block = blocks[-1]
    status_line = block[0]
    parts = status_line.split(None, 2)
    out: dict[str, object] = {"status_line": status_line}
    if len(parts) >= 2 and parts[1].isdigit():
        out["status"] = int(parts[1])

    headers: dict[str, str] = {}
    for line in block[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    for key in ("server", "location", "content-type", "via", "x-powered-by"):
        if key in headers:
            out[key.replace("-", "_")] = headers[key]
    return out


def inspect_http(hostname: str, scheme: str, timeout: int = 15) -> dict:
    curl = command_exists("curl")
    if not curl:
        return {"status": "error", "error": "curl no está instalado o no está en PATH"}

    command = [
        curl,
        "-sS",
        "-o", "/dev/null",
        "-D", "-",
        "--max-time", str(timeout),
        "--connect-timeout", str(min(timeout, 10)),
        "-A", f"Negro-Recon/{VERSION}",
    ]
    if scheme == "https":
        # Inspection only: keep the certificate mismatch visible in TLS results,
        # but allow one HTTPS request so the researcher can see the application response.
        command.append("-k")
    command.append(f"{scheme}://{hostname}/")

    try:
        proc = run_capture(command, timeout + 5)
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": f"{scheme.upper()} timeout"}

    parsed = parse_curl_headers(proc.stdout)
    if proc.returncode != 0:
        parsed["error"] = proc.stderr.strip()[:1000] or f"curl rc={proc.returncode}"
    if not parsed and proc.returncode == 0:
        parsed["error"] = "No se recibieron headers HTTP parseables"
    return parsed


def save_inspection(paths: dict[str, Path], host_id: int, hostname: str, payload: dict) -> Path:
    ts = payload["observed_at"]
    safe_ts = ts.replace(":", "-").replace("+", "_")
    out_dir = paths["raw"] / "inspect" / hostname
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{safe_ts}.json"
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    with db_connect(paths) as conn:
        conn.execute(
            "INSERT INTO host_inspections(host_id, observed_at, payload_json) VALUES(?, ?, ?)",
            (host_id, ts, json.dumps(payload, ensure_ascii=False)),
        )
    return out_path


def print_inspection(payload: dict) -> None:
    print("\nBASIC TRIAGE")
    print(f"Host: {payload['hostname']}")
    print(f"Observed: {payload['observed_at']}")
    print("-" * 72)

    dns = payload.get("dns", {})
    print("DNS")
    print(f"  A:     {', '.join(dns.get('a', [])) or '-'}")
    print(f"  AAAA:  {', '.join(dns.get('aaaa', [])) or '-'}")
    print(f"  CNAME: {', '.join(dns.get('cname', [])) or '-'}")
    for key in ("a_error", "aaaa_error", "cname_error"):
        if dns.get(key):
            print(f"  {key}: {dns[key]}")

    tls = payload.get("tls", {})
    print("TLS :443")
    print(f"  status:  {tls.get('status', '-')}")
    if tls.get("subject"):
        print(f"  subject: {tls['subject']}")
    if tls.get("issuer"):
        print(f"  issuer:  {tls['issuer']}")
    if tls.get("not_before") or tls.get("not_after"):
        print(f"  dates:   {tls.get('not_before', '-')} -> {tls.get('not_after', '-')}")
    if tls.get("sans"):
        shown = tls["sans"][:12]
        print(f"  SAN:     {', '.join(shown)}" + (" ..." if len(tls["sans"]) > 12 else ""))
    if tls.get("error"):
        print(f"  error:   {tls['error'][:300]}")

    for scheme in ("http", "https"):
        data = payload.get(scheme, {})
        print(scheme.upper())
        if isinstance(data.get("status"), int):
            print(f"  status:   {data['status']}")
        elif data.get("status_line"):
            print(f"  status:   {data['status_line']}")
        else:
            print("  status:   -")
        for key in ("server", "location", "content_type", "via", "x_powered_by"):
            if data.get(key):
                print(f"  {key}: {data[key]}")
        if data.get("error"):
            print(f"  error:    {data['error'][:300]}")
    print()


def inspect_host(domain: str, paths: dict[str, Path], hostname: str, timeout: int = 20) -> dict:
    hostname = hostname.strip().lower().rstrip(".")
    normalized = normalize_host(hostname, domain)
    if not normalized:
        raise RuntimeError(f"{hostname} no pertenece al target {domain}")

    with db_connect(paths) as conn:
        host_id, created = upsert_host(conn, hostname, "manual_inspect")
    if created:
        rebuild_inventory(paths, domain)
        print(f"[+] Host nuevo agregado al inventario desde inspección manual: {hostname}")

    payload = {
        "hostname": hostname,
        "observed_at": now_iso(),
        "dns": inspect_dns(hostname, min(timeout, 20)),
        "tls": inspect_tls(hostname, max(timeout, 20)),
        "http": inspect_http(hostname, "http", min(timeout, 20)),
        "https": inspect_http(hostname, "https", min(timeout, 20)),
    }
    out_path = save_inspection(paths, host_id, hostname, payload)
    print_inspection(payload)
    print(f"[+] Snapshot guardado: {out_path}")
    print("[i] La inspección NO marca el host como reviewed automáticamente.")
    return payload



def record_observation(conn: sqlite3.Connection, entity_type: str, entity_id: int, source: str, kind: str, value: str | None = None, payload: dict | list | None = None) -> None:
    conn.execute(
        "INSERT INTO observations(entity_type, entity_id, source, kind, value, payload_json, observed_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
        (entity_type, entity_id, source, kind, value, json.dumps(payload, ensure_ascii=False) if payload is not None else None, now_iso()),
    )


def _persist_url_list(domain: str, paths: dict[str, Path], source: str, urls: Iterable[str]) -> tuple[int, int, int]:
    normalized_urls: list[str] = []
    hosts: set[str] = set()
    new_hosts = 0
    new_resources = 0
    with db_connect(paths) as conn:
        for raw_url in urls:
            parsed = canonicalize_url(str(raw_url), domain)
            if not parsed:
                continue
            canonical, host, _, _, _ = parsed
            normalized_urls.append(canonical)
            host_created, resource_created = upsert_resource(conn, canonical, source, domain)
            hosts.add(host)
            new_hosts += int(host_created)
            new_resources += int(resource_created)
    write_lines(source_url_file(paths, source), normalized_urls)
    write_lines(source_host_file(paths, source), hosts)
    total, _ = rebuild_inventory(paths, domain)
    return new_hosts, new_resources, total


def collect_wayback_cdx(domain: str, paths: dict[str, Path], timeout: int = 60) -> dict:
    import negro_intel as intel
    source = "wayback_cdx"
    started = now_iso()
    try:
        settings = intel.load_settings()
        result = intel.wayback_cdx(domain, limit=int(settings.get("wayback_limit", 5000)), timeout=timeout)
        raw_path = paths["raw"] / "wayback-cdx.json"
        raw_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        urls = [c.get("original") for c in result.get("captures", []) if isinstance(c, dict) and c.get("original")]
        new_hosts, new_resources, total = _persist_url_list(domain, paths, source, urls)
        # Capture metadata is retained as observations on matching resources.
        with db_connect(paths) as conn:
            for capture in result.get("captures", [])[:20000]:
                if not isinstance(capture, dict):
                    continue
                parsed = canonicalize_url(str(capture.get("original", "")), domain)
                if not parsed:
                    continue
                row = conn.execute("SELECT id FROM resources WHERE url=?", (parsed[0],)).fetchone()
                if row:
                    record_observation(conn, "resource", int(row["id"]), source, "wayback_capture", str(capture.get("timestamp", "")), capture)
        log_run(paths, source, "ok" if urls else "empty", len(urls), None, started)
        return {"source": source, "captures": len(urls), "new_hosts": new_hosts, "new_resources": new_resources, "inventory": total, "raw": str(raw_path)}
    except Exception as exc:
        log_run(paths, source, "error", 0, str(exc), started)
        raise


def collect_urlscan_direct(domain: str, paths: dict[str, Path], timeout: int = 45) -> dict:
    import negro_intel as intel
    source = "urlscan_direct"
    started = now_iso()
    try:
        settings = intel.load_settings()
        result = intel.urlscan_direct(domain, detail_limit=int(settings.get("urlscan_detail_limit", 8)), timeout=timeout)
        raw_path = paths["raw"] / "urlscan-direct.json"
        raw_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        urls = result.get("urls", []) if isinstance(result, dict) else []
        new_hosts, new_resources, total = _persist_url_list(domain, paths, source, urls)
        with db_connect(paths) as conn:
            root_id, _ = upsert_host(conn, domain, source)
            for scan in result.get("scans", [])[:100] if isinstance(result, dict) else []:
                if isinstance(scan, dict):
                    record_observation(conn, "host", root_id, source, "urlscan_scan", str(scan.get("id", "")), scan)
        log_run(paths, source, "ok" if urls else "empty", len(urls), None, started)
        return {"source": source, "urls": len(urls), "new_hosts": new_hosts, "new_resources": new_resources, "inventory": total, "authenticated": result.get("authenticated"), "raw": str(raw_path)}
    except Exception as exc:
        log_run(paths, source, "error", 0, str(exc), started)
        raise


def collect_securitytrails(domain: str, paths: dict[str, Path], timeout: int = 40) -> dict:
    import negro_intel as intel
    source = "securitytrails"
    started = now_iso()
    try:
        result = intel.securitytrails_subdomains(domain, timeout=timeout)
        raw_path = paths["raw"] / "securitytrails-subdomains.json"
        raw_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        hosts = normalize_hosts(result.get("hosts", []), domain)
        total, delta_count = persist_host_source(source, hosts, domain, paths)
        log_run(paths, source, "ok" if hosts else "empty", len(hosts), None, started)
        return {"source": source, "hosts": len(hosts), "delta": delta_count, "inventory": total, "raw": str(raw_path)}
    except Exception as exc:
        log_run(paths, source, "error", 0, str(exc), started)
        raise


def securitytrails_history_for_host(domain: str, paths: dict[str, Path], hostname: str, timeout: int = 40) -> dict:
    import negro_intel as intel
    hostname = normalize_host(hostname, domain) or ""
    if not hostname:
        raise RuntimeError("Host fuera del target")
    result = intel.securitytrails_dns_history(hostname, timeout=timeout)
    out_dir = paths["raw"] / "passive-dns"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{hostname}.securitytrails.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with db_connect(paths) as conn:
        host_id, _ = upsert_host(conn, hostname, "securitytrails")
        record_observation(conn, "host", host_id, "securitytrails", "dns_history", None, result)
    return {"raw": str(out), "result": result}


def tls_san_pivot(domain: str, paths: dict[str, Path], hostname: str, timeout: int = 25) -> dict:
    hostname = normalize_host(hostname, domain) or ""
    if not hostname:
        raise RuntimeError("Host fuera del target")
    tls = inspect_tls(hostname, timeout=timeout)
    sans = []
    for value in tls.get("sans", []) if isinstance(tls, dict) else []:
        candidate = str(value).lower().rstrip(".")
        if candidate.startswith("*."):
            candidate = candidate[2:]
        normalized = normalize_host(candidate, domain)
        if normalized:
            sans.append(normalized)
    hosts = sorted(set(sans))
    total, delta = persist_host_source("tls_san", hosts, domain, paths)
    with db_connect(paths) as conn:
        host_id, _ = upsert_host(conn, hostname, "tls_san")
        record_observation(conn, "host", host_id, "tls_san", "certificate_sans", None, {"tls": tls, "imported": hosts})
    return {"host": hostname, "sans": hosts, "count": len(hosts), "delta": delta, "inventory": total}


def collect_github_code(domain: str, paths: dict[str, Path], timeout: int = 45) -> dict:
    import negro_intel as intel
    source = "github_code"
    started = now_iso()
    try:
        result = intel.github_code_search(domain, timeout=timeout)
        raw_path = paths["raw"] / "github-code.json"
        raw_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        combined = "\n".join(result.get("fragments", []))
        local = intel.analyze_js_text(combined, f"https://{domain}/", domain, max_contexts=80)
        urls = local.get("in_scope_urls", [])
        new_hosts, new_resources, total = _persist_url_list(domain, paths, source, urls)
        with db_connect(paths) as conn:
            root_id, _ = upsert_host(conn, domain, source)
            record_observation(conn, "host", root_id, source, "github_search", None, {"total_count": result.get("total_count"), "items": result.get("items", [])[:100]})
            for ws in local.get("websockets", []):
                record_observation(conn, "host", root_id, source, "websocket", ws, None)
        log_run(paths, source, "ok" if result.get("items") else "empty", len(result.get("items", [])), None, started)
        return {"source": source, "matches": len(result.get("items", [])), "new_hosts": new_hosts, "new_resources": new_resources, "inventory": total, "raw": str(raw_path)}
    except Exception as exc:
        log_run(paths, source, "error", 0, str(exc), started)
        raise


def discover_js_for_host(domain: str, paths: dict[str, Path], hostname: str, timeout: int = 30) -> dict:
    import negro_intel as intel
    hostname = normalize_host(hostname, domain) or ""
    if not hostname:
        raise RuntimeError("Host fuera del target")
    result = intel.discover_js(hostname, domain, timeout=timeout)
    with db_connect(paths) as conn:
        host_id, _ = upsert_host(conn, hostname, "js_discovery")
        for url in result.get("in_scope", []):
            upsert_resource(conn, url, "js_discovery", domain)
            conn.execute(
                "INSERT OR IGNORE INTO js_assets(host_id, url, source, discovered_at) VALUES(?, ?, 'js_discovery', ?)",
                (host_id, url, now_iso()),
            )
        for url in result.get("external", []):
            record_observation(conn, "host", host_id, "js_discovery", "external_script", url, None)
        record_observation(conn, "host", host_id, "js_discovery", "page_scripts", result.get("page_url"), {"in_scope": result.get("in_scope", []), "external": result.get("external", []), "errors": result.get("errors", [])})
    rebuild_inventory(paths, domain)
    return result


def _js_asset_row(paths: dict[str, Path], asset_id: int):
    with db_connect(paths) as conn:
        return conn.execute("SELECT j.*, h.hostname FROM js_assets j JOIN hosts h ON h.id=j.host_id WHERE j.id=?", (asset_id,)).fetchone()


def local_analyze_js_asset(domain: str, paths: dict[str, Path], asset_id: int, timeout: int = 35) -> dict:
    import hashlib
    import negro_intel as intel
    row = _js_asset_row(paths, asset_id)
    if not row:
        raise RuntimeError("JS asset no encontrado")
    settings = intel.load_settings()
    max_bytes = int(settings.get("js_max_download_mb", 8)) * 1024 * 1024
    raw, content_type, final_url = intel.http_bytes(row["url"], timeout=timeout, max_bytes=max_bytes, insecure=True)
    sha = hashlib.sha256(raw).hexdigest()
    out_dir = paths["raw"] / "js" / row["hostname"]
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / f"{sha[:16]}.js"
    raw_path.write_bytes(raw)
    text = raw.decode("utf-8", errors="replace")
    analysis_text = intel.beautify_js(text)
    local = intel.analyze_js_text(analysis_text, final_url, domain)
    sourcemap_url = None
    if local.get("source_maps"):
        # Keep one representative value for compatibility. fetch_sourcemap_for_asset
        # now tries every detected candidate and handles inline data: maps separately.
        candidates = list(local["source_maps"])
        external = [x for x in candidates if not str(x).lower().startswith("data:")]
        chosen = external[-1] if external else candidates[-1]
        sourcemap_url = chosen if str(chosen).lower().startswith("data:") else urllib.parse.urljoin(final_url, chosen)
    with db_connect(paths) as conn:
        conn.execute(
            "UPDATE js_assets SET size_bytes=?, sha256=?, local_path=?, sourcemap_url=?, local_analysis_json=?, analyzed_at=? WHERE id=?",
            (len(raw), sha, str(raw_path), sourcemap_url, json.dumps(local, ensure_ascii=False), now_iso(), asset_id),
        )
        host_id = int(row["host_id"])
        record_observation(conn, "host", host_id, "js_local", "js_analysis", row["url"], {"asset_id": asset_id, "size_bytes": len(raw), "content_type": content_type, "summary": {"in_scope_urls": len(local.get("in_scope_urls", [])), "relative_paths": len(local.get("relative_paths", [])), "websockets": len(local.get("websockets", [])), "source_maps": local.get("source_maps", []), "keywords": local.get("keywords", {})}})
        for url in local.get("in_scope_urls", []):
            upsert_resource(conn, url, "js_local", domain)
        for ws in local.get("websockets", []):
            record_observation(conn, "host", host_id, "js_local", "websocket", ws, None)
    rebuild_inventory(paths, domain)
    return {"asset_id": asset_id, "url": row["url"], "size_bytes": len(raw), "sha256": sha, "local_path": str(raw_path), "sourcemap_url": sourcemap_url, "analysis": local}


def fetch_sourcemap_for_asset(domain: str, paths: dict[str, Path], asset_id: int, timeout: int = 40) -> dict:
    import negro_intel as intel
    row = _js_asset_row(paths, asset_id)
    if not row:
        raise RuntimeError("JS asset no encontrado")

    local_analysis = {}
    try:
        local_analysis = json.loads(row["local_analysis_json"] or "{}")
    except Exception:
        local_analysis = {}

    detected = local_analysis.get("source_maps", []) if isinstance(local_analysis, dict) else []
    candidates: list[str] = []
    for candidate in detected if isinstance(detected, list) else []:
        if not isinstance(candidate, str) or not candidate.strip():
            continue
        candidate = candidate.strip()
        resolved = candidate if candidate.lower().startswith("data:") else urllib.parse.urljoin(row["url"], candidate)
        if resolved not in candidates:
            candidates.append(resolved)
    if row["sourcemap_url"] and row["sourcemap_url"] not in candidates:
        candidates.append(row["sourcemap_url"])
    if not candidates:
        raise RuntimeError("Este JS no tiene sourceMappingURL detectado")

    def rank(url: str) -> tuple[int, int]:
        low = url.lower()
        if low.startswith("data:"):
            return (2, 0)
        path = urllib.parse.urlsplit(url).path.lower()
        return (0 if path.endswith(".map") else 1, 0)

    ordered = sorted(enumerate(candidates), key=lambda item: (rank(item[1]), -item[0]))
    errors: list[str] = []
    raw = b""
    ctype = ""
    final_url = ""
    data = None
    selected = None
    attempted = 0
    for _, candidate in ordered:
        attempted += 1
        try:
            raw_try, ctype_try, final_try = intel.http_bytes(candidate, timeout=timeout, max_bytes=25_000_000, insecure=True)
            parsed = json.loads(raw_try.decode("utf-8", errors="replace"))
            if not isinstance(parsed, dict):
                raise ValueError("JSON raíz no es objeto")
            raw, ctype, final_url, data, selected = raw_try, ctype_try, final_try, parsed, candidate
            break
        except Exception as exc:
            label = "inline data: source map" if candidate.lower().startswith("data:") else candidate[:220]
            errors.append(f"{label}: {str(exc)[:260]}")

    if data is None or selected is None:
        detail = " | ".join(errors[:6])
        raise RuntimeError(f"Ninguno de los {len(candidates)} source maps detectados fue válido. {detail}")

    out_dir = paths["raw"] / "js" / row["hostname"]
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"asset-{asset_id}.js.map"
    out.write_bytes(raw)
    sm = intel.analyze_sourcemap_data(data, row["url"], domain)
    display_url = "inline:data:source-map" if selected.lower().startswith("data:") else final_url
    sm.update({
        "asset_id": asset_id,
        "url": display_url,
        "path": str(out),
        "content_type": ctype,
        "candidates_detected": len(candidates),
        "candidates_attempted": attempted,
        "candidate_errors": errors[:10],
    })
    sm_local = sm.get("analysis", {}) if isinstance(sm.get("analysis"), dict) else {}
    with db_connect(paths) as conn:
        for url in sm_local.get("in_scope_urls", []):
            upsert_resource(conn, url, "sourcemap", domain)
        conn.execute(
            "UPDATE js_assets SET sourcemap_url=?, sourcemap_analysis_json=?, sourcemap_path=?, sourcemap_analyzed_at=? WHERE id=?",
            (display_url, json.dumps(sm, ensure_ascii=False), str(out), now_iso(), asset_id),
        )
        record_observation(conn, "host", int(row["host_id"]), "sourcemap", "source_map", display_url, sm)
    rebuild_inventory(paths, domain)
    return sm


def _load_saved_sourcemap_analysis(paths: dict[str, Path], row, domain: str) -> dict | None:
    import negro_intel as intel
    raw_json = row["sourcemap_analysis_json"] if "sourcemap_analysis_json" in row.keys() else None
    if raw_json:
        try:
            data = json.loads(raw_json)
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    # Backward compatibility for v0.7.x workspaces: reuse the already downloaded
    # map from the latest observation and enrich it locally without new network traffic.
    saved_path = row["sourcemap_path"] if "sourcemap_path" in row.keys() else None
    observed_payload = None
    with db_connect(paths) as conn:
        rows = conn.execute(
            "SELECT payload_json FROM observations WHERE entity_type='host' AND entity_id=? AND source='sourcemap' AND kind='source_map' ORDER BY id DESC LIMIT 20",
            (int(row["host_id"]),),
        ).fetchall()
        for obs in rows:
            try:
                payload = json.loads(obs["payload_json"] or "{}")
            except Exception:
                continue
            if int(payload.get("asset_id", -1)) == int(row["id"]):
                observed_payload = payload
                saved_path = saved_path or payload.get("path")
                break
    if not saved_path:
        return observed_payload if isinstance(observed_payload, dict) else None
    path = Path(str(saved_path))
    if not path.exists():
        return observed_payload if isinstance(observed_payload, dict) else None
    try:
        parsed = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(parsed, dict):
            return observed_payload if isinstance(observed_payload, dict) else None
        sm = intel.analyze_sourcemap_data(parsed, row["url"], domain)
        sm.update({
            "asset_id": int(row["id"]),
            "url": (observed_payload or {}).get("url") or row["sourcemap_url"],
            "path": str(path),
            "content_type": (observed_payload or {}).get("content_type", "application/json"),
            "candidates_detected": (observed_payload or {}).get("candidates_detected", 0),
            "candidates_attempted": (observed_payload or {}).get("candidates_attempted", 0),
            "candidate_errors": (observed_payload or {}).get("candidate_errors", []),
            "recovered_from_v07": True,
        })
        with db_connect(paths) as conn:
            conn.execute(
                "UPDATE js_assets SET sourcemap_analysis_json=?, sourcemap_path=?, sourcemap_analyzed_at=COALESCE(sourcemap_analyzed_at, ?) WHERE id=?",
                (json.dumps(sm, ensure_ascii=False), str(path), now_iso(), int(row["id"])),
            )
        return sm
    except Exception:
        return observed_payload if isinstance(observed_payload, dict) else None

def ai_estimate_js_asset(paths: dict[str, Path], asset_id: int, model: str | None = None) -> dict:
    import negro_intel as intel
    row = _js_asset_row(paths, asset_id)
    if not row:
        raise RuntimeError("JS asset no encontrado")
    if not row["local_analysis_json"]:
        raise RuntimeError("Primero ejecuta análisis local del JS")
    with db_connect(paths) as conn:
        meta = conn.execute("SELECT value FROM meta WHERE key='domain'").fetchone()
    domain = meta["value"] if meta else (row["hostname"].split('.',1)[-1] if '.' in row["hostname"] else row["hostname"])
    settings = intel.load_settings()
    selected_model = model or str(settings.get("ai_model", "gpt-6-luna"))
    output_tokens = int(settings.get("ai_output_tokens", 3000))
    local = json.loads(row["local_analysis_json"])
    sourcemap = _load_saved_sourcemap_analysis(paths, row, domain)
    payload = intel.ai_payload(local, sourcemap, max_chars=int(settings.get("js_ai_max_chars", 650000)))
    estimate = intel.estimate_ai_cost(payload, selected_model, output_tokens, float(settings.get("usd_cop_rate", 0) or 0))
    estimate["payload_chars"] = len(payload)
    estimate["asset_id"] = asset_id
    estimate["fx_rate_date"] = settings.get("usd_cop_rate_date")
    estimate["source_map_included"] = bool(sourcemap)
    if sourcemap:
        estimate["source_map_application_sources"] = sourcemap.get("application_sources_count", 0)
        estimate["source_map_sources_with_content"] = sourcemap.get("application_sources_with_content", 0)
    return estimate


def ai_run_js_asset(paths: dict[str, Path], asset_id: int, model: str | None = None) -> dict:
    import negro_intel as intel
    row = _js_asset_row(paths, asset_id)
    if not row:
        raise RuntimeError("JS asset no encontrado")
    if not row["local_analysis_json"]:
        raise RuntimeError("Primero ejecuta análisis local del JS")
    with db_connect(paths) as conn:
        meta = conn.execute("SELECT value FROM meta WHERE key='domain'").fetchone()
    domain = meta["value"] if meta else (row["hostname"].split('.',1)[-1] if '.' in row["hostname"] else row["hostname"])
    settings = intel.load_settings()
    selected_model = model or str(settings.get("ai_model", "gpt-6-luna"))
    output_tokens = int(settings.get("ai_output_tokens", 3000))
    local = json.loads(row["local_analysis_json"])
    sourcemap = _load_saved_sourcemap_analysis(paths, row, domain)
    payload = intel.ai_payload(local, sourcemap, max_chars=int(settings.get("js_ai_max_chars", 650000)))
    estimate = intel.estimate_ai_cost(payload, selected_model, output_tokens, float(settings.get("usd_cop_rate", 0) or 0))
    estimate["source_map_included"] = bool(sourcemap)
    result, usage = intel.run_openai_js_analysis(payload, model=selected_model, output_tokens=output_tokens)
    with db_connect(paths) as conn:
        conn.execute(
            "INSERT INTO ai_analyses(js_asset_id, model, status, estimate_json, usage_json, result_json, created_at) VALUES(?, ?, 'done', ?, ?, ?, ?)",
            (asset_id, selected_model, json.dumps(estimate), json.dumps(usage), json.dumps(result, ensure_ascii=False), now_iso()),
        )
        record_observation(conn, "host", int(row["host_id"]), "ai_js", "ai_analysis", row["url"], {"asset_id": asset_id, "model": selected_model, "summary": result.get("summary"), "observation_count": len(result.get("observations", [])) if isinstance(result, dict) else 0, "source_map_included": bool(sourcemap)})
    return {"asset_id": asset_id, "model": selected_model, "estimate": estimate, "usage": usage, "result": result}

def print_inspection_history(paths: dict[str, Path], hostname: str, limit: int = 5) -> None:
    hostname = hostname.strip().lower().rstrip(".")
    with db_connect(paths) as conn:
        host = conn.execute("SELECT id FROM hosts WHERE hostname=?", (hostname,)).fetchone()
        if not host:
            print(f"[!] Host no existe en DB: {hostname}")
            return
        rows = conn.execute(
            "SELECT observed_at, payload_json FROM host_inspections WHERE host_id=? ORDER BY id DESC LIMIT ?",
            (host["id"], limit),
        ).fetchall()
    if not rows:
        print(f"[!] Sin inspecciones guardadas para {hostname}")
        return
    print(f"\nINSPECTION HISTORY — {hostname}\n")
    for row in rows:
        payload = json.loads(row["payload_json"])
        dns = payload.get("dns", {})
        tls = payload.get("tls", {})
        http = payload.get("http", {})
        https = payload.get("https", {})
        print(
            f"{row['observed_at']}  "
            f"A={','.join(dns.get('a', [])) or '-'}  "
            f"CNAME={','.join(dns.get('cname', [])) or '-'}  "
            f"TLS={tls.get('status', '-')}  "
            f"HTTP={http.get('status', '-')}  HTTPS={https.get('status', '-')}"
        )
    print()


def icon(review_state: str, classification: str) -> str:
    check = "x" if review_state == "reviewed" else ("~" if review_state == "in_progress" else " ")
    klass = {
        "unknown": "?",
        "informational": "i",
        "lead": "!",
        "discarded": "-",
        "finding": "F",
    }.get(classification, "?")
    return f"[{check}][{klass}]"


def get_sources(conn: sqlite3.Connection, entity: str, entity_id: int) -> list[str]:
    if entity == "host":
        rows = conn.execute("SELECT source FROM host_sources WHERE host_id=? ORDER BY source", (entity_id,)).fetchall()
    else:
        rows = conn.execute("SELECT source FROM resource_sources WHERE resource_id=? ORDER BY source", (entity_id,)).fetchall()
    return [r["source"] for r in rows]


def get_notes(conn: sqlite3.Connection, entity: str, entity_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT body, created_at FROM notes WHERE entity_type=? AND entity_id=? ORDER BY id",
        (entity, entity_id),
    ).fetchall()


def print_tree(paths: dict[str, Path], host_filter: str | None = None, resource_limit: int = 8) -> None:
    with db_connect(paths) as conn:
        if host_filter:
            rows = conn.execute("SELECT * FROM hosts WHERE hostname=?", (host_filter.lower().rstrip("."),)).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT h.*, COUNT(r.id) AS resource_count
                FROM hosts h LEFT JOIN resources r ON r.host_id=h.id
                GROUP BY h.id ORDER BY h.hostname
                """
            ).fetchall()

        if not rows:
            print("[!] No se encontraron hosts.")
            return

        for h in rows:
            count = h["resource_count"] if "resource_count" in h.keys() else conn.execute("SELECT COUNT(*) c FROM resources WHERE host_id=?", (h["id"],)).fetchone()["c"]
            sources = ",".join(get_sources(conn, "host", h["id"])) or "-"
            inspection_count = conn.execute("SELECT COUNT(*) c FROM host_inspections WHERE host_id=?", (h["id"],)).fetchone()["c"]
            print(f"{icon(h['review_state'], h['classification'])} {h['hostname']}  resources={count}  inspections={inspection_count}  sources={sources}")

            resources = conn.execute(
                "SELECT * FROM resources WHERE host_id=? ORDER BY path, url LIMIT ?",
                (h["id"], resource_limit),
            ).fetchall()
            for idx, r in enumerate(resources):
                branch = "└─" if idx == len(resources) - 1 and count <= resource_limit else "├─"
                rsources = ",".join(get_sources(conn, "resource", r["id"])) or "-"
                display = r["path"] + (("?" + r["query"]) if r["query"] else "")
                print(f"   {branch} {icon(r['review_state'], r['classification'])} {display}  [{rsources}]")
            if count > resource_limit:
                print(f"   └─ ... +{count - resource_limit} recursos")


def print_queue(paths: dict[str, Path], limit: int = 50) -> None:
    with db_connect(paths) as conn:
        hosts = conn.execute(
            "SELECT * FROM hosts WHERE review_state!='reviewed' ORDER BY CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, hostname LIMIT ?", (limit,)
        ).fetchall()
        resources = conn.execute(
            """
            SELECT r.*, h.hostname FROM resources r JOIN hosts h ON h.id=r.host_id
            WHERE r.review_state!='reviewed' ORDER BY CASE r.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, h.hostname, r.path LIMIT ?
            """,
            (limit,),
        ).fetchall()

        print(f"\nHOSTS PENDIENTES ({len(hosts)} mostrados)")
        for h in hosts:
            print(f"  {icon(h['review_state'], h['classification'])} [{h['priority']}] {h['hostname']}")
        print(f"\nRECURSOS PENDIENTES ({len(resources)} mostrados)")
        for r in resources:
            print(f"  {icon(r['review_state'], r['classification'])} [{r['priority']}] {r['hostname']} {r['path']}")


def print_leads(paths: dict[str, Path]) -> None:
    with db_connect(paths) as conn:
        hosts = conn.execute(
            "SELECT * FROM hosts WHERE classification IN ('lead','finding') ORDER BY classification DESC, hostname"
        ).fetchall()
        resources = conn.execute(
            """
            SELECT r.*, h.hostname FROM resources r JOIN hosts h ON h.id=r.host_id
            WHERE r.classification IN ('lead','finding')
            ORDER BY r.classification DESC, h.hostname, r.path
            """
        ).fetchall()
        print("\nLEADS / FINDINGS\n")
        for h in hosts:
            print(f"  {icon(h['review_state'], h['classification'])} HOST {h['hostname']}")
            for note in get_notes(conn, "host", h["id"]):
                print(f"      note {note['created_at']}: {note['body']}")
        for r in resources:
            print(f"  {icon(r['review_state'], r['classification'])} URL  {r['url']}")
            for note in get_notes(conn, "resource", r["id"]):
                print(f"      note {note['created_at']}: {note['body']}")


def log_event(conn: sqlite3.Connection, entity_type: str, entity_id: int, event_type: str, payload: dict | None = None) -> None:
    conn.execute(
        "INSERT INTO events(entity_type, entity_id, event_type, payload_json, created_at) VALUES(?, ?, ?, ?, ?)",
        (entity_type, entity_id, event_type, json.dumps(payload or {}, ensure_ascii=False), now_iso()),
    )


def mark_entity(paths: dict[str, Path], entity: str, identifier: str, review_state: str | None, classification: str | None, priority: str | None = None, note: str | None = None) -> None:
    if review_state and review_state not in REVIEW_STATES:
        raise RuntimeError(f"review_state inválido: {review_state}")
    if classification and classification not in CLASSIFICATIONS:
        raise RuntimeError(f"classification inválida: {classification}")
    if priority and priority not in PRIORITIES:
        raise RuntimeError(f"priority inválida: {priority}")

    with db_connect(paths) as conn:
        if entity == "host":
            row = conn.execute("SELECT * FROM hosts WHERE hostname=?", (identifier.lower().rstrip("."),)).fetchone()
            table = "hosts"
        else:
            row = conn.execute("SELECT * FROM resources WHERE url=?", (identifier,)).fetchone()
            table = "resources"
        if not row:
            raise RuntimeError(f"No existe {entity}: {identifier}")

        before = {
            "review_state": row["review_state"],
            "classification": row["classification"],
            "priority": row["priority"] if "priority" in row.keys() else "none",
        }
        new_review = review_state or before["review_state"]
        new_class = classification or before["classification"]
        new_priority = priority or before["priority"]
        conn.execute(
            f"UPDATE {table} SET review_state=?, classification=?, priority=?, updated_at=? WHERE id=?",
            (new_review, new_class, new_priority, now_iso(), row["id"]),
        )
        after = {"review_state": new_review, "classification": new_class, "priority": new_priority}
        if before != after:
            log_event(conn, entity, row["id"], "state_changed", {"before": before, "after": after})
        if note:
            conn.execute(
                "INSERT INTO notes(entity_type, entity_id, body, created_at) VALUES(?, ?, ?, ?)",
                (entity, row["id"], note, now_iso()),
            )
            log_event(conn, entity, row["id"], "note_added", {"body": note})
    print(f"[+] {entity} actualizado: {identifier} -> {new_review}/{new_class}/{new_priority}")


def interactive_mark(paths: dict[str, Path]) -> None:
    entity = input("Tipo [host/resource]: ").strip().lower()
    if entity not in ("host", "resource"):
        print("[!] Tipo inválido.")
        return
    identifier = input("Hostname o URL exacta: ").strip()
    print("Review: 1=pending  2=in_progress  3=reviewed")
    rv = input("Review [3]: ").strip() or "3"
    review_state = {"1":"pending", "2":"in_progress", "3":"reviewed"}.get(rv, "reviewed")
    print("Clasificación: 1=unknown  2=informational  3=lead  4=discarded  5=finding")
    mapping = {"1":"unknown", "2":"informational", "3":"lead", "4":"discarded", "5":"finding"}
    classification = mapping.get(input("Clasificación [1]: ").strip() or "1", "unknown")
    print("Prioridad: 1=none  2=low  3=medium  4=high")
    priority = {"1":"none", "2":"low", "3":"medium", "4":"high"}.get(input("Prioridad [1]: ").strip() or "1", "none")
    note = input("Nota (opcional): ").strip() or None
    mark_entity(paths, entity, identifier, review_state, classification, priority, note)


def print_status(domain: str, paths: dict[str, Path]) -> None:
    with db_connect(paths) as conn:
        host_total = conn.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"]
        resource_total = conn.execute("SELECT COUNT(*) c FROM resources").fetchone()["c"]
        pending_hosts = conn.execute("SELECT COUNT(*) c FROM hosts WHERE review_state!='reviewed'").fetchone()["c"]
        pending_resources = conn.execute("SELECT COUNT(*) c FROM resources WHERE review_state!='reviewed'").fetchone()["c"]
        leads = conn.execute("SELECT COUNT(*) c FROM hosts WHERE classification='lead'").fetchone()["c"] + conn.execute("SELECT COUNT(*) c FROM resources WHERE classification='lead'").fetchone()["c"]
        findings = conn.execute("SELECT COUNT(*) c FROM hosts WHERE classification='finding'").fetchone()["c"] + conn.execute("SELECT COUNT(*) c FROM resources WHERE classification='finding'").fetchone()["c"]
        last_runs = conn.execute(
            "SELECT source, status, result_count, error, finished_at FROM runs ORDER BY id DESC LIMIT 8"
        ).fetchall()

    print(f"\nTarget:    {domain}")
    print(f"Workspace: {paths['root']}")
    print(f"DB:        {paths['db_file']}")
    print("-" * 72)
    print(f"Hosts={host_total}  Recursos={resource_total}  Pendientes={pending_hosts + pending_resources}  Leads={leads}  Findings={findings}")
    print("-" * 72)
    if last_runs:
        print("Últimas ejecuciones:")
        for r in last_runs:
            suffix = f" — {r['error'][:90]}" if r["error"] else ""
            print(f"  {r['finished_at']}  {r['source']:<18} {r['status']:<6} {r['result_count']:<6}{suffix}")
    print()


def show_sources() -> None:
    print("\nFuentes / técnicas\n")
    for name, (status, label, purpose) in SOURCE_INFO.items():
        print(f"[{status:<12}] {name:<18} — {label}")
        print(f"  {purpose}")
    print()


def search_db(paths: dict[str, Path], pattern: str) -> None:
    like = f"%{pattern.lower()}%"
    with db_connect(paths) as conn:
        hosts = conn.execute("SELECT * FROM hosts WHERE lower(hostname) LIKE ? ORDER BY hostname", (like,)).fetchall()
        resources = conn.execute(
            """
            SELECT r.*, h.hostname FROM resources r JOIN hosts h ON h.id=r.host_id
            WHERE lower(r.url) LIKE ? ORDER BY h.hostname, r.path LIMIT 200
            """,
            (like,),
        ).fetchall()
    print(f"\nHosts ({len(hosts)}):")
    for h in hosts:
        print(f"  {icon(h['review_state'], h['classification'])} [{h['priority']}] {h['hostname']}")
    print(f"\nRecursos ({len(resources)}):")
    for r in resources:
        print(f"  {icon(r['review_state'], r['classification'])} {r['url']}")


def _legacy_config_load() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def target_key(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    safe = "".join(ch if (ch.isalnum() or ch in ".-") else "-" for ch in domain)
    return safe.strip("-.")


def targets_load() -> dict:
    data = {"last_target": None, "targets": {}}
    if TARGETS_PATH.exists():
        try:
            raw = json.loads(TARGETS_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                data["last_target"] = raw.get("last_target")
                targets = raw.get("targets")
                if isinstance(targets, dict):
                    data["targets"] = targets
        except Exception:
            pass

    # One-time/backward-compatible migration from v0.5's single target config.
    legacy = _legacy_config_load()
    if legacy.get("domain") and legacy.get("workspace"):
        key = target_key(str(legacy["domain"]))
        if key and key not in data["targets"]:
            data["targets"][key] = {
                "domain": str(legacy["domain"]).strip().lower().rstrip("."),
                "workspace": str(Path(str(legacy["workspace"])).expanduser()),
            }
        if not data.get("last_target"):
            data["last_target"] = key
    return data


def targets_save(data: dict) -> None:
    TARGETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    TARGETS_PATH.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def register_target(domain: str, workspace: Path, make_current: bool = True) -> str:
    domain = domain.strip().lower().rstrip(".")
    key = target_key(domain)
    if not key:
        raise ValueError("Target inválido")
    workspace = workspace.expanduser()
    data = targets_load()
    data.setdefault("targets", {})[key] = {"domain": domain, "workspace": str(workspace)}
    if make_current:
        data["last_target"] = key
    targets_save(data)
    if make_current:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps({"domain": domain, "workspace": str(workspace)}, indent=2) + "\n", encoding="utf-8")
    return key


def set_current_target(key: str) -> None:
    data = targets_load()
    target = data.get("targets", {}).get(key)
    if not target:
        raise KeyError(key)
    data["last_target"] = key
    targets_save(data)
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(target, indent=2) + "\n", encoding="utf-8")


def get_target(key: str) -> dict | None:
    target = targets_load().get("targets", {}).get(key)
    return dict(target) if isinstance(target, dict) else None


def list_targets() -> list[dict]:
    data = targets_load()
    current = data.get("last_target")
    result = []
    for key, target in sorted(data.get("targets", {}).items(), key=lambda item: item[1].get("domain", item[0])):
        result.append({"key": key, "domain": target.get("domain", key), "workspace": target.get("workspace", ""), "current": key == current})
    return result


def config_load() -> dict:
    data = targets_load()
    key = data.get("last_target")
    target = data.get("targets", {}).get(key) if key else None
    if target:
        return dict(target)
    return _legacy_config_load()


def config_save(domain: str, workspace: Path) -> None:
    register_target(domain, workspace, make_current=True)


def default_workspace(domain: str) -> Path:
    # Keep targets together. Existing users can override with -w or the Web form.
    return Path.home() / "Documents" / "recon" / domain


def suggested_workspace(domain: str) -> Path:
    current = config_load()
    try:
        if current.get("workspace"):
            parent = Path(str(current["workspace"])).expanduser().parent
            if parent.exists() or parent.parent.exists():
                return parent / domain
    except Exception:
        pass
    return default_workspace(domain)


def choose_target(force_new: bool = False) -> tuple[str, Path]:
    current = {} if force_new else config_load()
    if current.get("domain") and current.get("workspace"):
        answer = input(f"Usar target anterior {current['domain']} ({current['workspace']})? [Y/n]: ").strip().lower()
        if answer in ("", "y", "yes", "s", "si", "sí"):
            return current["domain"], Path(current["workspace"]).expanduser()

    domain = input("Dominio objetivo (ej. mercadolibre.com): ").strip().lower().rstrip(".")
    default = default_workspace(domain)
    raw = input(f"Workspace [{default}]: ").strip()
    workspace = Path(raw).expanduser() if raw else default
    config_save(domain, workspace)
    return domain, workspace


def interactive_menu() -> None:
    banner()
    domain, workspace = choose_target()
    paths = ensure_workspace(workspace, domain)

    while True:
        print(f"\nTarget actual: {domain}")
        print(f"Workspace:     {workspace}\n")
        print("[1] Dashboard / estado")
        print("[2] Ejecutar crt.sh")
        print("[3] Ejecutar Subfinder")
        print("[4] Ejecutar Amass passive")
        print("[5] Ejecutar GAU (elegir provider)")
        print("[6] Inspeccionar host (DNS / TLS / HTTP)")
        print("[7] Historial de inspección")
        print("[8] Ver árbol de assets")
        print("[9] Ver pendientes")
        print("[10] Marcar / revisar asset")
        print("[11] Ver leads / findings")
        print("[12] Buscar")
        print("[13] Ver fuentes")
        print("[14] Cambiar target")
        print("[0] Salir")
        choice = input("\nOpción > ").strip()

        try:
            if choice == "1":
                print_status(domain, paths)
            elif choice == "2":
                collect_source("crtsh", domain, paths, 300)
            elif choice == "3":
                collect_source("subfinder", domain, paths, 600)
            elif choice == "4":
                collect_source("amass", domain, paths, 7200)
            elif choice == "5":
                provider = input("Provider [otx/urlscan/wayback/commoncrawl] (default otx): ").strip().lower() or "otx"
                collect_gau_provider(provider, domain, paths, 600)
            elif choice == "6":
                hostname = input("Host a inspeccionar: ").strip()
                inspect_host(domain, paths, hostname)
            elif choice == "7":
                hostname = input("Host: ").strip()
                print_inspection_history(paths, hostname)
            elif choice == "8":
                host = input("Host específico (Enter = árbol general): ").strip() or None
                print_tree(paths, host_filter=host)
            elif choice == "9":
                print_queue(paths)
            elif choice == "10":
                interactive_mark(paths)
            elif choice == "11":
                print_leads(paths)
            elif choice == "12":
                search_db(paths, input("Texto a buscar: ").strip())
            elif choice == "13":
                show_sources()
            elif choice == "14":
                domain, workspace = choose_target(force_new=True)
                config_save(domain, workspace)
                paths = ensure_workspace(workspace, domain)
            elif choice == "0":
                print("Hasta luego. Negro queda olfateando.")
                return
            else:
                print("[!] Opción inválida.")
        except KeyboardInterrupt:
            print("\n[!] Operación cancelada.")
        except subprocess.TimeoutExpired:
            print("[!] La fuente alcanzó el timeout. Se registró como error; no equivale a 0 resultados.")
        except Exception as exc:
            print(f"[!] Error: {exc}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Negro Recon — passive Bug Bounty reconnaissance organizer")
    parser.add_argument("domain", help="Dominio objetivo. Ejecutar sin argumentos abre el menú.")
    parser.add_argument("-w", "--workspace", type=Path)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--version", action="version", version=f"Negro Recon {VERSION}")

    subs = parser.add_subparsers(dest="command")
    subs.add_parser("init")
    subs.add_parser("status")
    subs.add_parser("sources")

    runp = subs.add_parser("run", help="Ejecutar una o más fuentes de hosts")
    runp.add_argument("--sources", nargs="+", choices=["crtsh","subfinder","amass","gau_otx","gau_urlscan","gau_wayback","gau_commoncrawl"], default=["crtsh", "subfinder"])

    gaup = subs.add_parser("gau", help="Ejecutar GAU por provider")
    gaup.add_argument("--provider", choices=list(GAU_PROVIDERS), default="otx")

    subs.add_parser("wayback-cdx", help="Wayback CDX directo con metadata histórica")
    subs.add_parser("urlscan", help="URLScan directo: scans históricos y requests")
    subs.add_parser("securitytrails", help="SecurityTrails subdomains (requiere API key)")
    subs.add_parser("github-code", help="GitHub public code search (requiere token)")

    pdnsp = subs.add_parser("passive-dns", help="DNS histórico de un host vía SecurityTrails")
    pdnsp.add_argument("host")

    sanp = subs.add_parser("tls-san", help="Pivot de SANs TLS para un host")
    sanp.add_argument("host")

    jsdp = subs.add_parser("js-discover", help="Descubrir JS de un host seleccionado")
    jsdp.add_argument("host")

    jsap = subs.add_parser("js-analyze", help="Descargar y analizar localmente un JS asset")
    jsap.add_argument("asset_id", type=int)

    jssp = subs.add_parser("js-sourcemap", help="Descargar/analizar source map detectado")
    jssp.add_argument("asset_id", type=int)

    aiep = subs.add_parser("ai-estimate", help="Estimar tokens/costo antes de enviar JS a IA")
    aiep.add_argument("asset_id", type=int)
    aiep.add_argument("--model", choices=["gpt-6-luna", "gpt-6-sol"])

    aiap = subs.add_parser("ai-analyze", help="Analizar evidencia JS con OpenAI")
    aiap.add_argument("asset_id", type=int)
    aiap.add_argument("--model", choices=["gpt-6-luna", "gpt-6-sol"])

    inspectp = subs.add_parser("inspect", help="Triage básico de un host: DNS, TLS y HTTP/HTTPS")
    inspectp.add_argument("host")

    historyp = subs.add_parser("inspect-history", help="Ver inspecciones anteriores de un host")
    historyp.add_argument("host")
    historyp.add_argument("--limit", type=int, default=5)

    treep = subs.add_parser("tree", help="Mostrar árbol host -> recursos")
    treep.add_argument("--host")
    treep.add_argument("--resource-limit", type=int, default=8)

    queuep = subs.add_parser("queue", help="Mostrar assets pendientes")
    queuep.add_argument("--limit", type=int, default=50)

    subs.add_parser("leads", help="Mostrar leads y findings")

    searchp = subs.add_parser("search")
    searchp.add_argument("pattern")

    markp = subs.add_parser("mark", help="Marcar/revisar un host o recurso")
    markp.add_argument("entity", choices=["host", "resource"])
    markp.add_argument("identifier", help="Hostname exacto o URL canónica exacta")
    markp.add_argument("--review", choices=REVIEW_STATES)
    markp.add_argument("--classification", choices=CLASSIFICATIONS)
    markp.add_argument("--priority", choices=PRIORITIES)
    markp.add_argument("--note")

    return parser


def cli_main(args: argparse.Namespace) -> None:
    domain = args.domain.strip().lower().rstrip(".")
    workspace = args.workspace.expanduser() if args.workspace else default_workspace(domain)
    config_save(domain, workspace)
    paths = ensure_workspace(workspace, domain)

    if args.command == "init":
        print(f"[+] Workspace listo: {workspace}")
        print_status(domain, paths)
    elif args.command in (None, "status"):
        print_status(domain, paths)
    elif args.command == "sources":
        show_sources()
    elif args.command == "run":
        for source in args.sources:
            try:
                timeout = 7200 if source == "amass" and args.timeout == 600 else args.timeout
                collect_source(source, domain, paths, timeout)
            except Exception as exc:
                print(f"[!] {source}: {exc}", file=sys.stderr)
        print_status(domain, paths)
    elif args.command == "gau":
        collect_gau_provider(args.provider, domain, paths, args.timeout)
    elif args.command == "wayback-cdx":
        print(json.dumps(collect_wayback_cdx(domain, paths, min(args.timeout, 120)), indent=2, ensure_ascii=False))
    elif args.command == "urlscan":
        print(json.dumps(collect_urlscan_direct(domain, paths, min(args.timeout, 120)), indent=2, ensure_ascii=False))
    elif args.command == "securitytrails":
        print(json.dumps(collect_securitytrails(domain, paths, min(args.timeout, 120)), indent=2, ensure_ascii=False))
    elif args.command == "github-code":
        print(json.dumps(collect_github_code(domain, paths, min(args.timeout, 120)), indent=2, ensure_ascii=False))
    elif args.command == "passive-dns":
        print(json.dumps(securitytrails_history_for_host(domain, paths, args.host, min(args.timeout, 120)), indent=2, ensure_ascii=False))
    elif args.command == "tls-san":
        print(json.dumps(tls_san_pivot(domain, paths, args.host, min(args.timeout, 60)), indent=2, ensure_ascii=False))
    elif args.command == "js-discover":
        print(json.dumps(discover_js_for_host(domain, paths, args.host, min(args.timeout, 60)), indent=2, ensure_ascii=False))
    elif args.command == "js-analyze":
        print(json.dumps(local_analyze_js_asset(domain, paths, args.asset_id, min(args.timeout, 90)), indent=2, ensure_ascii=False))
    elif args.command == "js-sourcemap":
        print(json.dumps(fetch_sourcemap_for_asset(domain, paths, args.asset_id, min(args.timeout, 120)), indent=2, ensure_ascii=False))
    elif args.command == "ai-estimate":
        print(json.dumps(ai_estimate_js_asset(paths, args.asset_id, args.model), indent=2, ensure_ascii=False))
    elif args.command == "ai-analyze":
        print(json.dumps(ai_run_js_asset(paths, args.asset_id, args.model), indent=2, ensure_ascii=False))
    elif args.command == "inspect":
        inspect_host(domain, paths, args.host, min(args.timeout, 60))
    elif args.command == "inspect-history":
        print_inspection_history(paths, args.host, args.limit)
    elif args.command == "tree":
        print_tree(paths, host_filter=args.host, resource_limit=args.resource_limit)
    elif args.command == "queue":
        print_queue(paths, args.limit)
    elif args.command == "leads":
        print_leads(paths)
    elif args.command == "search":
        search_db(paths, args.pattern)
    elif args.command == "mark":
        mark_entity(paths, args.entity, args.identifier, args.review, args.classification, args.priority, args.note)


def main() -> None:
    # `negro web` uses the last configured target/workspace and starts a local UI.
    if len(sys.argv) >= 2 and sys.argv[1] == "web":
        web_parser = argparse.ArgumentParser(prog="negro web", description="Negro Web UI")
        web_parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
        web_parser.add_argument("--port", type=int, default=8765, help="TCP port (default: 8765)")
        web_args = web_parser.parse_args(sys.argv[2:])
        current = config_load()
        if not current.get("domain") or not current.get("workspace"):
            raise SystemExit("[!] No hay target configurado. Ejecuta `negro` o `negro <dominio> init` primero.")
        domain = current["domain"]
        workspace = Path(current["workspace"]).expanduser()
        if web_args.host not in ("127.0.0.1", "localhost", "::1"):
            print("[!] Negro Web no tiene autenticación. No lo expongas a Internet.")
        from negro_web import run_web
        run_web(domain, workspace, web_args.host, web_args.port)
        return

    if len(sys.argv) == 1:
        interactive_menu()
        return
    parser = build_parser()
    args = parser.parse_args()
    cli_main(args)


if __name__ == "__main__":
    main()
