#!/usr/bin/env python3
"""
Negro Recon v0.36.0
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

Negro is passive-first and policy-aware. v0.9 adds bounded, explicit active recon
(AXFR checks, smart DNS/VHost candidates, controlled crawling/CORS checks) plus a
deterministic lead engine. It never performs credential attacks, form submission,
resource claiming, destructive exploitation, DoS, or mass scanning by default.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

VERSION = "0.36.0"
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
    "dns_recon",
    "axfr",
    "active_dns",
    "vhost",
    "web_recon",
    "crawler",
    "burp_proxy",
    "burp_repeater",
    "burp_other",
]

GAU_PROVIDERS = {
    "otx": "gau_otx",
    "urlscan": "gau_urlscan",
    "wayback": "gau_wayback",
    "commoncrawl": "gau_commoncrawl",
}

CLASSIFICATIONS = ["unknown", "informational", "lead", "discarded", "finding"]
REVIEW_STATES = ["pending", "in_progress", "reviewed"]
# v0.20: automatic signals and human investigation state are separate concepts.
HUMAN_STATES = ["normal", "learning", "review_later", "interesting", "correlate", "finding", "discarded"]
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
    "dns_recon": ("DIRIGIDA", "DNS infrastructure", "NS/MX/SOA/TXT/SRV/PTR con pocas consultas."),
    "axfr": ("DIRIGIDA", "AXFR check", "Prueba una transferencia por nameserver; no recurre ni fuerza si falla."),
    "active_dns": ("ACTIVA LIMITADA", "Smart DNS candidates", "Valida sólo candidatos inteligentes dentro del presupuesto de política."),
    "vhost": ("ACTIVA LIMITADA", "Smart VHost discovery", "Fuzzing Host header sólo con candidatos pequeños y baseline."),
    "web_recon": ("DIRIGIDA", "Web recon", "Redirects, fingerprint, robots.txt y .well-known sobre un host."),
    "crawler": ("ACTIVA LIMITADA", "Controlled crawler", "BFS acotado, same-scope, sin submit de forms ni métodos destructivos."),
    "burp_proxy": ("TIEMPO REAL", "Burp Proxy", "Tráfico HTTP observado en Burp Proxy e ingerido por Negro."),
    "burp_repeater": ("TIEMPO REAL", "Burp Repeater", "Requests/responses probados manualmente en Burp Repeater."),
    "burp_other": ("TIEMPO REAL", "Burp traffic", "Tráfico observado por otras herramientas de Burp."),
    "lead_engine": ("LOCAL", "Correlation & Lead Engine", "Correlaciona evidencia para generar hipótesis accionables; no confirma findings."),
    "ai_target": ("OPCIONAL", "AI target triage", "Prioriza leads y explica pruebas concretas; requiere estimación y confirmación de costo."),
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


def normalize_scope(scope: str) -> str | None:
    scope = str(scope or "").strip().lower().rstrip(".")
    if scope.startswith("http://") or scope.startswith("https://"):
        try:
            scope = urllib.parse.urlsplit(scope).hostname or ""
        except Exception:
            return None
    if scope.startswith("*."):
        scope = scope[2:]
    if not scope or " " in scope or "/" in scope:
        return None
    return scope


def normalize_scopes(scopes: Iterable[str] | None, fallback_domain: str | None = None) -> list[str]:
    values: list[str] = []
    for item in scopes or []:
        value = normalize_scope(item)
        if value and value not in values:
            values.append(value)
    fallback = normalize_scope(fallback_domain or "")
    if fallback and fallback not in values:
        values.insert(0, fallback)
    return values


def host_matches_scope(host: str, scope: str) -> bool:
    host = str(host or "").strip().lower().rstrip(".")
    scope = normalize_scope(scope) or ""
    return bool(host and scope and (host == scope or host.endswith("." + scope)))


def normalize_host(host: str, domain: str, scopes: Iterable[str] | None = None) -> str | None:
    host = host.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    roots = normalize_scopes(scopes, domain)
    if any(host_matches_scope(host, root) for root in roots):
        return host
    return None


def normalize_hosts(hosts: Iterable[str], domain: str, scopes: Iterable[str] | None = None) -> list[str]:
    values = set()
    for host in hosts:
        value = normalize_host(host, domain, scopes)
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


def workspace_state(paths: dict[str, Path]) -> dict:
    try:
        if paths["state_file"].exists():
            raw = json.loads(paths["state_file"].read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
    except Exception:
        pass
    return {}


def workspace_scopes(paths: dict[str, Path], fallback_domain: str) -> list[str]:
    state = workspace_state(paths)
    return normalize_scopes(state.get("scopes") if isinstance(state.get("scopes"), list) else [], fallback_domain)


def workspace_project_name(paths: dict[str, Path], fallback_domain: str) -> str:
    state = workspace_state(paths)
    return str(state.get("project_name") or fallback_domain)


def db_connect(paths: dict[str, Path]) -> sqlite3.Connection:
    conn = sqlite3.connect(paths["db_file"], timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # SQLite remains a good fit for a local-first single-hunter workspace. WAL +
    # a busy timeout make simultaneous Burp ingestion and UI reads far less brittle.
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA temp_store = MEMORY")
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

            CREATE TABLE IF NOT EXISTS evidence_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type TEXT NOT NULL,
                entity_id INTEGER NOT NULL,
                kind TEXT NOT NULL DEFAULT 'image',
                original_name TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                mime_type TEXT,
                caption TEXT,
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

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dedupe_key TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',
                title TEXT NOT NULL,
                message TEXT,
                source TEXT NOT NULL DEFAULT 'engine',
                entity_type TEXT,
                entity_id INTEGER,
                resource_id INTEGER,
                operation_id INTEGER,
                exchange_id INTEGER,
                data_json TEXT,
                occurrences INTEGER NOT NULL DEFAULT 1,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                read_at TEXT
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

            CREATE TABLE IF NOT EXISTS resource_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource_id INTEGER NOT NULL,
                method TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 1,
                last_status INTEGER,
                authenticated_observed INTEGER NOT NULL DEFAULT 0,
                request_content_type TEXT,
                response_content_type TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(resource_id, method),
                FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS operation_sources (
                operation_id INTEGER NOT NULL,
                source TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (operation_id, source),
                FOREIGN KEY(operation_id) REFERENCES resource_operations(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS http_exchanges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_id INTEGER NOT NULL,
                source TEXT NOT NULL,
                tool TEXT,
                status_code INTEGER,
                request_hash TEXT NOT NULL,
                response_hash TEXT,
                fingerprint TEXT NOT NULL,
                request_b64 TEXT,
                response_b64 TEXT,
                request_size INTEGER NOT NULL DEFAULT 0,
                response_size INTEGER NOT NULL DEFAULT 0,
                request_headers_json TEXT,
                response_headers_json TEXT,
                query_json TEXT,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 1,
                UNIQUE(operation_id, fingerprint),
                FOREIGN KEY(operation_id) REFERENCES resource_operations(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS burp_repeater_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource_id INTEGER NOT NULL,
                method TEXT NOT NULL DEFAULT 'GET',
                url TEXT NOT NULL,
                request_b64 TEXT,
                caption TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                claimed_at TEXT,
                finished_at TEXT,
                error TEXT,
                FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE
            );

            -- v0.20: a Signal is machine evidence; a human state is the hunter's decision.
            CREATE TABLE IF NOT EXISTS entity_states (
                entity_type TEXT NOT NULL,
                entity_id INTEGER NOT NULL,
                state TEXT NOT NULL DEFAULT 'normal',
                category TEXT,
                note TEXT,
                source TEXT NOT NULL DEFAULT 'manual',
                updated_at TEXT NOT NULL,
                PRIMARY KEY(entity_type, entity_id)
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
                dismissed_at TEXT,
                FOREIGN KEY(exchange_id) REFERENCES http_exchanges(id) ON DELETE CASCADE,
                FOREIGN KEY(operation_id) REFERENCES resource_operations(id) ON DELETE CASCADE,
                FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS evidence_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                exchange_id INTEGER NOT NULL,
                resource_id INTEGER NOT NULL,
                human_state TEXT NOT NULL,
                request_hash TEXT,
                response_hash TEXT,
                request_zlib BLOB,
                response_zlib BLOB,
                request_size INTEGER NOT NULL DEFAULT 0,
                response_size INTEGER NOT NULL DEFAULT 0,
                observed_at TEXT,
                created_at TEXT NOT NULL,
                note TEXT,
                UNIQUE(exchange_id, human_state, request_hash, response_hash),
                FOREIGN KEY(exchange_id) REFERENCES http_exchanges(id) ON DELETE CASCADE,
                FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE
            );

            -- Foundation for Follow Value / Parameter Explorer (next phase).
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
                UNIQUE(exchange_id, normalized_name, location, value_hash),
                FOREIGN KEY(exchange_id) REFERENCES http_exchanges(id) ON DELETE CASCADE,
                FOREIGN KEY(operation_id) REFERENCES resource_operations(id) ON DELETE CASCADE,
                FOREIGN KEY(resource_id) REFERENCES resources(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',
                status TEXT NOT NULL DEFAULT 'draft',
                description TEXT,
                impact TEXT,
                remediation TEXT,
                source TEXT NOT NULL DEFAULT 'manual',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS finding_entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id INTEGER NOT NULL,
                relation TEXT NOT NULL DEFAULT 'affected',
                created_at TEXT NOT NULL,
                UNIQUE(finding_id, entity_type, entity_id, relation),
                FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS finding_retests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                result TEXT NOT NULL,
                notes TEXT,
                tested_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS finding_retest_entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                retest_id INTEGER NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id INTEGER NOT NULL,
                relation TEXT NOT NULL DEFAULT 'evidence',
                created_at TEXT NOT NULL,
                UNIQUE(retest_id, entity_type, entity_id, relation),
                FOREIGN KEY(retest_id) REFERENCES finding_retests(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_events_entity ON events(entity_type, entity_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_inspections_host ON host_inspections(host_id, observed_at);
            CREATE INDEX IF NOT EXISTS idx_resources_host ON resources(host_id);
            CREATE INDEX IF NOT EXISTS idx_hosts_review ON hosts(review_state, classification);
            CREATE INDEX IF NOT EXISTS idx_resources_review ON resources(review_state, classification);
            CREATE INDEX IF NOT EXISTS idx_observations_entity ON observations(entity_type, entity_id, observed_at);
            CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(read_at, last_seen_at);
            CREATE INDEX IF NOT EXISTS idx_notifications_entity ON notifications(entity_type, entity_id, last_seen_at);
            CREATE INDEX IF NOT EXISTS idx_js_assets_host ON js_assets(host_id, discovered_at);
            CREATE INDEX IF NOT EXISTS idx_ai_asset ON ai_analyses(js_asset_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_entity_states_state ON entity_states(state, entity_type, updated_at);
            CREATE INDEX IF NOT EXISTS idx_signal_occurrences_resource ON signal_occurrences(resource_id, reviewed_at, last_seen_at);
            CREATE INDEX IF NOT EXISTS idx_signal_occurrences_exchange ON signal_occurrences(exchange_id, kind);
            CREATE INDEX IF NOT EXISTS idx_evidence_snapshots_resource ON evidence_snapshots(resource_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_parameter_observations_name ON parameter_observations(normalized_name, resource_id);
            CREATE INDEX IF NOT EXISTS idx_parameter_observations_value ON parameter_observations(value_hash, resource_id);
            CREATE INDEX IF NOT EXISTS idx_operations_resource ON resource_operations(resource_id, method);
            CREATE INDEX IF NOT EXISTS idx_http_exchanges_operation ON http_exchanges(operation_id, last_seen_at);
            CREATE INDEX IF NOT EXISTS idx_burp_queue_status ON burp_repeater_queue(status, created_at);
            CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status, severity, updated_at);
            CREATE INDEX IF NOT EXISTS idx_finding_entities ON finding_entities(finding_id, entity_type, entity_id);
            CREATE INDEX IF NOT EXISTS idx_finding_retests ON finding_retests(finding_id, tested_at);
            CREATE INDEX IF NOT EXISTS idx_finding_retest_entities ON finding_retest_entities(retest_id, entity_type, entity_id);
            """
        )
        try:
            conn.execute("PRAGMA journal_mode = WAL")
        except sqlite3.DatabaseError:
            pass

        # Conservative schema migration for workspaces created by v0.3/v0.4.
        host_cols = {row["name"] for row in conn.execute("PRAGMA table_info(hosts)")}
        resource_cols = {row["name"] for row in conn.execute("PRAGMA table_info(resources)")}
        if "priority" not in host_cols:
            conn.execute("ALTER TABLE hosts ADD COLUMN priority TEXT NOT NULL DEFAULT 'none'")
        if "priority" not in resource_cols:
            conn.execute("ALTER TABLE resources ADD COLUMN priority TEXT NOT NULL DEFAULT 'none'")
        finding_cols = {row["name"] for row in conn.execute("PRAGMA table_info(findings)")}
        if "source" not in finding_cols:
            conn.execute("ALTER TABLE findings ADD COLUMN source TEXT NOT NULL DEFAULT 'manual'")

        js_cols = {row["name"] for row in conn.execute("PRAGMA table_info(js_assets)")}
        if "sourcemap_analysis_json" not in js_cols:
            conn.execute("ALTER TABLE js_assets ADD COLUMN sourcemap_analysis_json TEXT")
        if "sourcemap_path" not in js_cols:
            conn.execute("ALTER TABLE js_assets ADD COLUMN sourcemap_path TEXT")
        if "sourcemap_analyzed_at" not in js_cols:
            conn.execute("ALTER TABLE js_assets ADD COLUMN sourcemap_analyzed_at TEXT")

        # Intelligence + local search schemas are additive and conservative.
        import negro_hunter as hunter
        hunter.init_schema(conn)
        try:
            import negro_search as search_index
            search_index.init_schema(conn)
        except Exception as exc:
            # Search must never prevent the core workspace from opening. The Search
            # page surfaces an actionable error if the local SQLite lacks FTS5.
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('search_init_error',?)", (str(exc)[:500],))
        try:
            import negro_identity as identity_tools
            identity_tools.init_schema(conn)
        except Exception as exc:
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('identity_init_error',?)", (str(exc)[:500],))
        try:
            import negro_flows as flow_tools
            flow_tools.init_schema(conn)
        except Exception as exc:
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('flow_init_error',?)", (str(exc)[:500],))
        try:
            import negro_objects as object_tools
            object_tools.init_schema(conn)
            memory_stamp = conn.execute("SELECT value FROM meta WHERE key='identifier_memory_v1_built_at'").fetchone()
            param_count = int(conn.execute("SELECT COUNT(*) c FROM parameter_observations").fetchone()["c"] or 0)
            indexed_count = int(conn.execute("SELECT COUNT(*) c FROM identifier_observation_index").fetchone()["c"] or 0)
            if param_count and (not memory_stamp or indexed_count == 0):
                object_tools.rebuild_identifier_index(conn)
                conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('identifier_memory_v1_built_at',?)", (now_iso(),))
        except Exception as exc:
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('object_init_error',?)", (str(exc)[:500],))

        try:
            import negro_custom_signals as custom_signals
            custom_signals.init_schema(conn)
        except Exception as exc:
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('custom_signal_init_error',?)", (str(exc)[:500],))

        # Conservative v0.20 backfill: existing exchange-bound notifications were
        # automatic observations too. Preserve their read/unread status as the best
        # migration hint for reviewed/unreviewed Signals without rewriting history.
        conn.execute(
            """INSERT OR IGNORE INTO signal_occurrences(
                   dedupe_key,exchange_id,operation_id,resource_id,kind,category,severity,title,
                   why_json,evidence_json,source,occurrences,first_seen_at,last_seen_at,reviewed_at
               )
               SELECT n.dedupe_key || ':exchange:' || n.exchange_id, n.exchange_id, n.operation_id, n.resource_id,
                      n.kind, n.kind, n.severity, n.title, NULL, n.data_json, n.source,
                      COALESCE(n.occurrences,1), n.first_seen_at, n.last_seen_at, n.read_at
               FROM notifications n
               WHERE n.exchange_id IS NOT NULL"""
        )

        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('domain', ?)", (domain,))
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('version', ?)", (VERSION,))


def get_human_state(conn: sqlite3.Connection, entity_type: str, entity_id: int) -> dict:
    row = conn.execute(
        "SELECT * FROM entity_states WHERE entity_type=? AND entity_id=?",
        (entity_type, int(entity_id)),
    ).fetchone()
    return dict(row) if row else {"entity_type": entity_type, "entity_id": int(entity_id), "state": "normal", "category": None, "note": None, "source": None, "updated_at": None}


def _snapshot_exchange(conn: sqlite3.Connection, exchange_id: int, state: str, note: str | None = None) -> int | None:
    """Freeze the exact bytes that justified an important human decision."""
    if state not in {"interesting", "correlate", "finding"}:
        return None
    import base64
    import zlib
    row = conn.execute(
        """SELECT e.*,o.resource_id FROM http_exchanges e
           JOIN resource_operations o ON o.id=e.operation_id WHERE e.id=?""",
        (int(exchange_id),),
    ).fetchone()
    if not row:
        return None

    def packed(value):
        if not value:
            return None
        try:
            return sqlite3.Binary(zlib.compress(base64.b64decode(value, validate=False), 6))
        except Exception:
            return None

    cur = conn.execute(
        """INSERT OR IGNORE INTO evidence_snapshots(
               exchange_id,resource_id,human_state,request_hash,response_hash,request_zlib,response_zlib,
               request_size,response_size,observed_at,created_at,note
           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (int(exchange_id), int(row["resource_id"]), state, row["request_hash"], row["response_hash"],
         packed(row["request_b64"]), packed(row["response_b64"]), int(row["request_size"] or 0),
         int(row["response_size"] or 0), row["first_seen_at"], now_iso(), (note or "")[:2000]),
    )
    if cur.rowcount == 1:
        return int(cur.lastrowid)
    existing = conn.execute(
        """SELECT id FROM evidence_snapshots WHERE exchange_id=? AND human_state=?
           AND COALESCE(request_hash,'')=COALESCE(?, '') AND COALESCE(response_hash,'')=COALESCE(?, '')""",
        (int(exchange_id), state, row["request_hash"], row["response_hash"]),
    ).fetchone()
    return int(existing["id"]) if existing else None


def set_human_state(conn: sqlite3.Connection, entity_type: str, entity_id: int, state: str, *, category: str | None = None, note: str | None = None, source: str = "manual", snapshot_exchange_id: int | None = None) -> dict:
    if state not in HUMAN_STATES:
        raise ValueError(f"Estado humano inválido: {state}")
    ts = now_iso()
    conn.execute(
        """INSERT INTO entity_states(entity_type,entity_id,state,category,note,source,updated_at)
           VALUES(?,?,?,?,?,?,?)
           ON CONFLICT(entity_type,entity_id) DO UPDATE SET
             state=excluded.state,category=excluded.category,note=excluded.note,source=excluded.source,updated_at=excluded.updated_at""",
        (entity_type, int(entity_id), state, (category or "")[:120] or None, (note or "")[:2000] or None, source[:80], ts),
    )
    # Calling set_human_state for an exchange is an explicit human review action.
    # Even choosing Normal means "I looked at this", so pending cyan Signals must
    # stop presenting themselves as unreviewed without being discarded/deleted.
    if entity_type == "exchange":
        conn.execute("UPDATE signal_occurrences SET reviewed_at=COALESCE(reviewed_at,?) WHERE exchange_id=?", (ts, int(entity_id)))
    snapshot_id = None
    if snapshot_exchange_id or entity_type == "exchange":
        snapshot_id = _snapshot_exchange(conn, snapshot_exchange_id or int(entity_id), state, note)
    result = get_human_state(conn, entity_type, entity_id)
    result["snapshot_id"] = snapshot_id
    return result


def unreviewed_signal_count(conn: sqlite3.Connection, *, resource_id: int | None = None, exchange_id: int | None = None) -> int:
    sql = "SELECT COUNT(*) c FROM signal_occurrences WHERE reviewed_at IS NULL AND dismissed_at IS NULL"
    params: list[object] = []
    if resource_id is not None:
        sql += " AND resource_id=?"
        params.append(int(resource_id))
    if exchange_id is not None:
        sql += " AND exchange_id=?"
        params.append(int(exchange_id))
    return int(conn.execute(sql, params).fetchone()["c"] or 0)


def ensure_workspace(workspace: Path, domain: str, *, scopes: Iterable[str] | None = None, project_name: str | None = None) -> dict[str, Path]:
    paths = workspace_paths(workspace)
    for key in ("raw", "normalized", "delta", "inventory", "notes"):
        paths[key].mkdir(parents=True, exist_ok=True)

    normalized_domain = normalize_scope(domain) or str(domain).strip().lower().rstrip(".")
    requested_scopes = normalize_scopes(scopes, normalized_domain)
    if paths["state_file"].exists():
        state = json.loads(paths["state_file"].read_text(encoding="utf-8"))
        existing_domain = normalize_scope(state.get("domain") or "")
        existing_scopes = normalize_scopes(state.get("scopes") if isinstance(state.get("scopes"), list) else [], existing_domain or normalized_domain)
        if existing_domain and existing_domain != normalized_domain and normalized_domain not in existing_scopes:
            raise RuntimeError(f"Este workspace pertenece a {existing_domain}, no a {normalized_domain}")
        if scopes is None:
            requested_scopes = existing_scopes
    else:
        state = {"domain": normalized_domain, "version": VERSION}

    state["domain"] = normalized_domain
    state["project_name"] = str(project_name or state.get("project_name") or normalized_domain).strip()[:120]
    state["scopes"] = requested_scopes
    state["version"] = VERSION
    paths["state_file"].write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if not paths["inventory_file"].exists():
        paths["inventory_file"].write_text("", encoding="utf-8")
    if not paths["provenance_file"].exists():
        paths["provenance_file"].write_text("{}\n", encoding="utf-8")

    init_db(paths, normalized_domain)
    with db_connect(paths) as conn:
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('project_name',?)", (state["project_name"],))
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('scopes_json',?)", (json.dumps(requested_scopes),))
    migrate_existing_workspace(paths, normalized_domain)
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


def canonicalize_url(raw_url: str, domain: str, scopes: Iterable[str] | None = None) -> tuple[str, str, str, str, str] | None:
    raw_url = raw_url.strip()
    if not raw_url:
        return None
    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except ValueError:
        return None
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return None
    host = normalize_host(parsed.hostname, domain, scopes)
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


def upsert_resource(conn: sqlite3.Connection, raw_url: str, source: str, domain: str, scopes: Iterable[str] | None = None) -> tuple[bool, bool]:
    normalized = canonicalize_url(raw_url, domain, scopes)
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


def upsert_http_observation(
    paths: dict[str, Path],
    domain: str,
    *,
    url: str,
    method: str,
    source: str,
    status_code: int | None = None,
    authenticated: bool = False,
    request_content_type: str | None = None,
    response_content_type: str | None = None,
    tool: str | None = None,
    request_b64: str | None = None,
    response_b64: str | None = None,
    request_headers: list[dict] | None = None,
    response_headers: list[dict] | None = None,
    query: dict | list | str | None = None,
    response_body_b64: str | None = None,
) -> dict:
    """Ingesta HTTP sin duplicar el recurso por método.

    Para tráfico Burp, el recurso se modela por scheme+host+path. Los métodos
    observados viven como operaciones hijas y los intercambios exactos se
    deduplican conservando first/last seen y seen_count.
    """
    import base64
    import hashlib

    method = (method or "GET").strip().upper()[:24]
    source = (source or "burp_other").strip()[:64]
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL HTTP inválida")
    scopes = workspace_scopes(paths, domain)
    host = normalize_host(parsed.hostname, domain, scopes)
    if not host:
        raise ValueError(f"Host fuera de scope para el proyecto ({', '.join(scopes)})")
    netloc = host + (f":{parsed.port}" if parsed.port else "")
    path = parsed.path or "/"
    resource_url = urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))
    ts = now_iso()

    def raw_bytes(value: str | None) -> bytes:
        if not value:
            return b""
        try:
            return base64.b64decode(value, validate=False)
        except Exception:
            return b""

    req = raw_bytes(request_b64)
    resp = raw_bytes(response_b64)
    req_hash = hashlib.sha256(req).hexdigest() if req else hashlib.sha256((method + " " + resource_url).encode()).hexdigest()
    resp_hash = hashlib.sha256(resp).hexdigest() if resp else ""
    fingerprint = hashlib.sha256((req_hash + ":" + resp_hash + ":" + str(status_code or "")).encode()).hexdigest()

    with db_connect(paths) as conn:
        _, created_resource = upsert_resource(conn, resource_url, source, domain, scopes)
        r = conn.execute("SELECT id, host_id FROM resources WHERE url=?", (resource_url,)).fetchone()
        resource_id = int(r["id"])
        host_id = int(r["host_id"])
        op = conn.execute("SELECT * FROM resource_operations WHERE resource_id=? AND method=?", (resource_id, method)).fetchone()
        operation_created = op is None
        if op is None:
            cur = conn.execute(
                """INSERT INTO resource_operations(resource_id, method, first_seen_at, last_seen_at, seen_count, last_status, authenticated_observed, request_content_type, response_content_type, created_at, updated_at)
                   VALUES(?,?,?,?,1,?,?,?,?,?,?)""",
                (resource_id, method, ts, ts, status_code, 1 if authenticated else 0, request_content_type, response_content_type, ts, ts),
            )
            operation_id = int(cur.lastrowid)
        else:
            operation_id = int(op["id"])
            conn.execute(
                """UPDATE resource_operations SET last_seen_at=?, seen_count=seen_count+1,
                   last_status=COALESCE(?, last_status), authenticated_observed=MAX(authenticated_observed, ?),
                   request_content_type=COALESCE(?, request_content_type), response_content_type=COALESCE(?, response_content_type), updated_at=?
                   WHERE id=?""",
                (ts, status_code, 1 if authenticated else 0, request_content_type, response_content_type, ts, operation_id),
            )
        src = conn.execute("SELECT seen_count FROM operation_sources WHERE operation_id=? AND source=?", (operation_id, source)).fetchone()
        if src:
            conn.execute("UPDATE operation_sources SET last_seen_at=?, seen_count=seen_count+1 WHERE operation_id=? AND source=?", (ts, operation_id, source))
        else:
            conn.execute("INSERT INTO operation_sources(operation_id, source, first_seen_at, last_seen_at, seen_count) VALUES(?,?,?,?,1)", (operation_id, source, ts, ts))

        ex = conn.execute("SELECT id FROM http_exchanges WHERE operation_id=? AND fingerprint=?", (operation_id, fingerprint)).fetchone()
        exchange_created = ex is None
        if ex:
            exchange_id = int(ex["id"])
            conn.execute("UPDATE http_exchanges SET last_seen_at=?, seen_count=seen_count+1, status_code=COALESCE(?,status_code) WHERE id=?", (ts, status_code, exchange_id))
        else:
            cur = conn.execute(
                """INSERT INTO http_exchanges(operation_id, source, tool, status_code, request_hash, response_hash, fingerprint, request_b64, response_b64, request_size, response_size, request_headers_json, response_headers_json, query_json, first_seen_at, last_seen_at, seen_count)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (operation_id, source, tool, status_code, req_hash, resp_hash or None, fingerprint, request_b64, response_b64, len(req), len(resp),
                 json.dumps(request_headers or [], ensure_ascii=False), json.dumps(response_headers or [], ensure_ascii=False), json.dumps(query if query is not None else parsed.query, ensure_ascii=False), ts, ts),
            )
            exchange_id = int(cur.lastrowid)

        ctype = (response_content_type or "").lower()
        is_js = path.lower().endswith((".js", ".mjs")) or "javascript" in ctype or "ecmascript" in ctype
        js_created = False
        if is_js and response_body_b64:
            try:
                body = base64.b64decode(response_body_b64, validate=False)
            except Exception:
                body = b""
            if body:
                js_dir = paths["raw"] / "burp_js"
                js_dir.mkdir(parents=True, exist_ok=True)
                sha = hashlib.sha256(body).hexdigest()
                local = js_dir / f"{sha[:20]}.js"
                if not local.exists():
                    local.write_bytes(body)
                cur = conn.execute(
                    """INSERT OR IGNORE INTO js_assets(host_id, url, source, size_bytes, sha256, local_path, discovered_at) VALUES(?,?,?,?,?,?,?)""",
                    (host_id, resource_url, source, len(body), sha, str(local), ts),
                )
                js_created = cur.rowcount == 1

        conn.execute("UPDATE resources SET updated_at=? WHERE id=?", (ts, resource_id))
        conn.execute("UPDATE hosts SET updated_at=? WHERE id=?", (ts, host_id))

    return {
        "host_id": host_id, "resource_id": resource_id, "operation_id": operation_id, "exchange_id": exchange_id,
        "resource_created": created_resource, "operation_created": operation_created, "exchange_created": exchange_created, "js_created": js_created,
        "resource_url": resource_url, "method": method, "source": source,
        # Exact provenance for Burp-side annotation sync. These are hashes of the
        # exact request/response bytes that were persisted for this exchange.
        "request_hash": req_hash, "response_hash": resp_hash,
    }


def http_inventory_stats(paths: dict[str, Path]) -> dict[str, int]:
    with db_connect(paths) as conn:
        return {
            "operations": conn.execute("SELECT COUNT(*) c FROM resource_operations").fetchone()["c"],
            "http_exchanges": conn.execute("SELECT COUNT(*) c FROM http_exchanges").fetchone()["c"],
            "js_assets": conn.execute("SELECT COUNT(*) c FROM js_assets").fetchone()["c"],
        }


def migrate_existing_workspace(paths: dict[str, Path], domain: str) -> None:
    """Importa inventarios históricos sin borrar ni alterar estados/notas existentes."""
    scopes=workspace_scopes(paths, domain)
    imported = set()
    with db_connect(paths) as conn:
        for source in HOST_SOURCE_ORDER:
            path = source_host_file(paths, source)
            if path.exists():
                for host in normalize_hosts(read_lines(path), domain, scopes):
                    upsert_host(conn, host, source)
                    imported.add(host)

            if source.startswith("gau_") or source in {"wayback_cdx", "urlscan_direct", "github_code", "js_local", "sourcemap"}:
                url_path = source_url_file(paths, source)
                if url_path.exists():
                    for url in read_lines(url_path):
                        upsert_resource(conn, url, source, domain, scopes)

        for host in normalize_hosts(read_lines(paths["inventory_file"]), domain, scopes):
            if host not in imported:
                upsert_host(conn, host, "legacy_inventory")


def rebuild_inventory(paths: dict[str, Path], domain: str) -> tuple[int, dict[str, int]]:
    scopes=workspace_scopes(paths, domain)
    source_sets: dict[str, set[str]] = {}
    for source in HOST_SOURCE_ORDER:
        source_sets[source] = set(normalize_hosts(read_lines(source_host_file(paths, source)), domain, scopes))

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
    legacy = set(normalize_hosts(read_lines(paths["inventory_file"]), domain, scopes))
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
    intel: dict[str, dict[str, object]] = {}
    for entry in data:
        names: list[str] = []
        for field in ("name_value", "common_name"):
            value = entry.get(field)
            if isinstance(value, str):
                raw_names = [x.strip() for x in value.splitlines() if x.strip()]
                hosts.extend(raw_names)
                names.extend(raw_names)
        entry_seen = str(entry.get("entry_timestamp") or entry.get("not_before") or "")
        not_before = str(entry.get("not_before") or "")
        not_after = str(entry.get("not_after") or "")
        issuer = str(entry.get("issuer_name") or "").strip()
        cert_id = str(entry.get("id") or entry.get("min_cert_id") or entry.get("serial_number") or "")
        for original in names:
            cleaned = original.lstrip("*.").lower().rstrip(".")
            host = normalize_host(cleaned, domain)
            if not host:
                continue
            item = intel.setdefault(host, {"hostname":host,"first_seen":None,"last_seen":None,"not_before_min":None,"not_after_max":None,"certificate_ids":set(),"issuers":set(),"wildcard":False})
            if original.startswith("*."):
                item["wildcard"] = True
            for key, value, fn in (("first_seen", entry_seen, min), ("last_seen", entry_seen, max), ("not_before_min", not_before, min), ("not_after_max", not_after, max)):
                if value:
                    current = item.get(key)
                    item[key] = value if not current else fn(str(current), value)
            if cert_id:
                item["certificate_ids"].add(cert_id)
            if issuer:
                item["issuers"].add(issuer)
    serializable: list[dict[str, object]] = []
    for host, item in sorted(intel.items()):
        certs = sorted(item.pop("certificate_ids"))
        issuers = sorted(item.pop("issuers"))
        item["certificate_count"] = len(certs)
        item["certificate_ids_sample"] = certs[:20]
        item["issuers"] = issuers[:20]
        serializable.append(item)
    (paths["raw"] / "crtsh-intelligence.json").write_text(json.dumps({"domain":domain,"hosts":serializable,"generated_at":now_iso()}, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
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


def persist_crtsh_intelligence(domain: str, paths: dict[str, Path]) -> int:
    path = paths["raw"] / "crtsh-intelligence.json"
    if not path.exists():
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    count = 0
    with db_connect(paths) as conn:
        for item in data.get("hosts", []) if isinstance(data, dict) else []:
            if not isinstance(item, dict):
                continue
            host = normalize_host(str(item.get("hostname") or ""), domain)
            if not host:
                continue
            host_id, _ = upsert_host(conn, host, "crtsh")
            record_observation(conn, "host", host_id, "crtsh", "ct_intelligence", host, item)
            count += 1
    return count


def ct_intelligence(paths: dict[str, Path], limit: int = 500) -> dict:
    rows: list[dict] = []
    with db_connect(paths) as conn:
        for row in conn.execute("SELECT o.payload_json FROM observations o WHERE o.kind='ct_intelligence' ORDER BY o.id DESC LIMIT ?", (limit,)):
            try:
                p = json.loads(row["payload_json"] or "{}")
            except Exception:
                continue
            if isinstance(p, dict) and p.get("hostname"):
                rows.append(p)
    # Last observation for a hostname wins, then show newest CT sightings first.
    merged: dict[str, dict] = {}
    for item in rows:
        merged.setdefault(str(item.get("hostname")), item)
    items = list(merged.values())
    items.sort(key=lambda x: str(x.get("last_seen") or ""), reverse=True)
    return {"hosts":items,"total":len(items),"wildcards":sum(1 for x in items if x.get("wildcard"))}


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
        if source == "crtsh":
            persist_crtsh_intelligence(domain, paths)
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
                host_created, resource_created = upsert_resource(conn, canonical, source, domain, scopes)
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
    scopes = workspace_scopes(paths, domain)
    normalized = normalize_host(hostname, domain, scopes)
    if not normalized:
        raise RuntimeError(f"{hostname} no pertenece al proyecto ({', '.join(scopes)})")

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
    scopes = workspace_scopes(paths, domain)
    normalized_urls: list[str] = []
    hosts: set[str] = set()
    new_hosts = 0
    new_resources = 0
    with db_connect(paths) as conn:
        for raw_url in urls:
            parsed = canonicalize_url(str(raw_url), domain, scopes)
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
        if source == "crtsh":
            persist_crtsh_intelligence(domain, paths)
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
    scopes=workspace_scopes(paths, domain)
    hostname = normalize_host(hostname, domain, scopes) or ""
    if not hostname:
        raise RuntimeError("Host fuera del target")
    result = intel.discover_js(hostname, domain, scopes=scopes, timeout=timeout)
    with db_connect(paths) as conn:
        host_id, _ = upsert_host(conn, hostname, "js_discovery")
        for url in result.get("in_scope", []):
            upsert_resource(conn, url, "js_discovery", domain, scopes)
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
    import negro_hunter as hunter
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
    scopes=workspace_scopes(paths, domain)
    local = intel.analyze_js_text(analysis_text, final_url, domain, scopes=scopes)
    sourcemap_url = None
    if local.get("source_maps"):
        # Keep one representative value for compatibility. fetch_sourcemap_for_asset
        # now tries every detected candidate and handles inline data: maps separately.
        candidates = list(local["source_maps"])
        external = [x for x in candidates if not str(x).lower().startswith("data:")]
        chosen = external[-1] if external else candidates[-1]
        sourcemap_url = chosen if str(chosen).lower().startswith("data:") else urllib.parse.urljoin(final_url, chosen)
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        conn.execute(
            "UPDATE js_assets SET size_bytes=?, sha256=?, local_path=?, sourcemap_url=?, local_analysis_json=?, analyzed_at=? WHERE id=?",
            (len(raw), sha, str(raw_path), sourcemap_url, json.dumps(local, ensure_ascii=False), now_iso(), asset_id),
        )
        host_id = int(row["host_id"])
        record_observation(conn, "host", host_id, "js_local", "js_analysis", row["url"], {"asset_id": asset_id, "size_bytes": len(raw), "content_type": content_type, "summary": {"in_scope_urls": len(local.get("in_scope_urls", [])), "relative_paths": len(local.get("relative_paths", [])), "websockets": len(local.get("websockets", [])), "source_maps": local.get("source_maps", []), "keywords": local.get("keywords", {})}})
        discovered_urls: list[str] = []
        new_urls: list[str] = []
        discovered_resource_ids: list[int] = []
        for url in local.get("in_scope_urls", []):
            normalized = canonicalize_url(url, domain, scopes)
            if not normalized:
                continue
            canonical = normalized[0]
            _, created = upsert_resource(conn, canonical, "js_local", domain, scopes)
            rr = conn.execute("SELECT id FROM resources WHERE url=?", (canonical,)).fetchone()
            if rr:
                discovered_resource_ids.append(int(rr["id"]))
            discovered_urls.append(canonical)
            if created:
                new_urls.append(canonical)
        for ws in local.get("websockets", []):
            record_observation(conn, "host", host_id, "js_local", "websocket", ws, None)

        # One aggregated event per analyzed asset.  The JS analyzer already knew
        # these routes; v0.17.1 makes that knowledge visible to the hunter instead
        # of silently adding rows to Resources.
        js_detector=hunter.detector_settings("js_sensitive_route", conn)
        sensitive_tokens=tuple(x.lower() for x in hunter.detector_rule_list("js_sensitive_route", "path_tokens", conn))
        ignore_tokens=tuple(x.lower() for x in hunter.detector_rule_list("js_sensitive_route", "ignore_tokens", conn))
        only_new_routes=hunter.detector_rule_bool("js_sensitive_route", "only_new_routes", conn, False)
        sensitive_urls = []
        new_url_set=set(new_urls)
        for candidate in discovered_urls:
            if only_new_routes and candidate not in new_url_set:
                continue
            low_path = (urllib.parse.urlsplit(candidate).path or "/").lower()
            if ignore_tokens and any(tok in low_path for tok in ignore_tokens):
                continue
            if any(tok in low_path for tok in sensitive_tokens):
                sensitive_urls.append(candidate)

        if discovered_urls:
            hunter._upsert_notification(
                conn,
                dedupe_key=f"js_surface:{asset_id}:{sha[:16]}",
                kind="javascript_surface",
                severity="medium" if sensitive_urls else "low",
                title="JavaScript amplió la superficie" if new_urls else "Rutas observadas en JavaScript",
                message=(
                    f"{len(discovered_urls)} ruta(s) in-scope · {len(new_urls)} nueva(s)"
                    + (f" · {len(sensitive_urls)} merece(n) revisión" if sensitive_urls else "")
                ),
                source="js_local",
                entity_type="host",
                entity_id=host_id,
                data={
                    "asset_id": asset_id,
                    "javascript_url": row["url"],
                    "routes_count": len(discovered_urls),
                    "new_routes_count": len(new_urls),
                    "interesting_routes": sensitive_urls[:20],
                    "resource_ids": discovered_resource_ids[:100],
                    "graph_focus": f"js:{asset_id}",
                    "href": f"host/{host_id}#javascript",
                },
                emit=True,
            )

        if sensitive_urls and js_detector["enabled"]:
            lead_result = hunter.upsert_lead(
                conn,
                lead_key=f"js_sensitive_routes:{asset_id}:{sha[:16]}",
                host_id=host_id,
                resource_id=None,
                lead_type="javascript_surface",
                title="JavaScript revela rutas que merecen revisión",
                confidence="high",
                review_priority="medium",
                evidence=[{
                    "source": "javascript",
                    "asset_id": asset_id,
                    "url": row["url"],
                    "routes": sensitive_urls[:30],
                    "node_ids": [f"js:{asset_id}"] + [f"resource:{x}" for x in discovered_resource_ids[:30]],
                }],
                why="El bundle contiene rutas in-scope con nombres asociados a administración, operaciones internas o acciones sensibles. Esto amplía superficie; no demuestra que estén desprotegidas.",
                next_test="Abre las rutas descubiertas desde Resources/Mapa, identifica su método y contexto legítimo, y revisa control de acceso sin hacer fuzzing masivo.",
                confirm_if="Una ruta revelada expone funcionalidad sensible con controles insuficientes o habilita una cadena adicional.",
                discard_if="Las rutas son públicas/esperadas o aplican autenticación y autorización server-side de forma consistente.",
                source="JS_LOCAL",
            )
            lead_id, created = lead_result
            if created:
                hunter._upsert_notification(
                    conn,
                    dedupe_key=f"hypothesis:new:{lead_id}",
                    kind="hypothesis",
                    severity="medium",
                    title="Nueva hipótesis · superficie desde JavaScript",
                    message=f"{len(sensitive_urls)} ruta(s) del bundle merecen revisión manual.",
                    source="js_local",
                    entity_type="host",
                    entity_id=host_id,
                    data={
                        "lead_id": lead_id,
                        "lead_type": "javascript_surface",
                        "graph_focus": f"lead:{lead_id}",
                        "href": f"hypotheses#hypothesis-{lead_id}",
                    },
                    emit=True,
                )
    rebuild_inventory(paths, domain)
    return {"asset_id": asset_id, "url": row["url"], "size_bytes": len(raw), "sha256": sha, "local_path": str(raw_path), "sourcemap_url": sourcemap_url, "analysis": local,
            "routes": {"in_scope": len(discovered_urls), "new": len(new_urls), "interesting": len(sensitive_urls)}}


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
    evidence_hash = __import__("hashlib").sha256(payload.encode("utf-8", errors="ignore")).hexdigest()
    estimate = intel.estimate_ai_cost(payload, selected_model, output_tokens, float(settings.get("usd_cop_rate", 0) or 0))
    estimate["payload_chars"] = len(payload)
    estimate["evidence_hash"] = evidence_hash
    estimate["task_type"] = "js_triage"
    with db_connect(paths) as conn:
        try:
            import negro_hunter as hunter
            hunter.init_schema(conn)
            cached = conn.execute("SELECT created_at FROM ai_tasks WHERE task_type='js_triage' AND evidence_hash=? AND model=? AND status='done'", (evidence_hash, selected_model)).fetchone()
        except Exception:
            cached = None
    estimate["cached"] = bool(cached)
    estimate["cache_created_at"] = cached["created_at"] if cached else None
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
    evidence_hash = __import__("hashlib").sha256(payload.encode("utf-8", errors="ignore")).hexdigest()
    estimate = intel.estimate_ai_cost(payload, selected_model, output_tokens, float(settings.get("usd_cop_rate", 0) or 0))
    estimate["source_map_included"] = bool(sourcemap)
    estimate["evidence_hash"] = evidence_hash
    estimate["task_type"] = "js_triage"
    try:
        import negro_hunter as hunter
        with db_connect(paths) as conn:
            hunter.init_schema(conn)
            cached = conn.execute("SELECT result_json,usage_json,created_at FROM ai_tasks WHERE task_type='js_triage' AND evidence_hash=? AND model=? AND status='done'", (evidence_hash, selected_model)).fetchone()
        if cached:
            result = json.loads(cached["result_json"] or "{}")
            original_usage = json.loads(cached["usage_json"] or "{}")
            usage = {**original_usage, "cache_hit": True, "cache_created_at": cached["created_at"], "actual_cost_usd": 0.0, "actual_cost_cop": 0.0}
            estimate["cached"] = True
            return {"asset_id": asset_id, "model": selected_model, "estimate": estimate, "usage": usage, "result": result, "cached": True}
    except Exception:
        pass
    result, usage = intel.run_openai_js_analysis(payload, model=selected_model, output_tokens=output_tokens)
    try:
        import negro_hunter as hunter
        usage.update(hunter.actual_ai_cost(usage, selected_model, float(settings.get("usd_cop_rate", 0) or 0)))
    except Exception:
        pass
    with db_connect(paths) as conn:
        try:
            import negro_hunter as hunter
            hunter.init_schema(conn)
            conn.execute("INSERT INTO ai_tasks(task_type,evidence_hash,model,status,estimate_json,usage_json,result_json,created_at) VALUES('js_triage',?,?, 'done',?,?,?,?) ON CONFLICT(task_type,evidence_hash,model) DO UPDATE SET status='done',estimate_json=excluded.estimate_json,usage_json=excluded.usage_json,result_json=excluded.result_json,created_at=excluded.created_at", (evidence_hash, selected_model, json.dumps(estimate), json.dumps(usage), json.dumps(result, ensure_ascii=False), now_iso()))
        except Exception:
            pass
        conn.execute(
            "INSERT INTO ai_analyses(js_asset_id, model, status, estimate_json, usage_json, result_json, created_at) VALUES(?, ?, 'done', ?, ?, ?, ?)",
            (asset_id, selected_model, json.dumps(estimate), json.dumps(usage), json.dumps(result, ensure_ascii=False), now_iso()),
        )
        record_observation(conn, "host", int(row["host_id"]), "ai_js", "ai_analysis", row["url"], {"asset_id": asset_id, "model": selected_model, "summary": result.get("summary"), "observation_count": len(result.get("observations", [])) if isinstance(result, dict) else 0, "source_map_included": bool(sourcemap)})
    return {"asset_id": asset_id, "model": selected_model, "estimate": estimate, "usage": usage, "result": result}

def policy_get(paths: dict[str, Path]) -> dict:
    import negro_hunter as hunter
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        return hunter.policy_summary(conn)


def policy_set(paths: dict[str, Path], profile: str) -> dict:
    import negro_hunter as hunter
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        result = hunter.set_policy(conn, profile)
        conn.commit()
        return result


def dns_recon(domain: str, paths: dict[str, Path], timeout: int = 20) -> dict:
    import negro_hunter as hunter
    started = now_iso()
    result = hunter.dns_infrastructure(domain, timeout=min(6, max(2, timeout / 5)))
    raw = paths["raw"] / "dns-recon.json"
    raw.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        root_id, _ = upsert_host(conn, domain, "dns_recon")
        record_observation(conn, "host", root_id, "dns_recon", "dns_infrastructure", None, result)
        for _, ptr_host in (result.get("records", {}).get("PTR", {}) or {}).items():
            normalized = normalize_host(str(ptr_host), domain)
            if normalized:
                upsert_host(conn, normalized, "reverse_dns")
                hunter.relationship(conn, "host", root_id, "reverse_ptr", "host", normalized, "dns_recon", {"ptr": ptr_host})
    rebuild_inventory(paths, domain)
    log_run(paths, "dns_recon", "ok", sum(len(v) if isinstance(v, list) else len(v) if isinstance(v, dict) else 0 for v in result.get("records", {}).values()), None, started)
    return {**result, "raw": str(raw)}


def axfr_recon(domain: str, paths: dict[str, Path], timeout: int = 25) -> dict:
    import negro_hunter as hunter
    started = now_iso()
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        hunter.assert_policy(conn, "axfr")
    infra = hunter.dns_infrastructure(domain, timeout=min(5, max(2, timeout / 5)))
    nameservers = infra.get("records", {}).get("NS", []) or []
    result = hunter.axfr_check(domain, nameservers, timeout=min(8, max(3, timeout / max(1, len(nameservers)))))
    raw = paths["raw"] / "axfr.json"
    raw.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    imported: set[str] = set()
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        root_id, _ = upsert_host(conn, domain, "axfr")
        record_observation(conn, "host", root_id, "axfr", "zone_transfer", None, result)
        for nsres in result.get("results", []):
            if nsres.get("status") != "success":
                continue
            for rec in nsres.get("records", []):
                name = normalize_host(str(rec.get("name", "")), domain)
                if name:
                    upsert_host(conn, name, "axfr")
                    imported.add(name)
                # Hostnames embedded in CNAME/MX/NS/SRV values are also useful.
                value = str(rec.get("value", ""))
                for token in re.findall(r"(?:[A-Za-z0-9_-]+\.)+%s" % re.escape(domain), value, re.I):
                    n = normalize_host(token, domain)
                    if n:
                        upsert_host(conn, n, "axfr")
                        imported.add(n)
    total, _ = rebuild_inventory(paths, domain)
    successes = sum(1 for x in result.get("results", []) if x.get("status") == "success")
    log_run(paths, "axfr", "ok" if successes else "empty", len(imported), None, started)
    return {**result, "nameservers": nameservers, "successful_nameservers": successes, "imported_hosts": sorted(imported), "inventory": total, "raw": str(raw)}


def smart_host_candidates(domain: str, paths: dict[str, Path], requested_limit: int | None = None) -> dict:
    import negro_hunter as hunter
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        policy = hunter.policy_summary(conn)
        known = [r["hostname"] for r in conn.execute("SELECT hostname FROM hosts ORDER BY hostname").fetchall()]
    limit = requested_limit or int(policy.get("active_dns_max_candidates", 25))
    limit = min(limit, int(policy.get("active_dns_max_candidates", limit)))
    candidates = hunter.generate_smart_host_candidates(domain, known, max_candidates=limit)
    return {"policy": policy, "known_hosts": len(known), "candidates": candidates, "count": len(candidates)}


def active_dns_smart(domain: str, paths: dict[str, Path], candidates: list[str] | None = None) -> dict:
    import negro_hunter as hunter
    started = now_iso()
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        policy = hunter.policy_summary(conn)
        if candidates is None:
            known = [r["hostname"] for r in conn.execute("SELECT hostname FROM hosts ORDER BY hostname").fetchall()]
            candidates = hunter.generate_smart_host_candidates(domain, known, int(policy.get("active_dns_max_candidates", 25)))
        hunter.assert_policy(conn, "active_dns", len(candidates))
    result = hunter.active_dns_validate(domain, candidates, delay_s=float(policy.get("active_dns_delay_s", 0.35)))
    found_hosts = [x.get("hostname") for x in result.get("found", []) if x.get("hostname")]
    total, delta = persist_host_source("active_dns", normalize_hosts(found_hosts, domain), domain, paths)
    with db_connect(paths) as conn:
        root_id, _ = upsert_host(conn, domain, "active_dns")
        record_observation(conn, "host", root_id, "active_dns", "smart_candidates", None, result)
    log_run(paths, "active_dns", "ok" if found_hosts else "empty", len(found_hosts), None, started)
    return {**result, "delta": delta, "inventory": total, "policy": policy}


def vhost_smart(domain: str, paths: dict[str, Path], base_url: str, candidates: list[str] | None = None) -> dict:
    import negro_hunter as hunter
    started = now_iso()
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        policy = hunter.policy_summary(conn)
        if candidates is None:
            known = [r["hostname"] for r in conn.execute("SELECT hostname FROM hosts ORDER BY hostname").fetchall()]
            candidates = hunter.generate_smart_host_candidates(domain, known, int(policy.get("vhost_max_candidates", 25)))
        candidates = [x for x in candidates if normalize_host(x, domain)]
        hunter.assert_policy(conn, "vhost", len(candidates))
    result = hunter.vhost_discover(base_url, candidates, delay_s=float(policy.get("vhost_delay_s", 0.45)))
    found = [x.get("hostname") for x in result.get("found", []) if x.get("hostname") and not x.get("error")]
    total, delta = persist_host_source("vhost", normalize_hosts(found, domain), domain, paths)
    with db_connect(paths) as conn:
        root_id, _ = upsert_host(conn, domain, "vhost")
        record_observation(conn, "host", root_id, "vhost", "smart_vhost", base_url, result)
    log_run(paths, "vhost", "ok" if found else "empty", len(found), None, started)
    return {**result, "delta": delta, "inventory": total, "policy": policy}


def web_recon_host(domain: str, paths: dict[str, Path], hostname: str, timeout: int = 30) -> dict:
    import negro_hunter as hunter
    hostname = normalize_host(hostname, domain) or ""
    if not hostname:
        raise RuntimeError("Host fuera del target")
    started = now_iso()
    result = hunter.web_recon(hostname, timeout=min(12, max(4, timeout / 3)))
    out_dir = paths["raw"] / "web-recon"
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = out_dir / f"{hostname}.json"
    raw.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    imported_urls: list[str] = []
    imported_hosts: set[str] = set()
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        host_id, _ = upsert_host(conn, hostname, "web_recon")
        record_observation(conn, "host", host_id, "web_recon", "web_recon", result.get("final_url"), result)
        final = urllib.parse.urlsplit(result.get("final_url") or f"https://{hostname}/")
        origin = urllib.parse.urlunsplit((final.scheme or "https", final.netloc or hostname, "", "", ""))
        robots = result.get("robots", {}) or {}
        for group in robots.get("groups", []) or []:
            for rule in group.get("rules", []) or []:
                path = str(rule.get("path") or "")
                if not path or path == "/":
                    continue
                url = urllib.parse.urljoin(origin + "/", path)
                if canonicalize_url(url, domain):
                    upsert_resource(conn, url, "robots", domain)
                    imported_urls.append(url)
        for sm in robots.get("sitemaps", []) or []:
            if canonicalize_url(str(sm), domain):
                upsert_resource(conn, str(sm), "robots_sitemap", domain)
                imported_urls.append(str(sm))
        for wk_path, wk in (result.get("well_known", {}) or {}).items():
            wk_url = urllib.parse.urljoin(origin + "/", wk_path)
            if canonicalize_url(wk_url, domain):
                upsert_resource(conn, wk_url, "well_known", domain)
                imported_urls.append(wk_url)
            data = wk.get("json") if isinstance(wk, dict) else None
            if isinstance(data, dict):
                # OpenID endpoints/issuer/JWKS are structured, high-value relationships.
                for key in ("issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri", "registration_endpoint", "end_session_endpoint"):
                    value = data.get(key)
                    if not isinstance(value, str):
                        continue
                    parsed = canonicalize_url(value, domain)
                    if parsed:
                        upsert_resource(conn, value, "well_known_oidc", domain)
                        imported_urls.append(value)
                        imported_hosts.add(parsed[1])
                        hunter.relationship(conn, "host", host_id, f"oidc_{key}", "url", value, "well_known", {"path":wk_path})
                # assetlinks.json shape is a list, handled below separately.
            if wk_path.endswith("assetlinks.json") and isinstance(data, list):
                for entry in data[:100]:
                    try:
                        package = entry.get("target", {}).get("package_name")
                    except Exception:
                        package = None
                    if package:
                        hunter.relationship(conn, "host", host_id, "android_package", "package", str(package), "assetlinks", entry)
        for new_host in imported_hosts:
            upsert_host(conn, new_host, "well_known_oidc")
    rebuild_inventory(paths, domain)
    log_run(paths, "web_recon", "ok", len(imported_urls), None, started)
    return {**result, "imported_urls": len(set(imported_urls)), "imported_hosts": sorted(imported_hosts), "raw": str(raw)}


def crawl_host(domain: str, paths: dict[str, Path], hostname: str, max_urls: int | None = None, max_depth: int | None = None, timeout: int = 30) -> dict:
    import negro_hunter as hunter
    started = now_iso()
    hostname = normalize_host(hostname, domain) or ""
    if not hostname:
        raise RuntimeError("Host fuera del target")
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        policy = hunter.policy_summary(conn)
    cap_urls = int(policy.get("crawl_max_urls", 200))
    cap_depth = int(policy.get("crawl_max_depth", 2))
    use_urls = min(max_urls or cap_urls, cap_urls)
    use_depth = min(max_depth if max_depth is not None else cap_depth, cap_depth)
    result = hunter.crawl(hostname, domain=domain, max_urls=use_urls, max_depth=use_depth, delay_s=float(policy.get("crawl_delay_s", 0.35)), respect_robots=True, timeout=min(12, max(4, timeout / 3)))
    out_dir = paths["raw"] / "crawl"
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = out_dir / f"{hostname}.json"
    raw.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    source = "crawler"
    all_urls = list(result.get("links", [])) + list(result.get("documents", [])) + list(result.get("js_files", []))
    new_hosts, new_resources, total = _persist_url_list(domain, paths, source, all_urls)
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        host_id, _ = upsert_host(conn, hostname, source)
        # Store a bounded summary as observation; full output remains in raw/.
        summary = dict(result)
        summary["external_urls"] = (summary.get("external_urls") or [])[:300]
        summary["comments"] = (summary.get("comments") or [])[:300]
        summary["forms"] = (summary.get("forms") or [])[:300]
        summary["pages"] = (summary.get("pages") or [])[:500]
        record_observation(conn, "host", host_id, source, "crawl_result", result.get("seed"), summary)
        for url in result.get("js_files", []) or []:
            parsed = canonicalize_url(url, domain)
            if parsed:
                conn.execute("INSERT OR IGNORE INTO js_assets(host_id,url,source,discovered_at) VALUES(?,?,?,?)", (host_id, url, source, now_iso()))
        for item in result.get("external_urls", [])[:300]:
            record_observation(conn, "host", host_id, source, "external_url", item, None)
        for email in result.get("emails", [])[:100]:
            record_observation(conn, "host", host_id, source, "email", email, None)
        for nh in result.get("new_hosts", []) or []:
            n = normalize_host(nh, domain)
            if n:
                upsert_host(conn, n, source)
                hunter.relationship(conn, "host", host_id, "links_to_host", "host", n, source, None)
    rebuild_inventory(paths, domain)
    log_run(paths, source, "ok", int(result.get("visited", 0)), None, started)
    return {**result, "new_hosts_count": new_hosts, "new_resources": new_resources, "inventory": total, "policy": policy, "raw": str(raw)}


def cors_check_host(domain: str, paths: dict[str, Path], hostname: str, url: str | None = None, timeout: int = 20) -> dict:
    import negro_hunter as hunter
    hostname = normalize_host(hostname, domain) or ""
    if not hostname:
        raise RuntimeError("Host fuera del target")
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        hunter.assert_policy(conn, "cors")
        host_id, _ = upsert_host(conn, hostname, "cors_probe")
    target_url = url or f"https://{hostname}/"
    parsed = canonicalize_url(target_url, domain)
    if not parsed:
        raise RuntimeError("La URL de CORS debe estar dentro del target")
    result = hunter.cors_probe(target_url, timeout=min(12, max(4, timeout / 2)))
    with db_connect(paths) as conn:
        record_observation(conn, "host", host_id, "cors_probe", "cors_probe", target_url, result)
    return result


def cors_check_resource(domain: str, paths: dict[str, Path], resource_id: int, timeout: int = 20) -> dict:
    """Run the CORS probe against one concrete resource and attach evidence to it."""
    import negro_hunter as hunter
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        hunter.assert_policy(conn, "cors")
        row = conn.execute(
            "SELECT r.id, r.url, r.host_id, h.hostname FROM resources r JOIN hosts h ON h.id=r.host_id WHERE r.id=?",
            (resource_id,),
        ).fetchone()
    if not row:
        raise RuntimeError("Recurso no encontrado")
    parsed = canonicalize_url(row["url"], domain)
    if not parsed:
        raise RuntimeError("La URL del recurso está fuera del target")
    # Prefer the latest real Burp request for this resource so authenticated
    # cookies/Authorization and other useful browsing context are preserved.
    replay_headers: dict[str, str] = {}
    replay_source = None
    replay_method = None
    with db_connect(paths) as conn:
        ex = conn.execute(
            """SELECT e.request_headers_json, e.source, o.method
               FROM http_exchanges e
               JOIN resource_operations o ON o.id=e.operation_id
               WHERE o.resource_id=? AND e.request_headers_json IS NOT NULL
               ORDER BY CASE WHEN o.method='GET' THEN 0 ELSE 1 END, e.last_seen_at DESC
               LIMIT 1""",
            (resource_id,),
        ).fetchone()
        if ex:
            try:
                raw_headers = json.loads(ex["request_headers_json"] or "[]")
            except Exception:
                raw_headers = []
            if isinstance(raw_headers, list):
                for h in raw_headers:
                    if isinstance(h, dict) and h.get("name") and h.get("value") is not None:
                        replay_headers[str(h["name"])] = str(h["value"])
            replay_source = ex["source"]
            replay_method = ex["method"]
    result = hunter.cors_probe(row["url"], timeout=min(12, max(4, timeout / 2)), replay_headers=replay_headers or None)
    result["replay_source"] = replay_source
    result["replay_method"] = replay_method
    with db_connect(paths) as conn:
        record_observation(conn, "resource", int(row["id"]), "cors_probe", "cors_probe", row["url"], result)
        record_observation(conn, "host", int(row["host_id"]), "cors_probe", "cors_probe", row["url"], {**result, "resource_id": int(row["id"])})
        preferred_method = str(replay_method or "GET").upper()
        op = conn.execute("SELECT id FROM resource_operations WHERE resource_id=? AND method=?", (resource_id, preferred_method)).fetchone()
        if not op:
            op = conn.execute("SELECT id FROM resource_operations WHERE resource_id=? ORDER BY last_seen_at DESC LIMIT 1", (resource_id,)).fetchone()
        if op:
            if result.get("error"):
                cors_status = "pending"
            elif bool(result.get("likely_credentialed_cors")) or bool(result.get("interesting")):
                cors_status = "interesting"
            else:
                cors_status = "negative"
            note = "Origin controlado reflejado + credentials" if bool(result.get("likely_credentialed_cors")) else ("Señal CORS interesante" if bool(result.get("interesting")) else ("Sin reflexión insegura observada" if not result.get("error") else str(result.get("error"))[:500]))
            hunter.update_operation_test_coverage(conn, int(op["id"]), "cors", cors_status, note, source="cors_probe")
    return result


def historical_intelligence(paths: dict[str, Path]) -> dict:
    import negro_hunter as hunter
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        return hunter.historical_intelligence(conn)


def search_intelligence(domain: str, paths: dict[str, Path]) -> dict:
    import negro_hunter as hunter
    tech: list[str] = []
    keywords: set[str] = set()
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        for row in conn.execute("SELECT payload_json FROM observations WHERE kind='web_recon' ORDER BY id DESC LIMIT 50"):
            try:
                p = json.loads(row["payload_json"] or "{}")
                tech += [str(x.get("technology")) for x in p.get("fingerprints", []) if isinstance(x, dict) and x.get("technology")]
            except Exception:
                pass
        for h in conn.execute("SELECT hostname FROM hosts ORDER BY hostname LIMIT 500"):
            left = h["hostname"].replace("." + domain, "")
            for token in re.split(r"[-_.]", left):
                if 3 <= len(token) <= 24 and token not in {"www", "com", "net", "org"}:
                    keywords.add(token)
    return {"domain": domain, "queries": hunter.search_queries(domain, tech, sorted(keywords)[:10]), "technologies": sorted(set(tech))[:30], "keywords": sorted(keywords)[:20]}


def generate_hunter_leads(domain: str, paths: dict[str, Path]) -> dict:
    import negro_hunter as hunter
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        result = hunter.generate_leads(conn, domain)
        conn.commit()
        result["leads"] = hunter.list_leads(conn, 200)
        return result


def recalculate_hunter_intelligence(domain: str, paths: dict[str, Path]) -> dict:
    """Re-run local rule engines against evidence already stored in the workspace."""
    import negro_hunter as hunter
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        result = hunter.recalculate_intelligence(conn, domain)
        conn.commit()
        return result


def get_hunter_leads(paths: dict[str, Path], limit: int = 200) -> list[dict]:
    import negro_hunter as hunter
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        return hunter.list_leads(conn, limit)


def ai_estimate_target(domain: str, paths: dict[str, Path], model: str | None = None) -> dict:
    import negro_hunter as hunter
    settings = __import__("negro_intel").load_settings()
    selected_model = model or str(settings.get("ai_model", "gpt-6-luna"))
    output_tokens = int(settings.get("ai_output_tokens", 3000))
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        payload, evidence_hash = hunter.build_target_ai_payload(conn, domain, max_chars=int(settings.get("target_ai_max_chars", 500000)))
        cached = conn.execute("SELECT result_json,usage_json,created_at FROM ai_tasks WHERE task_type='target_triage' AND evidence_hash=? AND model=? AND status='done'", (evidence_hash, selected_model)).fetchone()
    estimate = __import__("negro_intel").estimate_ai_cost(payload, selected_model, output_tokens, float(settings.get("usd_cop_rate", 3344.62)))
    estimate.update({"task_type":"target_triage", "evidence_hash": evidence_hash, "payload_chars": len(payload), "cached": bool(cached), "cache_created_at": cached["created_at"] if cached else None})
    if cached:
        estimate["max_total_usd_est"] = 0.0
        estimate["max_total_cop_est"] = 0.0
        estimate["cache_note"] = "La misma evidencia ya fue analizada con este modelo; se reutilizará sin costo." 
    return estimate


def ai_run_target(domain: str, paths: dict[str, Path], model: str | None = None) -> dict:
    import negro_hunter as hunter
    import negro_intel as intel
    settings = intel.load_settings()
    selected_model = model or str(settings.get("ai_model", "gpt-6-luna"))
    output_tokens = int(settings.get("ai_output_tokens", 3000))
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        payload, evidence_hash = hunter.build_target_ai_payload(conn, domain, max_chars=int(settings.get("target_ai_max_chars", 500000)))
        cached = conn.execute("SELECT * FROM ai_tasks WHERE task_type='target_triage' AND evidence_hash=? AND model=? AND status='done'", (evidence_hash, selected_model)).fetchone()
        if cached:
            return {"cached": True, "model": selected_model, "evidence_hash": evidence_hash, "result": json.loads(cached["result_json"] or "{}"), "usage": json.loads(cached["usage_json"] or "{}"), "created_at": cached["created_at"]}
    estimate = intel.estimate_ai_cost(payload, selected_model, output_tokens, float(settings.get("usd_cop_rate", 3344.62)))
    result, usage = hunter.run_openai_target_analysis(payload, model=selected_model, output_tokens=output_tokens)
    usage.update(hunter.actual_ai_cost(usage, selected_model, float(settings.get("usd_cop_rate", 3344.62))))
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        conn.execute("INSERT OR REPLACE INTO ai_tasks(task_type,evidence_hash,model,status,estimate_json,usage_json,result_json,created_at) VALUES('target_triage',?,?,?,?,?,?,?)", (evidence_hash, selected_model, "done", json.dumps(estimate, ensure_ascii=False), json.dumps(usage, ensure_ascii=False), json.dumps(result, ensure_ascii=False), now_iso()))
    return {"cached": False, "model": selected_model, "evidence_hash": evidence_hash, "estimate": estimate, "usage": usage, "result": result}




def ai_estimate_graph_ideas(domain: str, paths: dict[str, Path], graph_data: dict, selected_node_id: str | None = None, model: str | None = None) -> dict:
    import negro_hunter as hunter
    import negro_intel as intel
    settings = intel.load_settings()
    selected_model = model or str(settings.get("ai_model", "gpt-6-luna"))
    output_tokens = int(settings.get("graph_ai_output_tokens", 6000))
    retry_output_tokens = max(output_tokens, int(settings.get("graph_ai_retry_output_tokens", 9000)))
    with db_connect(paths) as conn:
        payload, evidence_hash = hunter.build_graph_ai_payload(conn, domain, graph_data, selected_node_id=selected_node_id, max_chars=int(settings.get("graph_ai_max_chars", 220000)))
        cached = conn.execute("SELECT result_json,usage_json,created_at FROM ai_tasks WHERE task_type='graph_ideas' AND evidence_hash=? AND model=? AND status='done'", (evidence_hash, selected_model)).fetchone()
        if cached:
            try:
                cached_result = json.loads(cached["result_json"] or "{}")
            except Exception:
                cached_result = {}
            if not hunter.graph_ai_result_is_cacheable(cached_result):
                cached = None
    rate = float(settings.get("usd_cop_rate", 3344.62))
    estimate = intel.estimate_ai_cost(payload, selected_model, output_tokens, rate)
    retry_estimate = intel.estimate_ai_cost(payload, selected_model, retry_output_tokens, rate)
    first_usd = float(estimate.get("max_total_usd_est") or 0.0)
    first_cop = float(estimate.get("max_total_cop_est") or 0.0)
    retry_usd = float(retry_estimate.get("max_total_usd_est") or 0.0)
    retry_cop = float(retry_estimate.get("max_total_cop_est") or 0.0)
    worst_round_usd = first_usd + retry_usd
    worst_round_cop = first_cop + retry_cop
    estimate.update({
        "task_type":"graph_ideas","model":selected_model,"output_tokens_budget":output_tokens,"retry_output_tokens_budget":retry_output_tokens,"evidence_hash":evidence_hash,
        "cached":bool(cached),"selected_node_id":selected_node_id,"exploratory_retry_possible":True,"token_retry_possible":True,"max_calls":4,
        "first_call_max_total_usd_est":first_usd,"first_call_max_total_cop_est":first_cop,
        "token_retry_max_total_usd_est":retry_usd,"token_retry_max_total_cop_est":retry_cop,
        "max_total_usd_est":0.0 if cached else worst_round_usd * 2,
        "max_total_cop_est":0.0 if cached else worst_round_cop * 2,
        "cost_note":"Peor caso: reintento por límite de salida + segunda pasada exploratoria. Normalmente se usa una sola llamada." if not cached else "Resultado ya cacheado; no se ejecuta una nueva llamada."
    })
    return estimate


def ai_run_graph_ideas(domain: str, paths: dict[str, Path], graph_data: dict, selected_node_id: str | None = None, model: str | None = None) -> dict:
    import negro_hunter as hunter
    import negro_intel as intel
    settings = intel.load_settings()
    selected_model = model or str(settings.get("ai_model", "gpt-6-luna"))
    output_tokens = int(settings.get("graph_ai_output_tokens", 6000))
    retry_output_tokens = max(output_tokens, int(settings.get("graph_ai_retry_output_tokens", 9000)))
    reasoning_effort = str(settings.get("graph_ai_reasoning_effort", "low"))
    with db_connect(paths) as conn:
        payload, evidence_hash = hunter.build_graph_ai_payload(conn, domain, graph_data, selected_node_id=selected_node_id, max_chars=int(settings.get("graph_ai_max_chars", 220000)))
        cached = conn.execute("SELECT * FROM ai_tasks WHERE task_type='graph_ideas' AND evidence_hash=? AND model=? AND status='done'", (evidence_hash, selected_model)).fetchone()
        if cached:
            try:
                result = json.loads(cached["result_json"] or "{}")
            except Exception:
                result = {}
            if hunter.graph_ai_result_is_cacheable(result):
                result["hypotheses"] = hunter.persist_graph_ai_hypotheses(conn, result, evidence_hash=evidence_hash, selected_node_id=selected_node_id)
                result["cached"] = True
                return result
            # A malformed result must never become a permanent cache hit.
            conn.execute("UPDATE ai_tasks SET status='invalid' WHERE id=?", (cached["id"],))
    result, usage = hunter.run_openai_graph_ideas(payload, model=selected_model, output_tokens=output_tokens, retry_output_tokens=retry_output_tokens, reasoning_effort=reasoning_effort)
    attempts = 1
    # A valid but empty first answer is not an error. Try once more with a more
    # exploratory prompt so Negro can surface bounded quick checks from pending coverage.
    if hunter.graph_ai_result_is_cacheable(result) and not list(result.get("hypotheses") or []):
        retry_result, retry_usage = hunter.run_openai_graph_ideas(payload, model=selected_model, output_tokens=output_tokens, retry_output_tokens=retry_output_tokens, reasoning_effort=reasoning_effort, exploratory_retry=True)
        attempts = 2
        if hunter.graph_ai_result_is_cacheable(retry_result):
            result = retry_result
            result["exploratory_retry_used"] = True
        for key in ("input_tokens", "output_tokens", "reasoning_tokens", "total_tokens", "api_attempts"):
            a = usage.get(key)
            b = retry_usage.get(key)
            if isinstance(a, int) or isinstance(b, int):
                usage[key] = int(a or 0) + int(b or 0)
        usage["diagnostics"] = list(usage.get("diagnostics") or []) + list(retry_usage.get("diagnostics") or [])
    usage["attempts"] = attempts
    usage.update(hunter.actual_ai_cost(usage, selected_model, float(settings.get("usd_cop_rate", 3344.62))))
    cacheable = hunter.graph_ai_result_is_cacheable(result)
    with db_connect(paths) as conn:
        if cacheable:
            persisted = hunter.persist_graph_ai_hypotheses(conn, result, evidence_hash=evidence_hash, selected_node_id=selected_node_id)
            result["hypotheses"] = persisted
        result["cached"] = False
        result["retryable"] = not cacheable
        status = "done" if cacheable else "invalid"
        conn.execute("INSERT OR REPLACE INTO ai_tasks(task_type,evidence_hash,model,status,estimate_json,usage_json,result_json,created_at) VALUES('graph_ideas',?,?,?,?,?,?,?)", (evidence_hash, selected_model, status, None, json.dumps(usage, ensure_ascii=False), json.dumps(result, ensure_ascii=False), now_iso()))
    result["usage"] = usage
    return result


def update_lead_status(paths: dict[str, Path], lead_id: int, status: str) -> dict:
    allowed = {"candidate","testing","interesting","negative","postponed","confirmed","discarded"}
    if status not in allowed:
        raise ValueError("Estado de hipótesis inválido")
    with db_connect(paths) as conn:
        row = conn.execute("SELECT id,title,status FROM leads_v2 WHERE id=? AND upper(COALESCE(source,''))='AI'", (lead_id,)).fetchone()
        if not row:
            raise ValueError("Hipótesis no encontrada")
        conn.execute("UPDATE leads_v2 SET status=?,updated_at=? WHERE id=?", (status, now_iso(), lead_id))
        return {"id":lead_id,"title":row["title"],"status":status}

def update_hypothesis(paths: dict[str, Path], lead_id: int, *, status: str | None = None, result_notes: str | None = None) -> dict:
    import negro_hunter as hunter
    allowed = {"candidate","testing","interesting","negative","postponed","confirmed","discarded"}
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        row = conn.execute("SELECT id,title,status FROM leads_v2 WHERE id=? AND upper(COALESCE(source,''))='AI'", (lead_id,)).fetchone()
        if not row:
            raise ValueError("Hipótesis no encontrada")
        next_status = status or row["status"]
        if next_status not in allowed:
            raise ValueError("Estado de hipótesis inválido")
        notes = result_notes if result_notes is not None else conn.execute("SELECT result_notes FROM leads_v2 WHERE id=?", (lead_id,)).fetchone()["result_notes"]
        tested_at = now_iso() if next_status in {"negative","interesting","confirmed","discarded"} else None
        conn.execute("UPDATE leads_v2 SET status=?,result_notes=?,last_tested_at=COALESCE(?,last_tested_at),updated_at=? WHERE id=?", (next_status, notes, tested_at, now_iso(), lead_id))
        return {"id": lead_id, "title": row["title"], "status": next_status, "result_notes": notes}


def latest_target_ai(paths: dict[str, Path]) -> dict | None:
    import negro_hunter as hunter
    with db_connect(paths) as conn:
        hunter.init_schema(conn)
        row = conn.execute("SELECT * FROM ai_tasks WHERE task_type='target_triage' AND status='done' ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return None
    def load(v, default):
        try: return json.loads(v or "")
        except Exception: return default
    return {"row": dict(row), "estimate": load(row["estimate_json"], {}), "usage": load(row["usage_json"], {}), "result": load(row["result_json"], {})}

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


def register_target(domain: str, workspace: Path, make_current: bool = True, *, name: str | None = None, scopes: Iterable[str] | None = None) -> str:
    domain = (normalize_scope(domain) or "").strip()
    initial_roots = normalize_scopes(scopes, domain)
    if not initial_roots:
        raise ValueError("El proyecto necesita al menos un scope")
    domain = domain or initial_roots[0]
    key = target_key(name or domain)
    if not key:
        raise ValueError("Proyecto inválido")
    workspace = workspace.expanduser()
    data = targets_load()
    existing = data.setdefault("targets", {}).get(key, {})
    roots = normalize_scopes(scopes if scopes is not None else existing.get("scopes"), domain)
    display_name = str(name if name is not None else existing.get("name") or domain).strip()[:120]
    data["targets"][key] = {"domain": domain, "workspace": str(workspace), "name": display_name, "scopes": roots, **({"created_at": existing.get("created_at")} if existing.get("created_at") else {})}
    if make_current:
        data["last_target"] = key
    targets_save(data)
    if make_current:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(data["targets"][key], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return key


def update_target_project(key: str, *, name: str | None = None, scopes: Iterable[str] | None = None) -> dict:
    data = targets_load()
    target = data.get("targets", {}).get(key)
    if not isinstance(target, dict):
        raise KeyError(key)
    roots = normalize_scopes(scopes if scopes is not None else target.get("scopes"), target.get("domain"))
    if not roots:
        raise ValueError("El proyecto necesita al menos un scope")
    target["domain"] = normalize_scope(target.get("domain")) or roots[0]
    target["name"] = str(name if name is not None else target.get("name") or target["domain"]).strip()[:120]
    target["scopes"] = roots
    data["targets"][key] = target
    targets_save(data)
    workspace = Path(str(target.get("workspace") or "")).expanduser()
    ensure_workspace(workspace, target["domain"], scopes=roots, project_name=target["name"])
    if data.get("last_target") == key:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(target, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return dict(target)


def set_current_target(key: str) -> None:
    data = targets_load()
    target = data.get("targets", {}).get(key)
    if not target:
        raise KeyError(key)
    data["last_target"] = key
    targets_save(data)
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(target, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def get_target(key: str) -> dict | None:
    target = targets_load().get("targets", {}).get(key)
    if not isinstance(target, dict):
        return None
    out = dict(target)
    out.setdefault("name", out.get("domain", key))
    out["scopes"] = normalize_scopes(out.get("scopes") if isinstance(out.get("scopes"), list) else [], out.get("domain"))
    return out


def list_targets() -> list[dict]:
    data = targets_load()
    current = data.get("last_target")
    result = []
    for key, target in sorted(data.get("targets", {}).items(), key=lambda item: str(item[1].get("name") or item[1].get("domain") or item[0]).lower()):
        domain = target.get("domain", key)
        scopes = normalize_scopes(target.get("scopes") if isinstance(target.get("scopes"), list) else [], domain)
        result.append({"key": key, "name": target.get("name") or domain, "domain": domain, "scopes": scopes, "workspace": target.get("workspace", ""), "current": key == current})
    return result


def delete_target(key: str, *, delete_workspace: bool = True) -> dict:
    """Remove a registered target and, optionally, its Negro workspace.

    The workspace deletion is intentionally conservative: only the exact path
    registered for the target is eligible and obvious dangerous roots are rejected.
    """
    data = targets_load()
    target = data.get("targets", {}).get(key)
    if not isinstance(target, dict):
        raise KeyError(key)
    domain = str(target.get("domain") or key)
    workspace = Path(str(target.get("workspace") or "")).expanduser()
    deleted_workspace = False
    if delete_workspace and str(workspace):
        resolved = workspace.resolve()
        home = Path.home().resolve()
        dangerous = {Path('/').resolve(), home, (home/'.config').resolve(), (home/'.config'/'negro').resolve()}
        if resolved in dangerous or len(resolved.parts) < 3:
            raise ValueError(f"Ruta de workspace insegura para borrar: {resolved}")
        # Verify the workspace belongs to the target when the state marker exists.
        state_file = workspace_paths(resolved)["state_file"]
        if state_file.exists():
            try:
                state = json.loads(state_file.read_text(encoding="utf-8"))
            except Exception as exc:
                raise ValueError("No pude validar el state.json del workspace") from exc
            owner = str(state.get("domain") or "").strip().lower().rstrip('.')
            if owner and owner != domain.strip().lower().rstrip('.'):
                raise ValueError(f"El workspace pertenece a {owner}, no a {domain}")
        if resolved.exists():
            shutil.rmtree(resolved)
            deleted_workspace = True
    data.get("targets", {}).pop(key, None)
    remaining = sorted(data.get("targets", {}).keys())
    if data.get("last_target") == key:
        data["last_target"] = remaining[0] if remaining else None
    targets_save(data)
    if data.get("last_target"):
        current = data["targets"][data["last_target"]]
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
    else:
        CONFIG_PATH.unlink(missing_ok=True)
    return {"key": key, "domain": domain, "workspace": str(workspace), "workspace_deleted": deleted_workspace, "remaining": len(remaining), "next_target": data.get("last_target")}


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

    polp = subs.add_parser("policy", help="Ver/cambiar perfil de política del target")
    polp.add_argument("--profile", choices=["conservative", "mercadolibre", "lab"])

    subs.add_parser("dns-recon", help="DNS infrastructure: A/AAAA/NS/MX/SOA/TXT/SRV/PTR")
    subs.add_parser("axfr", help="Probar AXFR contra nameservers autoritativos")

    candp = subs.add_parser("smart-candidates", help="Generar candidatos DNS/VHost a partir de naming observado")
    candp.add_argument("--limit", type=int)

    adp = subs.add_parser("active-dns", help="Validar candidatos DNS inteligentes con wildcard detection")
    adp.add_argument("--candidate", action="append", default=[])

    vhp = subs.add_parser("vhost", help="VHost discovery dirigido con pocos candidatos")
    vhp.add_argument("base_url", help="URL real del servidor, p.ej. http://host:8080")
    vhp.add_argument("--candidate", action="append", default=[])

    wrp = subs.add_parser("web-recon", help="Redirect chain + fingerprint + robots.txt + .well-known")
    wrp.add_argument("host")

    crp = subs.add_parser("crawl", help="Crawler BFS controlado, same-scope, sin submit de forms")
    crp.add_argument("host")
    crp.add_argument("--max-urls", type=int)
    crp.add_argument("--max-depth", type=int)

    corp = subs.add_parser("cors-check", help="Una prueba CORS de bajo impacto con Origin controlado")
    corp.add_argument("host")
    corp.add_argument("--url")

    subs.add_parser("historical", help="Resumir inteligencia temporal de Wayback ya importada")
    subs.add_parser("search-intel", help="Generar dorks/queries dirigidas sin ejecutarlas automáticamente")
    subs.add_parser("generate-leads", help="Correlacionar evidencia y generar leads accionables")
    subs.add_parser("recalculate-intel", help="Recalcular hipótesis con reglas actuales usando sólo evidencia almacenada")

    atp = subs.add_parser("ai-target-estimate", help="Estimar IA para triage global del target")
    atp.add_argument("--model", choices=["gpt-6-luna", "gpt-6-sol"])
    arp = subs.add_parser("ai-target", help="Ejecutar IA global del target; usa cache por evidence hash")
    arp.add_argument("--model", choices=["gpt-6-luna", "gpt-6-sol"])

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
    elif args.command == "policy":
        print(json.dumps(policy_set(paths, args.profile) if args.profile else policy_get(paths), indent=2, ensure_ascii=False))
    elif args.command == "dns-recon":
        print(json.dumps(dns_recon(domain, paths, min(args.timeout, 60)), indent=2, ensure_ascii=False))
    elif args.command == "axfr":
        print(json.dumps(axfr_recon(domain, paths, min(args.timeout, 90)), indent=2, ensure_ascii=False))
    elif args.command == "smart-candidates":
        print(json.dumps(smart_host_candidates(domain, paths, args.limit), indent=2, ensure_ascii=False))
    elif args.command == "active-dns":
        candidates = args.candidate or None
        print(json.dumps(active_dns_smart(domain, paths, candidates), indent=2, ensure_ascii=False))
    elif args.command == "vhost":
        candidates = args.candidate or None
        print(json.dumps(vhost_smart(domain, paths, args.base_url, candidates), indent=2, ensure_ascii=False))
    elif args.command == "web-recon":
        print(json.dumps(web_recon_host(domain, paths, args.host, min(args.timeout, 60)), indent=2, ensure_ascii=False))
    elif args.command == "crawl":
        print(json.dumps(crawl_host(domain, paths, args.host, args.max_urls, args.max_depth, min(args.timeout, 120)), indent=2, ensure_ascii=False))
    elif args.command == "cors-check":
        print(json.dumps(cors_check_host(domain, paths, args.host, args.url, min(args.timeout, 45)), indent=2, ensure_ascii=False))
    elif args.command == "historical":
        print(json.dumps(historical_intelligence(paths), indent=2, ensure_ascii=False))
    elif args.command == "search-intel":
        print(json.dumps(search_intelligence(domain, paths), indent=2, ensure_ascii=False))
    elif args.command == "generate-leads":
        print(json.dumps(generate_hunter_leads(domain, paths), indent=2, ensure_ascii=False))
    elif args.command == "recalculate-intel":
        print(json.dumps(recalculate_hunter_intelligence(domain, paths), indent=2, ensure_ascii=False))
    elif args.command == "ai-target-estimate":
        print(json.dumps(ai_estimate_target(domain, paths, args.model), indent=2, ensure_ascii=False))
    elif args.command == "ai-target":
        print(json.dumps(ai_run_target(domain, paths, args.model), indent=2, ensure_ascii=False))
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
