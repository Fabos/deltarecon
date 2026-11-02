from __future__ import annotations

"""Negro Context Agent v1.9.

A conservative semantic layer over captured HTTP traffic.  The deterministic
layer inventories observations and builds candidate/evidence bundles.  The LLM
is only asked to infer meaning/roles/relationships for those candidates.

The agent never performs HTTP actions and never searches for vulnerabilities.
"""

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import negro_http_inspector as http_inspector
import negro_core as core
import negro_identity as identity_tools
import negro_objects as object_tools
import negro_intel as intel

AGENT_VERSION = "context-agent-v1.9"
HYBRID_MODEL = "hybrid-luna-sol"
MODEL_TIMEOUT_SECONDS = 120.0
MODEL_MAX_RETRIES = 1
LUNA_MODEL = "gpt-6-luna"
SOL_MODEL = "gpt-6.1-sol"
DEFAULT_MODEL = HYBRID_MODEL
DEFAULT_OUTPUT_TOKENS = 6000  # legacy fallback; v1.1 uses automatic per-batch output budgets
DEFAULT_AUTO_APPLY = 0.90
DEFAULT_SUGGEST = 0.70
DEFAULT_BATCH_SIZE = 48
MIN_BATCH_OUTPUT_TOKENS = 2200
MAX_BATCH_OUTPUT_TOKENS = 12000

CATEGORIES = (
    "identity", "credential", "business_object", "reference", "state", "action",
    "authorization_boundary", "context", "unknown",
)

NOISE_KEYS = {
    "accept", "accept_language", "accept_encoding", "user_agent", "host", "content_length",
    "content_type", "connection", "origin", "referer", "date", "server", "etag",
    "last_modified", "cache_control", "expires", "pragma", "via", "vary",
    "sec_fetch_dest", "sec_fetch_mode", "sec_fetch_site", "sec_ch_ua", "sec_ch_ua_mobile",
    "sec_ch_ua_platform", "upgrade_insecure_requests", "if_none_match", "if_modified_since",
}
TRACKING_PREFIXES = ("_ga", "_gid", "_gcl", "_fbp", "_ttp", "ttcsid", "__cf_bm", "cf_")
SEMANTIC_HINTS = (
    "id", "uuid", "ref", "account", "member", "user", "customer", "seller", "buyer",
    "tenant", "organization", "workspace", "company", "branch", "wallet", "order",
    "payment", "transaction", "booking", "shipment", "refund", "return", "invoice",
    "product", "benefit", "address", "card", "status", "state", "phase", "stage",
    "token", "authorization", "session", "role", "scope", "permission", "owner",
)

STATIC_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".webp", ".avif", ".mp4", ".webm", ".mp3",
}

GENERIC_CONTEXT_KEYS = {
    "id", "code", "key", "value", "name", "type", "status", "state", "phase", "stage",
    "reference", "ref", "identifier", "number", "uuid", "slug",
}
MAX_CONCEPT_VALUE_SAMPLES = 6
MAX_CONCEPT_ENDPOINTS = 12
MAX_CONCEPT_OBSERVATIONS = 48
HYBRID_LUNA_BATCH_SIZE = 64
HYBRID_SOL_MAX_FRACTION = 0.18
HYBRID_SOL_MIN_RESERVE = 4
HYBRID_SOL_MAX_RESERVE = 24

TELEMETRY_PATH_HINTS = (
    "logging", "log", "logs", "telemetry", "analytics", "collect", "metrics",
    "trace", "traces", "beacon", "pixel", "session-replay", "sessionreplay",
)
TELEMETRY_KEY_HINTS = (
    "event", "message", "timestamp", "duration", "latency", "browser", "screen",
    "trace", "correlation", "requestid", "request_id", "sessionreplay", "metric",
)
SEMANTIC_ID_SUFFIXES = ("identifier", "reference", "uuid", "number", "code", "ref", "id")
SEMANTIC_ROLE_PREFIXES = ("source", "destination", "target", "origin", "owner", "current", "selected", "from", "to")

TRANSPORT_NOISE_TOKENS = (
    "trace", "request_id", "requestid", "correlation_id", "correlationid", "ray",
    "timing", "cache", "content_security", "strict_transport", "x_frame", "x_content",
    "server_timing", "priority", "alt_svc", "cf_", "akamai", "datadog", "newrelic",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8", errors="ignore")).hexdigest()


def _norm_key(value: str) -> str:
    raw = str(value or "").strip().lower().replace("-", "_").replace(".", "_")
    return re.sub(r"[^a-z0-9_]+", "", raw)[:180]


def _table_exists(conn, name: str) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    return bool(row)


def init_schema(conn) -> None:
    identity_tools.init_schema(conn)
    object_tools.init_schema(conn)
    http_inspector.init_schema(conn)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS semantic_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exchange_id INTEGER NOT NULL,
            operation_id INTEGER,
            resource_id INTEGER,
            side TEXT NOT NULL,
            location TEXT NOT NULL,
            key_name TEXT NOT NULL,
            normalized_key TEXT NOT NULL,
            candidate_id TEXT,
            value_hash TEXT NOT NULL,
            value_preview TEXT,
            value_raw TEXT,
            value_kind TEXT NOT NULL DEFAULT 'scalar',
            method TEXT,
            hostname TEXT,
            path TEXT,
            flow_ids_json TEXT NOT NULL DEFAULT '[]',
            manual_classification TEXT,
            manual_identity_id INTEGER,
            manual_object_type TEXT,
            first_seen_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(exchange_id, side, location, key_name, value_hash)
        );
        CREATE INDEX IF NOT EXISTS idx_sem_obs_exchange ON semantic_observations(exchange_id,id);
        CREATE INDEX IF NOT EXISTS idx_sem_obs_candidate ON semantic_observations(candidate_id,id);
        CREATE INDEX IF NOT EXISTS idx_sem_obs_key_value ON semantic_observations(normalized_key,value_hash,id);
        CREATE INDEX IF NOT EXISTS idx_sem_obs_value ON semantic_observations(value_hash,id);
        CREATE INDEX IF NOT EXISTS idx_sem_obs_key ON semantic_observations(normalized_key,id);

        CREATE TABLE IF NOT EXISTS semantic_agent_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_version TEXT NOT NULL,
            mode TEXT NOT NULL DEFAULT 'incremental',
            model TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'estimated',
            watermark_exchange_before INTEGER NOT NULL DEFAULT 0,
            watermark_observation_before INTEGER NOT NULL DEFAULT 0,
            watermark_exchange_after INTEGER NOT NULL DEFAULT 0,
            watermark_observation_after INTEGER NOT NULL DEFAULT 0,
            new_observations INTEGER NOT NULL DEFAULT 0,
            candidate_count INTEGER NOT NULL DEFAULT 0,
            estimate_json TEXT,
            usage_json TEXT,
            result_json TEXT,
            cost_usd REAL,
            cost_cop REAL,
            error_text TEXT,
            created_at TEXT NOT NULL,
            finished_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sem_runs_status ON semantic_agent_runs(status,id DESC);

        CREATE TABLE IF NOT EXISTS semantic_inferences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            candidate_id TEXT NOT NULL,
            normalized_key TEXT NOT NULL,
            value_hash TEXT NOT NULL,
            value_preview TEXT,
            category TEXT NOT NULL,
            semantic_type TEXT,
            role TEXT,
            model_confidence REAL NOT NULL DEFAULT 0,
            evidence_confidence REAL NOT NULL DEFAULT 0,
            confidence REAL NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'candidate',
            source TEXT NOT NULL DEFAULT 'ai',
            explanation TEXT,
            evidence_json TEXT NOT NULL DEFAULT '[]',
            run_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(candidate_id, run_id),
            FOREIGN KEY(run_id) REFERENCES semantic_agent_runs(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_sem_inf_current ON semantic_inferences(candidate_id,id DESC);
        CREATE INDEX IF NOT EXISTS idx_sem_inf_value ON semantic_inferences(normalized_key,value_hash,id DESC);

        CREATE TABLE IF NOT EXISTS semantic_relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            src_candidate_id TEXT NOT NULL,
            relation TEXT NOT NULL,
            dst_candidate_id TEXT,
            dst_literal TEXT,
            model_confidence REAL NOT NULL DEFAULT 0,
            evidence_confidence REAL NOT NULL DEFAULT 0,
            confidence REAL NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'suggested',
            evidence_json TEXT NOT NULL DEFAULT '[]',
            explanation TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(run_id,src_candidate_id,relation,dst_candidate_id,dst_literal),
            FOREIGN KEY(run_id) REFERENCES semantic_agent_runs(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_sem_rel_src ON semantic_relations(src_candidate_id,id DESC);
        CREATE INDEX IF NOT EXISTS idx_sem_rel_dst ON semantic_relations(dst_candidate_id,id DESC);

        CREATE TABLE IF NOT EXISTS semantic_concept_relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            src_concept_id TEXT NOT NULL,
            relation TEXT NOT NULL,
            dst_concept_id TEXT,
            dst_literal TEXT,
            src_label TEXT,
            dst_label TEXT,
            model_confidence REAL NOT NULL DEFAULT 0,
            evidence_confidence REAL NOT NULL DEFAULT 0,
            confidence REAL NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'suggested',
            evidence_json TEXT NOT NULL DEFAULT '[]',
            explanation TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(run_id,src_concept_id,relation,dst_concept_id,dst_literal),
            FOREIGN KEY(run_id) REFERENCES semantic_agent_runs(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_sem_concept_rel_src ON semantic_concept_relations(src_concept_id,id DESC);
        CREATE INDEX IF NOT EXISTS idx_sem_concept_rel_dst ON semantic_concept_relations(dst_concept_id,id DESC);
        """
    )
    obs_cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(semantic_observations)").fetchall()}
    if "candidate_id" not in obs_cols:
        conn.execute("ALTER TABLE semantic_observations ADD COLUMN candidate_id TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sem_obs_candidate ON semantic_observations(candidate_id,id)")
    inf_cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(semantic_inferences)").fetchall()}
    if "model_confidence" not in inf_cols:
        conn.execute("ALTER TABLE semantic_inferences ADD COLUMN model_confidence REAL NOT NULL DEFAULT 0")
    if "evidence_confidence" not in inf_cols:
        conn.execute("ALTER TABLE semantic_inferences ADD COLUMN evidence_confidence REAL NOT NULL DEFAULT 0")
    run_cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(semantic_agent_runs)").fetchall()}
    if "cost_cop" not in run_cols:
        conn.execute("ALTER TABLE semantic_agent_runs ADD COLUMN cost_cop REAL")
    rel_cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(semantic_relations)").fetchall()}
    if "model_confidence" not in rel_cols:
        conn.execute("ALTER TABLE semantic_relations ADD COLUMN model_confidence REAL NOT NULL DEFAULT 0")
    if "evidence_confidence" not in rel_cols:
        conn.execute("ALTER TABLE semantic_relations ADD COLUMN evidence_confidence REAL NOT NULL DEFAULT 0")
    try:
        import negro_native_projection as native_projection
        native_projection.init_schema(conn)
        # Cheap/idempotent local replay: after an upgrade, already-paid semantic
        # memory is projected into native Identities without another model call.
        native_projection.project_current_memory(conn)
    except Exception:
        pass


def _flows_for_exchange(conn, exchange_id: int) -> list[int]:
    if not _table_exists(conn, "flow_steps"):
        return []
    rows = conn.execute(
        "SELECT DISTINCT flow_id FROM flow_steps WHERE exchange_id=? AND COALESCE(included,1)=1 ORDER BY flow_id",
        (int(exchange_id),),
    ).fetchall()
    return [int(r["flow_id"]) for r in rows]


def _manual_annotation_for(item: dict[str, Any]) -> dict[str, Any]:
    ann = item.get("annotation") or {}
    if not isinstance(ann, dict):
        return {}
    return ann


def sync_observations(conn, *, after_exchange_id: int = 0) -> dict[str, int]:
    """Parse newly captured exchanges into a durable local observation ledger."""
    init_schema(conn)
    rows = conn.execute(
        """SELECT e.id,e.operation_id,o.resource_id,o.method,r.path,h.hostname,e.last_seen_at
             FROM http_exchanges e
             JOIN resource_operations o ON o.id=e.operation_id
             JOIN resources r ON r.id=o.resource_id
             JOIN hosts h ON h.id=r.host_id
            WHERE e.id>? ORDER BY e.id""",
        (max(0, int(after_exchange_id)),),
    ).fetchall()
    inserted = 0
    latest_exchange = max(0, int(after_exchange_id))
    for row in rows:
        exid = int(row["id"])
        latest_exchange = max(latest_exchange, exid)
        payload = http_inspector.extract_exchange(conn, exid)
        if not payload:
            continue
        flow_ids = _flows_for_exchange(conn, exid)
        values = list(payload.get("values") or [])
        # JWT claims are first-class observations.  The bearer itself is retained
        # locally but is redacted before any LLM payload is constructed.
        expanded: list[dict[str, Any]] = []
        for item in values:
            expanded.append(item)
            for claim in item.get("jwt_claims") or []:
                expanded.append({
                    "side": item.get("side"),
                    "location": claim.get("location") or f"{item.get('location')}#jwt:{claim.get('key')}",
                    "key": f"jwt.{claim.get('key')}",
                    "value": claim.get("value"),
                    "preview": claim.get("value"),
                    "detected_type": "jwt_claim",
                    "annotation": claim.get("annotation"),
                })
        for item in expanded:
            value = str(item.get("value") or "")
            if value == "":
                continue
            key = str(item.get("key") or "value")
            norm = _norm_key(key) or "value"
            vh = http_inspector.sha(value)
            ann = _manual_annotation_for(item)
            before = conn.total_changes
            conn.execute(
                """INSERT OR IGNORE INTO semantic_observations(
                       exchange_id,operation_id,resource_id,side,location,key_name,normalized_key,candidate_id,value_hash,
                       value_preview,value_raw,value_kind,method,hostname,path,flow_ids_json,
                       manual_classification,manual_identity_id,manual_object_type,first_seen_at,created_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    exid, int(row["operation_id"] or 0) or None, int(row["resource_id"] or 0) or None,
                    str(item.get("side") or ""), str(item.get("location") or ""), key, norm, _candidate_id(norm, vh, value=value, kind=str(item.get("detected_type") or "scalar"), location=str(item.get("location") or "")), vh,
                    value[:500], value, str(item.get("detected_type") or "scalar"), str(row["method"] or ""),
                    str(row["hostname"] or ""), str(row["path"] or ""), json.dumps(flow_ids),
                    str(ann.get("classification") or "") or None, int(ann.get("identity_id") or 0) or None,
                    str(ann.get("object_type") or "") or None, str(row["last_seen_at"] or now_iso()), now_iso(),
                ),
            )
            if conn.total_changes > before:
                inserted += 1
    missing = conn.execute("SELECT id,normalized_key,value_hash,value_raw,value_kind,location FROM semantic_observations WHERE candidate_id IS NULL OR candidate_id='' LIMIT 5000").fetchall()
    for r in missing:
        cid = _candidate_id(str(r["normalized_key"]), str(r["value_hash"]), value=str(r["value_raw"] or ""), kind=str(r["value_kind"] or "scalar"), location=str(r["location"] or ""))
        conn.execute("UPDATE semantic_observations SET candidate_id=? WHERE id=?", (cid, int(r["id"])))
    max_obs = conn.execute("SELECT COALESCE(MAX(id),0) m FROM semantic_observations").fetchone()
    return {"exchanges_scanned": len(rows), "observations_inserted": inserted, "latest_exchange_id": latest_exchange, "latest_observation_id": int(max_obs["m"] or 0)}


def refresh_manual_ground_truth(conn) -> dict[str, Any]:
    """Align ledger with manual Workbench truth and report semantic candidates affected."""
    if not _table_exists(conn, "http_value_annotations"):
        return {"updates": 0, "candidate_ids": set()}
    changed = 0
    affected: set[str] = set()
    rows = conn.execute("SELECT exchange_id,side,location,key_name,value_hash,classification,identity_id,object_type FROM http_value_annotations").fetchall()
    for a in rows:
        matches = conn.execute(
            """SELECT id,candidate_id,manual_classification,manual_identity_id,manual_object_type
                 FROM semantic_observations
                WHERE exchange_id=? AND side=? AND location=? AND key_name=? AND value_hash=?""",
            (int(a["exchange_id"]),str(a["side"]),str(a["location"]),str(a["key_name"]),str(a["value_hash"])),
        ).fetchall()
        wanted=(str(a["classification"] or "") or None,int(a["identity_id"] or 0) or None,str(a["object_type"] or "") or None)
        for m in matches:
            current=(str(m["manual_classification"] or "") or None,int(m["manual_identity_id"] or 0) or None,str(m["manual_object_type"] or "") or None)
            if current != wanted:
                changed += 1
                if m["candidate_id"]: affected.add(str(m["candidate_id"]))
        conn.execute(
            """UPDATE semantic_observations SET manual_classification=?,manual_identity_id=?,manual_object_type=?
                 WHERE exchange_id=? AND side=? AND location=? AND key_name=? AND value_hash=?""",
            (*wanted,int(a["exchange_id"]),str(a["side"]),str(a["location"]),str(a["key_name"]),str(a["value_hash"])),
        )
    return {"updates": changed, "candidate_ids": affected}


def refresh_flow_memberships(conn) -> dict[str, Any]:
    """Refresh Flow context for old exchanges so incremental AI sees newly-created/edited Flows."""
    if not _table_exists(conn, "flow_steps"):
        return {"updates": 0, "candidate_ids": set()}
    updates=0
    affected: set[str]=set()
    exchange_ids=[int(r["exchange_id"]) for r in conn.execute("SELECT DISTINCT exchange_id FROM semantic_observations ORDER BY exchange_id").fetchall()]
    for exid in exchange_ids:
        current=_flows_for_exchange(conn, exid)
        rows=conn.execute("SELECT id,candidate_id,flow_ids_json FROM semantic_observations WHERE exchange_id=?",(exid,)).fetchall()
        desired=json.dumps(current)
        for r in rows:
            try: old=sorted(int(x) for x in json.loads(r["flow_ids_json"] or "[]"))
            except Exception: old=[]
            if old != current:
                conn.execute("UPDATE semantic_observations SET flow_ids_json=? WHERE id=?",(desired,int(r["id"])))
                updates += 1
                if r["candidate_id"]: affected.add(str(r["candidate_id"]))
    return {"updates": updates, "candidate_ids": affected}

def _last_success(conn) -> dict[str, int]:
    row = conn.execute(
        """SELECT watermark_exchange_after,watermark_observation_after
             FROM semantic_agent_runs WHERE status='completed' ORDER BY id DESC LIMIT 1"""
    ).fetchone()
    return {
        "exchange": int(row["watermark_exchange_after"] or 0) if row else 0,
        "observation": int(row["watermark_observation_after"] or 0) if row else 0,
    }


def _project_scopes(conn) -> list[str]:
    try:
        row = conn.execute("SELECT value FROM meta WHERE key='scopes_json'").fetchone()
        raw = json.loads(row["value"]) if row and row["value"] else []
    except Exception:
        raw = []
    scopes = []
    for item in raw if isinstance(raw, list) else []:
        value = _normalize_scope_host(item)
        if value and value not in scopes:
            scopes.append(value)
    return scopes


def _normalize_scope_host(value: str) -> str:
    """Normalize a target/scope entry to a hostname without widening it.

    Accepts plain hosts, wildcard roots and URL-like values. A root such as
    ``viveterpel.com`` intentionally matches ``www.viveterpel.com`` and other
    real subdomains, but never sibling/lookalike domains.
    """
    from urllib.parse import urlsplit

    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    raw = raw.lstrip(".")
    if raw.startswith("*."):
        raw = raw[2:]
    try:
        parsed = urlsplit(raw if "://" in raw else "//" + raw)
        host = parsed.hostname or ""
    except Exception:
        host = raw.split("/", 1)[0].split(":", 1)[0]
    return host.strip().lower().rstrip(".")


def _host_in_project_scope(hostname: str, scopes: list[str]) -> bool:
    host = _normalize_scope_host(hostname)
    if not host:
        return False
    for raw_scope in scopes:
        scope = _normalize_scope_host(raw_scope)
        if scope and (host == scope or host.endswith("." + scope)):
            return True
    return False


def _project_scope_policy(conn, target_key: str | None = None) -> tuple[list[str], list[dict[str, Any]]]:
    """Resolve every explicit Negro source that can make captured traffic eligible.

    The current project DB already proves project membership. Eligibility is then
    driven by the project's configured target roots, explicit Workbench host/endpoint
    rules, or Burp IN_SCOPE. Explicit Negro scope is authoritative; Burp EXCLUDED only vetoes traffic not explicitly included by Negro.
    """
    scopes = _project_scopes(conn)
    rules: list[dict[str, Any]] = []
    key = str(target_key or "").strip()
    if key:
        try:
            target = core.get_target(key) or {}
            for item in target.get("scopes") or []:
                value = str(item or "").strip().lower().rstrip(".")
                if value and value not in scopes:
                    scopes.append(value)
            domain = _normalize_scope_host(target.get("domain") or "")
            if domain and domain not in scopes:
                scopes.append(domain)
        except Exception:
            pass
        try:
            import negro_workbench as workbench
            rules = workbench.list_project_rules(key)
        except Exception:
            rules = []
    return scopes, rules


def _matches_project_rule(hostname: str, method: str, path: str, rules: list[dict[str, Any]]) -> bool:
    host = str(hostname or "").strip().lower().rstrip(".")
    meth = str(method or "").strip().upper()
    pth = str(path or "/").strip() or "/"
    for rule in rules:
        if str(rule.get("hostname") or "").strip().lower().rstrip(".") != host:
            continue
        kind = str(rule.get("rule_type") or "").strip().lower()
        if kind == "host":
            return True
        if kind == "endpoint" and str(rule.get("method") or "").strip().upper() == meth and str(rule.get("path") or "/").strip() == pth:
            return True
    return False


def _ai_scope_exchange_ids(conn, *, target_key: str | None = None) -> tuple[set[int], dict[str, Any], dict[int, list[str]]]:
    """Return project exchanges eligible for Context Agent plus explainability.

    Eligibility is hybrid:
      - project/target configured scope root,
      - an explicit Workbench host/endpoint analysis rule,
      - Burp IN_SCOPE.

    Explicit Negro target/rule scope is authoritative. Burp EXCLUDED only vetoes
    traffic that Negro has not deliberately included; UNKNOWN never vetoes Negro scope. This keeps cost bounded to deliberate target traffic while avoiding
    the v1.2 failure mode where valid project traffic could all become out-of-scope.
    """
    scopes, rules = _project_scope_policy(conn, target_key)
    try:
        rows = conn.execute(
            """SELECT e.id,COALESCE(e.burp_scope_status,'UNKNOWN') burp_scope_status,
                      h.hostname,o.method,r.path
                 FROM http_exchanges e
                 JOIN resource_operations o ON o.id=e.operation_id
                 JOIN resources r ON r.id=o.resource_id
                 JOIN hosts h ON h.id=r.host_id"""
        ).fetchall()
    except Exception:
        return set(), {
            "known_exchanges": 0, "scope_exchanges": 0, "excluded_exchanges": 0,
            "target_scope_exchanges": 0, "workbench_rule_exchanges": 0,
            "burp_in_scope_exchanges": 0, "burp_excluded_exchanges": 0,
            "burp_excluded_veto_exchanges": 0, "burp_excluded_overridden_exchanges": 0,
            "no_scope_exchanges": 0, "configured_scope_roots": scopes,
            "workbench_rule_count": len(rules), "excluded_hosts": [],
        }, {}

    allowed: set[int] = set()
    reasons: dict[int, list[str]] = {}
    target_hits = rule_hits = burp_hits = burp_excluded = no_scope = 0
    burp_excluded_veto = burp_excluded_overridden = 0
    excluded_host_exchanges: dict[str, int] = defaultdict(int)

    for row in rows:
        exid = int(row["id"])
        host = str(row["hostname"] or "").strip().lower().rstrip(".")
        method = str(row["method"] or "").strip().upper()
        path = str(row["path"] or "/").strip() or "/"
        status = str(row["burp_scope_status"] or "UNKNOWN").upper()

        matched: list[str] = []
        negro_explicit = False
        if _host_in_project_scope(host, scopes):
            matched.append("project_target")
            target_hits += 1
            negro_explicit = True
        if _matches_project_rule(host, method, path, rules):
            matched.append("workbench_rule")
            rule_hits += 1
            negro_explicit = True

        # Negro's explicit target configuration is authoritative. Burp can add
        # scope with IN_SCOPE, but EXCLUDED only vetoes traffic that Negro has
        # not explicitly included. This prevents stale/misaligned Burp scope
        # metadata from excluding a host the user deliberately targeted here.
        if status == "EXCLUDED":
            burp_excluded += 1
            if negro_explicit:
                matched.append("burp_excluded_overridden")
                burp_excluded_overridden += 1
            else:
                burp_excluded_veto += 1
                excluded_host_exchanges[host or "(sin host)"] += 1
                reasons[exid] = ["burp_excluded"]
                continue
        elif status == "IN_SCOPE":
            matched.append("burp_in_scope")
            burp_hits += 1

        if matched:
            allowed.add(exid)
            reasons[exid] = matched
        else:
            no_scope += 1
            excluded_host_exchanges[host or "(sin host)"] += 1
            reasons[exid] = ["no_scope_match"]

    excluded_hosts = [
        {"host": host, "exchanges": count}
        for host, count in sorted(excluded_host_exchanges.items(), key=lambda item: (-item[1], item[0]))[:12]
    ]
    stats: dict[str, Any] = {
        "known_exchanges": len(rows),
        "scope_exchanges": len(allowed),
        "excluded_exchanges": len(rows) - len(allowed),
        "target_scope_exchanges": target_hits,
        "workbench_rule_exchanges": rule_hits,
        "burp_in_scope_exchanges": burp_hits,
        "burp_excluded_exchanges": burp_excluded,
        "burp_excluded_veto_exchanges": burp_excluded_veto,
        "burp_excluded_overridden_exchanges": burp_excluded_overridden,
        "no_scope_exchanges": no_scope,
        "configured_scope_roots": scopes,
        "workbench_rule_count": len(rules),
        "excluded_hosts": excluded_hosts,
    }
    return allowed, stats, reasons


def _is_static_path(path: str) -> bool:
    low = str(path or "").lower().split("?", 1)[0]
    return any(low.endswith(ext) for ext in STATIC_EXTENSIONS)


def _looks_telemetry_path(path: str) -> bool:
    low = str(path or "").lower().split("?", 1)[0]
    segments=[seg for seg in low.split("/") if seg]
    if any(seg in TELEMETRY_PATH_HINTS for seg in segments):
        return True
    joined="/".join(segments)
    return joined.endswith("events/track") or joined.endswith("event/track")


def _candidate_has_flow(rows: list[dict[str, Any]]) -> bool:
    for r in rows:
        try:
            if json.loads(r.get("flow_ids_json") or "[]"):
                return True
        except Exception:
            pass
    return False


def _is_dormant_telemetry(rows: list[dict[str, Any]], *, has_existing: bool = False, graph_neighbor: bool = False, status_by_exchange: dict[int, int | None] | None = None) -> bool:
    """Keep likely telemetry in the ledger without paying LLM tokens for it yet.

    This is intentionally behavioral: a telemetry-looking path alone is not enough.
    Manual truth, graph memory, Flow membership, propagation, cross-endpoint reuse or
    auth/JWT evidence always wakes the candidate back up.
    """
    if not rows or has_existing or graph_neighbor:
        return False
    if any(r.get("manual_classification") for r in rows) or _candidate_has_flow(rows):
        return False
    sides = {str(r.get("side") or "") for r in rows}
    endpoints = {(str(r.get("method") or ""), str(r.get("path") or "")) for r in rows}
    kinds = {str(r.get("value_kind") or "").lower() for r in rows}
    key = _norm_key(rows[0].get("key_name") or "")
    if any(k.startswith("jwt") for k in kinds) or any(tok in key for tok in ("authorization", "token", "session", "account", "member", "user", "tenant", "organization", "wallet", "order", "payment")):
        return False
    if "request" in sides and "response" in sides:
        return False
    if len(endpoints) >= 2:
        return False
    paths = [str(r.get("path") or "") for r in rows]
    if not paths or not all(_looks_telemetry_path(p) for p in paths):
        return False
    statuses = []
    for r in rows:
        exid = int(r.get("exchange_id") or 0)
        if exid and status_by_exchange is not None and exid in status_by_exchange:
            statuses.append(status_by_exchange.get(exid))
    benign_status = bool(statuses) and all(s in {200, 202, 204, 304, None} for s in statuses)
    key_signal = any(tok in key for tok in TELEMETRY_KEY_HINTS) or key in {"value", "data", "payload", "info", "level"}
    # Repetition makes the classification safer; a single unfamiliar endpoint is
    # preserved as a normal candidate unless its key/status also scream telemetry.
    return (len(rows) >= 2 and (benign_status or key_signal)) or (benign_status and key_signal)


def _semantic_key_family(value: str) -> str:
    """Normalize alias-ish field names without hardcoding business object types."""
    key = _norm_key(value) or "value"
    # Remove contextual role prefixes while preserving the role itself elsewhere in
    # the evidence bundle (aliases/endpoints). fromMemberId and toMemberId should
    # teach one Member concept, not cost two semantic classifications.
    changed = True
    while changed:
        changed = False
        for prefix in SEMANTIC_ROLE_PREFIXES:
            if key.startswith(prefix) and len(key) > len(prefix) + 2:
                remainder = key[len(prefix):]
                # Avoid corrupting ordinary words such as `token` merely because
                # they begin with `to`. Role-prefix normalization is only useful
                # when what remains looks like a semantic/reference field.
                if any(h in remainder for h in SEMANTIC_HINTS) or any(remainder.endswith(s) for s in SEMANTIC_ID_SUFFIXES):
                    key = remainder
                    changed = True
                    break
    for suffix in SEMANTIC_ID_SUFFIXES:
        if key.endswith(suffix) and len(key) > len(suffix) + 2:
            key = key[:-len(suffix)]
            break
    return key or "value"


def _semantic_location_group(location: str) -> str:
    low = str(location or "").lower()
    if "#jwt:" in low or "jwt_claim" in low:
        return "jwt_claim"
    if "_header:" in low:
        return "header"
    if "_cookie:" in low:
        return "cookie"
    if any(tag in low for tag in ("_query:", "request_path:", "_json:", "_form:", "_multipart:", "_xml:")):
        return "structured"
    return "http"


def _is_semantic_candidate(rows: list[dict[str, Any]], score: float, *, has_existing: bool = False, graph_neighbor: bool = False) -> tuple[bool, list[str]]:
    """Conservative semantic gate.

    Every observation remains in the local ledger. This function only decides
    whether the LLM needs to see the candidate *now*. Candidates can wake up on
    later runs when they repeat, propagate, enter a Flow, receive a manual mark,
    or become connected to the semantic graph.
    """
    if not rows:
        return False, ["empty"]
    reasons: list[str] = []
    if any(r.get("manual_classification") for r in rows):
        return True, ["manual_ground_truth"]
    if has_existing:
        return True, ["existing_semantic_memory"]
    if graph_neighbor:
        return True, ["impact_graph_neighbor"]

    key = _norm_key(rows[0].get("key_name") or "")
    kinds = {str(r.get("value_kind") or "").lower() for r in rows}
    locations = [str(r.get("location") or "").lower() for r in rows]
    sides = {str(r.get("side") or "") for r in rows}
    endpoints = {(str(r.get("method") or ""), str(r.get("path") or "")) for r in rows}
    flows: set[int] = set()
    for r in rows:
        try:
            flows.update(int(x) for x in json.loads(r.get("flow_ids_json") or "[]"))
        except Exception:
            pass
    sample = str(rows[0].get("value_raw") or "")

    transportish = any(tok in key for tok in TRANSPORT_NOISE_TOKENS)
    # Auth/JWT semantics are always relevant, but raw secrets are redacted later.
    # Generic response headers ending in `id` (X-Trace-Id, X-Request-Id) can look
    # like entities to the generic inspector, so transport metadata is explicitly
    # prevented from creating an AI candidate on that signal alone.
    inspector_signal = any(http_inspector.default_classification(str(r.get("key_name") or ""), str(r.get("value_raw") or ""), str(r.get("location") or "")) != "ignore" for r in rows)
    if any(k.startswith("jwt") for k in kinds) or (inspector_signal and not transportish):
        reasons.append("inspector_semantic_signal")

    if any(h in key for h in SEMANTIC_HINTS):
        reasons.append("semantic_key_signal")
    if _reference_like(key, sample, str(rows[0].get("value_kind") or "scalar"), str(rows[0].get("location") or "")):
        reasons.append("reference_like")
    if "request" in sides and "response" in sides:
        reasons.append("produced_then_consumed")
    if len(endpoints) >= 2 and len(rows) >= 2:
        reasons.append("cross_endpoint_reuse")
    if flows:
        reasons.append("flow_context")

    structured = any(any(tag in loc for tag in ("_query:", "_json:", "_form:", "_multipart:", "_xml:", "request_path:")) for loc in locations)
    header_only = bool(locations) and all("_header:" in loc or "_cookie:" in loc for loc in locations)
    static_only = bool(rows) and all(_is_static_path(str(r.get("path") or "")) for r in rows)

    # Static assets and transport-only headers must earn their way in through an
    # explicit behavioral signal. A name like X-Request-Id contains "id" but is
    # still transport metadata unless it propagates into business traffic.
    behavioral = any(x in reasons for x in ("inspector_semantic_signal", "produced_then_consumed", "cross_endpoint_reuse", "flow_context"))
    strong = bool(reasons) and (
        behavioral
        or ("semantic_key_signal" in reasons and score >= 1.5)
        or ("reference_like" in reasons and score >= 1.5)
    )
    if static_only and not behavioral:
        return False, ["static_transport_noise"]
    if header_only and transportish and not behavioral:
        return False, ["transport_header_noise"]

    # Unique arbitrary JSON/header scalars are kept in the ledger but deferred.
    # They wake up automatically if future traffic adds behavioral evidence.
    if strong:
        return True, reasons
    if structured and score >= 2.0:
        return True, reasons + ["structured_behavior_score"]
    if not header_only and score >= 3.0:
        return True, reasons + ["behavior_score"]
    return False, reasons or ["insufficient_semantic_evidence"]


def _is_noise_key(key: str) -> bool:
    low = _norm_key(key)
    if low in NOISE_KEYS:
        return True
    return any(low.startswith(_norm_key(p)) for p in TRACKING_PREFIXES)


def _safe_value(row: dict[str, Any]) -> str:
    value = str(row.get("value_raw") or row.get("value_preview") or "")
    key = _norm_key(str(row.get("key_name") or ""))
    loc = str(row.get("location") or "").lower()
    kind = str(row.get("value_kind") or "")
    secretish = kind == "JWT" or "authorization" in loc or "cookie" in loc or any(x in key for x in ("token", "secret", "password", "apikey", "api_key", "session"))
    if secretish:
        if kind == "jwt_claim":
            return value[:240]
        return f"<redacted:{_sha(value)[:10]}>"
    return value[:240]


def _reference_like(key: str, value: str, kind: str = "scalar", location: str = "") -> bool:
    keyn = _norm_key(key)
    raw = str(value or "")
    low = raw.lower()
    if kind in {"JWT", "jwt_claim"} and keyn not in {"jwt_role","jwt_roles","jwt_scope","jwt_scp","jwt_aud"}:
        return True
    if any(tok in keyn for tok in ("id","uuid","ref","account","member","user","customer","tenant","organization","workspace","wallet","order","payment","transaction","booking","shipment","invoice","product","benefit","card","token","session")):
        return len(raw) >= 2
    if "request_path:" in str(location or "") and len(raw) >= 2:
        return True
    if re.fullmatch(r"\d{3,}", raw):
        return True
    if re.fullmatch(r"[0-9a-fA-F]{8,64}", raw) or re.fullmatch(r"[0-9a-fA-F-]{24,64}", raw):
        return True
    if len(raw) >= 8 and re.fullmatch(r"[A-Za-z0-9_.@:-]+", raw) and any(c.isdigit() for c in raw):
        return True
    return False


def _candidate_id(norm: str, value_hash: str, *, value: str = "", kind: str = "scalar", location: str = "") -> str:
    # Identifier-like concrete values are one lifecycle even when aliases change
    # (orderId -> id -> path segment). Low-cardinality state/context values remain
    # field-scoped so common values such as ACTIVE are not merged globally.
    if _reference_like(norm, value, kind, location):
        return "v_" + str(value_hash)[:16]
    return "f_" + _sha(f"{norm}|{value_hash}")[:16]


def _score_candidate(rows: list[dict[str, Any]]) -> float:
    if not rows:
        return 0.0
    key = _norm_key(rows[0].get("key_name") or "")
    if _is_noise_key(key) and not any(r.get("manual_classification") for r in rows):
        return -10.0
    score = 0.0
    sides = {str(r.get("side") or "") for r in rows}
    endpoints = {(str(r.get("method") or ""), str(r.get("path") or "")) for r in rows}
    locations = {str(r.get("location") or "") for r in rows}
    flows = set()
    for r in rows:
        try: flows.update(json.loads(r.get("flow_ids_json") or "[]"))
        except Exception: pass
    if len(rows) >= 2: score += 1.0
    if len(rows) >= 4: score += 1.0
    if len(endpoints) >= 2: score += 1.5
    if "request" in sides and "response" in sides: score += 2.5
    if len(locations) >= 2: score += 1.0
    if flows: score += 1.5
    if any(r.get("manual_classification") for r in rows): score += 4.0
    if any(str(r.get("value_kind") or "").lower().startswith("jwt") for r in rows): score += 3.0
    if any(h in key for h in SEMANTIC_HINTS): score += 2.0
    sample = str(rows[0].get("value_raw") or "")
    if re.fullmatch(r"[0-9a-fA-F-]{24,64}", sample) or re.fullmatch(r"[A-Za-z0-9_-]{8,80}", sample): score += 0.6
    return score



def _endpoint_family(path: str) -> str:
    """Normalize concrete resource identifiers out of a path for semantic clustering."""
    raw = str(path or "").split("?", 1)[0] or "/"
    parts = []
    for part in raw.split("/"):
        if not part:
            continue
        low = part.lower()
        if (
            re.fullmatch(r"\d{3,}", part)
            or re.fullmatch(r"[0-9a-fA-F-]{24,64}", part)
            or (len(part) >= 12 and re.fullmatch(r"[A-Za-z0-9_.:-]+", part) and any(c.isdigit() for c in part))
        ):
            parts.append("{id}")
        else:
            parts.append(low[:80])
    return "/" + "/".join(parts[:12])


def _location_family(location: str) -> str:
    low = str(location or "").lower()
    low = re.sub(r"\[\d+\]", "[]", low)
    if "#jwt:" in low or "jwt_claim" in low:
        return "jwt_claim"
    for token, label in (
        ("request_path:", "path"), ("_query:", "query"), ("_json:", "json"),
        ("_form:", "form"), ("_multipart:", "multipart"), ("_xml:", "xml"),
        ("_cookie:", "cookie"), ("_header:", "header"),
    ):
        if token in low:
            side = "request" if low.startswith("request") else "response" if low.startswith("response") else "http"
            return f"{side}_{label}"
    return "request_other" if low.startswith("request") else "response_other" if low.startswith("response") else "other"


def _concept_signature(candidate: dict[str, Any]) -> str:
    """Stable schema-family signature. Concrete values never participate.

    v1.6 intentionally learns semantic *families* rather than every syntactic
    field spelling. Alias-ish keys (fromMemberId/toMemberId/memberRef) can share
    one semantic classification, while generic keys such as `id` stay scoped to
    endpoint families to avoid accidental cross-object merging.
    """
    raw_key = _norm_key(str(candidate.get("normalized_key") or candidate.get("key") or "value")) or "value"
    family = _semantic_key_family(raw_key)
    endpoints = candidate.get("endpoints") or []
    locs = sorted({_semantic_location_group(str(ep.get("location") or "")) for ep in endpoints}) or ["http"]
    endpoint_families = sorted({_endpoint_family(str(ep.get("path") or "")) for ep in endpoints if str(ep.get("path") or "")})
    aliases = {_norm_key(str(a)) for a in (candidate.get("aliases") or []) if str(a)}
    alias_families = {_semantic_key_family(a) for a in aliases if a}
    if alias_families:
        # Prefer the shortest stable family represented by lifecycle aliases.
        family = sorted(alias_families | {family}, key=lambda x: (len(x), x))[0]

    semanticish = any(h in family for h in SEMANTIC_HINTS) or raw_key != family
    generic = raw_key in GENERIC_CONTEXT_KEYS or family in GENERIC_CONTEXT_KEYS or len(family) <= 2
    context = ",".join(locs[:3])
    # Unknown/generic fields remain endpoint scoped. Business-ish families may
    # span endpoints, which is precisely where the token savings come from.
    if generic or not semanticish:
        context += "|" + ",".join(endpoint_families[:3] or ["/"])
    flows = sorted({int(fid) for fid in (candidate.get("flow_ids") or []) if str(fid).isdigit()})
    # Flow is context, not identity: only generic fields need it in the signature.
    if generic and flows:
        context += "|flow=" + ",".join(str(x) for x in flows[:3])
    manual = candidate.get("manual_ground_truth") or []
    if manual:
        tags = sorted({f"{m.get('classification') or ''}:{m.get('object_type') or ''}" for m in manual})
        context += "|manual=" + ",".join(tags[:3])
    return f"{family}|{context}"


def _build_concept_units(candidates: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Compress concrete lifecycle candidates into schema-level semantic concepts.

    Nothing is dropped: every concrete candidate remains a member of exactly one
    concept. The LLM reasons about concepts; inferred semantics are later projected
    back to every member candidate locally.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    member_to_concept: dict[str, str] = {}
    for c in candidates:
        sig = _concept_signature(c)
        concept_id = "c_" + _sha(sig)[:16]
        grouped[concept_id].append(c)
        member_to_concept[str(c.get("candidate_id") or "")] = concept_id

    units: list[dict[str, Any]] = []
    for concept_id, members in grouped.items():
        members = sorted(members, key=lambda c: (0 if c.get("flow_ids") else 1, 0 if c.get("produced_then_consumed") else 1, -float(c.get("score") or 0), -int(c.get("occurrences") or 0), str(c.get("candidate_id") or "")))
        aliases = sorted({str(a) for c in members for a in (c.get("aliases") or []) if str(a)})
        keys = defaultdict(int)
        for c in members:
            keys[str(c.get("normalized_key") or "value")] += int(c.get("occurrences") or 1)
        norm = sorted(keys, key=lambda k: (-keys[k], k))[0] if keys else "value"
        samples=[]
        for c in members:
            v=str(c.get("value_sample") or "")
            if v and v not in samples:
                samples.append(v)
            if len(samples) >= MAX_CONCEPT_VALUE_SAMPLES:
                break
        endpoint_map: dict[tuple, dict[str, Any]] = {}
        for c in members:
            for ep in c.get("endpoints") or []:
                fam=_endpoint_family(str(ep.get("path") or ""))
                lf=_location_family(str(ep.get("location") or ""))
                sig=(str(ep.get("method") or ""),fam,str(ep.get("side") or ""),lf)
                item=endpoint_map.setdefault(sig,{"method":sig[0],"path_family":fam,"side":sig[2],"location_family":lf,"examples":0})
                item["examples"] += 1
        endpoints=sorted(endpoint_map.values(), key=lambda x:(-int(x["examples"]),x["path_family"],x["location_family"]))[:MAX_CONCEPT_ENDPOINTS]
        flow_ids=sorted({int(fid) for c in members for fid in (c.get("flow_ids") or []) if str(fid).isdigit()})
        obs=[]
        # Round-robin evidence preserves breadth across instances instead of letting
        # one noisy value consume the entire evidence window.
        per_member=[list(c.get("observation_ids") or []) for c in members]
        while len(obs)<MAX_CONCEPT_OBSERVATIONS and any(per_member):
            for bucket in per_member:
                if bucket and len(obs)<MAX_CONCEPT_OBSERVATIONS:
                    oid=int(bucket.pop(0))
                    if oid not in obs: obs.append(oid)
        reasons=sorted({str(r) for c in members for r in (c.get("selection_reasons") or []) if str(r)})
        manual=[m for c in members for m in (c.get("manual_ground_truth") or [])][:20]
        existing=[]
        seen_existing=set()
        for c in members:
            old=c.get("existing_inference") or {}
            if not old: continue
            sig=(old.get("category"),old.get("semantic_type"),old.get("role"),old.get("status"))
            if sig in seen_existing: continue
            seen_existing.add(sig)
            existing.append({**old,"member_count":sum(1 for x in members if (x.get("existing_inference") or {}).get("semantic_type")==old.get("semantic_type"))})
        unit={
            "candidate_id":concept_id,
            "concept_id":concept_id,
            "semantic_family":_semantic_key_family(norm),
            "normalized_key":norm,
            "key":str(members[0].get("key") or norm),
            "aliases":aliases[:16],
            "value_samples":samples,
            "value_sample":samples[0] if samples else "",
            "value_kind":str(members[0].get("value_kind") or "scalar"),
            "instance_count":len(members),
            "occurrences":sum(int(c.get("occurrences") or 0) for c in members),
            "request_occurrences":sum(int(c.get("request_occurrences") or 0) for c in members),
            "response_occurrences":sum(int(c.get("response_occurrences") or 0) for c in members),
            "produced_then_consumed":any(bool(c.get("produced_then_consumed")) for c in members),
            "endpoints":endpoints,
            "flow_ids":flow_ids[:30],
            "flow_priority":bool(flow_ids),
            "manual_ground_truth":manual,
            "observation_ids":obs,
            "score":round(max(float(c.get("score") or 0) for c in members),2),
            "selection_reasons":reasons,
            "existing_inference_summary":existing[:12],
            # Local-only expansion metadata. _batch_bundle strips these before API.
            "member_candidate_ids":[str(c.get("candidate_id") or "") for c in members],
        }
        units.append(unit)
    units.sort(key=lambda u:(0 if u.get("flow_priority") else 1, 0 if u.get("produced_then_consumed") else 1, -float(u.get("score") or 0),-int(u.get("instance_count") or 0),str(u.get("normalized_key") or "")))
    return units,member_to_concept


def _model_unit_payload(unit: dict[str, Any]) -> dict[str, Any]:
    return {k:v for k,v in unit.items() if k not in {"member_candidate_ids"}}


def _conceptize_relations(relations: list[dict[str, Any]], member_to_concept: dict[str, str]) -> list[dict[str, Any]]:
    grouped: dict[tuple, dict[str, Any]] = {}
    for r in relations:
        src=member_to_concept.get(str(r.get("src_candidate_id") or ""))
        dst_raw=str(r.get("dst_candidate_id") or "")
        dst=member_to_concept.get(dst_raw) if dst_raw else None
        if not src:
            continue
        sig=(src,str(r.get("relation") or "related_to"),dst,str(r.get("dst_literal") or ""))
        item=grouped.setdefault(sig,{"src_candidate_id":src,"relation":sig[1],"dst_candidate_id":dst,"dst_literal":sig[3] or None,"confidence":0.0,"status":str(r.get("status") or "suggested"),"explanation":str(r.get("explanation") or ""),"instance_relationships":0})
        item["confidence"]=max(float(item.get("confidence") or 0),float(r.get("confidence") or 0))
        item["instance_relationships"] += 1
    return list(grouped.values())


def _conceptize_transitions(transitions: list[dict[str, Any]], member_to_concept: dict[str, str]) -> list[dict[str, Any]]:
    out=[]
    for t in transitions:
        cid=member_to_concept.get(str(t.get("object_candidate_id") or ""))
        if not cid: continue
        item=dict(t); item["object_candidate_id"]=cid
        out.append(item)
    return out

def _existing_semantic_memory(conn) -> list[dict[str, Any]]:
    # No arbitrary semantic-memory cap: batching controls what is sent to the model.
    rows = conn.execute(
        """SELECT si.* FROM semantic_inferences si
             JOIN (SELECT candidate_id,MAX(id) id FROM semantic_inferences GROUP BY candidate_id) x ON x.id=si.id
            WHERE si.status IN ('auto_applied','confirmed','suggested','rejected')
            ORDER BY si.confidence DESC,si.id DESC"""
    ).fetchall()
    return [dict(r) for r in rows]


def _build_candidates(conn, *, since_observation_id: int, mode: str = "incremental", extra_impacted: set[str] | None = None, target_key: str | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw_rows = [dict(r) for r in conn.execute("SELECT * FROM semantic_observations ORDER BY id").fetchall()]
    scope_ids, scope_stats, scope_reasons = _ai_scope_exchange_ids(conn, target_key=target_key)
    if _table_exists(conn, "http_exchanges"):
        ex_meta_rows = conn.execute("SELECT id,status_code FROM http_exchanges").fetchall()
        known_exchange_ids = {int(r["id"]) for r in ex_meta_rows}
        status_by_exchange = {int(r["id"]): (int(r["status_code"]) if r["status_code"] is not None else None) for r in ex_meta_rows}
    else:
        known_exchange_ids = set()
        status_by_exchange = {}
    # Synthetic/unit/manual ledger rows without a backing exchange stay eligible;
    # real captured traffic must pass the project/Burp scope gate.
    all_rows = [r for r in raw_rows if int(r.get("exchange_id") or 0) not in known_exchange_ids or int(r.get("exchange_id") or 0) in scope_ids]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in all_rows:
        cid = str(r.get("candidate_id") or _candidate_id(str(r["normalized_key"]), str(r["value_hash"]), value=str(r.get("value_raw") or ""), kind=str(r.get("value_kind") or "scalar"), location=str(r.get("location") or "")))
        r["candidate_id"] = cid
        grouped[cid].append(r)

    extra_impacted=set(extra_impacted or set())
    if mode == "full" or int(since_observation_id) <= 0:
        impacted = set(grouped.keys())
        new_rows = all_rows
        direct = set(grouped.keys())
    else:
        new_rows = [r for r in all_rows if int(r["id"]) > int(since_observation_id)]
        direct = {str(r.get("candidate_id") or "") for r in new_rows if str(r.get("candidate_id") or "")} | {cid for cid in extra_impacted if cid in grouped}
        new_keys = {str(r["normalized_key"]) for r in new_rows}
        new_hashes = {str(r["value_hash"]) for r in new_rows}
        new_exchanges = {int(r["exchange_id"]) for r in new_rows}
        # Delta + impact set. Direct values are highest priority. Then expand
        # through the persistent semantic graph (up to two hops) so a new piece
        # of traffic can reinterpret an old relation without resending all raw
        # history. Finally add same-field/value peers and co-observed context.
        impacted = set(direct)
        graph_neighbors: set[str] = set()
        frontier = set(direct)
        if frontier and _table_exists(conn, "semantic_relations"):
            relation_rows = [dict(r) for r in conn.execute(
                "SELECT src_candidate_id,dst_candidate_id FROM semantic_relations WHERE status IN ('auto_applied','confirmed','suggested') ORDER BY id DESC LIMIT 1200"
            ).fetchall()]
            for _ in range(2):
                nxt: set[str] = set()
                for rel in relation_rows:
                    a=str(rel.get("src_candidate_id") or ""); b=str(rel.get("dst_candidate_id") or "")
                    if a in frontier and b in grouped: nxt.add(b)
                    if b in frontier and a in grouped: nxt.add(a)
                nxt -= impacted
                if not nxt: break
                graph_neighbors |= nxt
                impacted |= nxt
                frontier = nxt
        contextual: set[str] = set()
        for cid, rows in grouped.items():
            if any(str(r["normalized_key"]) in new_keys or str(r["value_hash"]) in new_hashes for r in rows):
                contextual.add(cid)
            if any(int(r["exchange_id"]) in new_exchanges for r in rows):
                contextual.add(cid)
        impacted |= contextual

    existing = {str(r["candidate_id"]): r for r in _existing_semantic_memory(conn)}
    candidates: list[dict[str, Any]] = []
    dormant_telemetry_candidates = 0
    dormant_telemetry_observations = 0
    for cid in impacted:
        rows = grouped.get(cid) or []
        score = _score_candidate(rows)
        if score < 0:
            continue
        has_existing = cid in existing
        is_graph_neighbor = mode != "full" and cid in locals().get("graph_neighbors", set())
        if _is_dormant_telemetry(rows, has_existing=has_existing, graph_neighbor=is_graph_neighbor, status_by_exchange=status_by_exchange):
            dormant_telemetry_candidates += 1
            dormant_telemetry_observations += len(rows)
            continue
        relevant, gate_reasons = _is_semantic_candidate(rows, score, has_existing=has_existing, graph_neighbor=is_graph_neighbor)
        if not relevant:
            continue
        alias_counts: dict[str,int] = defaultdict(int)
        for r in rows: alias_counts[str(r.get("normalized_key") or "value")] += 1
        norm = sorted(alias_counts, key=lambda k:(-alias_counts[k], k))[0] if alias_counts else "value"
        vh = str(rows[0].get("value_hash") or "")
        endpoints: list[dict[str, Any]] = []
        seen_ep = set()
        flow_ids = set()
        obs_ids = []
        manual = []
        for r in rows:
            obs_ids.append(int(r["id"]))
            ep_key = (r.get("method"), r.get("path"), r.get("side"), r.get("location"))
            if ep_key not in seen_ep:
                seen_ep.add(ep_key)
                endpoints.append({"method":r.get("method"),"path":r.get("path"),"side":r.get("side"),"location":r.get("location"),"exchange_id":r.get("exchange_id")})
            try: flow_ids.update(json.loads(r.get("flow_ids_json") or "[]"))
            except Exception: pass
            if r.get("manual_classification"):
                manual.append({"classification":r.get("manual_classification"),"identity_id":r.get("manual_identity_id"),"object_type":r.get("manual_object_type"),"observation_id":r.get("id")})
        sides = {str(r.get("side") or "") for r in rows}
        impact_tier = 0 if cid in direct else (1 if mode != "full" and cid in locals().get("graph_neighbors", set()) else 2)
        candidate = {
            "candidate_id": cid,
            "impact_tier": impact_tier,
            "key": str(rows[0].get("key_name") or norm),
            "normalized_key": norm,
            "aliases": sorted({str(r.get("key_name") or r.get("normalized_key") or "") for r in rows if str(r.get("key_name") or r.get("normalized_key") or "")}),
            "value_sample": _safe_value(rows[0]),
            "value_hash_prefix": vh[:12],
            "value_kind": str(rows[0].get("value_kind") or "scalar"),
            "occurrences": len(rows),
            "request_occurrences": sum(1 for r in rows if r.get("side") == "request"),
            "response_occurrences": sum(1 for r in rows if r.get("side") == "response"),
            "produced_then_consumed": "request" in sides and "response" in sides,
            "endpoints": endpoints,
            "flow_ids": sorted(int(x) for x in flow_ids if str(x).isdigit()),
            "manual_ground_truth": manual,
            "observation_ids": obs_ids[:100],
            "score": round(score, 2),
            "selection_reasons": gate_reasons,
        }
        if cid in existing:
            old = existing[cid]
            candidate["existing_inference"] = {k: old.get(k) for k in ("category","semantic_type","role","confidence","status","explanation")}
        candidates.append(candidate)

    candidates.sort(key=lambda x: (int(x.get("impact_tier") or 0), -float(x["score"]), -int(x["occurrences"]), x["normalized_key"]))
    # Always keep directly-new candidates first, then semantic-graph neighbors,
    # then broader co-observed/field impact context.
    traffic_new_ids = {str(r.get("candidate_id") or "") for r in new_rows if str(r.get("candidate_id") or "")}
    new_ids = set(direct)
    selected = candidates
    # impacted_before_gate is the number of lifecycle candidates touched by the
    # delta/impact graph before the semantic relevance gate.
    impacted_before_gate = len(impacted)
    scope_reason_obs: dict[str, int] = defaultdict(int)
    excluded_host_obs: dict[str, int] = defaultdict(int)
    for row in raw_rows:
        exid = int(row.get("exchange_id") or 0)
        if exid not in known_exchange_ids:
            continue
        if exid in scope_ids:
            for reason in scope_reasons.get(exid, []):
                scope_reason_obs[reason] += 1
        else:
            excluded_host_obs[str(row.get("hostname") or "(sin host)")] += 1
    excluded_hosts_obs = [
        {"host": host, "observations": count}
        for host, count in sorted(excluded_host_obs.items(), key=lambda item: (-item[1], item[0]))[:12]
    ]
    meta = {
        "total_observations": len(raw_rows),
        "scope_observations": len(all_rows),
        "excluded_scope_observations": max(0, len(raw_rows) - len(all_rows)),
        "scope_exchanges": int(scope_stats.get("scope_exchanges") or 0),
        "excluded_scope_exchanges": int(scope_stats.get("excluded_exchanges") or 0),
        "target_scope_exchanges": int(scope_stats.get("target_scope_exchanges") or 0),
        "workbench_rule_exchanges": int(scope_stats.get("workbench_rule_exchanges") or 0),
        "burp_in_scope_exchanges": int(scope_stats.get("burp_in_scope_exchanges") or 0),
        "burp_excluded_exchanges": int(scope_stats.get("burp_excluded_exchanges") or 0),
        "burp_excluded_veto_exchanges": int(scope_stats.get("burp_excluded_veto_exchanges") or 0),
        "burp_excluded_overridden_exchanges": int(scope_stats.get("burp_excluded_overridden_exchanges") or 0),
        "no_scope_exchanges": int(scope_stats.get("no_scope_exchanges") or 0),
        "configured_scope_roots": list(scope_stats.get("configured_scope_roots") or []),
        "workbench_rule_count": int(scope_stats.get("workbench_rule_count") or 0),
        "scope_observations_by_source": dict(scope_reason_obs),
        "excluded_hosts": excluded_hosts_obs,
        "new_observations": len(new_rows),
        "impacted_candidates_before_gate": impacted_before_gate,
        "deferred_candidates": max(0, impacted_before_gate - len(candidates)),
        "dormant_telemetry_candidates": dormant_telemetry_candidates,
        "dormant_telemetry_observations": dormant_telemetry_observations,
        "impacted_candidates": len(candidates),
        "selected_candidates": len(selected),
        "candidate_cap_applied": False,
        "new_candidate_ids": sorted(traffic_new_ids),
        "context_changed_candidate_ids": sorted(set(direct) - set(traffic_new_ids)),
        "graph_neighbor_candidates": len(locals().get("graph_neighbors", set())) if mode != "full" else 0,
    }
    return selected, meta


def _relations_memory(conn, candidate_ids: set[str]) -> list[dict[str, Any]]:
    if not candidate_ids:
        return []
    # Keep every current relation that touches the impacted set. Batching, not
    # arbitrary truncation, controls model payload size.
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM semantic_relations WHERE status IN ('auto_applied','confirmed','suggested') ORDER BY id DESC"
    ).fetchall()]
    out = []
    seen = set()
    for r in rows:
        if r.get("src_candidate_id") not in candidate_ids and r.get("dst_candidate_id") not in candidate_ids:
            continue
        sig = (r.get("src_candidate_id"), r.get("relation"), r.get("dst_candidate_id"), r.get("dst_literal"))
        if sig in seen:
            continue
        seen.add(sig)
        out.append({k:r.get(k) for k in ("src_candidate_id","relation","dst_candidate_id","dst_literal","confidence","status","explanation")})
    return out


def _state_transitions(conn, relevant_ids: set[str]) -> list[dict[str, Any]]:
    """Detect conservative state changes tied to a concrete identifier candidate."""
    if not relevant_ids:
        return []
    state_rows=[dict(r) for r in conn.execute(
        "SELECT * FROM semantic_observations WHERE normalized_key LIKE '%status%' OR normalized_key LIKE '%state%' OR normalized_key LIKE '%phase%' OR normalized_key LIKE '%stage%' ORDER BY exchange_id,id"
    ).fetchall()]
    timelines: dict[tuple[str,str], list[dict[str,Any]]] = defaultdict(list)
    for st in state_rows:
        exid=int(st.get("exchange_id") or 0)
        if not exid: continue
        neighbors=[dict(r) for r in conn.execute(
            "SELECT candidate_id,key_name,value_preview,id FROM semantic_observations WHERE exchange_id=? AND candidate_id LIKE 'v_%' AND candidate_id<>? ORDER BY id",
            (exid,str(st.get("candidate_id") or "")),
        ).fetchall()]
        for obj in neighbors:
            cid=str(obj.get("candidate_id") or "")
            state_cid=str(st.get("candidate_id") or "")
            if cid not in relevant_ids and state_cid not in relevant_ids:
                continue
            timelines[(cid,str(st.get("normalized_key") or "state"))].append({
                "exchange_id":exid,"state_candidate_id":state_cid,"state":_safe_value(st),
                "state_observation_id":int(st.get("id") or 0),"object_observation_id":int(obj.get("id") or 0),
                "object_key":str(obj.get("key_name") or ""),"object_value":str(obj.get("value_preview") or "")[:120],
            })
    out=[]
    for (obj_cid,field),events in timelines.items():
        ordered=[]
        for ev in events:
            if ordered and ordered[-1]["state"]==ev["state"]:
                continue
            ordered.append(ev)
        for a,b in zip(ordered,ordered[1:]):
            if a["state"]==b["state"]: continue
            out.append({
                "object_candidate_id":obj_cid,"object_key":b["object_key"],"object_value":b["object_value"],
                "state_field":field,"from":a["state"],"to":b["state"],
                "from_exchange_id":a["exchange_id"],"to_exchange_id":b["exchange_id"],
                "evidence_observation_ids":[a["object_observation_id"],a["state_observation_id"],b["object_observation_id"],b["state_observation_id"]],
            })
    return out



def _plan_candidate_batches(candidates: list[dict[str, Any]], *, batch_size: int = DEFAULT_BATCH_SIZE) -> list[list[str]]:
    """Group correlated candidates without dropping any candidate.

    Candidates sharing exchanges or Flows are preferentially kept together so
    relation discovery survives batching. Every candidate appears exactly once.
    """
    batch_size=max(8,int(batch_size or DEFAULT_BATCH_SIZE))
    order=[str(c.get("candidate_id") or "") for c in candidates if str(c.get("candidate_id") or "")]
    if not order:
        return []
    rank={cid:i for i,cid in enumerate(order)}
    by_id={str(c.get("candidate_id")):c for c in candidates}
    exchange_groups: dict[int,set[str]]=defaultdict(set)
    flow_groups: dict[int,set[str]]=defaultdict(set)
    for cid,c in by_id.items():
        for ep in c.get("endpoints") or []:
            exid=int(ep.get("exchange_id") or 0)
            if exid: exchange_groups[exid].add(cid)
        for fid in c.get("flow_ids") or []:
            try: flow_groups[int(fid)].add(cid)
            except Exception: pass
    adjacency: dict[str,set[str]]=defaultdict(set)
    for group in list(exchange_groups.values())+list(flow_groups.values()):
        if len(group)<2: continue
        vals=list(group)
        for cid in vals:
            adjacency[cid].update(x for x in vals if x!=cid)
    remaining=set(order); batches=[]
    while remaining:
        seed=min(remaining,key=lambda x:rank[x])
        batch=[]; queue=[seed]; queued={seed}
        while queue and len(batch)<batch_size:
            cid=queue.pop(0)
            if cid not in remaining: continue
            remaining.remove(cid); batch.append(cid)
            neighbors=sorted((n for n in adjacency.get(cid,set()) if n in remaining and n not in queued),key=lambda x:rank.get(x,10**9))
            queue.extend(neighbors); queued.update(neighbors)
        if len(batch)<batch_size and remaining:
            for cid in sorted(remaining,key=lambda x:rank[x])[:batch_size-len(batch)]:
                remaining.remove(cid); batch.append(cid)
        batches.append(batch)
    return batches


def _batch_bundle(bundle: dict[str, Any], candidate_ids: list[str], batch_no: int, batch_count: int) -> dict[str, Any]:
    ids=set(candidate_ids)
    model_units=bundle.get("model_units") or bundle.get("candidates") or []
    candidates=[_model_unit_payload(c) for c in model_units if str(c.get("candidate_id")) in ids]
    memory=[]
    for c in model_units:
        if str(c.get("candidate_id")) not in ids:
            continue
        for old in c.get("existing_inference_summary") or []:
            memory.append({"concept_id":c.get("candidate_id"),**old})
    relations=[r for r in bundle.get("existing_relations") or [] if str(r.get("src_candidate_id")) in ids or str(r.get("dst_candidate_id")) in ids]
    transitions=[t for t in bundle.get("state_transitions") or [] if str(t.get("object_candidate_id")) in ids]
    full_stats=bundle.get("stats") or {}
    batch_stats={k:full_stats.get(k) for k in ("new_observations","impacted_candidates","selected_candidates","model_concepts","manual_context_updates","flow_context_updates","graph_neighbor_candidates") if k in full_stats}
    batch_stats.update({"batch_no":batch_no,"batch_count":batch_count,"batch_concepts":len(candidates)})
    return {
        "agent":bundle.get("agent"),"mode":bundle.get("mode"),
        "watermark_before":bundle.get("watermark_before"),"watermark_after":bundle.get("watermark_after"),
        "stats":batch_stats,
        "instructions":bundle.get("instructions"),
        "batch":{"number":batch_no,"count":batch_count,"concept_ids":candidate_ids},
        "candidates":candidates,"existing_semantic_memory":memory,"existing_relations":relations,"state_transitions":transitions,
    }


def _auto_output_budget(candidate_count: int, relation_count: int = 0, transition_count: int = 0) -> int:
    # Adaptive ceiling. This reserves enough room; actual billing is based on
    # tokens really generated. Batching keeps the per-call ceiling bounded.
    wanted=1200 + max(0,int(candidate_count))*105 + max(0,int(relation_count))*35 + max(0,int(transition_count))*30
    step=500
    rounded=((wanted+step-1)//step)*step
    return max(MIN_BATCH_OUTPUT_TOKENS,min(MAX_BATCH_OUTPUT_TOKENS,rounded))


def _expected_output_tokens(output_budget: int, candidate_count: int) -> int:
    # Used only for a softer expected-cost display; hard-stop always uses the
    # maximum reserved output budget.
    return min(int(output_budget), max(900, 550 + int(candidate_count)*60))


def _batch_bundles(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    plan=bundle.get("batch_plan") or []
    count=len(plan)
    return [_batch_bundle(bundle,list(ids),idx+1,count) for idx,ids in enumerate(plan)]


def _merge_batch_results(results: list[dict[str, Any]], *, completeness: dict[str, Any]) -> dict[str, Any]:
    inf_by_id: dict[str,dict[str,Any]]={}
    rel_by_sig: dict[tuple,dict[str,Any]]={}
    summaries=[]
    for result in results:
        text=str(result.get("summary") or "").strip()
        if text: summaries.append(text)
        for inf in result.get("inferences") or []:
            cid=str(inf.get("candidate_id") or "")
            if not cid: continue
            prev=inf_by_id.get(cid)
            if prev is None or float(inf.get("confidence") or 0)>float(prev.get("confidence") or 0): inf_by_id[cid]=inf
        for rel in result.get("relationships") or []:
            sig=(str(rel.get("src_candidate_id") or ""),str(rel.get("relation") or ""),str(rel.get("dst_candidate_id") or ""),str(rel.get("dst_literal") or ""))
            prev=rel_by_sig.get(sig)
            if prev is None or float(rel.get("confidence") or 0)>float(prev.get("confidence") or 0): rel_by_sig[sig]=rel
    summary=f"Análisis completo en {completeness.get('batches_completed',0)}/{completeness.get('batches_total',0)} batches; {completeness.get('candidates_analyzed',0)} candidatos cubiertos."
    if summaries: summary += " " + " | ".join(summaries[:3])
    return {"summary":summary,"inferences":list(inf_by_id.values()),"relationships":list(rel_by_sig.values()),"completeness":completeness}

def build_analysis_bundle(conn, *, mode: str = "incremental", batch_size: int = DEFAULT_BATCH_SIZE, target_key: str | None = None) -> dict[str, Any]:
    init_schema(conn)
    last = _last_success(conn)
    sync_from = 0 if mode == "full" else last["exchange"]
    sync = sync_observations(conn, after_exchange_id=sync_from)
    manual_delta = refresh_manual_ground_truth(conn)
    flow_delta = refresh_flow_memberships(conn)
    since_obs = 0 if mode == "full" else last["observation"]
    semantic_changes=set(manual_delta.get("candidate_ids") or set()) | set(flow_delta.get("candidate_ids") or set())
    candidates, meta = _build_candidates(conn, since_observation_id=since_obs, mode=mode, extra_impacted=semantic_changes, target_key=target_key)
    meta["manual_context_updates"] = int(manual_delta.get("updates") or 0)
    meta["flow_context_updates"] = int(flow_delta.get("updates") or 0)

    # Concrete lifecycle candidates remain local. The model reasons over compressed
    # schema concepts so repeated instances do not multiply token cost.
    model_units, member_to_concept = _build_concept_units(candidates)
    ids = {str(c["candidate_id"]) for c in candidates}
    member_relations = _relations_memory(conn, ids)
    relations = _conceptize_relations(member_relations, member_to_concept)
    concept_ids={str(u.get("candidate_id") or "") for u in model_units}
    # Preserve schema-level relations learned on prior runs. They are cheap and
    # help a new delta reconnect with old business context.
    if _table_exists(conn,"semantic_concept_relations") and concept_ids:
        seen={(str(r.get("src_candidate_id") or ""),str(r.get("relation") or ""),str(r.get("dst_candidate_id") or ""),str(r.get("dst_literal") or "")) for r in relations}
        for rr in conn.execute("SELECT * FROM semantic_concept_relations WHERE status IN ('auto_applied','confirmed','suggested') ORDER BY id DESC").fetchall():
            r=dict(rr); src=str(r.get("src_concept_id") or ""); dst=str(r.get("dst_concept_id") or "")
            if src not in concept_ids and dst not in concept_ids: continue
            sig=(src,str(r.get("relation") or ""),dst,str(r.get("dst_literal") or ""))
            if sig in seen: continue
            seen.add(sig)
            relations.append({"src_candidate_id":src,"relation":r.get("relation"),"dst_candidate_id":dst or None,"dst_literal":r.get("dst_literal"),"confidence":r.get("confidence"),"status":r.get("status"),"explanation":r.get("explanation")})
    transitions = _conceptize_transitions(_state_transitions(conn, ids), member_to_concept)
    plan = _plan_candidate_batches(model_units, batch_size=batch_size)

    meta["instance_candidates"] = len(candidates)
    meta["model_concepts"] = len(model_units)
    meta["concept_clusters"] = len(model_units)
    meta["semantic_compression_ratio"] = round((len(candidates) / max(1,len(model_units))),2) if candidates else 1.0
    meta["batch_count"] = len(plan)
    meta["batch_size"] = int(batch_size)
    # selected_candidates keeps its original meaning: every relevant concrete
    # lifecycle is covered. model_concepts is what is actually billed to the LLM.
    meta["selected_candidates"] = len(candidates)

    bundle = {
        "agent": AGENT_VERSION,
        "mode": mode,
        "watermark_before": last,
        "watermark_after": {"exchange":sync["latest_exchange_id"],"observation":sync["latest_observation_id"]},
        "stats": {**sync, **meta},
        "instructions": {
            "precision_over_recall": True,
            "manual_ground_truth_wins": True,
            "do_not_search_vulnerabilities": True,
            "unknown_is_allowed": True,
            "no_candidate_truncation": True,
            "concept_clusters_not_instances": True,
            "infer_schema_semantics_then_project_locally": True,
        },
        # Local concrete candidates are never serialized wholesale to OpenAI.
        "candidates": candidates,
        "model_units": model_units,
        "member_to_concept": member_to_concept,
        "existing_relations": relations,
        "state_transitions": transitions,
        "batch_plan": plan,
    }
    return bundle


def _sol_reserve_count(concept_count: int) -> int:
    if concept_count <= 0:
        return 0
    reserve=max(HYBRID_SOL_MIN_RESERVE, int(round(concept_count * HYBRID_SOL_MAX_FRACTION)))
    return min(concept_count, HYBRID_SOL_MAX_RESERVE, reserve)


def _preflight_sol_reserve(bundle: dict[str, Any]) -> list[str]:
    """Reserve expensive review for the concepts most likely to need judgment.

    This never drops a concept from AI: Luna still sees every model unit. The
    reserve only estimates/selects which concepts may receive a second Sol pass.
    """
    units=list(bundle.get("model_units") or [])
    def risk(u: dict[str, Any]) -> tuple:
        key=str(u.get("normalized_key") or "")
        reasons=set(u.get("selection_reasons") or [])
        boundaryish=any(x in key for x in ("tenant","organization","workspace","company","account","permission","scope","owner"))
        generic=key in GENERIC_CONTEXT_KEYS or _semantic_key_family(key) in GENERIC_CONTEXT_KEYS
        return (
            0 if boundaryish else 1,
            0 if u.get("flow_priority") else 1,
            0 if u.get("produced_then_consumed") else 1,
            0 if generic else 1,
            -len(reasons),
            -float(u.get("score") or 0),
            str(u.get("candidate_id") or ""),
        )
    units.sort(key=risk)
    return [str(u.get("candidate_id") or "") for u in units[:_sol_reserve_count(len(units))] if str(u.get("candidate_id") or "")]


def _estimate_plan(bundle: dict[str, Any], *, model: str, plan: list[list[str]], usd_cop_rate: float | None = None) -> dict[str, Any]:
    details=[]
    totals={"input_tokens":0,"max_output_tokens":0,"expected_output_tokens":0,"max_usd":0.0,"expected_usd":0.0,"payload_chars":0}
    count=len(plan)
    for idx,ids in enumerate(plan):
        b=_batch_bundle(bundle,list(ids),idx+1,count)
        payload=json.dumps(b,ensure_ascii=False,separators=(",",":"))
        concept_count=len(b.get("candidates") or [])
        out_budget=_auto_output_budget(concept_count,len(b.get("existing_relations") or []),len(b.get("state_transitions") or []))
        expected_out=_expected_output_tokens(out_budget,concept_count)
        settings=intel.load_settings(); rate=float(usd_cop_rate if usd_cop_rate is not None else settings.get("usd_cop_rate") or 0)
        max_est=intel.estimate_ai_cost(payload,model,out_budget,rate)
        expected_est=intel.estimate_ai_cost(payload,model,expected_out,rate)
        details.append({"batch":idx+1,"concepts":concept_count,"input_tokens_est":int(max_est.get("input_tokens_est") or 0),"output_tokens_budget":out_budget,"expected_output_tokens":expected_out,"max_total_usd_est":float(max_est.get("max_total_usd_est") or 0),"max_total_cop_est":float(max_est.get("max_total_cop_est") or 0)})
        totals["input_tokens"] += int(max_est.get("input_tokens_est") or 0)
        totals["max_output_tokens"] += int(out_budget)
        totals["expected_output_tokens"] += int(expected_out)
        totals["max_usd"] += float(max_est.get("max_total_usd_est") or 0)
        totals["expected_usd"] += float(expected_est.get("max_total_usd_est") or 0)
        totals["payload_chars"] += len(payload)
    return {"model":model,"details":details,**totals}


def estimate_bundle(bundle: dict[str, Any], *, model: str = DEFAULT_MODEL, usd_cop_rate: float | None = None) -> dict[str, Any]:
    settings = intel.load_settings()
    rate = float(usd_cop_rate if usd_cop_rate is not None else settings.get("usd_cop_rate") or 0)
    stats=bundle.get("stats",{})
    plan=list(bundle.get("batch_plan") or [])

    if model == HYBRID_MODEL:
        luna_plan=_plan_candidate_batches(bundle.get("model_units") or [],batch_size=HYBRID_LUNA_BATCH_SIZE)
        luna=_estimate_plan(bundle,model=LUNA_MODEL,plan=luna_plan,usd_cop_rate=rate)
        reserve_ids=_preflight_sol_reserve(bundle)
        sol_plan=[reserve_ids[i:i+24] for i in range(0,len(reserve_ids),24)]
        sol=_estimate_plan(bundle,model=SOL_MODEL,plan=sol_plan,usd_cop_rate=rate) if sol_plan else {"details":[],"input_tokens":0,"max_output_tokens":0,"expected_output_tokens":0,"max_usd":0.0,"expected_usd":0.0,"payload_chars":0}
        max_usd=float(luna["max_usd"])+float(sol["max_usd"])
        # Sol is a reserve, not a guaranteed second pass. For the user-facing
        # expected cost assume roughly half of the reserved ambiguous concepts
        # actually need escalation; hard-stop/max still budgets the full reserve.
        expected_sol_usd=float(sol["expected_usd"])*0.5
        expected_usd=float(luna["expected_usd"])+expected_sol_usd
        details=[{**d,"stage":"Luna"} for d in luna["details"]]+[{**d,"stage":"Sol reserve"} for d in sol["details"]]
        return {
            "model":model,"pipeline_mode":"luna_then_selective_sol",
            "input_tokens_est":int(luna["input_tokens"])+int(sol["input_tokens"]),
            "luna_input_tokens_est":int(luna["input_tokens"]),"sol_input_tokens_reserve":int(sol["input_tokens"]),
            "output_tokens_budget":int(luna["max_output_tokens"])+int(sol["max_output_tokens"]),
            "output_tokens_max_batch":max([d["output_tokens_budget"] for d in details],default=0),
            "expected_output_tokens":int(luna["expected_output_tokens"])+int(sol["expected_output_tokens"]),
            "max_total_usd_est":max_usd,"expected_total_usd_est":expected_usd,"usd_cop_rate":rate,
            "max_total_cop_est":max_usd*rate,"expected_total_cop_est":expected_usd*rate,
            "luna_expected_cop_est":float(luna["expected_usd"])*rate,"sol_expected_cop_reserve":float(sol["expected_usd"])*rate,"sol_expected_cop_likely":expected_sol_usd*rate,
            "luna_max_cop_est":float(luna["max_usd"])*rate,"sol_max_cop_reserve":float(sol["max_usd"])*rate,
            "payload_chars":int(luna["payload_chars"])+int(sol["payload_chars"]),
            "candidate_count":int(stats.get("selected_candidates") or 0),"instance_candidates":int(stats.get("instance_candidates") or stats.get("selected_candidates") or 0),
            "concept_count":int(stats.get("model_concepts") or 0),"luna_concepts":int(stats.get("model_concepts") or 0),"sol_reserve_concepts":len(reserve_ids),
            "semantic_compression_ratio":float(stats.get("semantic_compression_ratio") or 1.0),"new_observations":int(stats.get("new_observations") or 0),
            "impacted_candidates":int(stats.get("impacted_candidates") or 0),"batch_count":len(details),"luna_batch_count":len(luna["details"]),"sol_reserve_batch_count":len(sol["details"]),
            "batches":details,"mode":bundle.get("mode"),"candidate_cap_applied":False,"pricing_snapshot":"2026-11-01",
        }

    direct=_estimate_plan(bundle,model=model,plan=plan,usd_cop_rate=rate)
    max_usd=float(direct["max_usd"]); expected_usd=float(direct["expected_usd"])
    return {
        "model":model,"pipeline_mode":"single_model","input_tokens_est":int(direct["input_tokens"]),
        "output_tokens_budget":int(direct["max_output_tokens"]),"output_tokens_max_batch":max((d["output_tokens_budget"] for d in direct["details"]),default=0),
        "expected_output_tokens":int(direct["expected_output_tokens"]),"max_total_usd_est":max_usd,"expected_total_usd_est":expected_usd,"usd_cop_rate":rate,
        "max_total_cop_est":max_usd*rate,"expected_total_cop_est":expected_usd*rate,"payload_chars":int(direct["payload_chars"]),
        "candidate_count":int(stats.get("selected_candidates") or 0),"instance_candidates":int(stats.get("instance_candidates") or stats.get("selected_candidates") or 0),
        "concept_count":int(stats.get("model_concepts") or 0),"semantic_compression_ratio":float(stats.get("semantic_compression_ratio") or 1.0),
        "new_observations":int(stats.get("new_observations") or 0),"impacted_candidates":int(stats.get("impacted_candidates") or 0),"batch_count":len(direct["details"]),
        "batches":direct["details"],"mode":bundle.get("mode"),"candidate_cap_applied":False,"pricing_snapshot":"2026-11-01",
    }


def _output_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["summary", "inferences", "relationships"],
        "properties": {
            "summary": {"type": "string"},
            "inferences": {
                "type": "array",
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["candidate_id","category","semantic_type","role","confidence","explanation","evidence_observation_ids"],
                    "properties": {
                        "candidate_id": {"type": "string"},
                        "category": {"type": "string", "enum": list(CATEGORIES)},
                        "semantic_type": {"type": "string"},
                        "role": {"type": "string"},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "explanation": {"type": "string"},
                        "evidence_observation_ids": {"type":"array","items":{"type":"integer"},"maxItems":40},
                    },
                },
            },
            "relationships": {
                "type": "array",
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["src_candidate_id","relation","dst_candidate_id","dst_literal","confidence","explanation","evidence_observation_ids"],
                    "properties": {
                        "src_candidate_id":{"type":"string"},
                        "relation":{"type":"string"},
                        "dst_candidate_id":{"type":["string","null"]},
                        "dst_literal":{"type":["string","null"]},
                        "confidence":{"type":"number","minimum":0,"maximum":1},
                        "explanation":{"type":"string"},
                        "evidence_observation_ids":{"type":"array","items":{"type":"integer"},"maxItems":40},
                    },
                },
            },
        },
    }


def _system_prompt() -> str:
    return """Eres el Context Agent de Negro, una herramienta de pentesting AUTORIZADO. Tu única tarea en esta fase es comprender el modelo semántico del negocio a partir de evidencia HTTP ya capturada. NO busques vulnerabilidades, NO propongas ataques y NO inventes datos.

Analiza CONCEPT CLUSTERS construidos determinísticamente desde URL/path/query params, headers, cookies, JWT claims, bodies request/response y Flows. Cada candidate_id representa un concepto/campo contextual y puede resumir muchas instancias concretas. value_samples son ejemplos, instance_count indica cuántas instancias locales cubre y endpoints resume dónde aparece. NO interpretes cada muestra como un concepto independiente. El nombre de una key es sólo una señal; prioriza comportamiento: producción en response y consumo posterior, repetición entre endpoints, cambio entre actores/cuentas, ubicación, método, estado y co-ocurrencias.

Categorías válidas:
- identity: actor/principal real del sistema.
- credential: artefacto de autenticación/sesión; NO es identidad.
- business_object: entidad estable del negocio.
- reference: referencia cuyo objeto exacto todavía no está suficientemente probado.
- state: estado o transición de una entidad/proceso.
- action: acción/capability del negocio.
- authorization_boundary: valor que separa dominios de autorización (tenant/org/account/workspace/etc.) sólo cuando la evidencia lo respalda.
- context: contexto útil (rol, scope, canal, etc.) que no encaja mejor arriba.
- unknown: evidencia insuficiente. Abstenerse es correcto.

REGLAS:
1. precision > recall. Para CADA candidate_id del batch devuelve exactamente una inference; si la evidencia no alcanza usa category=unknown con confianza baja en vez de omitirlo.
2. Respeta manual_ground_truth como evidencia de máxima prioridad; nunca la contradigas silenciosamente.
3. Usa semantic_type como nombre conceptual inferido (por ejemplo Member, Account, Order) pero NO dependas de una lista hardcodeada.
4. role describe el papel contextual (source, target, owner, actor, destination, etc.) cuando esté respaldado.
5. confidence debe reflejar la evidencia suministrada, no seguridad retórica. >=0.90 debe ser realmente fuerte.
6. Cada inference debe citar observation IDs REALES incluidos en su concept cluster. La inferencia se proyectará localmente a todas sus instancias.
7. Cada relationship debe conectar candidate IDs REALES del bundle o usar dst_literal cuando el destino no sea un candidato explícito.
8. existing_semantic_memory y existing_relations son memoria previa: úsala para reinterpretar evidencia nueva, pero permite reclasificar si aparece evidencia mejor.
9. state_transitions fue calculado determinísticamente: úsalo como evidencia fuerte de ciclo de vida, sin asumir que toda transición implica vulnerabilidad.
10. Nunca incluyas secretos/tokens en explanation.
11. Si existe first_pass, estás en una pasada de refinamiento: revisa críticamente esas inferencias Luna usando toda la evidencia del bundle. Puedes bajar confianza, cambiar categoría/tipo/rol o mantenerla; no estás obligado a ser más seguro.
12. Devuelve únicamente JSON válido según el schema."""


def _response_usage(response) -> dict[str, Any]:
    usage = getattr(response, "usage", None)
    return {
        "input_tokens": int(getattr(usage, "input_tokens", 0) or 0),
        "output_tokens": int(getattr(usage, "output_tokens", 0) or 0),
        "total_tokens": int(getattr(usage, "total_tokens", 0) or 0),
    }


class ContextAgentModelError(RuntimeError):
    def __init__(self, message: str, usage: dict[str, Any] | None = None):
        super().__init__(message)
        self.usage = usage or {"input_tokens":0,"output_tokens":0,"total_tokens":0}


def run_model(bundle: dict[str, Any], *, model: str = DEFAULT_MODEL, output_tokens: int = DEFAULT_OUTPUT_TOKENS, reasoning_effort: str = "medium") -> tuple[dict[str, Any], dict[str, Any]]:
    key = intel.load_secrets().get("OPENAI_API_KEY")
    if not key:
        raise RuntimeError(f"Falta OPENAI_API_KEY en {intel.SECRETS_PATH}")
    try:
        from openai import OpenAI  # type: ignore
    except Exception as exc:
        raise RuntimeError("El SDK de OpenAI no está disponible. Ejecuta ./install-web.sh") from exc
    client = OpenAI(api_key=key, timeout=MODEL_TIMEOUT_SECONDS, max_retries=MODEL_MAX_RETRIES)
    fmt = {"type":"json_schema","name":"negro_context_agent","description":"Modelo semántico incremental del tráfico HTTP de Negro.","schema":_output_schema(),"strict":True}
    response = client.responses.create(
        model=model,
        reasoning={"effort": reasoning_effort},
        max_output_tokens=max(1500, int(output_tokens)),
        instructions=_system_prompt(),
        input=json.dumps(bundle, ensure_ascii=False, separators=(",", ":")),
        text={"format": fmt},
    )
    if str(getattr(response, "status", "completed")) != "completed":
        reason = getattr(getattr(response, "incomplete_details", None), "reason", None)
        raise ContextAgentModelError(f"OpenAI no completó el análisis ({reason or getattr(response,'status','unknown')})", _response_usage(response))
    text = str(getattr(response, "output_text", "") or "")
    try:
        result = json.loads(text)
    except Exception as exc:
        raise ContextAgentModelError("OpenAI no devolvió JSON estructurado válido para Context Agent", _response_usage(response)) from exc
    expected={str(c.get("candidate_id") or "") for c in bundle.get("candidates") or [] if str(c.get("candidate_id") or "")}
    got={str(i.get("candidate_id") or "") for i in result.get("inferences") or [] if str(i.get("candidate_id") or "")}
    missing=sorted(expected-got)
    if missing:
        raise ContextAgentModelError(f"Context Agent devolvió un batch incompleto: faltan {len(missing)} concepto(s)", _response_usage(response))
    return result, _response_usage(response)


def _actual_cost(model: str, usage: dict[str, Any]) -> float:
    prices = intel.OPENAI_PRICING.get(model) or {}
    inp = int(usage.get("input_tokens") or 0)
    out = int(usage.get("output_tokens") or 0)
    long_context = inp > int(getattr(intel, "LONG_CONTEXT_THRESHOLD", 272000))
    ir = float(prices.get("long_input" if long_context else "input") or 0)
    orate = float(prices.get("long_output" if long_context else "output") or 0)
    return (inp / 1_000_000.0) * ir + (out / 1_000_000.0) * orate


def _latest_candidate_rows(conn, candidate_id: str) -> list[dict[str, Any]]:
    row = conn.execute("SELECT normalized_key,value_hash FROM semantic_inferences WHERE candidate_id=? ORDER BY id DESC LIMIT 1", (candidate_id,)).fetchone()
    if not row:
        return []
    return [dict(r) for r in conn.execute("SELECT * FROM semantic_observations WHERE normalized_key=? AND value_hash=? ORDER BY id", (row["normalized_key"], row["value_hash"])).fetchall()]


def _evidence_confidence(candidate: dict[str, Any]) -> float:
    """Conservative deterministic support score; never a semantic verdict by itself."""
    if candidate.get("manual_ground_truth"):
        return 0.99
    score=max(0.0, min(10.0, float(candidate.get("score") or 0.0)))
    support=0.34 + score * 0.052
    occ=int(candidate.get("occurrences") or 0)
    if candidate.get("produced_then_consumed"): support += 0.06
    if occ >= 4: support += 0.03
    if len(candidate.get("endpoints") or []) >= 3: support += 0.03
    if candidate.get("flow_ids"): support += 0.03
    return round(max(0.35, min(0.97, support)), 4)


def _final_confidence(model_confidence: float, evidence_confidence: float) -> float:
    # The final score cannot exceed the model's own confidence. Sparse
    # deterministic evidence therefore prevents an eloquent guess from being
    # auto-applied at 0.90+.
    model=max(0.0,min(1.0,float(model_confidence or 0)))
    evidence=max(0.0,min(1.0,float(evidence_confidence or 0)))
    return round(min(model, model * 0.65 + evidence * 0.35), 4)



def _relation_member_pairs(src_unit: dict[str, Any], dst_unit: dict[str, Any], candidate_map: dict[str, dict[str, Any]]) -> set[tuple[str,str]]:
    """Materialize only concrete relations supported by co-occurrence/unique Flow context."""
    src_ids=[cid for cid in src_unit.get("member_candidate_ids") or [] if cid in candidate_map]
    dst_ids=[cid for cid in dst_unit.get("member_candidate_ids") or [] if cid in candidate_map]
    pairs:set[tuple[str,str]]=set()
    src_ex={cid:{int(ep.get("exchange_id") or 0) for ep in candidate_map[cid].get("endpoints") or [] if int(ep.get("exchange_id") or 0)} for cid in src_ids}
    dst_ex={cid:{int(ep.get("exchange_id") or 0) for ep in candidate_map[cid].get("endpoints") or [] if int(ep.get("exchange_id") or 0)} for cid in dst_ids}
    for a in src_ids:
        for b in dst_ids:
            if src_ex[a] & dst_ex[b]:
                pairs.add((a,b))
    if pairs:
        return pairs
    if len(src_ids)==1 and len(dst_ids)==1:
        return {(src_ids[0],dst_ids[0])}
    # A Flow can bridge requests where the two values never occur in the same
    # exchange. Only materialize when that Flow has one unambiguous member on
    # each side; this avoids Cartesian relation explosions.
    src_by_flow:dict[int,set[str]]=defaultdict(set); dst_by_flow:dict[int,set[str]]=defaultdict(set)
    for cid in src_ids:
        for fid in candidate_map[cid].get("flow_ids") or []:
            try: src_by_flow[int(fid)].add(cid)
            except Exception: pass
    for cid in dst_ids:
        for fid in candidate_map[cid].get("flow_ids") or []:
            try: dst_by_flow[int(fid)].add(cid)
            except Exception: pass
    for fid in set(src_by_flow)&set(dst_by_flow):
        if len(src_by_flow[fid])==1 and len(dst_by_flow[fid])==1:
            pairs.add((next(iter(src_by_flow[fid])),next(iter(dst_by_flow[fid]))))
    return pairs


def _candidate_value_hash(conn, candidate: dict[str, Any]) -> str:
    ids=[int(x) for x in candidate.get("observation_ids") or [] if str(x).isdigit()]
    if not ids: return ""
    row=conn.execute("SELECT value_hash FROM semantic_observations WHERE id=?",(ids[0],)).fetchone()
    return str(row["value_hash"] or "") if row else ""

def _persist_result(conn, run_id: int, bundle: dict[str, Any], result: dict[str, Any], *, auto_apply_threshold: float = DEFAULT_AUTO_APPLY, suggest_threshold: float = DEFAULT_SUGGEST) -> dict[str, int]:
    concrete_map = {str(c["candidate_id"]): c for c in bundle.get("candidates") or []}
    concept_map = {str(c["candidate_id"]): c for c in bundle.get("model_units") or bundle.get("candidates") or []}
    now = now_iso()
    counts = {"inferences":0,"auto_applied":0,"suggested":0,"candidates":0,"relations":0,"concepts":0}

    # One model inference is projected onto every concrete lifecycle instance in
    # the concept. The expensive semantic decision happens once; Workbench still
    # receives per-value marks with per-instance evidence confidence.
    for inf in result.get("inferences") or []:
        concept_id = str(inf.get("candidate_id") or "")
        concept = concept_map.get(concept_id)
        if not concept and concept_id in concrete_map:
            concept = {**concrete_map[concept_id], "member_candidate_ids":[concept_id], "concept_id":concept_id}
        if not concept:
            continue
        category = str(inf.get("category") or "unknown")
        if category not in CATEGORIES:
            category = "unknown"
        model_conf = max(0.0, min(1.0, float(inf.get("confidence") or 0)))
        model_evidence=[int(x) for x in (inf.get("evidence_observation_ids") or []) if str(x).isdigit()]
        members=[cid for cid in (concept.get("member_candidate_ids") or [concept_id]) if cid in concrete_map]
        if not members and concept_id in concrete_map:
            members=[concept_id]
        for cid in members:
            c=concrete_map[cid]
            evidence_conf = _evidence_confidence(c)
            conf = _final_confidence(model_conf, evidence_conf)
            status = "auto_applied" if conf >= auto_apply_threshold and category != "unknown" else "suggested" if conf >= suggest_threshold and category != "unknown" else "candidate"
            valid_ids = set(int(x) for x in c.get("observation_ids") or [])
            evidence_ids = [x for x in model_evidence if x in valid_ids][:40] or list(valid_ids)[:12]
            conn.execute(
                """INSERT INTO semantic_inferences(candidate_id,normalized_key,value_hash,value_preview,category,semantic_type,role,model_confidence,evidence_confidence,confidence,status,source,explanation,evidence_json,run_id,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,'ai',?,?,?,?,?)""",
                (cid,c["normalized_key"],_candidate_value_hash(conn,c),str(c.get("value_sample") or "")[:500],category,str(inf.get("semantic_type") or "")[:120],str(inf.get("role") or "")[:120],model_conf,evidence_conf,conf,status,str(inf.get("explanation") or "")[:2000],json.dumps(evidence_ids),int(run_id),now,now),
            )
            counts["inferences"] += 1
            counts[status if status in counts else "candidates"] += 1
        counts["concepts"] += 1

    for rel in result.get("relationships") or []:
        src_concept=str(rel.get("src_candidate_id") or "")
        dst_raw=rel.get("dst_candidate_id")
        dst_concept=str(dst_raw) if dst_raw else None
        src_unit=concept_map.get(src_concept)
        if not src_unit and src_concept in concrete_map:
            src_unit={**concrete_map[src_concept],"member_candidate_ids":[src_concept],"concept_id":src_concept}
        dst_unit=concept_map.get(dst_concept) if dst_concept else None
        if dst_concept and not dst_unit and dst_concept in concrete_map:
            dst_unit={**concrete_map[dst_concept],"member_candidate_ids":[dst_concept],"concept_id":dst_concept}
        if not src_unit or (dst_concept and not dst_unit):
            continue
        relation=re.sub(r"[^a-zA-Z0-9_:-]+","_",str(rel.get("relation") or "related_to")).strip("_")[:100] or "related_to"
        model_rel_conf=max(0.0,min(1.0,float(rel.get("confidence") or 0)))
        src_support=_evidence_confidence(src_unit)
        dst_support=_evidence_confidence(dst_unit) if dst_unit else src_support
        evidence_rel_conf=min(src_support,dst_support)
        conf=_final_confidence(model_rel_conf,evidence_rel_conf)
        status="auto_applied" if conf>=auto_apply_threshold else "suggested" if conf>=suggest_threshold else "candidate"
        rel_obs=[int(x) for x in (rel.get("evidence_observation_ids") or []) if str(x).isdigit()][:50]
        # Preserve schema-level knowledge separately from concrete instance edges.
        inference_by_concept={str(x.get("candidate_id") or ""):x for x in result.get("inferences") or []}
        src_inf=inference_by_concept.get(src_concept) or {}; dst_inf=inference_by_concept.get(dst_concept or "") or {}
        src_label=str(src_inf.get("semantic_type") or src_inf.get("category") or src_unit.get("normalized_key") or src_concept)[:160]
        dst_label=str(dst_inf.get("semantic_type") or dst_inf.get("category") or (dst_unit or {}).get("normalized_key") or rel.get("dst_literal") or dst_concept or "")[:160]
        conn.execute(
            """INSERT OR IGNORE INTO semantic_concept_relations(run_id,src_concept_id,relation,dst_concept_id,dst_literal,src_label,dst_label,model_confidence,evidence_confidence,confidence,status,evidence_json,explanation,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (int(run_id),src_concept,relation,dst_concept,str(rel.get("dst_literal") or "")[:300] or None,src_label,dst_label,model_rel_conf,evidence_rel_conf,conf,status,json.dumps(rel_obs),str(rel.get("explanation") or "")[:2000],now),
        )
        counts["relations"] += 1
        if dst_unit:
            for src,dst in _relation_member_pairs(src_unit,dst_unit,concrete_map):
                src_support=_evidence_confidence(concrete_map[src]); dst_support=_evidence_confidence(concrete_map[dst])
                local_evidence=min(src_support,dst_support); local_conf=_final_confidence(model_rel_conf,local_evidence)
                local_status="auto_applied" if local_conf>=auto_apply_threshold else "suggested" if local_conf>=suggest_threshold else "candidate"
                valid=set(int(x) for x in concrete_map[src].get("observation_ids") or [])|set(int(x) for x in concrete_map[dst].get("observation_ids") or [])
                evidence=[x for x in rel_obs if x in valid][:50] or list(valid)[:12]
                conn.execute(
                    """INSERT OR IGNORE INTO semantic_relations(run_id,src_candidate_id,relation,dst_candidate_id,dst_literal,model_confidence,evidence_confidence,confidence,status,evidence_json,explanation,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (int(run_id),src,relation,dst,None,model_rel_conf,local_evidence,local_conf,local_status,json.dumps(evidence),str(rel.get("explanation") or "")[:2000],now),
                )
                counts["relations"] += 1
    return counts


def _select_sol_escalations(bundle: dict[str, Any], first_pass: dict[str, Any]) -> list[str]:
    """Pick concepts that deserve an expensive second opinion.

    Every concept has already been analyzed by Luna. Sol is only for ambiguity,
    authorization boundaries, conflicting memory or relation-heavy cases.
    """
    units={str(u.get("candidate_id") or ""):u for u in bundle.get("model_units") or []}
    scored: dict[str,float]={}
    for inf in first_pass.get("inferences") or []:
        cid=str(inf.get("candidate_id") or "")
        if cid not in units: continue
        conf=float(inf.get("confidence") or 0)
        cat=str(inf.get("category") or "")
        unit=units[cid]
        score=0.0
        if cat == "authorization_boundary": score += 8.0
        if 0.55 <= conf < 0.90: score += 6.0 + (0.90-conf)*4
        if cat == "unknown" and (unit.get("flow_priority") or unit.get("produced_then_consumed") or float(unit.get("score") or 0)>=5): score += 5.0
        if unit.get("existing_inference_summary"):
            old_types={str(x.get("semantic_type") or x.get("category") or "") for x in unit.get("existing_inference_summary") or []}
            new_type=str(inf.get("semantic_type") or cat)
            if old_types and new_type not in old_types: score += 7.0
        key=str(unit.get("normalized_key") or "")
        if any(x in key for x in ("tenant","organization","workspace","company","account","permission","scope","owner")): score += 2.5
        if unit.get("flow_priority"): score += 1.5
        if unit.get("produced_then_consumed"): score += 1.0
        if score > 0: scored[cid]=max(scored.get(cid,0),score)
    for rel in first_pass.get("relationships") or []:
        conf=float(rel.get("confidence") or 0)
        for cid in (str(rel.get("src_candidate_id") or ""),str(rel.get("dst_candidate_id") or "")):
            if cid in units and conf < 0.90:
                scored[cid]=max(scored.get(cid,0),4.5+(0.90-conf)*3)
    limit=_sol_reserve_count(len(units))
    return [cid for cid,_ in sorted(scored.items(),key=lambda x:(-x[1],x[0]))[:limit]]


def _refinement_bundle(bundle: dict[str, Any], ids: list[str], first_pass: dict[str, Any], batch_no: int, batch_count: int) -> dict[str, Any]:
    b=_batch_bundle(bundle,ids,batch_no,batch_count)
    idset=set(ids)
    b["instructions"]={**(b.get("instructions") or {}),"refinement_pass":True,"first_pass_model":LUNA_MODEL,"refine_only_listed_concepts":True}
    b["first_pass"]={
        "inferences":[x for x in first_pass.get("inferences") or [] if str(x.get("candidate_id") or "") in idset],
        "relationships":[x for x in first_pass.get("relationships") or [] if str(x.get("src_candidate_id") or "") in idset or str(x.get("dst_candidate_id") or "") in idset],
    }
    return b


def _overlay_refinement(first_pass: dict[str, Any], refinement: dict[str, Any], refined_ids: set[str]) -> dict[str, Any]:
    inf={str(x.get("candidate_id") or ""):x for x in first_pass.get("inferences") or [] if str(x.get("candidate_id") or "")}
    for x in refinement.get("inferences") or []:
        cid=str(x.get("candidate_id") or "")
        if cid in refined_ids: inf[cid]=x
    rel={
        (str(x.get("src_candidate_id") or ""),str(x.get("relation") or ""),str(x.get("dst_candidate_id") or ""),str(x.get("dst_literal") or "")):x
        for x in first_pass.get("relationships") or []
    }
    for x in refinement.get("relationships") or []:
        sig=(str(x.get("src_candidate_id") or ""),str(x.get("relation") or ""),str(x.get("dst_candidate_id") or ""),str(x.get("dst_literal") or ""))
        if sig[0] in refined_ids or sig[2] in refined_ids: rel[sig]=x
    return {"summary":str(first_pass.get("summary") or "") + (" | Sol refinó " + str(len(refined_ids)) + " concepto(s)." if refined_ids else ""),"inferences":list(inf.values()),"relationships":list(rel.values())}


def execute(conn, *, mode: str = "incremental", model: str = DEFAULT_MODEL, budget_cop: float | None = None, auto_apply_threshold: float = DEFAULT_AUTO_APPLY, suggest_threshold: float = DEFAULT_SUGGEST, reasoning_effort: str = "medium", target_key: str | None = None, progress_callback=None) -> dict[str, Any]:
    init_schema(conn)
    def _progress(**data):
        if progress_callback:
            try:
                progress_callback(dict(data))
            except Exception:
                pass
    _progress(stage="preparing", label="Preparando análisis", current=0, total=0, model=model)
    bundle = build_analysis_bundle(conn, mode=mode, target_key=target_key)
    estimate = estimate_bundle(bundle, model=model)
    rate=float(estimate.get("usd_cop_rate") or 0)
    if budget_cop is not None and float(estimate.get("max_total_cop_est") or 0) > float(budget_cop):
        raise RuntimeError(
            f"El costo máximo estimado COP ${float(estimate.get('max_total_cop_est') or 0):,.0f} "
            f"supera tu límite COP ${float(budget_cop):,.0f}. Negro no recorta contexto: aumenta el presupuesto o reduce el scope."
        )
    before = bundle.get("watermark_before") or {}; after = bundle.get("watermark_after") or {}
    cur = conn.execute(
        """INSERT INTO semantic_agent_runs(agent_version,mode,model,status,watermark_exchange_before,watermark_observation_before,watermark_exchange_after,watermark_observation_after,new_observations,candidate_count,estimate_json,created_at)
           VALUES(?,?,?,'running',?,?,?,?,?,?,?,?)""",
        (AGENT_VERSION,mode,model,int(before.get("exchange") or 0),int(before.get("observation") or 0),int(after.get("exchange") or 0),int(after.get("observation") or 0),int(bundle.get("stats",{}).get("new_observations") or 0),int(bundle.get("stats",{}).get("selected_candidates") or 0),json.dumps(estimate),now_iso()),
    )
    run_id=int(cur.lastrowid)
    # Persist the run row and release SQLite's write transaction before any
    # potentially slow network/model call. Keeping this transaction open across
    # Luna/Sol batches blocks Burp ingestion, notifications and other writers.
    conn.commit()
    _progress(stage="running", label="Run creado", run_id=run_id, current=0, total=int(estimate.get("batch_count") or 0), model=model, cost_cop=0.0)
    usage_by_model={LUNA_MODEL:{"input_tokens":0,"output_tokens":0,"total_tokens":0},SOL_MODEL:{"input_tokens":0,"output_tokens":0,"total_tokens":0}}
    completed_luna=completed_sol=0
    current_stage = LUNA_MODEL if model == HYBRID_MODEL else model
    result={}
    try:
        if not bundle.get("candidates"):
            completeness={"candidates_total":0,"candidates_analyzed":0,"concepts_total":0,"concepts_analyzed":0,"batches_total":0,"batches_completed":0,"coverage_pct":100.0,"truncated":False,"luna_concepts":0,"sol_refined":0}
            result={"summary":"No hay candidatos nuevos o impactados que justifiquen una llamada al modelo.","inferences":[],"relationships":[],"completeness":completeness}
        elif model == HYBRID_MODEL:
            luna_results=[]
            luna_plan=_plan_candidate_batches(bundle.get("model_units") or [],batch_size=HYBRID_LUNA_BATCH_SIZE)
            luna_bundles=[_batch_bundle(bundle,list(ids),idx+1,len(luna_plan)) for idx,ids in enumerate(luna_plan)]
            total_luna=len(luna_bundles)
            for batch_idx,b in enumerate(luna_bundles, start=1):
                out_budget=_auto_output_budget(len(b.get("candidates") or []),len(b.get("existing_relations") or []),len(b.get("state_transitions") or []))
                current_stage=LUNA_MODEL
                _progress(stage="luna", label="Luna analizando", run_id=run_id, current=batch_idx, total=total_luna, model=LUNA_MODEL, concepts=len(b.get("candidates") or []), cost_cop=sum(_actual_cost(m,u) for m,u in usage_by_model.items() if m in intel.OPENAI_PRICING)*rate)
                r,u=run_model(b,model=LUNA_MODEL,output_tokens=out_budget,reasoning_effort="low")
                luna_results.append(r); completed_luna += 1
                for k in usage_by_model[LUNA_MODEL]: usage_by_model[LUNA_MODEL][k]+=int(u.get(k) or 0)
                _progress(stage="luna", label="Luna analizando", run_id=run_id, current=batch_idx, total=total_luna, model=LUNA_MODEL, concepts=len(b.get("candidates") or []), cost_cop=sum(_actual_cost(m,u) for m,u in usage_by_model.items() if m in intel.OPENAI_PRICING)*rate)
            first=_merge_batch_results(luna_results,completeness={})
            escalate=_select_sol_escalations(bundle,first)
            final=first
            if escalate:
                sol_results=[]; sol_plan=[escalate[i:i+24] for i in range(0,len(escalate),24)]
                for idx,ids in enumerate(sol_plan):
                    b=_refinement_bundle(bundle,ids,first,idx+1,len(sol_plan))
                    out_budget=_auto_output_budget(len(ids),len(b.get("existing_relations") or []),len(b.get("state_transitions") or []))
                    current_stage=SOL_MODEL
                    _progress(stage="sol", label="Sol refinando", run_id=run_id, current=idx+1, total=len(sol_plan), model=SOL_MODEL, concepts=len(ids), cost_cop=sum(_actual_cost(m,u) for m,u in usage_by_model.items() if m in intel.OPENAI_PRICING)*rate)
                    r,u=run_model(b,model=SOL_MODEL,output_tokens=out_budget,reasoning_effort=reasoning_effort)
                    sol_results.append(r); completed_sol += 1
                    for k in usage_by_model[SOL_MODEL]: usage_by_model[SOL_MODEL][k]+=int(u.get(k) or 0)
                    _progress(stage="sol", label="Sol refinando", run_id=run_id, current=idx+1, total=len(sol_plan), model=SOL_MODEL, concepts=len(ids), cost_cop=sum(_actual_cost(m,u) for m,u in usage_by_model.items() if m in intel.OPENAI_PRICING)*rate)
                refine=_merge_batch_results(sol_results,completeness={})
                final=_overlay_refinement(first,refine,set(escalate))
            total_candidates=len(bundle.get("candidates") or []); total_concepts=len(bundle.get("model_units") or [])
            completeness={"candidates_total":total_candidates,"candidates_analyzed":total_candidates,"concepts_total":total_concepts,"concepts_analyzed":total_concepts,"batches_total":len(luna_bundles)+completed_sol,"batches_completed":completed_luna+completed_sol,"coverage_pct":100.0,"truncated":False,"luna_concepts":total_concepts,"sol_refined":len(escalate),"pipeline":"Luna→Sol selectivo"}
            result={**final,"completeness":completeness}
        else:
            batch_bundles=_batch_bundles(bundle); batch_results=[]
            if model not in usage_by_model: usage_by_model[model]={"input_tokens":0,"output_tokens":0,"total_tokens":0}
            for idx,b in enumerate(batch_bundles, start=1):
                out_budget=_auto_output_budget(len(b.get("candidates") or []),len(b.get("existing_relations") or []),len(b.get("state_transitions") or []))
                current_stage=model
                _progress(stage="model", label="Modelo analizando", run_id=run_id, current=idx, total=len(batch_bundles), model=model, concepts=len(b.get("candidates") or []), cost_cop=sum(_actual_cost(m,u) for m,u in usage_by_model.items() if m in intel.OPENAI_PRICING)*rate)
                r,u=run_model(b,model=model,output_tokens=out_budget,reasoning_effort=reasoning_effort)
                batch_results.append(r); completed_luna += 1
                for k in usage_by_model[model]: usage_by_model[model][k]+=int(u.get(k) or 0)
                _progress(stage="model", label="Modelo analizando", run_id=run_id, current=idx, total=len(batch_bundles), model=model, concepts=len(b.get("candidates") or []), cost_cop=sum(_actual_cost(m,u) for m,u in usage_by_model.items() if m in intel.OPENAI_PRICING)*rate)
            total_candidates=len(bundle.get("candidates") or []); total_concepts=len(bundle.get("model_units") or [])
            completeness={"candidates_total":total_candidates,"candidates_analyzed":total_candidates,"concepts_total":total_concepts,"concepts_analyzed":total_concepts,"batches_total":len(batch_bundles),"batches_completed":len(batch_bundles),"coverage_pct":100.0,"truncated":False,"luna_concepts":total_concepts if model==LUNA_MODEL else 0,"sol_refined":total_concepts if model==SOL_MODEL else 0}
            result=_merge_batch_results(batch_results,completeness=completeness)

        _progress(stage="persisting", label="Guardando memoria semántica", run_id=run_id, current=1, total=1, model=current_stage, cost_cop=sum(_actual_cost(m,u) for m,u in usage_by_model.items() if m in intel.OPENAI_PRICING)*rate)
        persisted=_persist_result(conn,run_id,bundle,result,auto_apply_threshold=auto_apply_threshold,suggest_threshold=suggest_threshold)
        projection={}
        try:
            import negro_native_projection as native_projection
            projection=native_projection.project_current_memory(conn, force=True)
        except Exception as projection_exc:
            projection={"error":str(projection_exc)[:1000]}
        cost=sum(_actual_cost(m,u) for m,u in usage_by_model.items() if m in intel.OPENAI_PRICING)
        cost_cop=cost*rate
        usage_total={"by_model":usage_by_model,"input_tokens":sum(int(u.get("input_tokens") or 0) for u in usage_by_model.values()),"output_tokens":sum(int(u.get("output_tokens") or 0) for u in usage_by_model.values()),"total_tokens":sum(int(u.get("total_tokens") or 0) for u in usage_by_model.values())}
        conn.execute("UPDATE semantic_agent_runs SET status='completed',usage_json=?,result_json=?,cost_usd=?,cost_cop=?,finished_at=? WHERE id=?",(json.dumps(usage_total),json.dumps(result,ensure_ascii=False),cost,cost_cop,now_iso(),run_id))
        conn.commit()
        _progress(stage="completed", label="Análisis completado", run_id=run_id, current=1, total=1, model=current_stage, cost_cop=cost_cop, coverage=float((result.get("completeness") or {}).get("coverage_pct") or 0))
        return {"ok":True,"run_id":run_id,"estimate":estimate,"usage":usage_total,"cost_usd":cost,"cost_cop":cost_cop,"result":result,"completeness":result.get("completeness") or {},"persisted":persisted,"native_projection":projection,"bundle_stats":bundle.get("stats",{})}
    except ContextAgentModelError as exc:
        # Preserve billed usage without persisting partial semantic memory.
        target=current_stage
        if target not in usage_by_model: usage_by_model[target]={"input_tokens":0,"output_tokens":0,"total_tokens":0}
        for k in usage_by_model[target]: usage_by_model[target][k]+=int((exc.usage or {}).get(k) or 0)
        cost=sum(_actual_cost(m,u) for m,u in usage_by_model.items() if m in intel.OPENAI_PRICING); cost_cop=cost*rate
        err={"completeness":{"coverage_pct":0.0,"truncated":True,"luna_batches_completed":completed_luna,"sol_batches_completed":completed_sol}}
        conn.execute("UPDATE semantic_agent_runs SET status='error',usage_json=?,result_json=?,cost_usd=?,cost_cop=?,error_text=?,finished_at=? WHERE id=?",(json.dumps({"by_model":usage_by_model}),json.dumps(err),cost,cost_cop,str(exc)[:2000],now_iso(),run_id))
        conn.commit()
        _progress(stage="error", label="El análisis falló", run_id=run_id, current=0, total=0, model=current_stage, cost_cop=cost_cop, error=str(exc)[:1000])
        raise
    except Exception as exc:
        cost=sum(_actual_cost(m,u) for m,u in usage_by_model.items() if m in intel.OPENAI_PRICING); cost_cop=cost*rate
        err={"completeness":{"coverage_pct":0.0,"truncated":True,"luna_batches_completed":completed_luna,"sol_batches_completed":completed_sol}}
        conn.execute("UPDATE semantic_agent_runs SET status='error',usage_json=?,result_json=?,cost_usd=?,cost_cop=?,error_text=?,finished_at=? WHERE id=?",(json.dumps({"by_model":usage_by_model}),json.dumps(err),cost,cost_cop,str(exc)[:2000],now_iso(),run_id))
        conn.commit()
        _progress(stage="error", label="El análisis falló", run_id=run_id, current=0, total=0, model=current_stage, cost_cop=cost_cop, error=str(exc)[:1000])
        raise


def estimate(conn, *, mode: str = "incremental", model: str = DEFAULT_MODEL, target_key: str | None = None) -> dict[str, Any]:
    bundle = build_analysis_bundle(conn, mode=mode, target_key=target_key)
    est = estimate_bundle(bundle, model=model)
    return {"estimate":est,"stats":bundle.get("stats",{}),"watermark_before":bundle.get("watermark_before"),"watermark_after":bundle.get("watermark_after"),"sample_candidates":bundle.get("candidates",[])[:12]}


def dashboard(conn) -> dict[str, Any]:
    init_schema(conn)
    runs = [dict(r) for r in conn.execute("SELECT * FROM semantic_agent_runs ORDER BY id DESC LIMIT 20").fetchall()]
    for r in runs:
        for key in ("estimate_json","usage_json","result_json"):
            try: r[key[:-5] if key.endswith('_json') else key] = json.loads(r.get(key) or "{}")
            except Exception: r[key[:-5] if key.endswith('_json') else key] = {}
    inferences = [dict(r) for r in conn.execute(
        """SELECT si.* FROM semantic_inferences si JOIN (SELECT candidate_id,MAX(id) id FROM semantic_inferences GROUP BY candidate_id) x ON x.id=si.id
           ORDER BY si.confidence DESC,si.id DESC LIMIT 200"""
    ).fetchall()]
    relations = [dict(r) for r in conn.execute("SELECT * FROM semantic_relations WHERE status IN ('auto_applied','confirmed','suggested') ORDER BY id DESC LIMIT 160").fetchall()]
    labels={str(i.get("candidate_id")): f"{str(i.get('semantic_type') or i.get('category') or 'Concept')}[{str(i.get('value_preview') or i.get('normalized_key') or '')[:40]}]" for i in inferences}
    for r in relations:
        r["src_label"] = labels.get(str(r.get("src_candidate_id"))) or str(r.get("src_candidate_id") or "")
        r["dst_label"] = labels.get(str(r.get("dst_candidate_id"))) if r.get("dst_candidate_id") else str(r.get("dst_literal") or "")
    try:
        native_rows=conn.execute("""SELECT l.*,i.name identity_name FROM identity_semantic_links l JOIN identities i ON i.id=l.identity_id
                                   ORDER BY l.confidence DESC,l.id DESC LIMIT 160""").fetchall()
        for row in native_rows:
            d=dict(row)
            val=str(d.get("value_preview") or "").strip()
            typ=str(d.get("semantic_type") or "Context")
            relations.append({
                **d,
                "src_candidate_id":f"identity:{int(d['identity_id'])}",
                "dst_candidate_id":str(d.get("candidate_id") or ""),
                "src_label":str(d.get("identity_name") or f"Identity #{d['identity_id']}"),
                "dst_label":f"{typ}[{val[:40]}]" if val else typ,
            })
    except Exception:
        pass
    total_cost = float(conn.execute("SELECT COALESCE(SUM(cost_usd),0) v FROM semantic_agent_runs WHERE cost_usd IS NOT NULL").fetchone()["v"] or 0)
    settings=intel.load_settings(); rate=float(settings.get("usd_cop_rate") or 0)
    total_cost_cop=float(conn.execute("SELECT COALESCE(SUM(cost_cop),0) v FROM semantic_agent_runs WHERE cost_cop IS NOT NULL").fetchone()["v"] or 0)
    if not total_cost_cop and total_cost: total_cost_cop=total_cost*rate
    counts = {
        "observations": int(conn.execute("SELECT COUNT(*) c FROM semantic_observations").fetchone()["c"] or 0),
        "inferences": len(inferences),
        "relations": len(relations),
        "runs": int(conn.execute("SELECT COUNT(*) c FROM semantic_agent_runs WHERE status='completed'").fetchone()["c"] or 0),
        "cost_usd": total_cost,
        "cost_cop": total_cost_cop,
    }
    native_projection={}
    try:
        import negro_native_projection as native_projection_tools
        native_projection=native_projection_tools.projection_summary(conn)
    except Exception:
        native_projection={}
    return {"runs":runs,"inferences":inferences,"relations":relations,"counts":counts,"native_projection":native_projection}


def _inference_display_bucket(inf: dict[str, Any]) -> tuple[int, int]:
    category=str(inf.get("category") or "")
    text=" ".join([str(inf.get("normalized_key") or ""),str(inf.get("semantic_type") or ""),str(inf.get("role") or ""),str(inf.get("explanation") or "")]).lower()
    technical_tokens=("transport","telemetry","timing","priority","browser","cache","cors","strict_transport","security policy","http transfer","nextjs","trace","correlation","rum","static asset","request metadata","response metadata")
    technical=category=="context" and any(t in text for t in technical_tokens)
    if technical: return (4,0)
    rank={"identity":0,"credential":0,"authorization_boundary":0,"business_object":1,"reference":1,"action":2,"state":2,"context":3}.get(category,3)
    return (rank,0)


def semantics_for_exchange(conn, exchange_id: int) -> dict[str, Any]:
    """Return current semantic marks/relations relevant to one HTTP exchange."""
    init_schema(conn)
    obs = [dict(r) for r in conn.execute("SELECT * FROM semantic_observations WHERE exchange_id=? ORDER BY id", (int(exchange_id),)).fetchall()]
    if not obs:
        return {"inferences":[],"relations":[]}
    latest = {str(r["candidate_id"]):dict(r) for r in conn.execute(
        """SELECT si.* FROM semantic_inferences si JOIN (SELECT candidate_id,MAX(id) id FROM semantic_inferences GROUP BY candidate_id) x ON x.id=si.id
           WHERE si.status IN ('auto_applied','confirmed','suggested')"""
    ).fetchall()}
    infs=[]; ids=set()
    for o in obs:
        cid=str(o.get("candidate_id") or _candidate_id(str(o["normalized_key"]),str(o["value_hash"]),value=str(o.get("value_raw") or ""),kind=str(o.get("value_kind") or "scalar"),location=str(o.get("location") or "")))
        inf=latest.get(cid)
        if inf:
            item=dict(inf); item["observation_id"]=int(o["id"]); item["side"]=o["side"]; item["location"]=o["location"]; item["key_name"]=o["key_name"]; item["value_hash"]=o["value_hash"]
            infs.append(item); ids.add(cid)
    rels=[]
    if ids:
        for r in conn.execute("SELECT * FROM semantic_relations WHERE status IN ('auto_applied','confirmed','suggested') ORDER BY id DESC LIMIT 400").fetchall():
            d=dict(r)
            if d.get("src_candidate_id") in ids or d.get("dst_candidate_id") in ids:
                src=latest.get(str(d.get("src_candidate_id") or "")) or {}
                dst=latest.get(str(d.get("dst_candidate_id") or "")) or {}
                def _label(x, fallback=""):
                    if not x:
                        return fallback
                    typ=str(x.get("semantic_type") or x.get("category") or "Concept")
                    val=str(x.get("value_preview") or x.get("normalized_key") or "").strip()
                    return f"{typ}[{val[:40]}]" if val else typ
                d["src_label"]=_label(src,str(d.get("src_candidate_id") or ""))
                d["dst_label"]=_label(dst,str(d.get("dst_literal") or d.get("dst_candidate_id") or ""))
                rels.append(d)
    summary=[]; technical=[]; seen=set()
    ordered=sorted(infs,key=lambda x:(_inference_display_bucket(x)[0],-float(x.get("confidence") or 0),int(x.get("id") or 0)))
    for i in ordered:
        cid=str(i.get("candidate_id") or "")
        if cid in seen: continue
        seen.add(cid)
        if _inference_display_bucket(i)[0] >= 4:
            technical.append(i)
        else:
            summary.append(i)
    native_identity=None; native_links=[]
    try:
        row=conn.execute("""SELECT i.id,i.name,i.kind,xi.confidence,xi.source,iam.status ai_status,iam.confidence ai_confidence,iam.semantic_type ai_semantic_type
                              FROM exchange_identities xi JOIN identities i ON i.id=xi.identity_id
                              LEFT JOIN identity_ai_meta iam ON iam.identity_id=i.id WHERE xi.exchange_id=? LIMIT 1""",(int(exchange_id),)).fetchone()
        if row:
            native_identity=dict(row)
            import negro_native_projection as native_projection
            native_links=native_projection.identity_links(conn,int(row["id"]),limit=16)
            for link in native_links:
                rels.insert(0,{
                    "src_label":str(row["name"]),"src_candidate_id":f"identity:{int(row['id'])}",
                    "relation":str(link.get("relation") or "related_to"),
                    "dst_label":str(link.get("semantic_type") or link.get("value_preview") or link.get("candidate_id") or "Context"),
                    "dst_candidate_id":str(link.get("candidate_id") or ""),
                    "confidence":float(link.get("confidence") or 0),"status":str(link.get("status") or "suggested"),
                    "explanation":"Native Identity projection",
                })
    except Exception:
        native_identity=None; native_links=[]
    return {"inferences":infs,"summary_inferences":summary,"technical_inferences":technical,"relations":rels[:80],"native_identity":native_identity,"native_links":native_links}


def synthetic_annotations_for_exchange(conn, exchange_id: int) -> list[dict[str, Any]]:
    """Project high-confidence AI semantics into Workbench without overwriting manual truth."""
    semantic = semantics_for_exchange(conn, exchange_id)
    manual_keys = set()
    if _table_exists(conn, "http_value_annotations"):
        for r in conn.execute("SELECT side,location,key_name,value_hash FROM http_value_annotations WHERE exchange_id=?", (int(exchange_id),)).fetchall():
            manual_keys.add((str(r["side"]),str(r["location"]),str(r["key_name"]),str(r["value_hash"])))
    out=[]
    cls_map={"identity":"resolver","credential":"auth","business_object":"entity","reference":"entity","state":"context","action":"context","authorization_boundary":"context","context":"context"}
    for inf in semantic.get("inferences") or []:
        status=str(inf.get("status") or "")
        conf=float(inf.get("confidence") or 0)
        # Human confirmation is ground truth for display. Medium-confidence AI
        # results are projected as visually-soft suggestions; low/rejected stay
        # out of the HTTP text and remain in semantic memory only.
        if status == "confirmed":
            pass
        elif status == "auto_applied" and conf >= DEFAULT_AUTO_APPLY:
            pass
        elif status == "suggested" and conf >= DEFAULT_SUGGEST:
            pass
        else:
            continue
        key=(str(inf.get("side") or ""),str(inf.get("location") or ""),str(inf.get("key_name") or ""),str(inf.get("value_hash") or ""))
        if key in manual_keys:
            continue
        cls=cls_map.get(str(inf.get("category") or ""))
        if not cls:
            continue
        obs=conn.execute("SELECT value_raw,value_preview FROM semantic_observations WHERE id=?", (int(inf.get("observation_id") or 0),)).fetchone()
        value=str((obs["value_raw"] if obs else "") or (obs["value_preview"] if obs else ""))
        out.append({
            "side":key[0],"location":key[1],"key_name":key[2],"value_hash":key[3],"value_raw":value,"value_preview":value[:500],
            "classification":cls,"identity_id":None,"identity_name":"","object_type":str(inf.get("semantic_type") or "") if cls=="entity" else "",
            "source":"context_agent","semantic_category":str(inf.get("category") or ""),"semantic_type":str(inf.get("semantic_type") or ""),
            "semantic_role":str(inf.get("role") or ""),"ai_confidence":float(inf.get("confidence") or 0),"ai_status":status,"inference_id":int(inf.get("id") or 0),
            "match_reason":str(inf.get("explanation") or ""),
        })
    return out

def decide_inference(conn, inference_id: int, decision: str) -> dict[str, Any]:
    init_schema(conn)
    row = conn.execute("SELECT * FROM semantic_inferences WHERE id=?", (int(inference_id),)).fetchone()
    if not row:
        raise ValueError("Inferencia no encontrada")
    decision = str(decision or "").strip().lower()
    if decision not in {"confirmed", "rejected"}:
        raise ValueError("Decisión inválida")
    conn.execute("UPDATE semantic_inferences SET status=?,updated_at=? WHERE id=?", (decision, now_iso(), int(inference_id)))
    return {"id":int(inference_id),"status":decision,"candidate_id":str(row["candidate_id"])}
