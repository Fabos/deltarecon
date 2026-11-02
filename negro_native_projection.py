from __future__ import annotations

"""Native semantic projection for Negro Context Agent.

Projects high-value AI semantic memory into Negro's native Identity model without
replacing human ground truth.  The projection is deterministic and local: it
never calls an LLM and can therefore replay already-paid Context Agent runs.
"""

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import negro_identity as identity_tools

PROJECTION_VERSION = "native-projection-v1"
MIN_IDENTITY_CONFIDENCE = 0.74

STRONG_IDENTITY_TOKENS = (
    "member", "participant", "customer", "client", "user", "person",
    "document", "identity", "subject", "userid", "customerid", "memberid",
)
WEAK_IDENTITY_TOKENS = ("email", "phone", "mobile", "name", "birthday", "birth", "contact")
TECHNICAL_TOKENS = (
    "transport", "telemetry", "timing", "priority", "browser", "cache", "cors",
    "security_policy", "securitypolicy", "nextjs", "trace", "correlation",
    "request metadata", "response metadata", "http ", "rum", "static asset",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", errors="ignore")).hexdigest()


def init_schema(conn) -> None:
    identity_tools.init_schema(conn)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS identity_ai_meta (
            identity_id INTEGER PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'provisional',
            confidence REAL NOT NULL DEFAULT 0,
            semantic_type TEXT,
            source_run_id INTEGER,
            evidence_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS identity_ai_attributes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_id INTEGER NOT NULL,
            candidate_id TEXT NOT NULL,
            normalized_key TEXT,
            semantic_type TEXT,
            role TEXT,
            attribute_kind TEXT NOT NULL DEFAULT 'attribute',
            value_hash TEXT,
            value_preview TEXT,
            confidence REAL NOT NULL DEFAULT 0,
            observation_id INTEGER,
            exchange_id INTEGER,
            location TEXT,
            source_run_id INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(identity_id,candidate_id),
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_identity_ai_attr_identity ON identity_ai_attributes(identity_id,attribute_kind,confidence DESC);
        CREATE INDEX IF NOT EXISTS idx_identity_ai_attr_candidate ON identity_ai_attributes(candidate_id);
        CREATE TABLE IF NOT EXISTS identity_semantic_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_id INTEGER NOT NULL,
            candidate_id TEXT NOT NULL,
            relation TEXT NOT NULL,
            semantic_type TEXT,
            role TEXT,
            value_preview TEXT,
            confidence REAL NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'suggested',
            source_run_id INTEGER,
            evidence_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(identity_id,candidate_id,relation),
            FOREIGN KEY(identity_id) REFERENCES identities(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_identity_sem_links_identity ON identity_semantic_links(identity_id,confidence DESC);
        CREATE TABLE IF NOT EXISTS identity_projection_conflicts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signature TEXT NOT NULL UNIQUE,
            candidate_ids_json TEXT NOT NULL,
            identity_ids_json TEXT NOT NULL,
            reason TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )


def _meta_get(conn, key: str) -> str:
    try:
        row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return str(row["value"] or "") if row else ""
    except Exception:
        return ""


def _meta_set(conn, key: str, value: str) -> None:
    conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (key, str(value)))


def _latest_inferences(conn) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute(
        """SELECT si.* FROM semantic_inferences si
             JOIN (SELECT candidate_id,MAX(id) id FROM semantic_inferences GROUP BY candidate_id) x ON x.id=si.id
             WHERE si.status IN ('auto_applied','confirmed','suggested')
             ORDER BY si.confidence DESC,si.id DESC"""
    ).fetchall()]


def _obs_for_candidate(conn, candidate_id: str) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM semantic_observations WHERE candidate_id=? ORDER BY id", (str(candidate_id),)
    ).fetchall()]


def _semantic_text(inf: dict[str, Any]) -> str:
    return " ".join([
        str(inf.get("normalized_key") or ""), str(inf.get("semantic_type") or ""),
        str(inf.get("role") or ""), str(inf.get("explanation") or ""),
    ]).lower()


def _is_technical(inf: dict[str, Any]) -> bool:
    text = _semantic_text(inf)
    return any(tok in text for tok in TECHNICAL_TOKENS)


def _is_strong_identity(inf: dict[str, Any]) -> bool:
    if str(inf.get("category") or "") != "identity":
        return False
    if float(inf.get("confidence") or 0) < MIN_IDENTITY_CONFIDENCE:
        return False
    text = _semantic_text(inf).replace("_", "")
    if any(tok in text for tok in ("email", "phone", "mobile", "name", "birthday", "birth")):
        # Contact attributes alone do not resolve an actor.
        return any(tok in text for tok in ("document", "member", "customerid", "userid", "subject"))
    return any(tok.replace("_", "") in text for tok in STRONG_IDENTITY_TOKENS)


def _is_identity_attribute(inf: dict[str, Any]) -> bool:
    if str(inf.get("category") or "") != "identity":
        return False
    text = _semantic_text(inf)
    return any(tok in text for tok in WEAK_IDENTITY_TOKENS) or not _is_strong_identity(inf)


def _candidate_exchange_ids(obs: list[dict[str, Any]]) -> set[int]:
    return {int(o.get("exchange_id") or 0) for o in obs if int(o.get("exchange_id") or 0) > 0}


def _actor_role_bucket(inf: dict[str, Any]) -> str:
    text=(str(inf.get("role") or "")+" "+str(inf.get("normalized_key") or "")+" "+str(inf.get("semantic_type") or "")).lower().replace("_"," ")
    if re.search(r"\b(source|from|sender|origin actor|actor source)\b", text):
        return "source"
    if re.search(r"\b(target|destination|to|recipient|receiver|actor target)\b", text):
        return "target"
    return "neutral"


def _roles_compatible(a: dict[str, Any], b: dict[str, Any]) -> bool:
    ra,rb=_actor_role_bucket(a),_actor_role_bucket(b)
    return ra=="neutral" or rb=="neutral" or ra==rb


def _existing_identity_ids(conn, candidate_ids: list[str], obs_map: dict[str, list[dict[str, Any]]]) -> set[int]:
    ids: set[int] = set()
    value_hashes: set[str] = set()
    exchange_ids: set[int] = set()
    for cid in candidate_ids:
        for o in obs_map.get(cid) or []:
            if o.get("manual_identity_id"):
                ids.add(int(o["manual_identity_id"]))
            if o.get("value_hash"):
                value_hashes.add(str(o["value_hash"]))
            if o.get("exchange_id"):
                exchange_ids.add(int(o["exchange_id"]))
    if value_hashes:
        marks = ",".join("?" for _ in value_hashes)
        rows = conn.execute(
            f"SELECT DISTINCT identity_id FROM identity_resolvers WHERE enabled=1 AND classification='resolver' AND value_hash IN ({marks})",
            tuple(value_hashes),
        ).fetchall()
        ids.update(int(r["identity_id"]) for r in rows)
    if exchange_ids:
        marks = ",".join("?" for _ in exchange_ids)
        rows = conn.execute(
            f"""SELECT DISTINCT identity_id FROM exchange_identities
                 WHERE exchange_id IN ({marks}) AND source IN ('manual','burp','manual_assignment','parameter_resolver','burp_update')""",
            tuple(exchange_ids),
        ).fetchall()
        ids.update(int(r["identity_id"]) for r in rows)
    return ids


def _identity_name(infs: list[dict[str, Any]], candidate_ids: list[str]) -> str:
    preferred = "Member"
    for inf in infs:
        typ = str(inf.get("semantic_type") or "").strip()
        if typ and typ.lower() not in {"identity", "identifier", "memberdocumentnumber", "customeremail"}:
            preferred = re.sub(r"[^a-zA-Z0-9 _.-]+", "", typ)[:48] or preferred
            if any(x in typ.lower() for x in ("member", "customer", "user", "participant", "person")):
                break
    sig = _sha("|".join(sorted(candidate_ids)))[:7].upper()
    return f"{preferred} · AI-{sig}"[:120]


def _upsert_meta(conn, identity_id: int, *, status: str, confidence: float, semantic_type: str, run_id: int | None, evidence: list[int]) -> None:
    now = now_iso()
    conn.execute(
        """INSERT INTO identity_ai_meta(identity_id,status,confidence,semantic_type,source_run_id,evidence_json,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(identity_id) DO UPDATE SET
             status=CASE WHEN identity_ai_meta.status='confirmed' THEN 'confirmed' ELSE excluded.status END,
             confidence=MAX(identity_ai_meta.confidence,excluded.confidence),
             semantic_type=COALESCE(NULLIF(excluded.semantic_type,''),identity_ai_meta.semantic_type),
             source_run_id=excluded.source_run_id,evidence_json=excluded.evidence_json,updated_at=excluded.updated_at""",
        (int(identity_id), status, float(confidence), str(semantic_type or "")[:120], run_id, json.dumps(evidence[:80]), now, now),
    )


def _upsert_attribute(conn, identity_id: int, inf: dict[str, Any], obs: dict[str, Any], kind: str) -> None:
    now = now_iso()
    conn.execute(
        """INSERT INTO identity_ai_attributes(identity_id,candidate_id,normalized_key,semantic_type,role,attribute_kind,value_hash,value_preview,confidence,observation_id,exchange_id,location,source_run_id,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(identity_id,candidate_id) DO UPDATE SET
             semantic_type=excluded.semantic_type,role=excluded.role,attribute_kind=excluded.attribute_kind,
             value_hash=excluded.value_hash,value_preview=excluded.value_preview,confidence=excluded.confidence,
             observation_id=excluded.observation_id,exchange_id=excluded.exchange_id,location=excluded.location,
             source_run_id=excluded.source_run_id,updated_at=excluded.updated_at""",
        (
            int(identity_id), str(inf.get("candidate_id") or ""), str(inf.get("normalized_key") or "")[:180],
            str(inf.get("semantic_type") or inf.get("category") or "")[:120], str(inf.get("role") or "")[:120], kind,
            str(obs.get("value_hash") or ""), str(obs.get("value_preview") or "")[:500], float(inf.get("confidence") or 0),
            int(obs.get("id") or 0) or None, int(obs.get("exchange_id") or 0) or None, str(obs.get("location") or "")[:300],
            int(inf.get("run_id") or 0) or None, now, now,
        ),
    )


def _resolver_for_observation(conn, identity_id: int, obs: dict[str, Any]) -> None:
    location = str(obs.get("location") or "")
    value_hash = str(obs.get("value_hash") or "")
    if not location or not value_hash:
        return
    now = now_iso()
    conn.execute(
        """INSERT INTO identity_resolvers(identity_id,context_id,resolver_type,selector,value_hash,value_preview,value_raw,enabled,source,created_at,updated_at,anchor_exchange_id,anchor_observation_id,classification)
           VALUES(?,NULL,'http_value',?,?,?,?,1,'ai_projection',?,?,?,?,'resolver')
           ON CONFLICT(identity_id,context_id,resolver_type,selector,value_hash)
           DO UPDATE SET value_preview=excluded.value_preview,value_raw=excluded.value_raw,enabled=1,source='ai_projection',updated_at=excluded.updated_at,
                         anchor_exchange_id=COALESCE(identity_resolvers.anchor_exchange_id,excluded.anchor_exchange_id),
                         anchor_observation_id=COALESCE(identity_resolvers.anchor_observation_id,excluded.anchor_observation_id),classification='resolver'""",
        (
            int(identity_id), location, value_hash, str(obs.get("value_preview") or "")[:120], str(obs.get("value_raw") or ""),
            now, now, int(obs.get("exchange_id") or 0) or None, int(obs.get("id") or 0) or None,
        ),
    )


def _relation_for(inf: dict[str, Any], kind: str) -> str:
    text = _semantic_text(inf)
    if kind == "credential": return "authenticated_by"
    if "email" in text or "phone" in text or "contact" in text: return "has_contact"
    if "document" in text: return "identified_by"
    if "referral" in text or "referido" in text: return "has_referral"
    if str(inf.get("category") or "") == "reference": return "associated_with"
    if kind == "context": return "has_context"
    return "described_by"


def _upsert_link(conn, identity_id: int, inf: dict[str, Any], relation: str, obs_ids: list[int]) -> None:
    now = now_iso()
    status = "confirmed" if str(inf.get("status") or "") == "confirmed" else "suggested"
    conn.execute(
        """INSERT INTO identity_semantic_links(identity_id,candidate_id,relation,semantic_type,role,value_preview,confidence,status,source_run_id,evidence_json,created_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(identity_id,candidate_id,relation) DO UPDATE SET semantic_type=excluded.semantic_type,role=excluded.role,value_preview=excluded.value_preview,
             confidence=MAX(identity_semantic_links.confidence,excluded.confidence),status=CASE WHEN identity_semantic_links.status='confirmed' THEN 'confirmed' ELSE excluded.status END,
             source_run_id=excluded.source_run_id,evidence_json=excluded.evidence_json,updated_at=excluded.updated_at""",
        (
            int(identity_id), str(inf.get("candidate_id") or ""), relation,
            str(inf.get("semantic_type") or inf.get("category") or "")[:120], str(inf.get("role") or "")[:120],
            str(inf.get("value_preview") or "")[:500], float(inf.get("confidence") or 0), status,
            int(inf.get("run_id") or 0) or None, json.dumps(obs_ids[:80]), now, now,
        ),
    )


def _record_conflict(conn, candidate_ids: list[str], identity_ids: set[int], reason: str) -> None:
    sig = _sha("|".join(sorted(candidate_ids)) + "::" + ",".join(map(str, sorted(identity_ids))))
    now = now_iso()
    conn.execute(
        """INSERT INTO identity_projection_conflicts(signature,candidate_ids_json,identity_ids_json,reason,status,created_at,updated_at)
           VALUES(?,?,?,?, 'open',?,?) ON CONFLICT(signature) DO UPDATE SET reason=excluded.reason,updated_at=excluded.updated_at""",
        (sig, json.dumps(sorted(candidate_ids)), json.dumps(sorted(identity_ids)), str(reason)[:1000], now, now),
    )


def project_current_memory(conn, *, force: bool = False) -> dict[str, Any]:
    """Project existing AI semantic memory into native Identity memory, locally.

    This function is idempotent and never calls a model.  It can replay an
    already-paid Context Agent run after a code upgrade.
    """
    init_schema(conn)
    if not _table_exists(conn, "semantic_inferences"):
        return {"projected": 0, "created": 0, "enriched": 0, "conflicts": 0, "reason": "no_semantic_memory"}
    max_row = conn.execute("SELECT COALESCE(MAX(id),0) m FROM semantic_inferences").fetchone()
    max_inf = int(max_row["m"] or 0)
    marker = _meta_get(conn, "native_projection_last_inference_id")
    version = _meta_get(conn, "native_projection_version")
    if not force and version == PROJECTION_VERSION and marker and int(marker or 0) >= max_inf:
        return {"projected": 0, "created": 0, "enriched": 0, "conflicts": 0, "up_to_date": True}

    infs = _latest_inferences(conn)
    by_cid = {str(i.get("candidate_id") or ""): i for i in infs}
    obs_map = {cid: _obs_for_candidate(conn, cid) for cid in by_cid}
    anchors = [i for i in infs if _is_strong_identity(i)]
    if not anchors:
        _meta_set(conn, "native_projection_version", PROJECTION_VERSION)
        _meta_set(conn, "native_projection_last_inference_id", str(max_inf))
        return {"projected": 0, "created": 0, "enriched": 0, "conflicts": 0, "anchors": 0}

    # Union strong identity candidates that repeatedly co-occur in the same HTTP exchange.
    parent = {str(i["candidate_id"]): str(i["candidate_id"]) for i in anchors}
    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb: parent[rb] = ra
    ex_map = {cid: _candidate_exchange_ids(obs_map.get(cid) or []) for cid in parent}
    anchor_ids = list(parent)
    for idx, a in enumerate(anchor_ids):
        for b in anchor_ids[idx+1:]:
            shared = ex_map[a] & ex_map[b]
            if shared and _roles_compatible(by_cid[a], by_cid[b]):
                union(a, b)
    groups: dict[str, list[str]] = defaultdict(list)
    for cid in anchor_ids: groups[find(cid)].append(cid)

    # Attach weak identity attributes / credentials / useful references only when
    # their evidence points to exactly one identity group.
    group_exchanges: dict[str, set[int]] = {g:set().union(*(ex_map[c] for c in cs)) for g,cs in groups.items()}
    attachments: dict[str, list[str]] = {g:[] for g in groups}
    for inf in infs:
        cid = str(inf.get("candidate_id") or "")
        if cid in parent or _is_technical(inf):
            continue
        category = str(inf.get("category") or "")
        if category not in {"identity", "credential", "reference", "context"}:
            continue
        if category == "context":
            text = _semantic_text(inf)
            if not any(k in text for k in ("role", "tenant", "organization", "channel", "origin", "country")):
                continue
        exs = _candidate_exchange_ids(obs_map.get(cid) or [])
        hits = [g for g, gx in group_exchanges.items() if exs & gx]
        if len(hits) == 1:
            attachments[hits[0]].append(cid)

    created = enriched = conflicts = projected = resolver_count = link_count = 0
    projected_identity_ids: set[int] = set()
    for gid, strong_ids in groups.items():
        group_infs = [by_cid[c] for c in strong_ids]
        existing = _existing_identity_ids(conn, strong_ids, obs_map)
        if len(existing) > 1:
            _record_conflict(conn, strong_ids, existing, "Múltiples identities existentes coinciden con resolvers fuertes; Negro no auto-mergea.")
            conflicts += 1
            continue
        confidence = max(float(i.get("confidence") or 0) for i in group_infs)
        if existing:
            identity_id = next(iter(existing)); enriched += 1
            meta_status = "existing"
        else:
            name = _identity_name(group_infs, strong_ids)
            identity_id = identity_tools.create_identity(conn, name, kind="person", notes="Identity provisional creada por Context Agent; confirmar/corregir/rechazar antes de usar como ground truth.")
            created += 1; meta_status = "provisional"
        projected_identity_ids.add(identity_id)
        evidence_ids: list[int] = []
        sem_type = next((str(i.get("semantic_type") or "") for i in group_infs if i.get("semantic_type")), "Identity")
        for cid in strong_ids:
            inf = by_cid[cid]
            obs_list = obs_map.get(cid) or []
            evidence_ids.extend(int(o.get("id") or 0) for o in obs_list if int(o.get("id") or 0))
            if obs_list:
                _upsert_attribute(conn, identity_id, inf, obs_list[0], "resolver")
            for o in obs_list:
                _resolver_for_observation(conn, identity_id, o); resolver_count += 1
            _upsert_link(conn, identity_id, inf, "identified_by", [int(o.get("id") or 0) for o in obs_list if int(o.get("id") or 0)]); link_count += 1
            projected += 1
        _upsert_meta(conn, identity_id, status=meta_status, confidence=confidence, semantic_type=sem_type, run_id=max(int(i.get("run_id") or 0) for i in group_infs), evidence=evidence_ids)

        for cid in attachments.get(gid) or []:
            inf = by_cid[cid]; obs_list = obs_map.get(cid) or []
            if not obs_list: continue
            category = str(inf.get("category") or "")
            kind = "attribute" if category == "identity" else "credential" if category == "credential" else "reference" if category == "reference" else "context"
            _upsert_attribute(conn, identity_id, inf, obs_list[0], kind)
            relation = _relation_for(inf, kind)
            _upsert_link(conn, identity_id, inf, relation, [int(o.get("id") or 0) for o in obs_list if int(o.get("id") or 0)]); link_count += 1
            projected += 1
            # Attach exact auth material only when this semantic candidate matches
            # a material fingerprint already extracted by Negro.
            if kind == "credential":
                for o in obs_list[:12]:
                    exid = int(o.get("exchange_id") or 0)
                    if not exid: continue
                    for material in identity_tools.extract_auth_materials(conn, exid):
                        if str(material.get("fingerprint") or "") == str(o.get("value_hash") or ""):
                            identity_tools._learn_material(conn, identity_id, None, material, source="ai_projection", classification="auth")

    # Resolver matching projects the Identity back across every historical Request
    # that contains one of the learned strong values. Manual assignments win.
    if projected_identity_ids:
        identity_tools.resolve_all(conn, limit=100000)

    _meta_set(conn, "native_projection_version", PROJECTION_VERSION)
    _meta_set(conn, "native_projection_last_inference_id", str(max_inf))
    conn.commit()
    return {
        "projected": projected, "created": created, "enriched": enriched,
        "conflicts": conflicts, "resolvers": resolver_count, "links": link_count,
        "identities": len(projected_identity_ids), "max_inference_id": max_inf,
    }


def _table_exists(conn, name: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone())


def identity_meta(conn, identity_id: int) -> dict[str, Any] | None:
    init_schema(conn)
    row = conn.execute("SELECT * FROM identity_ai_meta WHERE identity_id=?", (int(identity_id),)).fetchone()
    return dict(row) if row else None


def identity_links(conn, identity_id: int, *, limit: int = 20) -> list[dict[str, Any]]:
    init_schema(conn)
    return [dict(r) for r in conn.execute(
        "SELECT * FROM identity_semantic_links WHERE identity_id=? ORDER BY confidence DESC,id DESC LIMIT ?",
        (int(identity_id), max(1,min(int(limit),100))),
    ).fetchall()]


def projection_summary(conn) -> dict[str, Any]:
    init_schema(conn)
    return {
        "ai_identities": int(conn.execute("SELECT COUNT(*) c FROM identity_ai_meta").fetchone()["c"] or 0),
        "provisional": int(conn.execute("SELECT COUNT(*) c FROM identity_ai_meta WHERE status='provisional'").fetchone()["c"] or 0),
        "links": int(conn.execute("SELECT COUNT(*) c FROM identity_semantic_links").fetchone()["c"] or 0),
        "conflicts": int(conn.execute("SELECT COUNT(*) c FROM identity_projection_conflicts WHERE status='open'").fetchone()["c"] or 0),
    }
