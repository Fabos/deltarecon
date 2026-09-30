#!/usr/bin/env python3
"""Local web workspace for Negro Recon v0.19.

v0.8 adds a multi-target web workspace while keeping every target isolated in its
own existing Negro workspace/SQLite database. The UI stays local-first and calls
the same core functions used by the CLI.
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import shutil
import threading
import traceback
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
import urllib.parse
from typing import Any
from urllib.parse import urlsplit

import negro_core as core
import negro_rules as rulebook

try:
    from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    _WEB_IMPORT_ERROR = None
except ImportError as exc:  # CLI remains usable without web dependencies
    FastAPI = File = Form = HTTPException = Request = UploadFile = None  # type: ignore
    FileResponse = HTMLResponse = JSONResponse = RedirectResponse = StaticFiles = Jinja2Templates = None  # type: ignore
    _WEB_IMPORT_ERROR = exc

JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()
JOB_MAX_CONCURRENCY = 3
JOB_SLOTS = threading.Semaphore(JOB_MAX_CONCURRENCY)

# Repeater bridge polling must stay lightweight. Never run workspace migrations on
# every /next poll: on large bounty workspaces that can take seconds and make the
# Burp HTTP client time out/cancel the request. Cleanup of stale claims is also
# throttled instead of rescanning every workspace once per second.
REPEATER_CLEANUP_LOCK = threading.Lock()
REPEATER_LAST_CLEANUP_TS = 0.0
REPEATER_CLEANUP_INTERVAL_SECONDS = 30.0
# Only one current Burp bridge instance may consume the Repeater queue. Older
# extension builds started a daemon poller but did not stop it when the JAR was
# removed, so orphan pollers could keep claiming queue items invisibly. v0.16.7
# requires an instance id and keeps a short in-memory consumer lease.
REPEATER_BRIDGE_LOCK = threading.Lock()
REPEATER_ACTIVE_BRIDGE_ID: str | None = None
REPEATER_ACTIVE_BRIDGE_LAST_SEEN = 0.0
REPEATER_BRIDGE_LEASE_SECONDS = 5.0
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

UI_LABELS = {
    "pending": "Pendiente", "in_progress": "En revisión", "reviewed": "Revisado",
    "unknown": "Sin clasificar", "informational": "Informativo", "lead": "Interesante",
    "discarded": "Descartado", "finding": "Hallazgo",
    "none": "Sin prioridad", "low": "Baja", "medium": "Media", "high": "Alta", "critical": "Crítica", "info": "Informativa",
    "normal": "Normal", "untested": "Pendiente", "testing": "En prueba", "tested": "Revisado", "interesting": "Interesante",
    "candidate": "Candidata", "negative": "Negativa", "postponed": "Para después", "confirmed": "Confirmada",
    "draft": "Borrador", "reported": "Reportado", "retest_required": "Retest pendiente", "still_vulnerable": "Sigue vulnerable",
    "fixed": "Corregido", "fix_verified": "Corrección verificada", "closed": "Cerrado", "inconclusive": "No concluyente",
    "not_applicable": "No aplica", "quick": "Chequeo rápido",
    "queued": "En cola", "running": "Ejecutando", "done": "Terminado", "error": "Error",
    "affected": "Afectado", "evidence": "Evidencia", "step": "Paso",
    "AI": "IA", "ENGINE": "Motor", "MANUAL": "Manual",
    "resource": "Recurso", "host": "Host", "operation": "Método", "exchange": "Solicitud HTTP",
    "js_asset": "JavaScript", "observation": "Observación",
    "burp_proxy": "Burp Proxy", "burp_repeater": "Burp Repeater", "burp_other": "Burp",
    "request": "Solicitud", "response": "Respuesta", "cluster": "Grupo", "target": "Proyecto",
    "authorization": "Autorización", "business_logic": "Lógica de negocio", "state_transition": "Transición de estado",
    "cors": "CORS", "oauth": "OAuth/OIDC", "javascript": "JavaScript", "api": "API", "feature_flag": "Feature flags", "other": "Otro",
    "bola_surface": "Superficie BOLA/IDOR", "cloud_storage": "Almacenamiento cloud", "directory_listing": "Listado de directorio",
    "dom_xss": "DOM XSS", "oauth_oidc_surface": "Superficie OAuth/OIDC", "open_redirect": "Open redirect",
    "secret_or_client_config": "Secretos/configuración cliente", "source_map": "Source map", "ssrf_surface": "Superficie SSRF",
    "subdomain_takeover": "Subdomain takeover",
    "access_object_reference": "Autorización horizontal / IDOR",
    "mass_assignment": "Asignación masiva",
    "method_access_control": "Control de acceso por método HTTP",
    "redirect_body_access_control": "Datos expuestos antes de redirect",
    "proxy_path_access_control": "Control de acceso por ruta/proxy",
    "referer_access_control": "Control de acceso basado en Referer",
    "javascript_surface": "Superficie descubierta en JavaScript",
}

def _ui_label(value: Any) -> str:
    raw = str(value or "")
    return UI_LABELS.get(raw, raw.replace("_", " ").strip().capitalize() if raw else "—")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _set_job(job_id: str, **values: Any) -> None:
    with JOBS_LOCK:
        if job_id in JOBS:
            JOBS[job_id].update(values)


def _snapshot_target(target_key: str) -> dict[str, int]:
    target = core.get_target(target_key)
    if not target:
        return {}
    try:
        domain = str(target.get("domain", "")).strip().lower().rstrip(".")
        workspace = Path(str(target.get("workspace", ""))).expanduser()
        paths = core.ensure_workspace(workspace, domain)
        with core.db_connect(paths) as conn:
            return {
                "hosts": int(conn.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"]),
                "resources": int(conn.execute("SELECT COUNT(*) c FROM resources").fetchone()["c"]),
                "operations": int(conn.execute("SELECT COUNT(*) c FROM resource_operations").fetchone()["c"]),
                "http_exchanges": int(conn.execute("SELECT COUNT(*) c FROM http_exchanges").fetchone()["c"]),
                "js_assets": int(conn.execute("SELECT COUNT(*) c FROM js_assets").fetchone()["c"]),
                "observations": int(conn.execute("SELECT COUNT(*) c FROM observations").fetchone()["c"]),
            }
    except Exception:
        return {}


def _diff_snapshot(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    return {k: int(after.get(k, 0)) - int(before.get(k, 0)) for k in sorted(set(before) | set(after))}


def _start_job(label: str, target_key: str, fn, *args, **kwargs) -> str:
    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id,
            "target_key": target_key,
            "label": label,
            "status": "queued",
            "queued_at": _now(),
            "started_at": None,
            "finished_at": None,
            "error": None,
            "summary": None,
        }

    before = _snapshot_target(target_key)

    def runner() -> None:
        with JOB_SLOTS:
            _set_job(job_id, status="running", started_at=_now())
            try:
                result = fn(*args, **kwargs)
                after = _snapshot_target(target_key)
                _set_job(job_id, status="done", finished_at=_now(), summary={"delta": _diff_snapshot(before, after), "before": before, "after": after, "result": result if isinstance(result, (str, int, float, bool, dict, list, type(None))) else None})
            except Exception as exc:  # surfaced in UI; traceback remains in server console
                traceback.print_exc()
                _set_job(job_id, status="error", finished_at=_now(), error=str(exc)[:1000])

    thread = threading.Thread(target=runner, name=f"negro-{job_id}", daemon=True)
    thread.start()
    return job_id


def _db(paths: dict[str, Path]):
    return core.db_connect(paths)


def _sources(conn, entity: str, entity_id: int) -> list[str]:
    return core.get_sources(conn, entity, entity_id)


def _notes(conn, entity: str, entity_id: int):
    return core.get_notes(conn, entity, entity_id)


def _external_url(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = urlsplit(value)
    except Exception:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    return value


def _coverage_state(review_state: str | None) -> str:
    return {"pending": "untested", "in_progress": "testing", "reviewed": "tested"}.get(str(review_state or ""), "untested")


def _entity_signal(conn, entity_type: str, entity_id: int, classification: str | None = None) -> tuple[str, int]:
    """Return visual signal independently from coverage.

    Real Finding links are authoritative. Legacy classification remains compatible,
    and strong observations can lift an asset to Interesting without pretending a
    vulnerability is confirmed.
    """
    finding_count = int(conn.execute(
        "SELECT COUNT(DISTINCT finding_id) c FROM finding_entities WHERE entity_type=? AND entity_id=?",
        (entity_type, entity_id),
    ).fetchone()["c"] or 0)
    if finding_count or classification == "finding":
        return "finding", finding_count
    if classification == "lead":
        return "interesting", 0
    try:
        # Persistent hypotheses/leads also lift the asset visually, unless the
        # investigator already marked them negative/discarded.
        if entity_type == "resource":
            lead_count = int(conn.execute("SELECT COUNT(*) c FROM leads_v2 WHERE resource_id=? AND COALESCE(rule_active,1)=1 AND status NOT IN ('negative','discarded')", (entity_id,)).fetchone()["c"] or 0)
            if lead_count:
                return "interesting", 0
        elif entity_type == "host":
            lead_count = int(conn.execute("SELECT COUNT(*) c FROM leads_v2 WHERE host_id=? AND COALESCE(rule_active,1)=1 AND status NOT IN ('negative','discarded')", (entity_id,)).fetchone()["c"] or 0)
            if lead_count:
                return "interesting", 0
    except Exception:
        pass
    try:
        rows = conn.execute(
            "SELECT source,kind,payload_json FROM observations WHERE entity_type=? AND entity_id=? ORDER BY id DESC LIMIT 50",
            (entity_type, entity_id),
        ).fetchall()
        for row in rows:
            payload = {}
            try:
                payload = json.loads(row["payload_json"] or "{}")
            except Exception:
                pass
            if bool(payload.get("likely_credentialed_cors")) or bool(payload.get("interesting")):
                return "interesting", 0
    except Exception:
        pass
    return "normal", 0


def _visual_state(coverage: str, signal: str) -> str:
    if signal == "finding":
        return "finding"
    if signal == "interesting":
        return "interesting"
    if coverage == "tested":
        return "tested"
    if coverage == "untested":
        return "untested"
    return "normal"


def _target_context(target_key: str) -> tuple[str, Path, dict[str, Path]]:
    target = core.get_target(target_key)
    if not target:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    domain = str(target.get("domain", "")).strip().lower().rstrip(".")
    workspace = Path(str(target.get("workspace", ""))).expanduser()
    if not domain or not workspace:
        raise HTTPException(status_code=500, detail="Proyecto mal configurado")
    paths = core.ensure_workspace(workspace, domain, scopes=target.get("scopes"), project_name=target.get("name"))
    return domain, workspace, paths


def _create_finding(conn, *, title: str, severity: str = "info", status: str = "confirmed", description: str = "", source: str = "manual") -> int:
    now = _now()
    severity = severity if severity in {"info","low","medium","high","critical"} else "info"
    status = status if status in {"draft","confirmed","reported","retest_required","still_vulnerable","fixed","fix_verified","closed"} else "confirmed"
    cur = conn.execute(
        "INSERT INTO findings(title,severity,status,description,source,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
        ((title or "Finding sin título").strip()[:240], severity, status, (description or "").strip(), source[:80], now, now),
    )
    return int(cur.lastrowid)


def _link_finding(conn, finding_id: int, entity_type: str, entity_id: int, relation: str = "affected") -> None:
    conn.execute(
        "INSERT OR IGNORE INTO finding_entities(finding_id,entity_type,entity_id,relation,created_at) VALUES(?,?,?,?,?)",
        (finding_id, entity_type, int(entity_id), (relation or "affected").strip()[:80], _now()),
    )
    conn.execute("UPDATE findings SET updated_at=? WHERE id=?", (_now(), finding_id))


def _ensure_finding_for_entity(conn, entity_type: str, entity_id: int, title: str, source: str = "manual_mark") -> int:
    row = conn.execute(
        "SELECT f.id FROM findings f JOIN finding_entities fe ON fe.finding_id=f.id WHERE fe.entity_type=? AND fe.entity_id=? ORDER BY f.updated_at DESC LIMIT 1",
        (entity_type, entity_id),
    ).fetchone()
    if row:
        return int(row["id"])
    fid = _create_finding(conn, title=title, status="confirmed", source=source)
    _link_finding(conn, fid, entity_type, entity_id, "affected")
    return fid


def _safe_extract_zip(upload_path: Path, destination: Path) -> None:
    destination = destination.resolve()
    with zipfile.ZipFile(upload_path) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in Path(name).parts:
                raise ValueError("Backup inválido: ruta insegura")
            out = (destination / name).resolve()
            if destination not in out.parents and out != destination:
                raise ValueError("Backup inválido: ruta fuera del workspace")
        zf.extractall(destination)



def _notification_rows(paths: dict[str, Path], limit: int = 100, unread_only: bool = False) -> tuple[list[dict[str, Any]], int]:
    with _db(paths) as conn:
        unread = int(conn.execute("SELECT COUNT(*) c FROM notifications WHERE read_at IS NULL").fetchone()["c"] or 0)
        sql = "SELECT * FROM notifications"
        params: list[Any] = []
        if unread_only:
            sql += " WHERE read_at IS NULL"
        sql += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, last_seen_at DESC LIMIT ?"
        params.append(max(1, min(limit, 500)))
        rows = conn.execute(sql, params).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            try:
                data = json.loads(item.get("data_json") or "{}")
            except Exception:
                data = {}
            item["data"] = data if isinstance(data, dict) else {}
            href = item["data"].get("href")
            item["href"] = f"{href}" if isinstance(href, str) and href else None
            out.append(item)
    return out, unread


def _graph_inventory_counts(paths: dict[str, Path]) -> dict[str, int]:
    with _db(paths) as conn:
        return {
            "target": 1,
            "host": int(conn.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"] or 0),
            "resource": int(conn.execute("SELECT COUNT(*) c FROM resources").fetchone()["c"] or 0),
            "operation": int(conn.execute("SELECT COUNT(*) c FROM resource_operations").fetchone()["c"] or 0),
            "request": int(conn.execute("SELECT COUNT(*) c FROM http_exchanges").fetchone()["c"] or 0),
            "observation": int(conn.execute("SELECT COUNT(*) c FROM observations").fetchone()["c"] or 0),
            "lead": int(conn.execute("SELECT COUNT(*) c FROM leads_v2 WHERE COALESCE(rule_active,1)=1").fetchone()["c"] or 0),
            "finding": int(conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"] or 0),
        }


def _dashboard_data(paths: dict[str, Path]) -> dict[str, Any]:
    with _db(paths) as conn:
        def one(sql: str, params: tuple[Any, ...] = ()) -> int:
            return int(conn.execute(sql, params).fetchone()["c"] or 0)
        hosts_total = one("SELECT COUNT(*) c FROM hosts")
        resources_total = one("SELECT COUNT(*) c FROM resources")
        host_discarded = one("SELECT COUNT(*) c FROM hosts WHERE classification='discarded'")
        resource_discarded = one("SELECT COUNT(*) c FROM resources WHERE classification='discarded'")
        host_pending = one("SELECT COUNT(*) c FROM hosts WHERE classification!='discarded' AND review_state='pending'")
        resource_pending = one("SELECT COUNT(*) c FROM resources WHERE classification!='discarded' AND review_state='pending'")
        host_progress = one("SELECT COUNT(*) c FROM hosts WHERE classification!='discarded' AND review_state='in_progress'")
        resource_progress = one("SELECT COUNT(*) c FROM resources WHERE classification!='discarded' AND review_state='in_progress'")
        host_reviewed = one("SELECT COUNT(*) c FROM hosts WHERE classification!='discarded' AND review_state='reviewed'")
        resource_reviewed = one("SELECT COUNT(*) c FROM resources WHERE classification!='discarded' AND review_state='reviewed'")
        host_done = host_reviewed + host_discarded
        resource_done = resource_reviewed + resource_discarded
        stats = {
            "hosts": hosts_total,
            "resources": resources_total,
            "host_active": max(0, hosts_total - host_discarded),
            "resource_active": max(0, resources_total - resource_discarded),
            "host_pending": host_pending,
            "resource_pending": resource_pending,
            "host_in_progress": host_progress,
            "resource_in_progress": resource_progress,
            "host_reviewed": host_reviewed,
            "resource_reviewed": resource_reviewed,
            "host_discarded": host_discarded,
            "resource_discarded": resource_discarded,
            "host_progress_pct": round((host_done / hosts_total * 100.0), 1) if hosts_total else 0.0,
            "resource_progress_pct": round((resource_done / resources_total * 100.0), 1) if resources_total else 0.0,
            "pending": host_pending + resource_pending,
            "in_progress": host_progress + resource_progress,
            "reviewed": host_reviewed + resource_reviewed,
            "leads": one("SELECT COUNT(*) c FROM leads_v2 WHERE COALESCE(rule_active,1)=1 AND status NOT IN ('negative','discarded')")
                     + one("SELECT COUNT(*) c FROM hosts WHERE classification='lead'")
                     + one("SELECT COUNT(*) c FROM resources WHERE classification='lead'"),
            "findings": one("SELECT COUNT(*) c FROM findings"),
            "discarded": host_discarded + resource_discarded,
            "informational": one("SELECT COUNT(*) c FROM hosts WHERE classification='informational'") + one("SELECT COUNT(*) c FROM resources WHERE classification='informational'"),
            "operations": one("SELECT COUNT(*) c FROM resource_operations"),
            "http_exchanges": one("SELECT COUNT(*) c FROM http_exchanges"),
            "hypotheses": one("SELECT COUNT(*) c FROM leads_v2 WHERE COALESCE(rule_active,1)=1"),
            "notifications_unread": one("SELECT COUNT(*) c FROM notifications WHERE read_at IS NULL"),
        }
        priority = conn.execute(
            """SELECT h.*,
                      (SELECT COUNT(*) FROM leads_v2 l WHERE COALESCE(l.rule_active,1)=1 AND l.status NOT IN ('negative','discarded') AND (l.host_id=h.id OR l.resource_id IN (SELECT id FROM resources rr WHERE rr.host_id=h.id))) AS active_lead_count
               FROM hosts h
               WHERE h.priority='high' OR h.classification IN ('lead','finding')
                  OR EXISTS (SELECT 1 FROM leads_v2 l WHERE COALESCE(l.rule_active,1)=1 AND l.status NOT IN ('negative','discarded') AND (l.host_id=h.id OR l.resource_id IN (SELECT id FROM resources rr WHERE rr.host_id=h.id)))
               ORDER BY CASE h.classification WHEN 'finding' THEN 0 WHEN 'lead' THEN 1 ELSE 2 END,
                        CASE h.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                        active_lead_count DESC, h.updated_at DESC LIMIT 12"""
        ).fetchall()
        recent_runs = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 10").fetchall()
    return {"stats": stats, "priority_hosts": priority, "recent_runs": recent_runs}

def _target_cards() -> list[dict[str, Any]]:
    cards: list[dict[str, Any]] = []
    for target in core.list_targets():
        item: dict[str, Any] = dict(target)
        item.update({"hosts": 0, "resources": 0, "leads": 0, "findings": 0, "error": None})
        try:
            domain = str(target["domain"])
            paths = core.ensure_workspace(Path(str(target["workspace"])).expanduser(), domain, scopes=target.get("scopes"), project_name=target.get("name"))
            with _db(paths) as conn:
                item["hosts"] = conn.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"]
                item["resources"] = conn.execute("SELECT COUNT(*) c FROM resources").fetchone()["c"]
                item["leads"] = conn.execute("SELECT COUNT(*) c FROM hosts WHERE classification='lead'").fetchone()["c"] + conn.execute("SELECT COUNT(*) c FROM resources WHERE classification='lead'").fetchone()["c"]
                item["findings"] = conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
        except BaseException as exc:
            item["error"] = str(exc)[:180]
        cards.append(item)
    return cards


def _hypothesis_rows(paths: dict[str, Path], q: str = "", status: str = "", source: str = "", kind: str = "", validity: str = "current") -> list[dict[str, Any]]:
    import negro_hunter as hunter
    with _db(paths) as conn:
        hunter.init_schema(conn)
        sql = """SELECT l.*, h.hostname, r.url AS resource_url FROM leads_v2 l
                 LEFT JOIN hosts h ON h.id=l.host_id LEFT JOIN resources r ON r.id=l.resource_id WHERE 1=1"""
        params: list[Any] = []
        if validity == "current":
            sql += " AND COALESCE(l.rule_active,1)=1"
        elif validity == "inactive":
            sql += " AND COALESCE(l.rule_active,1)=0"
        if q:
            sql += " AND (lower(l.title) LIKE ? OR lower(COALESCE(l.why_interesting,'')) LIKE ? OR lower(COALESCE(l.next_test,'')) LIKE ?)"
            like=f"%{q.lower()}%"; params += [like,like,like]
        if status:
            sql += " AND l.status=?"; params.append(status)
        if source:
            sql += " AND lower(l.source)=?"; params.append(source.lower())
        if kind:
            sql += " AND l.lead_type=?"; params.append(kind)
        sql += " ORDER BY CASE l.status WHEN 'testing' THEN 0 WHEN 'interesting' THEN 1 WHEN 'candidate' THEN 2 WHEN 'confirmed' THEN 3 WHEN 'negative' THEN 4 ELSE 5 END, CASE l.review_priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, l.updated_at DESC LIMIT 500"
        rows=conn.execute(sql,params).fetchall()
        out=[]
        for r in rows:
            item=dict(r)
            try:item['evidence']=json.loads(item.pop('evidence_json') or '[]')
            except Exception:item['evidence']=[]
            try:item['test_plan']=json.loads(item.get('test_plan_json') or '[]')
            except Exception:item['test_plan']=[]
            ai_meta={}
            rule_matches=[]
            for ev in item['evidence']:
                if isinstance(ev,dict) and ev.get('source')=='ai_graph' and not ai_meta:
                    ai_meta=ev
                if isinstance(ev,dict) and isinstance(ev.get('rule_match'),dict):
                    rule_matches.append(ev.get('rule_match'))
            detector_map={
                'access_object_reference':'access_object_reference','mass_assignment':'mass_assignment',
                'method_access_control':'method_access_control','redirect_body_access_control':'redirect_body_access_control',
                'proxy_path_access_control':'proxy_path_access_control','referer_access_control':'referer_access_control',
                'cors':'cors','javascript_surface':'js_sensitive_route','open_redirect':'open_redirect',
                'ssrf_surface':'ssrf_surface','secret_or_client_config':'secret_candidate',
                'sensitive_response':'sensitive_response','sensitive_url':'sensitive_url','source_map':'source_map'
            }
            item['rule_matches']=rule_matches
            item['detector_id']=detector_map.get(str(item.get('lead_type') or ''))
            item['plain_language']=str(ai_meta.get('plain_language') or '')
            item['investigation_priority']=str(ai_meta.get('investigation_priority') or ('high' if item.get('review_priority')=='high' else 'medium' if item.get('review_priority')=='medium' else 'quick'))
            item['priority_reasons']=[str(x) for x in (ai_meta.get('priority_reasons') or [])][:4]
            node_ids=[str(x) for x in (ai_meta.get('node_ids') or []) if isinstance(x,str)]
            item['node_ids']=node_ids
            refs=hunter.hypothesis_refs_from_nodes(conn,node_ids) if node_ids else {'evidence_refs':[],'resource_id':item.get('resource_id'),'primary_method':None,'primary_exchange_id':None}
            item.update(refs)
            if item.get('resource_id') and not item.get('resource_url'):
                rr=conn.execute('SELECT url FROM resources WHERE id=?',(item['resource_id'],)).fetchone(); item['resource_url']=rr['url'] if rr else None
            out.append(item)
        return out


def _host_rows(paths: dict[str, Path], q: str = "", review: str = "", classification: str = "", priority: str = "", resource_review: str = "", limit: int = 500):
    # Inventory search is intentionally unified: one query can match a hostname,
    # resource path, complete URL or stored query string. Resource counts remain
    # totals for the host, independent of the search term.
    sql = """
        SELECT h.*,
               (SELECT COUNT(*) FROM resources r WHERE r.host_id=h.id) AS resource_count,
               (SELECT COUNT(*) FROM host_inspections i WHERE i.host_id=h.id) AS inspection_count
        FROM hosts h
        WHERE 1=1
    """
    params: list[Any] = []
    q_norm = q.strip().lower()
    if q_norm:
        like = f"%{q_norm}%"
        sql += """ AND (lower(h.hostname) LIKE ? OR EXISTS (
            SELECT 1 FROM resources rq WHERE rq.host_id=h.id AND (
                lower(COALESCE(rq.path,'')) LIKE ? OR
                lower(COALESCE(rq.url,'')) LIKE ? OR
                lower(COALESCE(rq.query,'')) LIKE ?
            )
        ))"""
        params.extend([like, like, like, like])
    if review:
        sql += " AND h.review_state=?"
        params.append(review)
    if classification:
        sql += " AND h.classification=?"
        params.append(classification)
    if priority:
        sql += " AND h.priority=?"
        params.append(priority)
    if resource_review:
        sql += " AND EXISTS (SELECT 1 FROM resources rsf WHERE rsf.host_id=h.id AND rsf.review_state=?)"
        params.append(resource_review)
    sql += " ORDER BY CASE h.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, h.hostname LIMIT ?"
    params.append(max(1, min(limit, 2000)))
    with _db(paths) as conn:
        rows = conn.execute(sql, params).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            coverage = _coverage_state(row["review_state"])
            signal, direct_findings = _entity_signal(conn, "host", row["id"], row["classification"])
            child_findings = conn.execute(
                """SELECT COUNT(DISTINCT fe.finding_id) c FROM finding_entities fe
                   JOIN resources r ON fe.entity_type='resource' AND fe.entity_id=r.id
                   WHERE r.host_id=?""", (row["id"],)
            ).fetchone()["c"] or 0
            if q_norm:
                like = f"%{q_norm}%"
                extra = " AND review_state=?" if resource_review else ""
                rparams: list[Any] = [row["id"], like, like, like]
                if resource_review: rparams.append(resource_review)
                resource_rows = conn.execute(
                    f"""SELECT id,path,url,query,review_state,classification,priority FROM resources
                       WHERE host_id=? AND (lower(COALESCE(path,'')) LIKE ? OR lower(COALESCE(url,'')) LIKE ? OR lower(COALESCE(query,'')) LIKE ?){extra}
                       ORDER BY CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, path LIMIT 8""",
                    rparams,
                ).fetchall()
            elif resource_review:
                resource_rows = conn.execute(
                    """SELECT id,path,url,query,review_state,classification,priority FROM resources WHERE host_id=? AND review_state=?
                       ORDER BY CASE classification WHEN 'finding' THEN 0 WHEN 'lead' THEN 1 ELSE 2 END,
                                CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, path LIMIT 8""",
                    (row["id"], resource_review),
                ).fetchall()
            else:
                resource_rows = conn.execute(
                    """SELECT id,path,url,query,review_state,classification,priority FROM resources WHERE host_id=?
                       ORDER BY CASE classification WHEN 'finding' THEN 0 WHEN 'lead' THEN 1 ELSE 2 END,
                                CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, path LIMIT 4""",
                    (row["id"],),
                ).fetchall()
            resource_preview = []
            for rr in resource_rows:
                rsig, rfind = _entity_signal(conn, "resource", rr["id"], rr["classification"])
                resource_preview.append({**dict(rr), "coverage_state": _coverage_state(rr["review_state"]), "signal_state": rsig, "finding_count": int(rfind)})
            item.update({
                "coverage_state": coverage, "signal_state": signal,
                "finding_count": int(direct_findings), "child_finding_count": int(child_findings),
                "total_finding_count": int(direct_findings) + int(child_findings),
                "resource_preview": resource_preview,
                "resource_matches": len(resource_preview) if (q_norm or resource_review) else 0,
            })
            out.append(item)
        return out


def _group_detections(analysis: dict[str, Any] | None) -> dict[str, list[dict[str, Any]]]:
    groups = {"potential_secret": [], "public_client_config": [], "surface_config": []}
    if not isinstance(analysis, dict):
        return groups
    for item in analysis.get("detections", []) or []:
        if not isinstance(item, dict):
            continue
        category = str(item.get("category") or "surface_config")
        groups.setdefault(category, []).append(item)
    return groups


def _latest_observation_payload(observations: list[dict[str, Any]], source: str, kind: str, *, asset_id: int | None = None) -> dict[str, Any] | None:
    for item in observations:
        row = item.get("row")
        payload = item.get("payload")
        if not row or row["source"] != source or row["kind"] != kind or not isinstance(payload, dict):
            continue
        if asset_id is not None and int(payload.get("asset_id", -1)) != int(asset_id):
            continue
        return payload
    return None


def _host_detail(paths: dict[str, Path], host_id: int) -> dict[str, Any] | None:
    with _db(paths) as conn:
        host = conn.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
        if not host:
            return None
        resources = conn.execute(
            "SELECT * FROM resources WHERE host_id=? ORDER BY CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, path, url LIMIT 250",
            (host_id,),
        ).fetchall()
        host_sources = _sources(conn, "host", host_id)
        host_notes = _notes(conn, "host", host_id)
        resource_data = []
        for r in resources:
            operations = conn.execute(
                "SELECT * FROM resource_operations WHERE resource_id=? ORDER BY method", (r["id"],)
            ).fetchall()
            op_data = []
            for op in operations:
                sources = conn.execute("SELECT * FROM operation_sources WHERE operation_id=? ORDER BY source", (op["id"],)).fetchall()
                exchanges = conn.execute(
                    "SELECT id, source, tool, status_code, request_size, response_size, first_seen_at, last_seen_at, seen_count FROM http_exchanges WHERE operation_id=? ORDER BY last_seen_at DESC LIMIT 5",
                    (op["id"],),
                ).fetchall()
                op_data.append({"row": op, "sources": sources, "exchanges": exchanges})
            source_details = conn.execute(
                "SELECT source, first_seen_at FROM resource_sources WHERE resource_id=? ORDER BY first_seen_at, source",
                (r["id"],),
            ).fetchall()
            evidence = conn.execute(
                "SELECT * FROM evidence_attachments WHERE entity_type='resource' AND entity_id=? ORDER BY id DESC",
                (r["id"],),
            ).fetchall()
            cors_row = conn.execute(
                "SELECT payload_json, observed_at FROM observations WHERE entity_type='resource' AND entity_id=? AND source='cors_probe' AND kind='cors_probe' ORDER BY id DESC LIMIT 1",
                (r["id"],),
            ).fetchone()
            cors_result = None
            if cors_row:
                try:
                    cors_result = json.loads(cors_row["payload_json"] or "{}")
                    if isinstance(cors_result, dict):
                        cors_result["observed_at"] = cors_row["observed_at"]
                except Exception:
                    cors_result = None
            r_coverage = _coverage_state(r["review_state"])
            r_signal, r_finding_count = _entity_signal(conn, "resource", r["id"], r["classification"])
            resource_data.append({
                "row": r,
                "coverage_state": r_coverage,
                "signal_state": r_signal,
                "finding_count": r_finding_count,
                "sources": _sources(conn, "resource", r["id"]),
                "source_details": source_details,
                "primary_source": source_details[0]["source"] if source_details else None,
                "first_seen_at": source_details[0]["first_seen_at"] if source_details else r["created_at"],
                "notes": _notes(conn, "resource", r["id"]),
                "evidence": evidence,
                "open_url": _external_url(r["url"]),
                "operations": op_data,
                "cors_result": cors_result,
            })
        inspections = conn.execute(
            "SELECT id, observed_at, payload_json FROM host_inspections WHERE host_id=? ORDER BY id DESC LIMIT 10",
            (host_id,),
        ).fetchall()
        inspection_data = []
        for item in inspections:
            try:
                payload = json.loads(item["payload_json"])
            except Exception:
                payload = {}
            inspection_data.append({"id": item["id"], "observed_at": item["observed_at"], "payload": payload})
        events = conn.execute(
            "SELECT * FROM events WHERE entity_type='host' AND entity_id=? ORDER BY id DESC LIMIT 30",
            (host_id,),
        ).fetchall()
        event_data = []
        for e in events:
            try:
                payload = json.loads(e["payload_json"] or "{}")
            except Exception:
                payload = {}
            event_data.append({"row": e, "payload": payload})

        observations = conn.execute(
            "SELECT * FROM observations WHERE entity_type='host' AND entity_id=? ORDER BY id DESC LIMIT 60",
            (host_id,),
        ).fetchall()
        observation_data = []
        for o in observations:
            try:
                payload = json.loads(o["payload_json"] or "null")
            except Exception:
                payload = None
            observation_data.append({"row": o, "payload": payload})

        js_rows = conn.execute(
            "SELECT * FROM js_assets WHERE host_id=? ORDER BY id DESC", (host_id,)
        ).fetchall()
        js_assets = []
        for j in js_rows:
            try:
                local = json.loads(j["local_analysis_json"] or "null")
            except Exception:
                local = None
            ai_rows = conn.execute(
                "SELECT * FROM ai_analyses WHERE js_asset_id=? ORDER BY id DESC LIMIT 3", (j["id"],)
            ).fetchall()
            analyses = []
            for a in ai_rows:
                try:
                    result = json.loads(a["result_json"] or "null")
                except Exception:
                    result = None
                try:
                    estimate = json.loads(a["estimate_json"] or "null")
                except Exception:
                    estimate = None
                try:
                    usage = json.loads(a["usage_json"] or "null")
                except Exception:
                    usage = None
                analyses.append({"row": a, "result": result, "estimate": estimate, "usage": usage})
            sourcemap = None
            try:
                sourcemap = json.loads(j["sourcemap_analysis_json"] or "null") if "sourcemap_analysis_json" in j.keys() else None
            except Exception:
                sourcemap = None
            if not isinstance(sourcemap, dict):
                sourcemap = _latest_observation_payload(observation_data, "sourcemap", "source_map", asset_id=int(j["id"]))
            sm_local = sourcemap.get("analysis", {}) if isinstance(sourcemap, dict) and isinstance(sourcemap.get("analysis"), dict) else {}
            js_assets.append({
                "row": j,
                "local": local,
                "local_detection_groups": _group_detections(local),
                "sourcemap": sourcemap,
                "sourcemap_detection_groups": _group_detections(sm_local),
                "ai": analyses,
            })
        tls_san_result = _latest_observation_payload(observation_data, "tls_san", "certificate_sans")
        linked_findings = conn.execute("SELECT f.*,fe.relation FROM findings f JOIN finding_entities fe ON fe.finding_id=f.id WHERE fe.entity_type='host' AND fe.entity_id=? ORDER BY f.updated_at DESC", (host_id,)).fetchall()
        all_findings = conn.execute("SELECT id,title,status,severity FROM findings ORDER BY updated_at DESC LIMIT 200").fetchall()
        coverage_state = _coverage_state(host["review_state"])
        signal_state, finding_count = _entity_signal(conn, "host", host_id, host["classification"])
    return {
        "host": host,
        "host_https_url": f"https://{host['hostname']}/",
        "host_http_url": f"http://{host['hostname']}/",
        "sources": host_sources,
        "notes": host_notes,
        "resources": resource_data,
        "inspections": inspection_data,
        "events": event_data,
        "observations": observation_data,
        "tls_san_result": tls_san_result,
        "js_assets": js_assets,
        "operation_count": sum(len(x["operations"]) for x in resource_data),
        "exchange_count": sum(sum(len(op["exchanges"]) for op in x["operations"]) for x in resource_data),
        "linked_findings": linked_findings,
        "all_findings": all_findings,
        "coverage_state": coverage_state,
        "signal_state": signal_state,
        "finding_count": finding_count,
    }


def _tree_data(paths: dict[str, Path], q: str = "", review: str = "", classification: str = "", priority: str = "", host_limit: int = 250):
    hosts = _host_rows(paths, q, review, classification, priority, host_limit)
    result = []
    with _db(paths) as conn:
        for h in hosts:
            resources = conn.execute("SELECT * FROM resources WHERE host_id=? ORDER BY path, url LIMIT 20", (h["id"],)).fetchall()
            result.append({
                "host": h,
                "open_url": f"https://{h['hostname']}/",
                "sources": _sources(conn, "host", h["id"]),
                "resources": [
                    {"row": r, "sources": _sources(conn, "resource", r["id"]), "open_url": _external_url(r["url"])}
                    for r in resources
                ],
            })
    return result



def _decode_http_blob(value: str | None, limit: int = 300000) -> str:
    if not value:
        return ""
    try:
        raw = base64.b64decode(value)
        if len(raw) > limit:
            raw = raw[:limit] + b"\n\n[... truncated by Negro UI ...]"
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return "[No se pudo decodificar el mensaje HTTP]"


def _resource_detail(paths: dict[str, Path], resource_id: int) -> dict[str, Any] | None:
    import negro_hunter as hunter
    with _db(paths) as conn:
        row = conn.execute(
            """SELECT r.*, h.hostname FROM resources r JOIN hosts h ON h.id=r.host_id WHERE r.id=?""",
            (resource_id,),
        ).fetchone()
        if not row:
            return None
        source_details = conn.execute(
            "SELECT source, first_seen_at FROM resource_sources WHERE resource_id=? ORDER BY first_seen_at, source",
            (resource_id,),
        ).fetchall()
        notes = _notes(conn, "resource", resource_id)
        evidence = conn.execute(
            "SELECT * FROM evidence_attachments WHERE entity_type='resource' AND entity_id=? ORDER BY id DESC",
            (resource_id,),
        ).fetchall()
        cors_row = conn.execute(
            "SELECT payload_json, observed_at FROM observations WHERE entity_type='resource' AND entity_id=? AND source='cors_probe' AND kind='cors_probe' ORDER BY id DESC LIMIT 1",
            (resource_id,),
        ).fetchone()
        cors_result = None
        if cors_row:
            try:
                cors_result = json.loads(cors_row["payload_json"] or "{}")
                if isinstance(cors_result, dict):
                    cors_result["observed_at"] = cors_row["observed_at"]
            except Exception:
                pass
        operations = []
        resource_test_summary = {k: 0 for k in hunter.TEST_STATUSES}
        for op in conn.execute("SELECT * FROM resource_operations WHERE resource_id=? ORDER BY method", (resource_id,)).fetchall():
            sources = conn.execute("SELECT * FROM operation_sources WHERE operation_id=? ORDER BY source", (op["id"],)).fetchall()
            exchanges = []
            for ex in conn.execute("SELECT * FROM http_exchanges WHERE operation_id=? ORDER BY last_seen_at DESC LIMIT 30", (op["id"],)).fetchall():
                exd = dict(ex)
                exd["request_text"] = _decode_http_blob(ex["request_b64"])
                exd["response_text"] = _decode_http_blob(ex["response_b64"])
                exchanges.append(exd)
            tests = hunter.ensure_operation_test_coverage(conn, int(op["id"]))
            test_summary = hunter.operation_test_summary(conn, int(op["id"]))
            for k,v in test_summary.items():
                resource_test_summary[k] = resource_test_summary.get(k, 0) + int(v)
            operations.append({"row": op, "sources": sources, "exchanges": exchanges, "tests": tests, "test_summary": test_summary})
        observations = []
        for o in conn.execute("SELECT * FROM observations WHERE entity_type='resource' AND entity_id=? ORDER BY id DESC LIMIT 50", (resource_id,)).fetchall():
            d = dict(o)
            try: d["payload"] = json.loads(o["payload_json"] or "null")
            except Exception: d["payload"] = None
            observations.append(d)
        linked_findings = conn.execute(
            """SELECT f.*, fe.relation FROM findings f JOIN finding_entities fe ON fe.finding_id=f.id
               WHERE fe.entity_type='resource' AND fe.entity_id=? ORDER BY f.updated_at DESC""",
            (resource_id,),
        ).fetchall()
        # Resource-level investigation help.  Keep this compact: leads/hypotheses
        # tell the hunter *why this resource deserves attention*, while detailed
        # per-method coverage remains available lower in the HTTP section.
        resource_hypotheses = []
        for l in conn.execute(
            """SELECT * FROM leads_v2 WHERE resource_id=? AND COALESCE(rule_active,1)=1 AND status NOT IN ('negative','discarded')
               ORDER BY CASE status WHEN 'confirmed' THEN 0 WHEN 'interesting' THEN 1 WHEN 'testing' THEN 2
                                    WHEN 'candidate' THEN 3 WHEN 'postponed' THEN 4 ELSE 5 END,
                        CASE review_priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                        updated_at DESC LIMIT 20""",
            (resource_id,),
        ).fetchall():
            item = dict(l)
            try:
                item["evidence"] = json.loads(l["evidence_json"] or "[]")
            except Exception:
                item["evidence"] = []
            resource_hypotheses.append(item)

        review_aids = []
        for op in operations:
            o = op["row"]
            for t in op["tests"]:
                if str(t.get("status") or "pending") not in {"pending","testing","interesting"}:
                    continue
                review_aids.append({
                    "operation_id": int(o["id"]), "method": str(o["method"]),
                    "test_key": t.get("test_key"), "label": t.get("label"),
                    "hint": t.get("hint"), "status": t.get("status"),
                })
        review_aids = review_aids[:14]
        all_findings = conn.execute("SELECT id,title,status,severity FROM findings ORDER BY updated_at DESC LIMIT 200").fetchall()
        coverage = _coverage_state(row["review_state"])
        signal, finding_count = _entity_signal(conn, "resource", resource_id, row["classification"])
        return {
            "resource": row,
            "source_details": source_details,
            "notes": notes,
            "evidence": evidence,
            "cors_result": cors_result,
            "operations": operations,
            "test_summary": resource_test_summary,
            "test_statuses": ["pending","testing","negative","interesting","confirmed","not_applicable"],
            "observations": observations,
            "resource_hypotheses": resource_hypotheses,
            "review_aids": review_aids,
            "linked_findings": linked_findings,
            "all_findings": all_findings,
            "coverage_state": coverage,
            "signal_state": signal,
            "finding_count": finding_count,
            "open_url": _external_url(row["url"]),
        }


def _finding_detail(paths: dict[str, Path], finding_id: int) -> dict[str, Any] | None:
    with _db(paths) as conn:
        finding = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not finding:
            return None
        links = []
        for link in conn.execute("SELECT * FROM finding_entities WHERE finding_id=? ORDER BY id", (finding_id,)).fetchall():
            label = f"{link['entity_type']} #{link['entity_id']}"
            href = None
            if link["entity_type"] == "resource":
                r = conn.execute("SELECT path,host_id FROM resources WHERE id=?", (link["entity_id"],)).fetchone()
                if r:
                    label = r["path"]
                    href = f"resource/{link['entity_id']}"
            elif link["entity_type"] == "host":
                h = conn.execute("SELECT hostname FROM hosts WHERE id=?", (link["entity_id"],)).fetchone()
                if h:
                    label = h["hostname"]
                    href = f"host/{link['entity_id']}"
            elif link["entity_type"] == "exchange":
                ex = conn.execute("SELECT id,status_code,source FROM http_exchanges WHERE id=?", (link["entity_id"],)).fetchone()
                if ex: label = f"HTTP exchange #{ex['id']} · {ex['source']} · {ex['status_code'] or '—'}"
            links.append({"row": link, "label": label, "href": href})
        retests = []
        for rr in conn.execute("SELECT * FROM finding_retests WHERE finding_id=? ORDER BY tested_at DESC,id DESC", (finding_id,)).fetchall():
            rd = dict(rr)
            rlinks = []
            try:
                rows = conn.execute("SELECT * FROM finding_retest_entities WHERE retest_id=? ORDER BY id", (rr["id"],)).fetchall()
            except Exception:
                rows = []
            for link in rows:
                label = f"{link['entity_type']} #{link['entity_id']}"
                href = None
                if link["entity_type"] == "exchange":
                    ex = conn.execute("SELECT e.id,e.status_code,e.source,o.method,r.path,r.id AS resource_id FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id WHERE e.id=?", (link["entity_id"],)).fetchone()
                    if ex:
                        label = f"Exchange #{ex['id']} · {ex['method']} {ex['path']} · HTTP {ex['status_code'] or '—'}"
                        href = f"resource/{ex['resource_id']}#http"
                rlinks.append({"row": link, "label": label, "href": href})
            rd["entities"] = rlinks
            retests.append(rd)
        evidence = conn.execute("SELECT * FROM evidence_attachments WHERE entity_type='finding' AND entity_id=? ORDER BY id DESC", (finding_id,)).fetchall()
        notes = _notes(conn, "finding", finding_id)
        return {"finding": finding, "finding_links": links, "retests": retests, "finding_evidence": evidence, "finding_notes": notes}


def _graph_data_full(paths: dict[str, Path], domain: str, *, exchange_limit: int = 120, observation_limit: int = 120) -> dict[str, Any]:
    import negro_hunter as hunter
    """Build a read-only graph projection from Negro's existing relational model.

    The graph never duplicates authoritative entities. Node IDs are stable references
    such as ``resource:17`` and edges explain why two existing records are connected.
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    routes: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()
    seen_edges: set[str] = set()

    def add_node(node_id: str, node_type: str, label: str, *, state: str = "normal", meta: dict[str, Any] | None = None, href: str | None = None) -> str:
        if node_id in seen_nodes:
            return node_id
        seen_nodes.add(node_id)
        nodes.append({"id": node_id, "type": node_type, "label": str(label), "state": state or "normal", "meta": meta or {}, "href": href})
        return node_id

    def add_edge(src: str, dst: str, relation: str, *, source: str | None = None, evidence: Any = None) -> None:
        key = f"{src}|{relation}|{dst}|{source or ''}"
        if src == dst or key in seen_edges or src not in seen_nodes or dst not in seen_nodes:
            return
        seen_edges.add(key)
        edges.append({"id": f"e{len(edges)+1}", "source": src, "target": dst, "relation": relation, "meta": {"source": source, "evidence": evidence}})

    project_name = core.workspace_project_name(paths, domain)
    target_id = add_node("target:root", "target", project_name, state="normal", meta={"domain": domain, "project_name": project_name})
    with _db(paths) as conn:
        hosts = conn.execute("SELECT * FROM hosts ORDER BY hostname").fetchall()
        host_by_name: dict[str, str] = {}
        for h in hosts:
            coverage = _coverage_state(h["review_state"])
            signal, finding_count = _entity_signal(conn, "host", h["id"], h["classification"])
            state = _visual_state(coverage, signal)
            nid = add_node(f"host:{h['id']}", "host", h["hostname"], state=state, meta={"id": h["id"], "coverage": coverage, "signal": signal, "review": h["review_state"], "classification": h["classification"], "finding_count": finding_count, "priority": h["priority"], "updated_at": h["updated_at"]}, href=f"host/{h['id']}")
            host_by_name[str(h["hostname"]).lower()] = nid
            add_edge(target_id, nid, "contains", source="inventory")

        resources = conn.execute("SELECT r.*,h.hostname FROM resources r JOIN hosts h ON h.id=r.host_id ORDER BY r.id").fetchall()
        resource_by_url: dict[str, str] = {}
        resource_by_host_path: dict[tuple[str, str], str] = {}
        for r in resources:
            coverage = _coverage_state(r["review_state"])
            signal, finding_count = _entity_signal(conn, "resource", r["id"], r["classification"])
            state = _visual_state(coverage, signal)
            nid = add_node(f"resource:{r['id']}", "resource", r["path"] or r["url"], state=state, meta={"id": r["id"], "url": r["url"], "host": r["hostname"], "coverage": coverage, "signal": signal, "review": r["review_state"], "classification": r["classification"], "finding_count": finding_count, "priority": r["priority"], "updated_at": r["updated_at"]}, href=f"resource/{r['id']}")
            resource_by_url[str(r["url"])] = nid
            resource_by_host_path[(str(r["hostname"]).lower(), str(r["path"] or "/"))] = nid
            add_edge(f"host:{r['host_id']}", nid, "contains", source="inventory")
            for rs in conn.execute("SELECT source,first_seen_at FROM resource_sources WHERE resource_id=? ORDER BY first_seen_at", (r["id"],)).fetchall():
                src_name = str(rs["source"])
                sid = add_node(f"source:{src_name}", "source", src_name.replace("_", " "), meta={"source": src_name})
                add_edge(sid, nid, "discovered", source=src_name, evidence={"first_seen_at": rs["first_seen_at"]})

        operations = conn.execute("SELECT o.*,r.path,r.url FROM resource_operations o JOIN resources r ON r.id=o.resource_id ORDER BY o.id").fetchall()
        for o in operations:
            label = f"{o['method']} {o['path']}"
            hunter.ensure_operation_test_coverage(conn, int(o["id"]))
            test_summary = hunter.operation_test_summary(conn, int(o["id"]))
            has_test_signal = int(test_summary.get("interesting",0)) > 0 or int(test_summary.get("confirmed",0)) > 0
            state = "interesting" if has_test_signal or (o["last_status"] and int(o["last_status"]) >= 500) else "normal"
            nid = add_node(f"operation:{o['id']}", "operation", label, state=state, meta={"id": o["id"], "method": o["method"], "status": o["last_status"], "seen_count": o["seen_count"], "authenticated": bool(o["authenticated_observed"]), "last_seen_at": o["last_seen_at"], "url": o["url"], "test_summary": test_summary})
            add_edge(f"resource:{o['resource_id']}", nid, "supports", source="http_model")
            for osrc in conn.execute("SELECT source,first_seen_at,last_seen_at,seen_count FROM operation_sources WHERE operation_id=?", (o["id"],)).fetchall():
                src_name = str(osrc["source"])
                sid = add_node(f"source:{src_name}", "source", src_name.replace("_", " "), meta={"source": src_name})
                add_edge(sid, nid, "observed", source=src_name, evidence={"seen_count": osrc["seen_count"], "first_seen_at": osrc["first_seen_at"], "last_seen_at": osrc["last_seen_at"]})

        exchanges = conn.execute("""SELECT e.*,o.method,o.resource_id,r.path FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id ORDER BY e.last_seen_at DESC LIMIT ?""", (max(10, min(exchange_limit, 500)),)).fetchall()
        for e in exchanges:
            label = f"#{e['id']} {e['method']} · {e['status_code'] or '—'}"
            nid = add_node(f"exchange:{e['id']}", "request", label, meta={"id": e["id"], "source": e["source"], "tool": e["tool"], "status": e["status_code"], "seen_count": e["seen_count"], "request_size": e["request_size"], "response_size": e["response_size"], "last_seen_at": e["last_seen_at"], "path": e["path"]})
            add_edge(f"operation:{e['operation_id']}", nid, "observed_in", source=e["source"], evidence={"seen_count": e["seen_count"], "last_seen_at": e["last_seen_at"]})

        js_rows = conn.execute("SELECT * FROM js_assets ORDER BY discovered_at DESC LIMIT 150").fetchall()
        for js in js_rows:
            label = Path(urllib.parse.urlsplit(js["url"]).path).name or js["url"]
            try:
                js_local = json.loads(js["local_analysis_json"] or "{}")
            except Exception:
                js_local = {}
            discovered = list(js_local.get("in_scope_urls", []) or []) if isinstance(js_local, dict) else []
            sensitive = []
            for u in discovered:
                p = urllib.parse.urlsplit(str(u))
                lowp = (p.path or "/").lower()
                if any(x in lowp for x in ("admin","internal","manage","approve","audit","export","delete","role","permission","debug","ops","feature","staff","backoffice")):
                    sensitive.append(str(u))
            js_state = "interesting" if sensitive else "tested" if js["analyzed_at"] else "untested"
            nid = add_node(f"js:{js['id']}", "javascript", label, state=js_state, meta={"id": js["id"], "url": js["url"], "source": js["source"], "size_bytes": js["size_bytes"], "analyzed_at": js["analyzed_at"], "discovered_at": js["discovered_at"], "routes_count": len(discovered), "interesting_routes": len(sensitive)})
            add_edge(f"host:{js['host_id']}", nid, "contains", source=js["source"])
            for candidate in discovered[:300]:
                try:
                    pu = urllib.parse.urlsplit(str(candidate))
                    rnode = resource_by_url.get(str(candidate)) or resource_by_host_path.get(((pu.hostname or "").lower(), pu.path or "/"))
                except Exception:
                    rnode = None
                if rnode:
                    add_edge(nid, rnode, "discovered", source="js_local", evidence={"url": str(candidate), "asset_id": int(js["id"])})

        obs_rows = conn.execute("SELECT * FROM observations ORDER BY id DESC LIMIT ?", (max(10, min(observation_limit, 500)),)).fetchall()
        for o in obs_rows:
            try:
                opayload = json.loads(o["payload_json"] or "{}")
            except Exception:
                opayload = {}
            state = "interesting" if bool(opayload.get("likely_credentialed_cors")) or bool(opayload.get("interesting")) else "normal"
            label = str(o["kind"]).replace("_", " ")
            nid = add_node(f"observation:{o['id']}", "observation", label, state=state, meta={"id": o["id"], "source": o["source"], "kind": o["kind"], "value": o["value"], "observed_at": o["observed_at"]})
            parent = f"{o['entity_type']}:{o['entity_id']}"
            if parent in seen_nodes:
                add_edge(parent, nid, "tested_by", source=o["source"])

        # Hunter leads are already persistent investigation hypotheses/leads.
        try:
            lead_rows = conn.execute("SELECT * FROM leads_v2 WHERE COALESCE(rule_active,1)=1 ORDER BY updated_at DESC LIMIT 150").fetchall()
        except Exception:
            lead_rows = []
        for l in lead_rows:
            state = "tested" if l["status"] in ("discarded", "negative") else "finding" if l["status"] in ("confirmed",) else "interesting"
            lsource = l["source"] if "source" in l.keys() else "ENGINE"
            nid = add_node(f"lead:{l['id']}", "lead", l["title"], state=state, meta={"id": l["id"], "type": l["lead_type"], "status": l["status"], "confidence": l["confidence"], "priority": l["review_priority"], "source": lsource, "why": l["why_interesting"], "next_test": l["next_test"], "result_notes": l["result_notes"] if "result_notes" in l.keys() else "", "updated_at": l["updated_at"]}, href=f"hypotheses#hypothesis-{l['id']}")
            linked = False
            try:
                ev = json.loads(l["evidence_json"] or "[]")
            except Exception:
                ev = []
            for evidence in ev if isinstance(ev, list) else []:
                if not isinstance(evidence, dict):
                    continue
                for node_id in evidence.get("node_ids") or []:
                    if isinstance(node_id, str) and node_id in seen_nodes:
                        add_edge(node_id, nid, "supports_hypothesis", source=str(lsource).lower(), evidence={"reason":"Referenced by hypothesis evidence"})
                        linked = True
            if not linked and l["resource_id"] and f"resource:{l['resource_id']}" in seen_nodes:
                add_edge(f"resource:{l['resource_id']}", nid, "produced_lead", source=str(lsource).lower())
            elif not linked and l["host_id"] and f"host:{l['host_id']}" in seen_nodes:
                add_edge(f"host:{l['host_id']}", nid, "produced_lead", source=str(lsource).lower())

        findings = conn.execute("SELECT * FROM findings ORDER BY updated_at DESC").fetchall()
        for f in findings:
            nid = add_node(f"finding:{f['id']}", "finding", f["title"], state="finding", meta={"id": f["id"], "severity": f["severity"], "status": f["status"], "description": f["description"], "updated_at": f["updated_at"]}, href=f"finding/{f['id']}")
            for fe in conn.execute("SELECT * FROM finding_entities WHERE finding_id=?", (f["id"],)).fetchall():
                parent = f"{fe['entity_type']}:{fe['entity_id']}"
                if parent in seen_nodes:
                    add_edge(parent, nid, fe["relation"] or "supports_finding", source="finding")

        # Existing semantic relationships enrich the graph without replacing canonical entities.
        try:
            rel_rows = conn.execute("SELECT * FROM relationships ORDER BY id DESC LIMIT 250").fetchall()
        except Exception:
            rel_rows = []
        for rel in rel_rows:
            src = f"{rel['src_type']}:{rel['src_id']}" if rel["src_id"] is not None else None
            if not src or src not in seen_nodes:
                continue
            dst = None
            if rel["dst_type"] == "host":
                dst = host_by_name.get(str(rel["dst_value"]).lower())
            elif rel["dst_type"] == "url":
                dst = resource_by_url.get(str(rel["dst_value"]))
            if not dst:
                safe = re.sub(r"[^a-zA-Z0-9_.:-]+", "_", str(rel["dst_value"]))[:120]
                dst = add_node(f"external:{rel['dst_type']}:{safe}", "external", str(rel["dst_value"]), meta={"type": rel["dst_type"], "value": rel["dst_value"]})
            try:
                evidence = json.loads(rel["evidence_json"] or "null")
            except Exception:
                evidence = rel["evidence_json"]
            add_edge(src, dst, rel["relation"], source=rel["source"], evidence=evidence)

        routes = _investigation_routes(conn, limit=10)

    type_counts: dict[str, int] = {}
    for n in nodes:
        type_counts[n["type"]] = type_counts.get(n["type"], 0) + 1
    return {"target": project_name, "nodes": nodes, "edges": edges, "routes": routes, "counts": type_counts, "generated_at": _now()}


def _investigation_routes(conn, *, host_id: int | None = None, resource_ids: list[int] | None = None, limit: int = 8) -> list[dict[str, Any]]:
    """Build deterministic, evidence-backed investigation paths.

    A route is *not* an exploit chain.  It is a compact sequence from observed
    evidence to an active hypothesis and its next manual test.  AI hypotheses
    participate naturally because they are persisted in leads_v2 too.
    """
    where = ["COALESCE(l.rule_active,1)=1", "l.status NOT IN ('negative','discarded')"]
    params: list[Any] = []
    if resource_ids:
        marks = ','.join('?' * len(resource_ids))
        if host_id:
            where.append(f"(l.host_id=? OR l.resource_id IN ({marks}))")
            params.extend([host_id, *resource_ids])
        else:
            where.append(f"l.resource_id IN ({marks})")
            params.extend(resource_ids)
    elif host_id:
        where.append("l.host_id=?")
        params.append(host_id)

    rows = conn.execute(
        f"""SELECT l.*,h.hostname,r.path,r.url FROM leads_v2 l
             LEFT JOIN hosts h ON h.id=l.host_id LEFT JOIN resources r ON r.id=l.resource_id
             WHERE {' AND '.join(where)}
             ORDER BY CASE l.status WHEN 'confirmed' THEN 0 WHEN 'interesting' THEN 1 WHEN 'testing' THEN 2 ELSE 3 END,
                      CASE l.review_priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                      CASE l.confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                      l.updated_at DESC LIMIT ?""",
        (*params, max(1, limit * 3)),
    ).fetchall()

    status_score = {"confirmed": 45, "interesting": 34, "testing": 28, "candidate": 20, "postponed": 8}
    priority_score = {"high": 28, "medium": 18, "low": 8}
    confidence_score = {"high": 14, "medium": 9, "low": 4}
    routes: list[dict[str, Any]] = []
    for l in rows:
        rid = int(l["resource_id"] or 0)
        hid = int(l["host_id"] or 0)
        if rid and not hid:
            rr = conn.execute("SELECT host_id FROM resources WHERE id=?", (rid,)).fetchone()
            hid = int(rr["host_id"]) if rr else 0
        try:
            evidence = json.loads(l["evidence_json"] or "[]")
        except Exception:
            evidence = []

        exchange_id = 0
        operation_id = 0
        method = ""
        path = str(l["path"] or "")
        for ev in evidence if isinstance(evidence, list) else []:
            if not isinstance(ev, dict):
                continue
            if not exchange_id and ev.get("exchange_id"):
                try: exchange_id = int(ev.get("exchange_id"))
                except Exception: exchange_id = 0
        if exchange_id:
            ex = conn.execute(
                """SELECT e.operation_id,o.method,o.resource_id,r.path,r.host_id
                   FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id
                   JOIN resources r ON r.id=o.resource_id WHERE e.id=?""", (exchange_id,)
            ).fetchone()
            if ex:
                operation_id = int(ex["operation_id"]); method = str(ex["method"] or "")
                rid = rid or int(ex["resource_id"]); hid = hid or int(ex["host_id"]); path = path or str(ex["path"] or "")
        if rid and not operation_id:
            op = conn.execute("SELECT id,method FROM resource_operations WHERE resource_id=? ORDER BY last_seen_at DESC LIMIT 1", (rid,)).fetchone()
            if op:
                operation_id = int(op["id"]); method = str(op["method"] or "")

        node_ids = []
        if hid: node_ids.append(f"host:{hid}")
        if rid: node_ids.append(f"resource:{rid}")
        if operation_id: node_ids.append(f"operation:{operation_id}")
        if exchange_id: node_ids.append(f"exchange:{exchange_id}")
        node_ids.append(f"lead:{int(l['id'])}")

        score = status_score.get(str(l["status"]), 12) + priority_score.get(str(l["review_priority"]), 5) + confidence_score.get(str(l["confidence"]), 3)
        if exchange_id: score += 6
        if str(l["source"] or "").upper().startswith("AI"): score += 3
        routes.append({
            "id": f"route:{int(l['id'])}", "lead_id": int(l["id"]), "host_id": hid or None, "resource_id": rid or None,
            "score": score, "title": str(l["title"]), "lead_type": str(l["lead_type"]), "status": str(l["status"]),
            "priority": str(l["review_priority"]), "confidence": str(l["confidence"]), "source": str(l["source"] or "ENGINE"),
            "method": method, "path": path, "node_ids": node_ids,
            "why": str(l["why_interesting"] or ""), "next_test": str(l["next_test"] or ""),
        })
    routes.sort(key=lambda x: (-int(x["score"]), x["title"]))
    return routes[:limit]


def _graph_data(paths: dict[str, Path], domain: str, *, scope: str = "overview", host_id: int | None = None,
                resource_id: int | None = None, exchange_limit: int = 100, observation_limit: int = 100) -> dict[str, Any]:
    """Progressive graph projection for large real-world targets.

    overview -> Target + aggregated hosts only.
    host     -> one host + its resources/operations and bounded evidence.
    resource -> one resource + methods + bounded Burp/evidence/hypotheses/findings.

    The browser never needs 5k+ resource nodes just to open the map.
    """
    import negro_hunter as hunter
    scope = (scope or "overview").lower()
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_node(nid: str, typ: str, label: str, *, state: str="normal", meta: dict[str, Any] | None=None, href: str | None=None):
        if nid in seen: return nid
        seen.add(nid); nodes.append({"id":nid,"type":typ,"label":str(label),"state":state,"meta":meta or {},"href":href}); return nid
    def add_edge(a: str,b: str,rel: str,source: str="inventory",evidence: Any=None):
        if a in seen and b in seen and a != b:
            edges.append({"id":f"e{len(edges)+1}","source":a,"target":b,"relation":rel,"meta":{"source":source,"evidence":evidence}})

    project_name = core.workspace_project_name(paths, domain)
    target=add_node("target:root","target",project_name,meta={"domain":domain,"project_name":project_name})
    with _db(paths) as conn:
        total_hosts=int(conn.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"] or 0)
        total_resources=int(conn.execute("SELECT COUNT(*) c FROM resources").fetchone()["c"] or 0)
        total_ops=int(conn.execute("SELECT COUNT(*) c FROM resource_operations").fetchone()["c"] or 0)
        totals={"target":1,"host":total_hosts,"resource":total_resources,"operation":total_ops,
                "request":int(conn.execute("SELECT COUNT(*) c FROM http_exchanges").fetchone()["c"] or 0),
                "observation":int(conn.execute("SELECT COUNT(*) c FROM observations").fetchone()["c"] or 0),
                "lead":int(conn.execute("SELECT COUNT(*) c FROM leads_v2").fetchone()["c"] or 0),
                "finding":int(conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"] or 0)}

        if scope == "routes":
            # Compact cross-resource projection used by "Qué probar ahora".
            # The overview endpoint intentionally loads only host summaries for
            # performance, while investigation routes reference deeper
            # resource/operation/exchange/lead nodes.  Materialize only the
            # top evidence-backed routes so the canvas can actually draw them
            # without loading the entire target.
            routes = _investigation_routes(conn, limit=8)
            for route in routes:
                hid = int(route.get("host_id") or 0)
                rid = int(route.get("resource_id") or 0)
                lead_id = int(route.get("lead_id") or 0)

                hn = None
                if hid:
                    h = conn.execute("SELECT * FROM hosts WHERE id=?", (hid,)).fetchone()
                    if h:
                        hcov = _coverage_state(h["review_state"]); hsig, hfind = _entity_signal(conn, "host", hid, h["classification"])
                        hn = add_node(
                            f"host:{hid}", "host", h["hostname"], state=_visual_state(hcov, hsig),
                            meta={"id":hid,"coverage":hcov,"signal":hsig,"finding_count":hfind,"review":h["review_state"],"classification":h["classification"],"priority":h["priority"]},
                            href=f"host/{hid}",
                        )
                        add_edge(target, hn, "contains", source="investigation_routes")

                rn = None
                if rid:
                    r = conn.execute("SELECT r.*,h.hostname FROM resources r JOIN hosts h ON h.id=r.host_id WHERE r.id=?", (rid,)).fetchone()
                    if r:
                        if not hn:
                            hid = int(r["host_id"] or 0)
                            h = conn.execute("SELECT * FROM hosts WHERE id=?", (hid,)).fetchone()
                            if h:
                                hcov = _coverage_state(h["review_state"]); hsig, hfind = _entity_signal(conn, "host", hid, h["classification"])
                                hn = add_node(f"host:{hid}", "host", h["hostname"], state=_visual_state(hcov, hsig), meta={"id":hid,"coverage":hcov,"signal":hsig,"finding_count":hfind,"review":h["review_state"],"classification":h["classification"],"priority":h["priority"]}, href=f"host/{hid}")
                                add_edge(target, hn, "contains", source="investigation_routes")
                        rcov = _coverage_state(r["review_state"]); rsig, rfind = _entity_signal(conn, "resource", rid, r["classification"])
                        rn = add_node(
                            f"resource:{rid}", "resource", r["path"] or r["url"], state=_visual_state(rcov, rsig),
                            meta={"id":rid,"url":r["url"],"host":r["hostname"],"coverage":rcov,"signal":rsig,"review":r["review_state"],"classification":r["classification"],"finding_count":rfind,"priority":r["priority"]},
                            href=f"resource/{rid}",
                        )
                        if hn: add_edge(hn, rn, "contains", source="investigation_routes")

                opn = None
                op_id = 0
                ex_id = 0
                # route.node_ids already contains the exact evidence chain
                # selected by _investigation_routes.
                for node_id in route.get("node_ids") or []:
                    if str(node_id).startswith("operation:"):
                        try: op_id = int(str(node_id).split(":", 1)[1])
                        except Exception: op_id = 0
                    elif str(node_id).startswith("exchange:"):
                        try: ex_id = int(str(node_id).split(":", 1)[1])
                        except Exception: ex_id = 0

                if op_id:
                    o = conn.execute("SELECT o.*,r.path,r.url FROM resource_operations o JOIN resources r ON r.id=o.resource_id WHERE o.id=?", (op_id,)).fetchone()
                    if o:
                        test_summary = hunter.operation_test_summary(conn, op_id)
                        ostate = "interesting" if int(test_summary.get("interesting",0)) + int(test_summary.get("confirmed",0)) > 0 or (o["last_status"] and int(o["last_status"]) >= 500) else "normal"
                        opn = add_node(f"operation:{op_id}", "operation", f"{o['method']} {o['path']}", state=ostate, meta={"id":op_id,"method":o["method"],"status":o["last_status"],"seen_count":o["seen_count"],"authenticated":bool(o["authenticated_observed"]),"last_seen_at":o["last_seen_at"],"url":o["url"],"test_summary":test_summary})
                        parent = f"resource:{int(o['resource_id'])}"
                        add_edge(parent, opn, "supports", source="investigation_routes")

                exn = None
                if ex_id:
                    e = conn.execute("SELECT e.*,o.method,r.path FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id WHERE e.id=?", (ex_id,)).fetchone()
                    if e:
                        exn = add_node(f"exchange:{ex_id}", "request", f"#{ex_id} {e['method']} · {e['status_code'] or '—'}", meta={"id":ex_id,"source":e["source"],"tool":e["tool"],"status":e["status_code"],"seen_count":e["seen_count"],"last_seen_at":e["last_seen_at"],"path":e["path"]})
                        add_edge(f"operation:{int(e['operation_id'])}", exn, "observed_in", source=e["source"] or "investigation_routes")

                if lead_id:
                    l = conn.execute("SELECT * FROM leads_v2 WHERE id=?", (lead_id,)).fetchone()
                    if l:
                        lst = "tested" if l["status"] in ("discarded","negative") else "finding" if l["status"] == "confirmed" else "interesting"
                        ln = add_node(
                            f"lead:{lead_id}", "lead", l["title"], state=lst,
                            meta={"id":lead_id,"type":l["lead_type"],"status":l["status"],"confidence":l["confidence"],"priority":l["review_priority"],"source":l["source"],"why":l["why_interesting"],"next_test":l["next_test"],"result_notes":l["result_notes"] if "result_notes" in l.keys() else ""},
                            href=f"hypotheses#hypothesis-{lead_id}",
                        )
                        if exn:
                            add_edge(exn, ln, "supports_hypothesis", source=str(l["source"] or "engine").lower(), evidence={"exchange_id":ex_id})
                        elif rn:
                            add_edge(rn, ln, "produced_lead", source=str(l["source"] or "engine").lower())
                        elif hn:
                            add_edge(hn, ln, "produced_lead", source=str(l["source"] or "engine").lower())

            counts: dict[str, int] = {}
            for n in nodes: counts[n["type"]] = counts.get(n["type"], 0) + 1
            return {
                "target": project_name, "nodes": nodes, "edges": edges, "routes": routes, "counts": totals, "generated_at": _now(),
                "meta": {"scope":"routes","scope_label":"Qué probar ahora · rutas de investigación","large_target":total_resources>800,"loaded_counts":counts},
            }

        if scope == "overview" or (scope == "host" and not host_id) or (scope == "resource" and not resource_id):
            rows=conn.execute("""
                SELECT h.*,
                  (SELECT COUNT(*) FROM resources r WHERE r.host_id=h.id) resource_count,
                  (SELECT COUNT(*) FROM resources r WHERE r.host_id=h.id AND r.classification='discarded') discarded_resources,
                  (SELECT COUNT(*) FROM resources r WHERE r.host_id=h.id AND r.review_state='pending' AND r.classification!='discarded') pending_resources,
                  (SELECT COUNT(*) FROM resource_operations o JOIN resources r ON r.id=o.resource_id WHERE r.host_id=h.id) operation_count,
                  (SELECT COUNT(*) FROM resources r WHERE r.host_id=h.id AND r.classification='lead') interesting_resources,
                  (SELECT COUNT(*) FROM leads_v2 l WHERE l.host_id=h.id AND COALESCE(l.rule_active,1)=1 AND l.status NOT IN ('negative','discarded')) lead_count,
                  (SELECT COUNT(DISTINCT fe.finding_id) FROM finding_entities fe LEFT JOIN resources rr ON fe.entity_type='resource' AND fe.entity_id=rr.id WHERE (fe.entity_type='host' AND fe.entity_id=h.id) OR rr.host_id=h.id) finding_count
                FROM hosts h ORDER BY CASE WHEN h.classification='finding' THEN 0 WHEN h.classification='lead' THEN 1 WHEN h.review_state='in_progress' THEN 2 ELSE 3 END, h.hostname
            """).fetchall()
            important=[]; grouped={"pending":[],"reviewed":[],"discarded":[]}
            for h in rows:
                is_important = bool(int(h["finding_count"] or 0) or int(h["lead_count"] or 0) or int(h["interesting_resources"] or 0) or h["classification"] in ('lead','finding') or h["review_state"]=='in_progress' or h["priority"] in ('high','medium') or int(h["operation_count"] or 0)>0)
                if is_important and len(important)<70:
                    important.append(h)
                else:
                    bucket='discarded' if h["classification"]=='discarded' else 'reviewed' if h["review_state"]=='reviewed' else 'pending'
                    grouped[bucket].append(h)
            for h in important:
                coverage=_coverage_state(h["review_state"]); signal="finding" if int(h["finding_count"] or 0)>0 else "interesting" if h["classification"]=='lead' or int(h["interesting_resources"] or 0)>0 or int(h["lead_count"] or 0)>0 else "normal"
                nid=add_node(f"host:{h['id']}","host",h["hostname"],state=_visual_state(coverage,signal),
                    meta={"id":h["id"],"coverage":coverage,"signal":signal,"review":h["review_state"],"classification":h["classification"],"priority":h["priority"],
                          "resource_count":int(h["resource_count"] or 0),"pending_resources":int(h["pending_resources"] or 0),"discarded_resources":int(h["discarded_resources"] or 0),
                          "operation_count":int(h["operation_count"] or 0),"interesting_resources":int(h["interesting_resources"] or 0),"lead_count":int(h["lead_count"] or 0),"finding_count":int(h["finding_count"] or 0)}, href=f"host/{h['id']}")
                add_edge(target,nid,"contains")
            cluster_labels={"pending":"Hosts pendientes","reviewed":"Hosts revisados","discarded":"Hosts descartados"}
            cluster_hrefs={"pending":"hosts?review=pending","reviewed":"hosts?review=reviewed","discarded":"hosts?classification=discarded"}
            cluster_states={"pending":"untested","reviewed":"tested","discarded":"tested"}
            for bucket,items in grouped.items():
                if not items: continue
                cid=add_node(f"cluster:hosts:{bucket}","cluster",f"{cluster_labels[bucket]} · {len(items)}",state=cluster_states[bucket],meta={"count":len(items),"group":"hosts","bucket":bucket,"note":"Agrupados para que el mapa siga siendo usable. Abre Inventario para filtrar/buscar."},href=cluster_hrefs[bucket])
                add_edge(target,cid,"contains",source="progressive_disclosure")
            routes=_investigation_routes(conn, limit=6)
            return {"target":project_name,"nodes":nodes,"edges":edges,"routes":routes,"counts":totals,"generated_at":_now(),
                    "meta":{"scope":"overview","large_target":total_resources>800,"scope_label":"Vista general","host_count":total_hosts,"resource_count":total_resources,"important_hosts":len(important),"grouped_hosts":sum(len(v) for v in grouped.values())}}

        selected_resource=None
        selected_host=None
        if scope == "resource" and resource_id:
            selected_resource=conn.execute("SELECT r.*,h.hostname FROM resources r JOIN hosts h ON h.id=r.host_id WHERE r.id=?",(resource_id,)).fetchone()
            if not selected_resource:
                return {"target":project_name,"nodes":[nodes[0]],"edges":[],"counts":totals,"generated_at":_now(),"meta":{"scope":"overview"}}
            host_id=int(selected_resource["host_id"])
        if host_id:
            selected_host=conn.execute("SELECT * FROM hosts WHERE id=?",(host_id,)).fetchone()
        if not selected_host:
            return _graph_data(paths,domain,scope="overview")

        h=selected_host
        hcov=_coverage_state(h["review_state"]); hsig,hfind=_entity_signal(conn,"host",h["id"],h["classification"])
        hn=add_node(f"host:{h['id']}","host",h["hostname"],state=_visual_state(hcov,hsig),meta={"id":h["id"],"coverage":hcov,"signal":hsig,"finding_count":hfind,"review":h["review_state"],"classification":h["classification"],"priority":h["priority"]},href=f"host/{h['id']}")
        add_edge(target,hn,"contains")

        if scope == "resource" and selected_resource is not None:
            resources=[selected_resource]
            resource_limit=1
        else:
            resource_limit=180
            resources=conn.execute("""SELECT r.*,h.hostname FROM resources r JOIN hosts h ON h.id=r.host_id WHERE r.host_id=?
                ORDER BY CASE r.classification WHEN 'finding' THEN 0 WHEN 'lead' THEN 1 WHEN 'discarded' THEN 5 ELSE 2 END,
                         CASE r.review_state WHEN 'in_progress' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END, r.updated_at DESC LIMIT ?""",(host_id,resource_limit)).fetchall()
        rids=[int(r["id"]) for r in resources]
        visible_resource_by_url: dict[str, str] = {}
        visible_resource_by_host_path: dict[tuple[str, str], str] = {}
        for r in resources:
            cov=_coverage_state(r["review_state"]); sig,fc=_entity_signal(conn,"resource",r["id"],r["classification"])
            rn=add_node(f"resource:{r['id']}","resource",r["path"] or r["url"],state=_visual_state(cov,sig),meta={"id":r["id"],"url":r["url"],"host":r["hostname"],"coverage":cov,"signal":sig,"review":r["review_state"],"classification":r["classification"],"finding_count":fc,"priority":r["priority"]},href=f"resource/{r['id']}")
            visible_resource_by_url[str(r["url"])] = rn
            visible_resource_by_host_path[(str(r["hostname"]).lower(), str(r["path"] or "/"))] = rn
            add_edge(hn,rn,"contains")
        if scope == "host":
            total_for_host=int(conn.execute("SELECT COUNT(*) c FROM resources WHERE host_id=?",(host_id,)).fetchone()["c"] or 0)
            hidden=max(0,total_for_host-len(resources))
            if hidden:
                cn=add_node(f"cluster:hidden_resources:{host_id}","cluster",f"Otros recursos · {hidden}",meta={"count":hidden,"host_id":host_id,"note":"Usa Inventario/buscador para acotar antes de expandir más."},href=f"host/{host_id}")
                add_edge(hn,cn,"contains",source="progressive_disclosure")

        if rids:
            marks=','.join('?'*len(rids))
            ops=conn.execute(f"SELECT o.*,r.path,r.url FROM resource_operations o JOIN resources r ON r.id=o.resource_id WHERE o.resource_id IN ({marks}) ORDER BY o.last_seen_at DESC LIMIT 360",rids).fetchall()
            opids=[]
            for o in ops:
                opids.append(int(o["id"]))
                test_summary=hunter.operation_test_summary(conn,int(o["id"]))
                state="interesting" if int(test_summary.get("interesting",0))+int(test_summary.get("confirmed",0))>0 or (o["last_status"] and int(o["last_status"])>=500) else "normal"
                on=add_node(f"operation:{o['id']}","operation",f"{o['method']} {o['path']}",state=state,meta={"id":o["id"],"method":o["method"],"status":o["last_status"],"seen_count":o["seen_count"],"authenticated":bool(o["authenticated_observed"]),"last_seen_at":o["last_seen_at"],"url":o["url"],"test_summary":test_summary})
                add_edge(f"resource:{o['resource_id']}",on,"supports",source="http_model")
            if opids:
                omarks=','.join('?'*len(opids))
                exchanges=conn.execute(f"SELECT e.*,o.method,r.path FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id JOIN resources r ON r.id=o.resource_id WHERE e.operation_id IN ({omarks}) ORDER BY e.last_seen_at DESC LIMIT ?",(*opids,max(10,min(exchange_limit,120)))).fetchall()
                for e in exchanges:
                    en=add_node(f"exchange:{e['id']}","request",f"#{e['id']} {e['method']} · {e['status_code'] or '—'}",meta={"id":e["id"],"source":e["source"],"tool":e["tool"],"status":e["status_code"],"seen_count":e["seen_count"],"last_seen_at":e["last_seen_at"],"path":e["path"]})
                    add_edge(f"operation:{e['operation_id']}",en,"observed_in",source=e["source"])

            # Observations only for visible host/resources.
            obs=conn.execute("SELECT * FROM observations WHERE (entity_type='host' AND entity_id=?) OR (entity_type='resource' AND entity_id IN (%s)) ORDER BY id DESC LIMIT ?" % (','.join('?'*len(rids))), (host_id,*rids,max(10,min(observation_limit,100)))).fetchall() if rids else []
            for o in obs:
                try: payload=json.loads(o["payload_json"] or '{}')
                except Exception: payload={}
                st="interesting" if bool(payload.get("interesting")) or bool(payload.get("likely_credentialed_cors")) else "normal"
                on=add_node(f"observation:{o['id']}","observation",str(o["kind"]).replace('_',' '),state=st,meta={"id":o["id"],"source":o["source"],"kind":o["kind"],"value":o["value"],"observed_at":o["observed_at"]})
                parent=f"{o['entity_type']}:{o['entity_id']}"; add_edge(parent,on,"tested_by",source=o["source"])

            leads=conn.execute(f"SELECT * FROM leads_v2 WHERE COALESCE(rule_active,1)=1 AND (host_id=? OR resource_id IN ({marks})) ORDER BY updated_at DESC LIMIT 80",(host_id,*rids)).fetchall()
            for l in leads:
                st="tested" if l["status"] in ('discarded','negative') else "finding" if l["status"]=='confirmed' else "interesting"
                ln=add_node(f"lead:{l['id']}","lead",l["title"],state=st,meta={"id":l["id"],"type":l["lead_type"],"status":l["status"],"confidence":l["confidence"],"priority":l["review_priority"],"source":l["source"],"why":l["why_interesting"],"next_test":l["next_test"],"result_notes":l["result_notes"] if "result_notes" in l.keys() else ""},href=f"hypotheses#hypothesis-{l['id']}")
                parent=f"resource:{l['resource_id']}" if l["resource_id"] and f"resource:{l['resource_id']}" in seen else hn
                add_edge(parent,ln,"produced_lead",source=str(l["source"]).lower())
                try: lev=json.loads(l["evidence_json"] or '[]')
                except Exception: lev=[]
                for ev in lev if isinstance(lev,list) else []:
                    if not isinstance(ev,dict): continue
                    exid=ev.get('exchange_id')
                    if exid and f"exchange:{exid}" in seen:
                        add_edge(f"exchange:{exid}",ln,"supports_hypothesis",source=str(l["source"]).lower(),evidence={"exchange_id":exid})
                        break
            findings=conn.execute("SELECT DISTINCT f.* FROM findings f JOIN finding_entities fe ON fe.finding_id=f.id LEFT JOIN resources rr ON fe.entity_type='resource' AND fe.entity_id=rr.id WHERE (fe.entity_type='host' AND fe.entity_id=?) OR rr.host_id=? ORDER BY f.updated_at DESC LIMIT 100",(host_id,host_id)).fetchall()
            for f in findings:
                fn=add_node(f"finding:{f['id']}","finding",f["title"],state="finding",meta={"id":f["id"],"severity":f["severity"],"status":f["status"],"description":f["description"]},href=f"finding/{f['id']}")
                for fe in conn.execute("SELECT * FROM finding_entities WHERE finding_id=?",(f["id"],)).fetchall():
                    parent=f"{fe['entity_type']}:{fe['entity_id']}"; add_edge(parent,fn,fe["relation"] or 'affected_by',source='finding')

        # JS is useful at host scope but bounded; resources don't need every bundle node.
        if scope == "host":
            jsrows=conn.execute("SELECT * FROM js_assets WHERE host_id=? ORDER BY discovered_at DESC LIMIT 60",(host_id,)).fetchall()
            for js in jsrows:
                label=Path(urllib.parse.urlsplit(js["url"]).path).name or js["url"]
                try: js_local=json.loads(js["local_analysis_json"] or '{}')
                except Exception: js_local={}
                discovered=list(js_local.get("in_scope_urls",[]) or []) if isinstance(js_local,dict) else []
                sensitive=[]
                for u in discovered:
                    lowp=(urllib.parse.urlsplit(str(u)).path or '/').lower()
                    if any(x in lowp for x in ("admin","internal","manage","approve","audit","export","delete","role","permission","debug","ops","feature","staff","backoffice")):
                        sensitive.append(str(u))
                jstate="interesting" if sensitive else "tested" if js["analyzed_at"] else "untested"
                jn=add_node(f"js:{js['id']}","javascript",label,state=jstate,meta={"id":js["id"],"url":js["url"],"source":js["source"],"analyzed_at":js["analyzed_at"],"routes_count":len(discovered),"interesting_routes":len(sensitive)})
                add_edge(hn,jn,"contains",source=js["source"])
                for candidate in discovered[:300]:
                    try:
                        pu=urllib.parse.urlsplit(str(candidate))
                        rnode=visible_resource_by_url.get(str(candidate)) or visible_resource_by_host_path.get(((pu.hostname or '').lower(),pu.path or '/'))
                    except Exception:
                        rnode=None
                    if not rnode:
                        # A frontend bundle commonly discovers routes on a sibling
                        # API host.  Keep that cross-host relationship visible even
                        # while the map is scoped to the frontend host.
                        rr=conn.execute(
                            """SELECT r.*,h.hostname,h.review_state AS host_review,h.classification AS host_classification,h.priority AS host_priority
                               FROM resources r JOIN hosts h ON h.id=r.host_id
                               WHERE r.url=? OR (lower(h.hostname)=? AND r.path=?) ORDER BY CASE WHEN r.url=? THEN 0 ELSE 1 END LIMIT 1""",
                            (str(candidate), (pu.hostname or '').lower(), pu.path or '/', str(candidate)),
                        ).fetchone()
                        if rr:
                            related_hn=f"host:{rr['host_id']}"
                            if related_hn not in seen:
                                rhcov=_coverage_state(rr["host_review"]); rhsig,rhfind=_entity_signal(conn,"host",rr["host_id"],rr["host_classification"])
                                add_node(related_hn,"host",rr["hostname"],state=_visual_state(rhcov,rhsig),meta={"id":rr["host_id"],"coverage":rhcov,"signal":rhsig,"review":rr["host_review"],"classification":rr["host_classification"],"priority":rr["host_priority"],"finding_count":rhfind,"related_from_js":True},href=f"host/{rr['host_id']}")
                                add_edge(target,related_hn,"contains",source="js_cross_host")
                            rnode=f"resource:{rr['id']}"
                            if rnode not in seen:
                                rcov=_coverage_state(rr["review_state"]); rsig,rfc=_entity_signal(conn,"resource",rr["id"],rr["classification"])
                                add_node(rnode,"resource",rr["path"] or rr["url"],state=_visual_state(rcov,rsig),meta={"id":rr["id"],"url":rr["url"],"host":rr["hostname"],"coverage":rcov,"signal":rsig,"review":rr["review_state"],"classification":rr["classification"],"finding_count":rfc,"priority":rr["priority"],"related_from_js":True},href=f"resource/{rr['id']}")
                                add_edge(related_hn,rnode,"contains",source="js_cross_host")
                            visible_resource_by_url[str(rr["url"])]=rnode
                            visible_resource_by_host_path[(str(rr["hostname"]).lower(),str(rr["path"] or '/'))]=rnode
                    if rnode:
                        add_edge(jn,rnode,"discovered",source="js_local",evidence={"url":str(candidate),"asset_id":int(js["id"])})

        routes=_investigation_routes(conn, host_id=host_id, resource_ids=rids, limit=8)

    counts: dict[str,int]={}
    for n in nodes: counts[n["type"]]=counts.get(n["type"],0)+1
    label="Recurso" if scope=='resource' else "Host" if scope=='host' else "Vista general"
    return {"target":project_name,"nodes":nodes,"edges":edges,"routes":routes,"counts":totals,"generated_at":_now(),
            "meta":{"scope":scope,"scope_label":label,"host_id":host_id,"resource_id":resource_id,"large_target":total_resources>800,"loaded_counts":counts}}


def create_app(default_domain: str, default_workspace: Path):
    if _WEB_IMPORT_ERROR is not None:
        raise RuntimeError("Faltan dependencias web. Ejecuta ./install-web.sh o instala requirements.txt") from _WEB_IMPORT_ERROR

    existing_project = None
    try:
        wanted = default_workspace.expanduser().resolve()
        for item in core.list_targets():
            try:
                if Path(str(item.get("workspace") or "")).expanduser().resolve() == wanted:
                    existing_project = item
                    break
            except Exception:
                continue
    except Exception:
        existing_project = None
    if existing_project:
        default_key = str(existing_project["key"])
        core.set_current_target(default_key)
    else:
        default_key = core.register_target(default_domain, default_workspace, make_current=True)
    root = Path(__file__).resolve().parent
    templates = Jinja2Templates(directory=str(root / "web" / "templates"))

    app = FastAPI(title="Negro Recon", docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=str(root / "web" / "static")), name="static")
    csrf_token = secrets.token_urlsafe(32)

    def render(request: Request, name: str, target_key: str, domain: str, workspace: Path, **ctx):
        base_context = {
            "domain": domain,
            "workspace": str(workspace),
            "target_key": target_key,
            "target_base": f"/t/{target_key}",
            "project": core.get_target(target_key) or {"name": domain, "domain": domain, "scopes": [domain]},
            "targets": core.list_targets(),
            "version": core.VERSION,
            "review_states": core.REVIEW_STATES,
            "classifications": core.CLASSIFICATIONS,
            "priorities": core.PRIORITIES,
            "ui_label": _ui_label,
            "csrf_token": csrf_token,
        }
        return templates.TemplateResponse(request=request, name=name, context={**base_context, **ctx})

    def verify_csrf(value: str) -> None:
        if not secrets.compare_digest(value or "", csrf_token):
            raise HTTPException(status_code=403, detail="CSRF token inválido")

    @app.get("/", response_class=HTMLResponse)
    def root_redirect(request: Request):
        data = core.targets_load()
        targets = core.list_targets()
        key = data.get("last_target")
        if key and core.get_target(str(key)):
            return RedirectResponse(url=f"/t/{key}/", status_code=307)
        if targets:
            return RedirectResponse(url=f"/t/{targets[0]['key']}/", status_code=307)
        return templates.TemplateResponse(request=request, name="targets_empty.html", context={"version":core.VERSION,"csrf_token":csrf_token,"targets":[]})

    @app.post("/targets/create")
    def target_create(request: Request, name: str = Form(""), domain: str = Form(...), scopes: str = Form(""), workspace: str = Form(""), csrf: str = Form(...)):
        verify_csrf(csrf)
        domain = domain.strip().lower().rstrip(".")
        if domain.startswith("http://") or domain.startswith("https://") or not DOMAIN_RE.fullmatch(domain):
            return templates.TemplateResponse(request=request, name="target_error.html", status_code=400, context={"message":"Usa un scope principal válido, por ejemplo example.com", "version":core.VERSION})
        scope_values=[x.strip() for x in re.split(r"[\n,;]+", scopes or "") if x.strip()]
        scope_values=core.normalize_scopes(scope_values, domain)
        for scope in scope_values:
            if not DOMAIN_RE.fullmatch(scope):
                return templates.TemplateResponse(request=request, name="target_error.html", status_code=400, context={"message":f"Scope inválido: {scope}", "version":core.VERSION})
        project_name=(name or domain).strip()
        target_workspace = Path(workspace).expanduser() if workspace.strip() else core.suggested_workspace(core.target_key(project_name) or domain)
        try:
            core.ensure_workspace(target_workspace, domain, scopes=scope_values, project_name=project_name)
            key = core.register_target(domain, target_workspace, make_current=True, name=project_name, scopes=scope_values)
        except Exception as exc:
            print(f"[!] No pude crear proyecto {project_name}: {exc}")
            return templates.TemplateResponse(request=request, name="target_error.html", status_code=400, context={"message":str(exc), "workspace":str(target_workspace), "version":core.VERSION})
        return RedirectResponse(url=f"/t/{key}/", status_code=303)

    @app.post("/t/{target_key}/project")
    def project_update(request: Request, target_key: str, name: str = Form(...), scopes: str = Form(...), csrf: str = Form(...)):
        verify_csrf(csrf)
        target=core.get_target(target_key)
        if not target:
            raise HTTPException(status_code=404, detail="Proyecto no encontrado")
        values=[x.strip() for x in re.split(r"[\n,;]+", scopes or "") if x.strip()]
        roots=core.normalize_scopes(values, target.get("domain"))
        if not roots:
            raise HTTPException(status_code=400, detail="Agrega al menos un scope")
        for scope in roots:
            if not DOMAIN_RE.fullmatch(scope):
                raise HTTPException(status_code=400, detail=f"Scope inválido: {scope}")
        updated=core.update_target_project(target_key, name=name.strip() or target.get("name") or target.get("domain"), scopes=roots)
        try:
            import negro_hunter as hunter
            paths=core.ensure_workspace(Path(str(updated.get("workspace") or target.get("workspace"))).expanduser(), updated.get("domain") or target.get("domain"), scopes=roots, project_name=updated.get("name"))
            with _db(paths) as conn:
                hunter.retire_first_party_cors(conn, roots)
        except Exception as exc:
            print(f"[project] CORS cleanup warning: {exc}")
        return RedirectResponse(url=f"/t/{target_key}/settings?project=saved", status_code=303)

    @app.get("/t/{target_key}/backup")
    def target_backup(target_key: str):
        domain, workspace, paths = _target_context(target_key)
        backup_dir = Path.home() / ".config" / "negro" / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        out = backup_dir / f"negro-backup-{core.target_key(domain)}-{stamp}.zip"
        target_meta=core.get_target(target_key) or {}; manifest = {"format": 2, "negro_version": core.VERSION, "domain": domain, "name": target_meta.get("name") or domain, "scopes": target_meta.get("scopes") or [domain], "target_key": target_key, "created_at": _now()}
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
            for file in workspace.rglob("*"):
                if file.is_file():
                    try:
                        rel = file.relative_to(workspace)
                    except Exception:
                        continue
                    if any(part in {".git","__pycache__"} for part in rel.parts):
                        continue
                    zf.write(file, Path("workspace") / rel)
        return FileResponse(path=str(out), filename=out.name, media_type="application/zip")

    @app.post("/targets/{target_key}/delete")
    def target_delete(request: Request, target_key: str, confirm_domain: str = Form(...), delete_workspace: str = Form("yes"), csrf: str = Form(...)):
        verify_csrf(csrf)
        target = core.get_target(target_key)
        if not target:
            raise HTTPException(status_code=404, detail="Target no encontrado")
        domain = str(target.get("domain") or "")
        if confirm_domain.strip().lower().rstrip('.') != domain.lower().rstrip('.'):
            raise HTTPException(status_code=400, detail="Escribe el dominio exacto para confirmar el borrado")
        try:
            result = core.delete_target(target_key, delete_workspace=(delete_workspace == "yes"))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if result.get("next_target"):
            return RedirectResponse(url=f"/t/{result['next_target']}/?deleted=1", status_code=303)
        return RedirectResponse(url="/?deleted=1", status_code=303)

    @app.post("/targets/restore")
    async def target_restore(request: Request, backup: UploadFile = File(...), workspace: str = Form(""), csrf: str = Form(...)):
        verify_csrf(csrf)
        if not (backup.filename or "").lower().endswith(".zip"):
            raise HTTPException(status_code=400, detail="Selecciona un backup .zip de Negro")
        tmp_dir = Path.home() / ".config" / "negro" / "restore-tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        tmp = tmp_dir / f"{uuid.uuid4().hex}.zip"
        data = await backup.read()
        if len(data) > 1024 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="Backup demasiado grande")
        tmp.write_bytes(data)
        try:
            with zipfile.ZipFile(tmp) as zf:
                try:
                    manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
                except Exception:
                    raise HTTPException(status_code=400, detail="Backup sin manifest.json válido")
                domain = str(manifest.get("domain") or "").strip().lower().rstrip(".")
                if not DOMAIN_RE.fullmatch(domain):
                    raise HTTPException(status_code=400, detail="Dominio inválido dentro del backup")
            target_workspace = Path(workspace).expanduser() if workspace.strip() else core.suggested_workspace(domain)
            if target_workspace.exists() and any(target_workspace.iterdir()):
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
                target_workspace = target_workspace.parent / f"{target_workspace.name}-restore-{stamp}"
            staging = target_workspace.parent / f".{target_workspace.name}.restore-{uuid.uuid4().hex[:8]}"
            staging.mkdir(parents=True, exist_ok=False)
            _safe_extract_zip(tmp, staging)
            extracted = staging / "workspace"
            if not extracted.exists():
                shutil.rmtree(staging, ignore_errors=True)
                raise HTTPException(status_code=400, detail="Backup no contiene workspace/")
            target_workspace.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(extracted), str(target_workspace))
            shutil.rmtree(staging, ignore_errors=True)
            core.ensure_workspace(target_workspace, domain, scopes=manifest.get("scopes"), project_name=manifest.get("name") or domain)
            key = core.register_target(domain, target_workspace, make_current=True, name=manifest.get("name") or domain, scopes=manifest.get("scopes"))
            return RedirectResponse(url=f"/t/{key}/?restored=1", status_code=303)
        finally:
            tmp.unlink(missing_ok=True)

    @app.get("/t/{target_key}/settings", response_class=HTMLResponse)
    def settings_page(request: Request, target_key: str):
        import negro_intel as intel
        import negro_hunter as hunter
        domain, workspace, paths = _target_context(target_key)
        settings=intel.load_settings()
        lead_type_map={
            "access_object_reference":"access_object_reference", "mass_assignment":"mass_assignment",
            "method_access_control":"method_access_control", "redirect_body_access_control":"redirect_body_access_control",
            "proxy_path_access_control":"proxy_path_access_control", "referer_access_control":"referer_access_control",
            "js_sensitive_route":"javascript_surface", "cors":"cors", "open_redirect":"open_redirect",
            "ssrf_surface":"ssrf_surface", "secret_candidate":"secret_or_client_config",
            "sensitive_response":"sensitive_response", "sensitive_url":"sensitive_url", "source_map":"source_map",
        }
        notification_kind_map={
            "js_sensitive_route":"javascript_surface", "ssrf_surface":"url_fetch", "secret_candidate":"secret_candidate",
            "sensitive_url":"secret_in_url", "api_docs":"api_docs", "error_disclosure":"error_disclosure",
        }
        personal_library=settings.get("detector_rule_library") if isinstance(settings.get("detector_rule_library"),dict) else {}
        with _db(paths) as conn:
            row=conn.execute("SELECT value FROM meta WHERE key='detector_rules_json'").fetchone()
            try: project_rules=json.loads(row["value"]) if row and row["value"] else {}
            except Exception: project_rules={}
            if not isinstance(project_rules,dict): project_rules={}
            stats={}
            detector_rows=[]
            for detector_id,meta in hunter.DETECTOR_CATALOG.items():
                lead_type=lead_type_map.get(detector_id,detector_id)
                lead_count=int(conn.execute("SELECT COUNT(*) c FROM leads_v2 WHERE lead_type=? AND COALESCE(rule_active,1)=1 AND status NOT IN ('negative','discarded')",(lead_type,)).fetchone()["c"] or 0)
                nk=notification_kind_map.get(detector_id,detector_id)
                notif_count=int(conn.execute("SELECT COUNT(*) c FROM notifications WHERE kind=?",(nk,)).fetchone()["c"] or 0)
                effective=hunter.detector_settings(detector_id,conn)
                gl=rulebook.normalize_layer(personal_library.get(detector_id))
                pl=rulebook.normalize_layer(project_rules.get(detector_id))
                list_count=sum(len(v) for v in (effective.get("lists") or {}).values())
                condition_count=len(effective.get("conditions") or {})
                personal_count=sum(len(v) for b in ("add","exclude") for v in (gl.get(b) or {}).values()) + len(gl.get("conditions") or {})
                project_count=sum(len(v) for b in ("add","exclude") for v in (pl.get(b) or {}).values()) + len(pl.get("conditions") or {})
                detector_rows.append({
                    "id":detector_id, **meta, "active_count":lead_count, "notification_count":notif_count,
                    "enabled":bool(effective.get("enabled",True)), "rule_count":list_count+condition_count,
                    "personal_count":personal_count, "project_count":project_count,
                })
        return render(request, "settings.html", target_key, domain, workspace, settings=settings, detector_rows=detector_rows, secret_status=intel.secret_status(), secrets_path=str(intel.SECRETS_PATH))

    @app.post("/t/{target_key}/settings")
    def settings_save(request: Request, target_key: str, ai_model: str = Form(...), ai_output_tokens: int = Form(...), usd_cop_rate: float = Form(...), csrf: str = Form(...)):
        import negro_intel as intel
        verify_csrf(csrf)
        domain, workspace, _ = _target_context(target_key)
        if ai_model not in intel.OPENAI_PRICING:
            raise HTTPException(status_code=400, detail="Modelo inválido")
        if ai_output_tokens < 500 or ai_output_tokens > 12000:
            raise HTTPException(status_code=400, detail="ai_output_tokens fuera de rango")
        if usd_cop_rate <= 0:
            raise HTTPException(status_code=400, detail="Tasa USD/COP inválida")
        intel.save_settings({"ai_model":ai_model, "ai_output_tokens":ai_output_tokens, "usd_cop_rate":usd_cop_rate, "usd_cop_rate_date":datetime.now().date().isoformat()})
        return RedirectResponse(url=f"/t/{target_key}/settings?saved=1", status_code=303)

    @app.post("/t/{target_key}/settings/detectors")
    async def detector_settings_save(request: Request, target_key: str):
        """Bulk enable/disable only. Rule content lives in each guided editor."""
        import negro_hunter as hunter
        form=await request.form()
        verify_csrf(str(form.get("csrf") or ""))
        domain, workspace, paths = _target_context(target_key)
        with _db(paths) as conn:
            row=conn.execute("SELECT value FROM meta WHERE key='detector_rules_json'").fetchone()
            try: out=json.loads(row["value"]) if row and row["value"] else {}
            except Exception: out={}
            if not isinstance(out,dict): out={}
            for detector_id in hunter.DETECTOR_CATALOG:
                layer=rulebook.normalize_layer(out.get(detector_id))
                layer["enabled"] = str(form.get(f"detector_{detector_id}_enabled") or "") == "on"
                out[detector_id]=layer
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('detector_rules_json',?)", (json.dumps(out, ensure_ascii=False, sort_keys=True),))
        return RedirectResponse(url=f"/t/{target_key}/settings?detectors=saved#detectors", status_code=303)

    def _rule_text(values: Any) -> str:
        return "\n".join(str(x) for x in (values or []) if str(x).strip())

    def _parse_rule_lines(value: Any) -> list[str]:
        out=[]; seen=set()
        for raw in str(value or "").replace("\r","").split("\n"):
            item=raw.strip()
            if not item or item.lower() in seen: continue
            seen.add(item.lower()); out.append(item)
        return out

    @app.get("/t/{target_key}/settings/detectors/{detector_id}", response_class=HTMLResponse)
    def detector_rule_page(request: Request, target_key: str, detector_id: str):
        import negro_intel as intel
        import negro_hunter as hunter
        if detector_id not in hunter.DETECTOR_CATALOG:
            raise HTTPException(status_code=404, detail="Detector no encontrado")
        domain, workspace, paths = _target_context(target_key)
        settings=intel.load_settings()
        personal_library=settings.get("detector_rule_library") if isinstance(settings.get("detector_rule_library"),dict) else {}
        with _db(paths) as conn:
            row=conn.execute("SELECT value FROM meta WHERE key='detector_rules_json'").fetchone()
            try: project_rules=json.loads(row["value"]) if row and row["value"] else {}
            except Exception: project_rules={}
            if not isinstance(project_rules,dict): project_rules={}
            effective=hunter.detector_settings(detector_id,conn)
        global_layer=rulebook.normalize_layer(personal_library.get(detector_id))
        project_layer=rulebook.normalize_layer(project_rules.get(detector_id))
        builtin=rulebook.BUILTIN_RULES.get(detector_id) or {"enabled":True,"lists":{},"conditions":{}}
        schema=rulebook.SCHEMAS.get(detector_id) or {"lists":{},"conditions":{}}
        list_rows=[]
        for name,(label,help_text) in (schema.get("lists") or {}).items():
            prov=(effective.get("provenance") or {}).get(name) or {}
            effective_values=list((effective.get("lists") or {}).get(name) or [])
            personal_lower={str(x).lower() for x in (prov.get("personal") or [])}
            project_lower={str(x).lower() for x in (prov.get("project") or [])}
            effective_entries=[]
            for value in effective_values:
                low=str(value).lower()
                source="project" if low in project_lower else "personal" if low in personal_lower else "builtin"
                effective_entries.append({"value":value,"source":source})
            list_rows.append({
                "name":name,"label":label,"help":help_text,
                "builtin":_rule_text((builtin.get("lists") or {}).get(name)),
                "personal_add":_rule_text((global_layer.get("add") or {}).get(name)),
                "personal_exclude":_rule_text((global_layer.get("exclude") or {}).get(name)),
                "project_add":_rule_text((project_layer.get("add") or {}).get(name)),
                "project_exclude":_rule_text((project_layer.get("exclude") or {}).get(name)),
                "effective":effective_values,"effective_entries":effective_entries,
                "provenance":prov,
            })
        condition_rows=[]
        for name,(label,help_text) in (schema.get("conditions") or {}).items():
            built=(builtin.get("conditions") or {}).get(name)
            gv=(global_layer.get("conditions") or {}).get(name,None)
            pv=(project_layer.get("conditions") or {}).get(name,None)
            ev=(effective.get("conditions") or {}).get(name,built)
            condition_rows.append({"name":name,"label":label,"help":help_text,"builtin":built,"personal":gv,"project":pv,"effective":ev,"type":"bool" if isinstance(built,bool) else "number" if isinstance(built,(int,float)) else "text"})
        regex_warnings=[]
        if detector_id=="error_disclosure":
            for pattern in (effective.get("lists") or {}).get("custom_regex",[]):
                try: re.compile(pattern)
                except re.error as exc: regex_warnings.append(f"{pattern}: {exc}")
        return render(request,"detector_rules.html",target_key,domain,workspace,
            detector_id=detector_id,detector= hunter.DETECTOR_CATALOG[detector_id], effective=effective,
            global_layer=global_layer,project_layer=project_layer,list_rows=list_rows,condition_rows=condition_rows,
            regex_warnings=regex_warnings)

    @app.post("/t/{target_key}/settings/detectors/{detector_id}")
    async def detector_rule_save(request: Request, target_key: str, detector_id: str):
        import negro_intel as intel
        import negro_hunter as hunter
        if detector_id not in hunter.DETECTOR_CATALOG:
            raise HTTPException(status_code=404, detail="Detector no encontrado")
        form=await request.form()
        verify_csrf(str(form.get("csrf") or ""))
        action=str(form.get("action") or "save")
        domain, workspace, paths = _target_context(target_key)
        settings=intel.load_settings()
        personal_library=settings.get("detector_rule_library") if isinstance(settings.get("detector_rule_library"),dict) else {}
        personal_library=dict(personal_library)
        with _db(paths) as conn:
            row=conn.execute("SELECT value FROM meta WHERE key='detector_rules_json'").fetchone()
            try: project_rules=json.loads(row["value"]) if row and row["value"] else {}
            except Exception: project_rules={}
            if not isinstance(project_rules,dict): project_rules={}

            if action == "reset_project":
                project_rules.pop(detector_id,None)
                conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('detector_rules_json',?)",(json.dumps(project_rules,ensure_ascii=False,sort_keys=True),))
                return RedirectResponse(url=f"/t/{target_key}/settings/detectors/{detector_id}?reset=project",status_code=303)
            if action == "reset_personal":
                personal_library.pop(detector_id,None)
                intel.save_settings({"detector_rule_library":personal_library})
                return RedirectResponse(url=f"/t/{target_key}/settings/detectors/{detector_id}?reset=personal",status_code=303)

            schema=rulebook.SCHEMAS.get(detector_id) or {"lists":{},"conditions":{}}
            global_layer={"add":{},"exclude":{},"conditions":{}}
            project_layer={"add":{},"exclude":{},"conditions":{}}
            ge=str(form.get("personal_enabled") or "inherit")
            pe=str(form.get("project_enabled") or "inherit")
            if ge in {"true","false"}: global_layer["enabled"]=(ge=="true")
            if pe in {"true","false"}: project_layer["enabled"]=(pe=="true")
            for name in (schema.get("lists") or {}):
                for layer,prefix in ((global_layer,"personal"),(project_layer,"project")):
                    adds=_parse_rule_lines(form.get(f"{prefix}_add__{name}"))
                    excludes=_parse_rule_lines(form.get(f"{prefix}_exclude__{name}"))
                    if adds: layer["add"][name]=adds
                    if excludes: layer["exclude"][name]=excludes
            builtin=rulebook.BUILTIN_RULES.get(detector_id) or {"conditions":{}}
            for name in (schema.get("conditions") or {}):
                built=(builtin.get("conditions") or {}).get(name)
                for layer,prefix in ((global_layer,"personal"),(project_layer,"project")):
                    raw=str(form.get(f"{prefix}_condition__{name}") or "inherit").strip()
                    if raw=="inherit" or raw=="": continue
                    if isinstance(built,bool):
                        if raw in {"true","false"}: layer["conditions"][name]=(raw=="true")
                    elif isinstance(built,int):
                        try: layer["conditions"][name]=int(raw)
                        except ValueError: pass
                    elif isinstance(built,float):
                        try: layer["conditions"][name]=float(raw)
                        except ValueError: pass
                    else:
                        layer["conditions"][name]=raw
            global_layer=rulebook.normalize_layer(global_layer)
            project_layer=rulebook.normalize_layer(project_layer)
            if global_layer: personal_library[detector_id]=global_layer
            else: personal_library.pop(detector_id,None)
            if project_layer: project_rules[detector_id]=project_layer
            else: project_rules.pop(detector_id,None)
            intel.save_settings({"detector_rule_library":personal_library})
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('detector_rules_json',?)",(json.dumps(project_rules,ensure_ascii=False,sort_keys=True),))
        return RedirectResponse(url=f"/t/{target_key}/settings/detectors/{detector_id}?saved=1",status_code=303)

    @app.get("/t/{target_key}/", response_class=HTMLResponse)
    def dashboard(request: Request, target_key: str):
        domain, workspace, paths = _target_context(target_key)
        core.set_current_target(target_key)
        data = _dashboard_data(paths)
        with JOBS_LOCK:
            jobs = [j for j in JOBS.values() if j.get("target_key") == target_key][-8:][::-1]
        return render(request, "dashboard.html", target_key, domain, workspace, **data, jobs=jobs, target_cards=_target_cards())

    @app.get("/t/{target_key}/notifications", response_class=HTMLResponse)
    def notifications_page(request: Request, target_key: str):
        domain, workspace, paths = _target_context(target_key)
        rows, unread = _notification_rows(paths, 250, False)
        return render(request, "notifications.html", target_key, domain, workspace, notifications=rows, unread=unread)

    @app.get("/api/t/{target_key}/notifications", response_class=JSONResponse)
    def notifications_api(target_key: str, after_id: int = 0, limit: int = 50):
        _, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            unread = int(conn.execute("SELECT COUNT(*) c FROM notifications WHERE read_at IS NULL").fetchone()["c"] or 0)
            rows = conn.execute(
                """SELECT * FROM notifications WHERE id>? ORDER BY id ASC LIMIT ?""",
                (max(0, after_id), max(1, min(limit, 100))),
            ).fetchall()
            items=[]
            for r in rows:
                item=dict(r)
                try: data=json.loads(item.get('data_json') or '{}')
                except Exception: data={}
                item['data']=data if isinstance(data,dict) else {}
                href=item['data'].get('href') if isinstance(item['data'],dict) else None
                item['href']=f"/t/{target_key}/{href}" if isinstance(href,str) and href else f"/t/{target_key}/intelligence#leads"
                items.append(item)
            latest = int(conn.execute("SELECT COALESCE(MAX(id),0) m FROM notifications").fetchone()["m"] or 0)
        return {"items":items,"unread":unread,"latest_id":latest}

    @app.post("/t/{target_key}/notifications/read")
    def notifications_read(target_key: str, notification_id: int = Form(0), all_items: str = Form(""), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            if all_items == 'yes':
                conn.execute("UPDATE notifications SET read_at=? WHERE read_at IS NULL", (_now(),))
            elif notification_id:
                conn.execute("UPDATE notifications SET read_at=? WHERE id=?", (_now(), notification_id))
        return RedirectResponse(url=f"/t/{target_key}/notifications", status_code=303)

    @app.get("/t/{target_key}/intelligence", response_class=HTMLResponse)
    def intelligence_page(request: Request, target_key: str):
        import negro_intel as intel
        domain, workspace, paths = _target_context(target_key)
        return render(
            request, "intelligence.html", target_key, domain, workspace,
            policy=core.policy_get(paths),
            leads=core.get_hunter_leads(paths, 250),
            historical=core.historical_intelligence(paths),
            ct=core.ct_intelligence(paths),
            search=core.search_intelligence(domain, paths),
            notifications=_notification_rows(paths, 20, False)[0],
            notifications_unread=_notification_rows(paths, 1, False)[1],
            latest_ai=core.latest_target_ai(paths),
            settings=intel.load_settings(),
            secret_status=intel.secret_status(),
        )

    @app.post("/t/{target_key}/policy")
    def set_policy(target_key: str, profile: str = Form(...), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        core.policy_set(paths, profile)
        return RedirectResponse(url=f"/t/{target_key}/intelligence", status_code=303)

    @app.post("/t/{target_key}/intel/dns")
    def intel_dns(request: Request, target_key: str, csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        job_id = _start_job("DNS infrastructure", target_key, core.dns_recon, domain, paths, 30)
        refresh_url = f"/t/{target_key}/intelligence"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id":job_id,"job_url":f"/api/jobs/{job_id}","refresh_url":refresh_url})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.post("/t/{target_key}/intel/axfr")
    def intel_axfr(request: Request, target_key: str, csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        job_id = _start_job("AXFR check", target_key, core.axfr_recon, domain, paths, 45)
        refresh_url = f"/t/{target_key}/intelligence"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id":job_id,"job_url":f"/api/jobs/{job_id}","refresh_url":refresh_url})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.post("/t/{target_key}/intel/active-dns")
    def intel_active_dns(request: Request, target_key: str, csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        job_id = _start_job("Smart DNS candidates", target_key, core.active_dns_smart, domain, paths, None)
        refresh_url = f"/t/{target_key}/intelligence"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id":job_id,"job_url":f"/api/jobs/{job_id}","refresh_url":refresh_url})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.post("/t/{target_key}/intel/leads")
    def intel_leads(request: Request, target_key: str, csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        job_id = _start_job("Correlation Engine", target_key, core.generate_hunter_leads, domain, paths)
        refresh_url = f"/t/{target_key}/intelligence#leads"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id":job_id,"job_url":f"/api/jobs/{job_id}","refresh_url":refresh_url})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.post("/t/{target_key}/intel/recalculate")
    def intel_recalculate(request: Request, target_key: str, return_to: str = Form("hypotheses"), csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        job_id = _start_job("Recalcular inteligencia local", target_key, core.recalculate_hunter_intelligence, domain, paths)
        destination = return_to if return_to in {"hypotheses","settings","graph","intelligence"} else "hypotheses"
        refresh_url = f"/t/{target_key}/{destination}"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id":job_id,"job_url":f"/api/jobs/{job_id}","refresh_url":refresh_url})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.get("/api/t/{target_key}/ai-target-estimate", response_class=JSONResponse)
    def ai_target_estimate(target_key: str, model: str = ""):
        domain, _, paths = _target_context(target_key)
        try:
            return core.ai_estimate_target(domain, paths, model or None)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/t/{target_key}/ai-target-run")
    def ai_target_run(request: Request, target_key: str, model: str = Form(""), confirm_cost: str = Form(""), csrf: str = Form(...)):
        verify_csrf(csrf)
        if confirm_cost != "yes":
            raise HTTPException(status_code=400, detail="Debes estimar y confirmar el costo antes de enviar a IA")
        domain, _, paths = _target_context(target_key)
        try:
            estimate = core.ai_estimate_target(domain, paths, model or None)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        job_id = _start_job(f"AI target · {estimate['model']}", target_key, core.ai_run_target, domain, paths, model or None)
        refresh_url = f"/t/{target_key}/intelligence#ai-target"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id":job_id,"job_url":f"/api/jobs/{job_id}","refresh_url":refresh_url,"estimate":estimate})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.get("/t/{target_key}/hosts", response_class=HTMLResponse)
    def hosts(request: Request, target_key: str, q: str = "", review: str = "", classification: str = "", priority: str = "", resource_review: str = ""):
        domain, workspace, paths = _target_context(target_key)
        rows = _host_rows(paths, q, review, classification, priority, resource_review)
        return render(request, "hosts.html", target_key, domain, workspace, hosts=rows, q=q, review=review, classification=classification, priority=priority, resource_review=resource_review)

    @app.get("/t/{target_key}/tree", response_class=HTMLResponse)
    def tree(request: Request, target_key: str, q: str = "", review: str = "", classification: str = "", priority: str = ""):
        domain, workspace, paths = _target_context(target_key)
        data = _tree_data(paths, q, review, classification, priority)
        return render(request, "tree.html", target_key, domain, workspace, tree=data, q=q, review=review, classification=classification, priority=priority)

    @app.get("/t/{target_key}/hypotheses", response_class=HTMLResponse)
    def hypotheses_page(request: Request, target_key: str, q: str = "", status: str = "", source: str = "", kind: str = "", validity: str = "current"):
        domain, workspace, paths = _target_context(target_key)
        validity = validity if validity in {"current","inactive","all"} else "current"
        rows = _hypothesis_rows(paths, q=q, status=status, source=source, kind=kind, validity=validity)
        kinds=sorted({str(x.get('lead_type') or '') for x in rows if x.get('lead_type')})
        return render(request, "hypotheses.html", target_key, domain, workspace, hypotheses=rows, q=q, hypothesis_status=status, hypothesis_source=source, hypothesis_kind=kind, hypothesis_kinds=kinds, hypothesis_validity=validity)

    @app.post("/t/{target_key}/hypothesis/{lead_id}/update")
    def hypothesis_update(request: Request, target_key: str, lead_id: int, status: str = Form(...), result_notes: str = Form(""), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        try:
            core.update_hypothesis(paths, lead_id, status=status, result_notes=result_notes.strip())
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return RedirectResponse(url=f"/t/{target_key}/hypotheses#hypothesis-{lead_id}", status_code=303)

    @app.get("/t/{target_key}/graph", response_class=HTMLResponse)
    def graph_page(request: Request, target_key: str):
        import negro_intel as intel
        domain, workspace, paths = _target_context(target_key)
        counts = _graph_inventory_counts(paths)
        return render(request, "graph.html", target_key, domain, workspace, graph_counts=counts, graph_generated=_now(), settings=intel.load_settings(), secret_status=intel.secret_status())

    @app.get("/api/t/{target_key}/graph", response_class=JSONResponse)
    def graph_api(target_key: str, scope: str = "overview", host_id: int = 0, resource_id: int = 0, focus: str = "", exchanges: int = 100, observations: int = 100):
        domain, _, paths = _target_context(target_key)
        if focus:
            try:
                typ, raw_id = focus.split(":", 1); entity_id = int(raw_id)
            except Exception:
                typ, entity_id = "", 0
            if entity_id:
                with _db(paths) as conn:
                    if typ == 'host': host_id = entity_id; scope = 'host'
                    elif typ == 'resource': resource_id = entity_id; scope = 'resource'
                    elif typ == 'operation':
                        rr=conn.execute("SELECT resource_id FROM resource_operations WHERE id=?",(entity_id,)).fetchone()
                        if rr: resource_id=int(rr['resource_id']); scope='resource'
                    elif typ == 'js':
                        rr=conn.execute("SELECT host_id FROM js_assets WHERE id=?",(entity_id,)).fetchone()
                        if rr: host_id=int(rr['host_id']); scope='host'
                    elif typ == 'lead':
                        rr=conn.execute("SELECT host_id,resource_id FROM leads_v2 WHERE id=?",(entity_id,)).fetchone()
                        if rr and rr['resource_id']: resource_id=int(rr['resource_id']); scope='resource'
                        elif rr and rr['host_id']: host_id=int(rr['host_id']); scope='host'
                    elif typ == 'finding':
                        rr=conn.execute("SELECT entity_type,entity_id FROM finding_entities WHERE finding_id=? ORDER BY CASE entity_type WHEN 'resource' THEN 0 WHEN 'host' THEN 1 ELSE 2 END LIMIT 1",(entity_id,)).fetchone()
                        if rr and rr['entity_type']=='resource': resource_id=int(rr['entity_id']); scope='resource'
                        elif rr and rr['entity_type']=='host': host_id=int(rr['entity_id']); scope='host'
        return _graph_data(paths, domain, scope=scope, host_id=host_id or None, resource_id=resource_id or None, exchange_limit=exchanges, observation_limit=observations)

    @app.get("/api/t/{target_key}/graph/ideas-estimate", response_class=JSONResponse)
    def graph_ideas_estimate(target_key: str, model: str = "", selected_node_id: str = ""):
        domain, _, paths = _target_context(target_key)
        graph_data = _graph_data_full(paths, domain)
        try:
            return core.ai_estimate_graph_ideas(domain, paths, graph_data, selected_node_id or None, model or None)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/t/{target_key}/graph/ideas-run")
    def graph_ideas_run(request: Request, target_key: str, model: str = Form(""), selected_node_id: str = Form(""), confirm_cost: str = Form(""), csrf: str = Form(...)):
        verify_csrf(csrf)
        if confirm_cost != "yes":
            raise HTTPException(status_code=400, detail="Confirma el costo estimado antes de ejecutar IA")
        domain, _, paths = _target_context(target_key)
        graph_data = _graph_data_full(paths, domain)
        job_id = _start_job("AI graph ideas", target_key, core.ai_run_graph_ideas, domain, paths, graph_data, selected_node_id or None, model or None)
        payload = {"job_id":job_id,"job_url":f"/api/jobs/{job_id}","refresh_url":f"/t/{target_key}/graph"}
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse(payload)
        return RedirectResponse(url=payload["refresh_url"], status_code=303)

    @app.post("/t/{target_key}/lead/{lead_id}/status")
    def graph_lead_status(request: Request, target_key: str, lead_id: int, status: str = Form(...), result_notes: str | None = Form(None), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        try:
            result = core.update_hypothesis(paths, lead_id, status=status, result_notes=result_notes.strip() if result_notes is not None else None)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse(result)
        return RedirectResponse(url=f"/t/{target_key}/graph", status_code=303)

    @app.get("/t/{target_key}/host/{host_id}", response_class=HTMLResponse)
    def host_detail(request: Request, target_key: str, host_id: int):
        import negro_intel as intel
        domain, workspace, paths = _target_context(target_key)
        detail = _host_detail(paths, host_id)
        if not detail:
            raise HTTPException(status_code=404, detail="Host no encontrado")
        return render(request, "host.html", target_key, domain, workspace, **detail, intel_settings=intel.load_settings(), secret_status=intel.secret_status(), dependency_status=intel.runtime_dependency_status())


    @app.get("/t/{target_key}/resource/{resource_id}", response_class=HTMLResponse)
    def resource_detail(request: Request, target_key: str, resource_id: int):
        domain, workspace, paths = _target_context(target_key)
        detail = _resource_detail(paths, resource_id)
        if not detail:
            raise HTTPException(status_code=404, detail="Recurso no encontrado")
        return render(request, "resource.html", target_key, domain, workspace, **detail)

    @app.post("/t/{target_key}/operation/{operation_id}/test")
    def operation_test_update(target_key: str, operation_id: int, test_key: str = Form(...), status: str = Form(...), notes: str = Form(""), csrf: str = Form(...)):
        import negro_hunter as hunter
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT o.id,o.resource_id FROM resource_operations o WHERE o.id=?", (operation_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Operación no encontrada")
            try:
                hunter.update_operation_test_coverage(conn, operation_id, test_key.strip(), status.strip(), notes.strip(), source="manual")
            except Exception as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            resource_id = int(row["resource_id"])
        return RedirectResponse(url=f"/t/{target_key}/resource/{resource_id}#operation-{operation_id}-coverage", status_code=303)

    @app.get("/t/{target_key}/findings", response_class=HTMLResponse)
    def findings(request: Request, target_key: str, status: str = "", severity: str = ""):
        domain, workspace, paths = _target_context(target_key)
        sql = "SELECT f.*, (SELECT COUNT(*) FROM finding_entities fe WHERE fe.finding_id=f.id) entity_count, (SELECT COUNT(*) FROM finding_retests fr WHERE fr.finding_id=f.id) retest_count FROM findings f WHERE 1=1"
        params = []
        if status:
            sql += " AND status=?"; params.append(status)
        if severity:
            sql += " AND severity=?"; params.append(severity)
        sql += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, updated_at DESC"
        with _db(paths) as conn:
            rows = conn.execute(sql, params).fetchall()
        return render(request, "findings.html", target_key, domain, workspace, findings=rows, finding_status=status, finding_severity=severity)

    @app.post("/t/{target_key}/findings/create")
    def finding_create(target_key: str, title: str = Form(...), severity: str = Form("info"), status: str = Form("draft"), description: str = Form(""), resource_id: int | None = Form(None), host_id: int | None = Form(None), exchange_id: int | None = Form(None), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            fid = _create_finding(conn, title=title, severity=severity, status=status, description=description, source="web")
            if resource_id:
                _link_finding(conn, fid, "resource", resource_id, "affected")
                conn.execute("UPDATE resources SET classification='finding', updated_at=? WHERE id=?", (_now(), resource_id))
            if host_id:
                _link_finding(conn, fid, "host", host_id, "affected")
                conn.execute("UPDATE hosts SET classification='finding', updated_at=? WHERE id=?", (_now(), host_id))
            if exchange_id:
                _link_finding(conn, fid, "exchange", exchange_id, "evidence")
        return RedirectResponse(url=f"/t/{target_key}/finding/{fid}", status_code=303)

    @app.get("/t/{target_key}/finding/{finding_id}", response_class=HTMLResponse)
    def finding_detail(request: Request, target_key: str, finding_id: int):
        domain, workspace, paths = _target_context(target_key)
        detail = _finding_detail(paths, finding_id)
        if not detail:
            raise HTTPException(status_code=404, detail="Finding no encontrado")
        return render(request, "finding.html", target_key, domain, workspace, **detail)

    @app.post("/t/{target_key}/finding/{finding_id}/update")
    def finding_update(target_key: str, finding_id: int, title: str = Form(...), severity: str = Form(...), status: str = Form(...), description: str = Form(""), impact: str = Form(""), remediation: str = Form(""), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            conn.execute("UPDATE findings SET title=?,severity=?,status=?,description=?,impact=?,remediation=?,updated_at=? WHERE id=?", (title.strip()[:240], severity, status, description.strip(), impact.strip(), remediation.strip(), _now(), finding_id))
        return RedirectResponse(url=f"/t/{target_key}/finding/{finding_id}", status_code=303)

    @app.post("/t/{target_key}/finding/{finding_id}/retest")
    def finding_retest(target_key: str, finding_id: int, result: str = Form(...), notes: str = Form(""), exchange_id: int | None = Form(None), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        if result not in {"still_vulnerable","fixed","fix_verified","inconclusive"}:
            raise HTTPException(status_code=400, detail="Resultado de retest inválido")
        now = _now()
        status_map = {"still_vulnerable":"retest_required", "fixed":"fixed", "fix_verified":"closed", "inconclusive":"retest_required"}
        with _db(paths) as conn:
            cur = conn.execute("INSERT INTO finding_retests(finding_id,result,notes,tested_at,created_at) VALUES(?,?,?,?,?)", (finding_id, result, notes.strip(), now, now))
            retest_id = int(cur.lastrowid)
            if exchange_id:
                conn.execute("INSERT OR IGNORE INTO finding_retest_entities(retest_id,entity_type,entity_id,relation,created_at) VALUES(?, 'exchange', ?, 'evidence', ?)", (retest_id, exchange_id, now))
            if result in status_map:
                conn.execute("UPDATE findings SET status=?,updated_at=? WHERE id=?", (status_map[result], now, finding_id))
        return RedirectResponse(url=f"/t/{target_key}/finding/{finding_id}#retests", status_code=303)


    @app.post("/t/{target_key}/finding/{finding_id}/note")
    def finding_note(target_key: str, finding_id: int, body: str = Form(...), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        body = body.strip()
        if body:
            with _db(paths) as conn:
                conn.execute("INSERT INTO notes(entity_type,entity_id,body,created_at) VALUES('finding',?,?,?)", (finding_id, body, _now()))
                conn.execute("UPDATE findings SET updated_at=? WHERE id=?", (_now(), finding_id))
        return RedirectResponse(url=f"/t/{target_key}/finding/{finding_id}#evidence", status_code=303)

    @app.post("/t/{target_key}/finding/{finding_id}/evidence")
    async def finding_evidence(target_key: str, finding_id: int, csrf: str = Form(...), caption: str = Form(""), evidence: UploadFile = File(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        allowed = {"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp", "image/gif": ".gif"}
        mime = (evidence.content_type or "").lower()
        if mime not in allowed:
            raise HTTPException(status_code=400, detail="La evidencia debe ser PNG, JPG, WEBP o GIF")
        data = await evidence.read()
        if not data or len(data) > 8 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="La evidencia debe pesar entre 1 byte y 8 MB")
        ev_dir = Path(paths["notes"]) / "evidence"
        ev_dir.mkdir(parents=True, exist_ok=True)
        stored = f"finding-{finding_id}-{uuid.uuid4().hex[:12]}{allowed[mime]}"
        dest = ev_dir / stored
        dest.write_bytes(data)
        with _db(paths) as conn:
            conn.execute("INSERT INTO evidence_attachments(entity_type,entity_id,kind,original_name,stored_path,mime_type,caption,created_at) VALUES('finding',?,?,?,?,?,?,?)", (finding_id, "image", (evidence.filename or stored)[:255], str(dest), mime, caption.strip()[:500], _now()))
            conn.execute("UPDATE findings SET updated_at=? WHERE id=?", (_now(), finding_id))
        return RedirectResponse(url=f"/t/{target_key}/finding/{finding_id}#evidence", status_code=303)

    @app.post("/t/{target_key}/finding/{finding_id}/entity")
    def finding_add_entity(target_key: str, finding_id: int, entity_type: str = Form(...), entity_id: int = Form(...), relation: str = Form("affected"), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        if entity_type not in {"resource","host","exchange","operation","js_asset","observation"}:
            raise HTTPException(status_code=400, detail="Tipo de entidad no permitido")
        with _db(paths) as conn:
            conn.execute("INSERT OR IGNORE INTO finding_entities(finding_id,entity_type,entity_id,relation,created_at) VALUES(?,?,?,?,?)", (finding_id, entity_type, entity_id, relation.strip()[:80] or "affected", _now()))
            conn.execute("UPDATE findings SET updated_at=? WHERE id=?", (_now(), finding_id))
        return RedirectResponse(url=f"/t/{target_key}/finding/{finding_id}#chain", status_code=303)

    @app.post("/t/{target_key}/resource/{resource_id}/finding-link")
    def resource_link_finding(target_key: str, resource_id: int, finding_id: int = Form(...), relation: str = Form("affected"), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            _link_finding(conn, finding_id, "resource", resource_id, relation.strip()[:80] or "affected")
            conn.execute("UPDATE resources SET classification='finding', updated_at=? WHERE id=?", (_now(), resource_id))
        return RedirectResponse(url=f"/t/{target_key}/resource/{resource_id}#findings", status_code=303)

    @app.post("/t/{target_key}/host/{host_id}/finding-link")
    def host_link_finding(target_key: str, host_id: int, finding_id: int = Form(...), relation: str = Form("affected"), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            _link_finding(conn, finding_id, "host", host_id, relation.strip()[:80] or "affected")
            conn.execute("UPDATE hosts SET classification='finding', updated_at=? WHERE id=?", (_now(), host_id))
        return RedirectResponse(url=f"/t/{target_key}/host/{host_id}#findings", status_code=303)

    @app.post("/t/{target_key}/host/{host_id}/state")
    def host_state(target_key: str, host_id: int, review_state: str = Form(...), classification: str = Form(...), priority: str = Form(...), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT hostname FROM hosts WHERE id=?", (host_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Host no encontrado")
        core.mark_entity(paths, "host", row["hostname"], review_state, classification, priority, None)
        if classification == "finding":
            with _db(paths) as conn:
                _ensure_finding_for_entity(conn, "host", host_id, f"Finding en {row['hostname']}")
        return RedirectResponse(url=f"/t/{target_key}/host/{host_id}", status_code=303)

    @app.post("/t/{target_key}/resource/{resource_id}/state")
    def resource_state(target_key: str, resource_id: int, review_state: str = Form(...), classification: str = Form(...), priority: str = Form(...), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT url, host_id FROM resources WHERE id=?", (resource_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Recurso no encontrado")
        core.mark_entity(paths, "resource", row["url"], review_state, classification, priority, None)
        if classification == "finding":
            with _db(paths) as conn:
                _ensure_finding_for_entity(conn, "resource", resource_id, f"Finding en {row['url']}")
        return RedirectResponse(url=f"/t/{target_key}/resource/{resource_id}", status_code=303)

    @app.post("/t/{target_key}/host/{host_id}/note")
    def host_note(target_key: str, host_id: int, body: str = Form(...), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        body = body.strip()
        with _db(paths) as conn:
            row = conn.execute("SELECT hostname FROM hosts WHERE id=?", (host_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Host no encontrado")
        if body:
            core.mark_entity(paths, "host", row["hostname"], None, None, None, body)
        return RedirectResponse(url=f"/t/{target_key}/host/{host_id}#notes", status_code=303)

    @app.post("/t/{target_key}/resource/{resource_id}/note")
    def resource_note(target_key: str, resource_id: int, body: str = Form(...), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        body = body.strip()
        with _db(paths) as conn:
            row = conn.execute("SELECT url, host_id FROM resources WHERE id=?", (resource_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Recurso no encontrado")
        if body:
            core.mark_entity(paths, "resource", row["url"], None, None, None, body)
        return RedirectResponse(url=f"/t/{target_key}/resource/{resource_id}", status_code=303)

    @app.post("/t/{target_key}/resource/{resource_id}/cors")
    def resource_cors(request: Request, target_key: str, resource_id: int, csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT host_id, path FROM resources WHERE id=?", (resource_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Recurso no encontrado")
        job_id = _start_job(f"CORS {row['path']}", target_key, core.cors_check_resource, domain, paths, resource_id, 20)
        refresh_url = f"/t/{target_key}/resource/{resource_id}"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id": job_id, "job_url": f"/api/jobs/{job_id}", "refresh_url": refresh_url})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.post("/t/{target_key}/resource/{resource_id}/evidence")
    async def resource_evidence(target_key: str, resource_id: int, csrf: str = Form(...), caption: str = Form(""), evidence: UploadFile = File(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT host_id FROM resources WHERE id=?", (resource_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Recurso no encontrado")
        allowed = {"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp", "image/gif": ".gif"}
        mime = (evidence.content_type or "").lower()
        if mime not in allowed:
            raise HTTPException(status_code=400, detail="La evidencia debe ser PNG, JPG, WEBP o GIF")
        data = await evidence.read()
        if not data or len(data) > 8 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="La evidencia debe pesar entre 1 byte y 8 MB")
        ev_dir = Path(paths["notes"]) / "evidence"
        ev_dir.mkdir(parents=True, exist_ok=True)
        stored = f"resource-{resource_id}-{uuid.uuid4().hex[:12]}{allowed[mime]}"
        dest = ev_dir / stored
        dest.write_bytes(data)
        with _db(paths) as conn:
            cur = conn.execute(
                "INSERT INTO evidence_attachments(entity_type,entity_id,kind,original_name,stored_path,mime_type,caption,created_at) VALUES('resource',?,?,?,?,?,?,?)",
                (resource_id, "image", (evidence.filename or stored)[:255], str(dest), mime, caption.strip()[:500], _now()),
            )
            conn.commit()
        return RedirectResponse(url=f"/t/{target_key}/resource/{resource_id}#evidence", status_code=303)

    @app.get("/t/{target_key}/evidence/{evidence_id}")
    def evidence_file(target_key: str, evidence_id: int):
        _, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT * FROM evidence_attachments WHERE id=?", (evidence_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Evidencia no encontrada")
        path = Path(row["stored_path"]).resolve()
        base = (Path(paths["notes"]) / "evidence").resolve()
        if base not in path.parents or not path.exists():
            raise HTTPException(status_code=404, detail="Archivo de evidencia no disponible")
        return FileResponse(path, media_type=row["mime_type"] or "application/octet-stream", filename=row["original_name"])

    @app.post("/t/{target_key}/resource/{resource_id}/send-repeater")
    def resource_send_repeater(request: Request, target_key: str, resource_id: int, method: str = Form("GET"), exchange_id: int = Form(0), csrf: str = Form(...)):
        """Queue an exact observed request for Burp Repeater when possible.

        Prefer a specific exchange (when the user clicked an exchange card), otherwise
        select the latest non-empty request for the requested operation.  If historical
        data has no raw request at all, enqueue a minimal but valid HTTP/1.1 request
        instead of allowing Burp to open a blank Repeater tab.
        """
        print(f"[repeater-ui] submit target={target_key} resource={resource_id} method={method} exchange={exchange_id or '-'}", flush=True)
        try:
            verify_csrf(csrf)
        except Exception as exc:
            print(f"[repeater-ui] csrf_failed target={target_key} resource={resource_id} error={type(exc).__name__}: {exc}", flush=True)
            raise
        _, _, paths = _target_context(target_key)
        method = (method or "GET").upper().strip()[:24]
        with _db(paths) as conn:
            row = conn.execute("SELECT id, url, host_id, path FROM resources WHERE id=?", (resource_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Recurso no encontrado")
            op = conn.execute("SELECT id FROM resource_operations WHERE resource_id=? AND method=?", (resource_id, method)).fetchone()
            request_b64 = None
            selected_exchange_id = 0
            request_size = 0
            if op and exchange_id:
                ex = conn.execute(
                    """SELECT id,request_b64,request_size FROM http_exchanges
                       WHERE id=? AND operation_id=? AND request_b64 IS NOT NULL
                         AND request_size>0 AND LENGTH(TRIM(request_b64))>0""",
                    (exchange_id, op["id"]),
                ).fetchone()
                if ex:
                    request_b64 = ex["request_b64"]
                    request_size = int(ex["request_size"] or 0)
                    selected_exchange_id = int(ex["id"])
            if op and not request_b64:
                ex = conn.execute(
                    """SELECT id,request_b64,request_size FROM http_exchanges
                       WHERE operation_id=? AND request_b64 IS NOT NULL
                         AND request_size>0 AND LENGTH(TRIM(request_b64))>0
                       ORDER BY last_seen_at DESC,id DESC LIMIT 1""",
                    (op["id"],),
                ).fetchone()
                if ex:
                    request_b64 = ex["request_b64"]
                    request_size = int(ex["request_size"] or 0)
                    selected_exchange_id = int(ex["id"])
            if not request_b64:
                parsed = urllib.parse.urlsplit(str(row["url"]))
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                host = parsed.hostname or ""
                if parsed.port and not ((parsed.scheme == "https" and parsed.port == 443) or (parsed.scheme == "http" and parsed.port == 80)):
                    host = f"{host}:{parsed.port}"
                raw = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\n\r\n".encode("iso-8859-1", errors="replace")
                request_b64 = base64.b64encode(raw).decode("ascii")
                request_size = len(raw)
            caption = f"Negro · {method} {row['path']}" + (f" · ex#{selected_exchange_id}" if selected_exchange_id else "")
            cur = conn.execute(
                "INSERT INTO burp_repeater_queue(resource_id, method, url, request_b64, caption, status, created_at) VALUES(?,?,?,?,?,'pending',?)",
                (resource_id, method, row["url"], request_b64, caption, _now()),
            )
            queue_id = int(cur.lastrowid)
            print(f"[repeater-queue] queued id={queue_id} target={target_key} resource={resource_id} method={method} exchange={selected_exchange_id or '-'} request_bytes={request_size}", flush=True)
        suffix = f"#exchange-{selected_exchange_id}" if selected_exchange_id else "#http"
        refresh_url = f"/t/{target_key}/resource/{resource_id}{suffix}"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({
                "ok": True,
                "queued": True,
                "queue_id": queue_id,
                "resource_id": resource_id,
                "exchange_id": selected_exchange_id or None,
                "request_bytes": request_size,
                "method": method,
                "refresh_url": refresh_url,
            })
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.post("/t/{target_key}/host/{host_id}/inspect")
    def host_inspect(request: Request, target_key: str, host_id: int, csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT hostname FROM hosts WHERE id=?", (host_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Host no encontrado")
        job_id = _start_job(f"inspect {row['hostname']}", target_key, core.inspect_host, domain, paths, row["hostname"], 30)
        refresh_url = f"/t/{target_key}/host/{host_id}"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id": job_id, "job_url": f"/api/jobs/{job_id}", "refresh_url": refresh_url})
        return RedirectResponse(url=f"{refresh_url}?inspection=started", status_code=303)

    @app.post("/t/{target_key}/host/{host_id}/tls-san")
    def host_tls_san(request: Request, target_key: str, host_id: int, csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT hostname FROM hosts WHERE id=?", (host_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Host no encontrado")
        job_id = _start_job(f"TLS SAN {row['hostname']}", target_key, core.tls_san_pivot, domain, paths, row["hostname"], 30)
        refresh_url = f"/t/{target_key}/host/{host_id}"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id": job_id, "job_url": f"/api/jobs/{job_id}", "refresh_url": refresh_url})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.post("/t/{target_key}/host/{host_id}/passive-dns")
    def host_passive_dns(request: Request, target_key: str, host_id: int, csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT hostname FROM hosts WHERE id=?", (host_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Host no encontrado")
        job_id = _start_job(f"Passive DNS {row['hostname']}", target_key, core.securitytrails_history_for_host, domain, paths, row["hostname"], 45)
        refresh_url = f"/t/{target_key}/host/{host_id}"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id": job_id, "job_url": f"/api/jobs/{job_id}", "refresh_url": refresh_url})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.post("/t/{target_key}/host/{host_id}/web-recon")
    def host_web_recon(request: Request, target_key: str, host_id: int, csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT hostname FROM hosts WHERE id=?", (host_id,)).fetchone()
        if not row: raise HTTPException(status_code=404, detail="Host no encontrado")
        job_id = _start_job(f"Web recon {row['hostname']}", target_key, core.web_recon_host, domain, paths, row["hostname"], 30)
        refresh_url = f"/t/{target_key}/host/{host_id}#observations"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id":job_id,"job_url":f"/api/jobs/{job_id}","refresh_url":refresh_url})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.post("/t/{target_key}/host/{host_id}/crawl")
    def host_crawl(request: Request, target_key: str, host_id: int, csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT hostname FROM hosts WHERE id=?", (host_id,)).fetchone()
        if not row: raise HTTPException(status_code=404, detail="Host no encontrado")
        job_id = _start_job(f"Crawl {row['hostname']}", target_key, core.crawl_host, domain, paths, row["hostname"], None, None, 45)
        refresh_url = f"/t/{target_key}/host/{host_id}#observations"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id":job_id,"job_url":f"/api/jobs/{job_id}","refresh_url":refresh_url})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.post("/t/{target_key}/host/{host_id}/cors")
    def host_cors(request: Request, target_key: str, host_id: int, csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT hostname FROM hosts WHERE id=?", (host_id,)).fetchone()
        if not row: raise HTTPException(status_code=404, detail="Host no encontrado")
        job_id = _start_job(f"CORS {row['hostname']}", target_key, core.cors_check_host, domain, paths, row["hostname"], None, 20)
        refresh_url = f"/t/{target_key}/host/{host_id}#observations"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id":job_id,"job_url":f"/api/jobs/{job_id}","refresh_url":refresh_url})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.post("/t/{target_key}/host/{host_id}/vhost")
    def host_vhost(request: Request, target_key: str, host_id: int, csrf: str = Form(...), base_url: str = Form("")):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT hostname FROM hosts WHERE id=?", (host_id,)).fetchone()
        if not row: raise HTTPException(status_code=404, detail="Host no encontrado")
        base_url = (base_url or "").strip() or f"https://{row['hostname']}/"
        try:
            parsed = urllib.parse.urlsplit(base_url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError
        except Exception:
            raise HTTPException(status_code=400, detail="Base URL VHost inválida. Usa http(s)://host[:puerto]/")
        job_id = _start_job(f"Smart VHost {row['hostname']}", target_key, core.vhost_smart, domain, paths, base_url, None)
        refresh_url = f"/t/{target_key}/host/{host_id}#observations"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id":job_id,"job_url":f"/api/jobs/{job_id}","refresh_url":refresh_url})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.post("/t/{target_key}/host/{host_id}/js-discover")
    def host_js_discover(request: Request, target_key: str, host_id: int, csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT hostname FROM hosts WHERE id=?", (host_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Host no encontrado")
        job_id = _start_job(f"JS discovery {row['hostname']}", target_key, core.discover_js_for_host, domain, paths, row["hostname"], 35)
        refresh_url = f"/t/{target_key}/host/{host_id}#javascript"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id": job_id, "job_url": f"/api/jobs/{job_id}", "refresh_url": refresh_url})
        return RedirectResponse(url=refresh_url, status_code=303)

    def _asset_context(target_key: str, asset_id: int):
        domain, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT j.*, h.id AS page_host_id FROM js_assets j JOIN hosts h ON h.id=j.host_id WHERE j.id=?", (asset_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="JS asset no encontrado")
        return domain, paths, row

    @app.post("/t/{target_key}/js/{asset_id}/local-analyze")
    def js_local_analyze(request: Request, target_key: str, asset_id: int, csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, paths, row = _asset_context(target_key, asset_id)
        job_id = _start_job(f"JS local #{asset_id}", target_key, core.local_analyze_js_asset, domain, paths, asset_id, 60)
        refresh_url = f"/t/{target_key}/host/{row['page_host_id']}#javascript"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id": job_id, "job_url": f"/api/jobs/{job_id}", "refresh_url": refresh_url})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.post("/t/{target_key}/js/{asset_id}/sourcemap")
    def js_sourcemap(request: Request, target_key: str, asset_id: int, csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, paths, row = _asset_context(target_key, asset_id)
        job_id = _start_job(f"Source map #{asset_id}", target_key, core.fetch_sourcemap_for_asset, domain, paths, asset_id, 75)
        refresh_url = f"/t/{target_key}/host/{row['page_host_id']}#javascript"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id": job_id, "job_url": f"/api/jobs/{job_id}", "refresh_url": refresh_url})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.get("/api/t/{target_key}/js/{asset_id}/ai-estimate", response_class=JSONResponse)
    def js_ai_estimate(target_key: str, asset_id: int, model: str = ""):
        _, paths, _ = _asset_context(target_key, asset_id)
        try:
            return core.ai_estimate_js_asset(paths, asset_id, model or None)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/t/{target_key}/js/{asset_id}/ai-run")
    def js_ai_run(request: Request, target_key: str, asset_id: int, model: str = Form(""), confirm_cost: str = Form(""), csrf: str = Form(...)):
        verify_csrf(csrf)
        if confirm_cost != "yes":
            raise HTTPException(status_code=400, detail="Debes estimar y confirmar el costo antes de enviar a IA")
        _, paths, row = _asset_context(target_key, asset_id)
        # Recompute estimate server-side immediately before creating the billable job.
        try:
            estimate = core.ai_estimate_js_asset(paths, asset_id, model or None)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        job_id = _start_job(f"AI JS #{asset_id} · {estimate['model']}", target_key, core.ai_run_js_asset, paths, asset_id, model or None)
        refresh_url = f"/t/{target_key}/host/{row['page_host_id']}#javascript"
        if request.headers.get("x-requested-with") == "NegroFetch" or "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"job_id": job_id, "job_url": f"/api/jobs/{job_id}", "refresh_url": refresh_url, "estimate": estimate})
        return RedirectResponse(url=refresh_url, status_code=303)

    @app.post("/t/{target_key}/scan")
    def scan(target_key: str, source: str = Form(...), csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        allowed = {"crtsh","subfinder","amass","gau_otx","gau_urlscan","gau_wayback","gau_commoncrawl","wayback_cdx","urlscan_direct","securitytrails","github_code"}
        if source not in allowed:
            raise HTTPException(status_code=400, detail="Fuente inválida")
        if source.startswith("gau_"):
            provider = source.removeprefix("gau_")
            _start_job(f"scan {source}", target_key, core.collect_gau_provider, provider, domain, paths, 900)
        elif source == "wayback_cdx":
            _start_job("Wayback CDX direct", target_key, core.collect_wayback_cdx, domain, paths, 120)
        elif source == "urlscan_direct":
            _start_job("URLScan direct", target_key, core.collect_urlscan_direct, domain, paths, 120)
        elif source == "securitytrails":
            _start_job("SecurityTrails subdomains", target_key, core.collect_securitytrails, domain, paths, 120)
        elif source == "github_code":
            _start_job("GitHub public code", target_key, core.collect_github_code, domain, paths, 120)
        else:
            timeout = 7200 if source == "amass" else 900
            _start_job(f"scan {source}", target_key, core.collect_source, source, domain, paths, timeout)
        return RedirectResponse(url=f"/t/{target_key}/?scan=started", status_code=303)

    def _matching_target_for_host(hostname: str):
        host = (hostname or "").strip().lower().rstrip(".")
        candidates = []
        for target in core.list_targets():
            for scope in target.get("scopes") or [target.get("domain")]:
                scope = str(scope or "").strip().lower().rstrip(".")
                if core.host_matches_scope(host, scope):
                    candidates.append((len(scope), target))
        if not candidates:
            return None
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]

    @app.get("/api/ingest/health", response_class=JSONResponse)
    def ingest_health():
        return {"ok": True, "version": core.VERSION, "targets": len(core.list_targets()), "mode": "auto-route"}

    @app.post("/api/ingest/http", response_class=JSONResponse)
    async def ingest_http(request: Request):
        try:
            raw_body = await request.body()
            payload = json.loads(raw_body.decode("utf-8"))
        except UnicodeDecodeError as exc:
            first_byte = raw_body[0] if raw_body else None
            raise HTTPException(status_code=400, detail=f"JSON inválido: UTF-8 en byte {exc.start}; body_len={len(raw_body)}; first_byte={first_byte}")
        except json.JSONDecodeError as exc:
            first_byte = raw_body[0] if raw_body else None
            raise HTTPException(status_code=400, detail=f"JSON inválido: {exc.msg} en posición {exc.pos}; body_len={len(raw_body)}; first_byte={first_byte}")
        except Exception:
            first_byte = raw_body[0] if 'raw_body' in locals() and raw_body else None
            body_len = len(raw_body) if 'raw_body' in locals() else -1
            raise HTTPException(status_code=400, detail=f"JSON inválido; body_len={body_len}; first_byte={first_byte}")
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="Payload inválido")
        url = str(payload.get("url") or "").strip()
        try:
            parsed = urllib.parse.urlsplit(url)
        except Exception:
            parsed = None
        if not parsed or parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise HTTPException(status_code=400, detail="url HTTP(S) requerida")
        target = _matching_target_for_host(parsed.hostname)
        if not target:
            return JSONResponse({"accepted": False, "reason": "host_out_of_scope", "host": parsed.hostname}, status_code=202)
        domain = str(target["domain"])
        target_key = str(target["key"])
        paths = core.ensure_workspace(Path(str(target["workspace"])).expanduser(), domain, scopes=target.get("scopes"), project_name=target.get("name"))
        tool = str(payload.get("tool") or "OTHER").upper()
        source = "burp_proxy" if tool == "PROXY" else ("burp_repeater" if tool == "REPEATER" else "burp_other")
        try:
            result = core.upsert_http_observation(
                paths, domain,
                url=url,
                method=str(payload.get("method") or "GET"),
                source=source,
                status_code=int(payload["status_code"]) if payload.get("status_code") is not None else None,
                authenticated=bool(payload.get("authenticated")),
                request_content_type=str(payload.get("request_content_type") or "") or None,
                response_content_type=str(payload.get("response_content_type") or "") or None,
                tool=tool,
                request_b64=payload.get("request_b64"),
                response_b64=payload.get("response_b64"),
                request_headers=payload.get("request_headers") if isinstance(payload.get("request_headers"), list) else None,
                response_headers=payload.get("response_headers") if isinstance(payload.get("response_headers"), list) else None,
                query=payload.get("query"),
                response_body_b64=payload.get("response_body_b64"),
            )
        except ValueError as exc:
            return JSONResponse({"accepted": False, "reason": str(exc)}, status_code=202)
        # Passive Burp intelligence: inspect only the traffic already captured. This
        # never sends a network request and stores only masked secret values.
        passive = {"signals": [], "new_notifications": []}
        try:
            import negro_hunter as hunter
            with _db(paths) as conn:
                passive = hunter.analyze_http_exchange(conn, int(result["exchange_id"]), domain, emit_notifications=True)
        except Exception as exc:
            print(f"[burp-intel] exchange={result.get('exchange_id')} error={type(exc).__name__}: {str(exc)[:180]}")
        return {"accepted": True, "target_key": target_key, "target_domain": domain, "project_name": target.get("name") or domain, **result,
                "signal_count": len(passive.get("signals") or []),
                "new_notification_count": len(passive.get("new_notifications") or [])}

    @app.get("/api/bridge/findings/{target_key}", response_class=JSONResponse)
    def bridge_findings(target_key: str):
        _, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            rows = conn.execute("SELECT id,title,severity,status,updated_at FROM findings ORDER BY updated_at DESC,id DESC LIMIT 200").fetchall()
        return {"target_key": target_key, "findings": [dict(r) for r in rows]}

    @app.post("/api/bridge/action", response_class=JSONResponse)
    async def bridge_action(request: Request):
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="JSON inválido")
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="Payload inválido")
        target_key = str(payload.get("target_key") or "").strip()
        action = str(payload.get("action") or "").strip()
        if action not in {"open","interesting","create_finding","attach_finding","retest"}:
            raise HTTPException(status_code=400, detail="Acción Burp inválida")
        _, _, paths = _target_context(target_key)
        resource_id = int(payload.get("resource_id") or 0)
        operation_id = int(payload.get("operation_id") or 0)
        exchange_id = int(payload.get("exchange_id") or 0)
        with _db(paths) as conn:
            if exchange_id and (not resource_id or not operation_id):
                rr = conn.execute("SELECT o.id operation_id,o.resource_id FROM http_exchanges e JOIN resource_operations o ON o.id=e.operation_id WHERE e.id=?", (exchange_id,)).fetchone()
                if rr:
                    operation_id = int(rr["operation_id"]); resource_id = int(rr["resource_id"])
            resource = conn.execute("SELECT r.*,h.hostname FROM resources r JOIN hosts h ON h.id=r.host_id WHERE r.id=?", (resource_id,)).fetchone() if resource_id else None
            if not resource:
                raise HTTPException(status_code=404, detail="Resource del tráfico no encontrado en Negro")
            operation = conn.execute("SELECT * FROM resource_operations WHERE id=? AND resource_id=?", (operation_id, resource_id)).fetchone() if operation_id else None
            if exchange_id:
                ex = conn.execute("SELECT id FROM http_exchanges WHERE id=? AND operation_id=?", (exchange_id, operation_id)).fetchone()
                if not ex:
                    raise HTTPException(status_code=404, detail="Exchange no encontrado")
            web_path = f"/t/{target_key}/resource/{resource_id}"
            if action == "open":
                return {"ok": True, "action": action, "web_path": web_path}
            if action == "interesting":
                conn.execute("UPDATE resources SET classification=CASE WHEN classification='finding' THEN classification ELSE 'lead' END, review_state=CASE WHEN review_state='pending' THEN 'in_progress' ELSE review_state END, updated_at=? WHERE id=?", (_now(), resource_id))
                if exchange_id:
                    conn.execute("INSERT INTO notes(entity_type,entity_id,body,created_at) VALUES('resource',?,?,?)", (resource_id, f"Marcado Interesting desde Burp · exchange #{exchange_id}", _now()))
                return {"ok": True, "action": action, "target_key": target_key, "resource_id": resource_id, "web_path": web_path}
            if action == "create_finding":
                default_title = f"{operation['method'] if operation else 'HTTP'} {resource['path']}"
                fid = _create_finding(conn, title=str(payload.get("title") or default_title), severity=str(payload.get("severity") or "info"), status="confirmed", description=str(payload.get("description") or ""), source="burp_context")
                _link_finding(conn, fid, "resource", resource_id, "affected")
                if operation_id: _link_finding(conn, fid, "operation", operation_id, "affected_operation")
                if exchange_id: _link_finding(conn, fid, "exchange", exchange_id, "evidence")
                conn.execute("UPDATE resources SET classification='finding', review_state=CASE WHEN review_state='pending' THEN 'in_progress' ELSE review_state END, updated_at=? WHERE id=?", (_now(), resource_id))
                return {"ok": True, "action": action, "finding_id": fid, "web_path": f"/t/{target_key}/finding/{fid}"}
            finding_id = int(payload.get("finding_id") or 0)
            finding = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone() if finding_id else None
            if not finding:
                raise HTTPException(status_code=404, detail="Finding no encontrado")
            if action == "attach_finding":
                _link_finding(conn, finding_id, "resource", resource_id, "affected")
                if operation_id: _link_finding(conn, finding_id, "operation", operation_id, "affected_operation")
                if exchange_id: _link_finding(conn, finding_id, "exchange", exchange_id, "evidence")
                conn.execute("UPDATE resources SET classification='finding', updated_at=? WHERE id=?", (_now(), resource_id))
                return {"ok": True, "action": action, "finding_id": finding_id, "web_path": f"/t/{target_key}/finding/{finding_id}"}
            result = str(payload.get("result") or "inconclusive")
            if result not in {"still_vulnerable","fixed","fix_verified","inconclusive"}:
                raise HTTPException(status_code=400, detail="Resultado de retest inválido")
            now = _now()
            cur = conn.execute("INSERT INTO finding_retests(finding_id,result,notes,tested_at,created_at) VALUES(?,?,?,?,?)", (finding_id, result, str(payload.get("notes") or "").strip(), now, now))
            retest_id = int(cur.lastrowid)
            if exchange_id:
                conn.execute("INSERT OR IGNORE INTO finding_retest_entities(retest_id,entity_type,entity_id,relation,created_at) VALUES(?, 'exchange', ?, 'evidence', ?)", (retest_id, exchange_id, now))
            status_map = {"still_vulnerable":"retest_required","fixed":"fixed","fix_verified":"closed","inconclusive":"retest_required"}
            conn.execute("UPDATE findings SET status=?,updated_at=? WHERE id=?", (status_map[result], now, finding_id))
            return {"ok": True, "action": action, "finding_id": finding_id, "retest_id": retest_id, "web_path": f"/t/{target_key}/finding/{finding_id}#retests"}

    def _bridge_workspace_paths(target: dict[str, Any]) -> tuple[str, str, dict[str, Path]] | None:
        """Return already-initialized workspace paths without migrations.

        Bridge polling runs every second. Calling ensure_workspace() here would
        re-run schema checks + legacy inventory migration for every target, which
        is catastrophically expensive on large workspaces (thousands of resources).
        """
        try:
            domain = str(target["domain"])
            target_key = str(target["key"])
            workspace = Path(str(target["workspace"])).expanduser()
            paths = core.workspace_paths(workspace)
            if not paths["db_file"].exists():
                return None
            return target_key, domain, paths
        except Exception:
            return None

    def _bridge_cleanup_stale_claims() -> int:
        global REPEATER_LAST_CLEANUP_TS
        now_ts = datetime.now(timezone.utc).timestamp()
        if now_ts - REPEATER_LAST_CLEANUP_TS < REPEATER_CLEANUP_INTERVAL_SECONDS:
            return 0
        if not REPEATER_CLEANUP_LOCK.acquire(blocking=False):
            return 0
        try:
            # Re-check after taking the lock in case another request just cleaned.
            now_ts = datetime.now(timezone.utc).timestamp()
            if now_ts - REPEATER_LAST_CLEANUP_TS < REPEATER_CLEANUP_INTERVAL_SECONDS:
                return 0
            REPEATER_LAST_CLEANUP_TS = now_ts
            cutoff = now_ts - 30
            recovered = 0
            for target in core.list_targets():
                info = _bridge_workspace_paths(target)
                if not info:
                    continue
                _, _, paths = info
                try:
                    with _db(paths) as conn:
                        rows = conn.execute("SELECT id, claimed_at FROM burp_repeater_queue WHERE status='claimed' AND finished_at IS NULL").fetchall()
                        for stale in rows:
                            try:
                                claimed = datetime.fromisoformat(str(stale["claimed_at"] or ""))
                                if claimed.tzinfo is None:
                                    claimed = claimed.replace(tzinfo=timezone.utc)
                                if claimed.timestamp() <= cutoff:
                                    conn.execute("UPDATE burp_repeater_queue SET status='error', finished_at=?, error=? WHERE id=? AND status='claimed'", (_now(), "claim_timeout_no_ack", stale["id"]))
                                    recovered += 1
                            except Exception:
                                continue
                except Exception as exc:
                    print(f"[repeater-next] cleanup target error: {exc}", flush=True)
            return recovered
        finally:
            REPEATER_CLEANUP_LOCK.release()


    def _bridge_consumer_allowed(bridge_id: str) -> tuple[bool, str | None]:
        global REPEATER_ACTIVE_BRIDGE_ID, REPEATER_ACTIVE_BRIDGE_LAST_SEEN
        now_ts = datetime.now(timezone.utc).timestamp()
        with REPEATER_BRIDGE_LOCK:
            active = REPEATER_ACTIVE_BRIDGE_ID
            stale = (now_ts - REPEATER_ACTIVE_BRIDGE_LAST_SEEN) > REPEATER_BRIDGE_LEASE_SECONDS
            if not active or active == bridge_id or stale:
                REPEATER_ACTIVE_BRIDGE_ID = bridge_id
                REPEATER_ACTIVE_BRIDGE_LAST_SEEN = now_ts
                return True, None
            return False, active

    @app.get("/api/bridge/repeater/status", response_class=JSONResponse)
    def bridge_repeater_status():
        totals = {"pending": 0, "claimed": 0, "done": 0, "error": 0}
        latest = []
        for target in core.list_targets():
            try:
                info = _bridge_workspace_paths(target)
                if not info:
                    continue
                _, domain, paths = info
                with _db(paths) as conn:
                    for row in conn.execute("SELECT status, COUNT(*) AS n FROM burp_repeater_queue GROUP BY status").fetchall():
                        st = str(row["status"] or "")
                        if st in totals: totals[st] += int(row["n"] or 0)
                    row = conn.execute("SELECT id,status,method,url,created_at,claimed_at,finished_at,error FROM burp_repeater_queue ORDER BY id DESC LIMIT 1").fetchone()
                    if row:
                        latest.append({"target_key": str(target["key"]), "domain": domain, **dict(row)})
            except Exception:
                continue
        latest.sort(key=lambda x: int(x.get("id") or 0), reverse=True)
        now_ts = datetime.now(timezone.utc).timestamp()
        with REPEATER_BRIDGE_LOCK:
            active = REPEATER_ACTIVE_BRIDGE_ID
            last_seen = REPEATER_ACTIVE_BRIDGE_LAST_SEEN
        bridge = {
            "active": bool(active and (now_ts - last_seen) <= REPEATER_BRIDGE_LEASE_SECONDS),
            "instance": str(active or "")[:8] or None,
            "last_seen_seconds_ago": round(max(0.0, now_ts - last_seen), 2) if active else None,
        }
        return {"ok": True, "version": core.VERSION, "counts": totals, "bridge": bridge, "latest": latest[:10]}

    @app.get("/api/bridge/repeater/next", response_class=JSONResponse)
    def bridge_repeater_next(request: Request):
        bridge_id = str(request.headers.get("x-negro-bridge-id") or "").strip()
        bridge_version = str(request.headers.get("x-negro-bridge-version") or "").strip()
        if not bridge_id:
            # Legacy/orphan bridge pollers must never consume queue items.
            return JSONResponse(
                status_code=428,
                content={"pending": False, "error": "bridge_id_required", "required_version": "0.16.7"},
            )
        allowed, active_id = _bridge_consumer_allowed(bridge_id)
        if not allowed:
            return {"pending": False, "busy": True, "active_bridge": str(active_id or "")[:8]}

        # IMPORTANT: this endpoint is polled every second by Burp. It must never
        # initialize/migrate workspaces. Large targets can contain thousands of
        # resources and re-running migrations here caused >3s requests, Java
        # timeouts and FastAPI CancelledError/500 responses.
        import time
        started = time.perf_counter()
        targets = core.list_targets()
        recovered = _bridge_cleanup_stale_claims()
        if recovered:
            print(f"[repeater-queue] expired_stale_claims={recovered}", flush=True)

        pending: list[tuple[str, str, str, dict[str, Path], dict[str, Any]]] = []
        scanned = 0
        for target in targets:
            info = _bridge_workspace_paths(target)
            if not info:
                continue
            target_key, domain, paths = info
            scanned += 1
            try:
                with _db(paths) as conn:
                    row = conn.execute("SELECT * FROM burp_repeater_queue WHERE status='pending' ORDER BY created_at, id LIMIT 1").fetchone()
                    if row:
                        pending.append((str(row["created_at"] or ""), target_key, domain, paths, dict(row)))
            except Exception as exc:
                print(f"[repeater-next] scan target={target_key} error={exc}", flush=True)

        if not pending:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            # Keep normal polling quiet unless it becomes unexpectedly slow.
            if elapsed_ms >= 500:
                print(f"[repeater-next] empty targets={scanned} elapsed_ms={elapsed_ms}", flush=True)
            return {"pending": False, "scan_ms": elapsed_ms}

        pending.sort(key=lambda x: (x[0], int(x[4].get("id") or 0)))
        _, target_key, domain, paths, item = pending[0]
        try:
            with _db(paths) as conn:
                cur = conn.execute(
                    "UPDATE burp_repeater_queue SET status='claimed', claimed_at=? WHERE id=? AND status='pending'",
                    (_now(), item["id"]),
                )
                if cur.rowcount != 1:
                    return {"pending": False}
                row = conn.execute("SELECT * FROM burp_repeater_queue WHERE id=?", (item["id"],)).fetchone()
                if not row or row["status"] != "claimed":
                    return {"pending": False}
                item = dict(row)
        except Exception as exc:
            print(f"[repeater-next] claim id={item.get('id')} error={exc}", flush=True)
            return JSONResponse(status_code=500, content={"pending": False, "error": "queue_claim_failed"})

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        print(
            f"[repeater-next] claimed id={item.get('id')} target={target_key} bridge={bridge_id[:8]} v={bridge_version or '?'} "
            f"bytes_b64={len(str(item.get('request_b64') or ''))} elapsed_ms={elapsed_ms}",
            flush=True,
        )
        return {"pending": True, "target_key": target_key, "domain": domain, "scan_ms": elapsed_ms, **item}

    @app.post("/api/bridge/repeater/{target_key}/{queue_id}/ack", response_class=JSONResponse)
    async def bridge_repeater_ack(target_key: str, queue_id: int, request: Request):
        _, _, paths = _target_context(target_key)
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        ok = bool(payload.get("ok")) if isinstance(payload, dict) else False
        error = str(payload.get("error") or "")[:1000] if isinstance(payload, dict) else ""
        with _db(paths) as conn:
            conn.execute("UPDATE burp_repeater_queue SET status=?, finished_at=?, error=? WHERE id=?", ("done" if ok else "error", _now(), error or None, queue_id))
        return {"ok": True}

    @app.get("/api/t/{target_key}/jobs", response_class=JSONResponse)
    def jobs_api(target_key: str):
        if not core.get_target(target_key):
            raise HTTPException(status_code=404, detail="Target no encontrado")
        with JOBS_LOCK:
            jobs = [j for j in JOBS.values() if j.get("target_key") == target_key][-20:][::-1]
        return {"jobs": jobs}

    @app.get("/api/jobs/{job_id}", response_class=JSONResponse)
    def job_api(job_id: str):
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                raise HTTPException(status_code=404, detail="Job no encontrado")
            return dict(job)

    @app.get("/api/t/{target_key}/summary", response_class=JSONResponse)
    def summary_api(target_key: str):
        _, _, paths = _target_context(target_key)
        return _dashboard_data(paths)["stats"]

    return app


def run_web(domain: str, workspace: Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise SystemExit("[!] Uvicorn no está instalado. Ejecuta ./install-web.sh") from exc

    app = create_app(domain, workspace)
    print(f"[+] Negro Web — multi-target · inicial: {domain}")
    print(f"[+] Workspace inicial: {workspace}")
    print(f"[+] Abre: http://{host if host != '0.0.0.0' else '127.0.0.1'}:{port}")
    print("[i] La UI no tiene autenticación; por defecto sólo escucha en localhost.")
    uvicorn.run(app, host=host, port=port, log_level="info")
