#!/usr/bin/env python3
"""Local web workspace for Negro Recon v0.10.

v0.8 adds a multi-target web workspace while keeping every target isolated in its
own existing Negro workspace/SQLite database. The UI stays local-first and calls
the same core functions used by the CLI.
"""
from __future__ import annotations

import json
import re
import secrets
import threading
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
import urllib.parse
from typing import Any
from urllib.parse import urlsplit

import negro_core as core

try:
    from fastapi import FastAPI, Form, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    _WEB_IMPORT_ERROR = None
except ImportError as exc:  # CLI remains usable without web dependencies
    FastAPI = Form = HTTPException = Request = None  # type: ignore
    HTMLResponse = JSONResponse = RedirectResponse = StaticFiles = Jinja2Templates = None  # type: ignore
    _WEB_IMPORT_ERROR = exc

JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()
JOB_MAX_CONCURRENCY = 3
JOB_SLOTS = threading.Semaphore(JOB_MAX_CONCURRENCY)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


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


def _target_context(target_key: str) -> tuple[str, Path, dict[str, Path]]:
    target = core.get_target(target_key)
    if not target:
        raise HTTPException(status_code=404, detail="Target no encontrado")
    domain = str(target.get("domain", "")).strip().lower().rstrip(".")
    workspace = Path(str(target.get("workspace", ""))).expanduser()
    if not domain or not workspace:
        raise HTTPException(status_code=500, detail="Target mal configurado")
    paths = core.ensure_workspace(workspace, domain)
    return domain, workspace, paths


def _dashboard_data(paths: dict[str, Path]) -> dict[str, Any]:
    with _db(paths) as conn:
        stats = {
            "hosts": conn.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"],
            "resources": conn.execute("SELECT COUNT(*) c FROM resources").fetchone()["c"],
            "pending": conn.execute("SELECT COUNT(*) c FROM hosts WHERE review_state='pending'").fetchone()["c"]
                       + conn.execute("SELECT COUNT(*) c FROM resources WHERE review_state='pending'").fetchone()["c"],
            "in_progress": conn.execute("SELECT COUNT(*) c FROM hosts WHERE review_state='in_progress'").fetchone()["c"]
                           + conn.execute("SELECT COUNT(*) c FROM resources WHERE review_state='in_progress'").fetchone()["c"],
            "reviewed": conn.execute("SELECT COUNT(*) c FROM hosts WHERE review_state='reviewed'").fetchone()["c"]
                        + conn.execute("SELECT COUNT(*) c FROM resources WHERE review_state='reviewed'").fetchone()["c"],
            "leads": conn.execute("SELECT COUNT(*) c FROM hosts WHERE classification='lead'").fetchone()["c"]
                    + conn.execute("SELECT COUNT(*) c FROM resources WHERE classification='lead'").fetchone()["c"],
            "findings": conn.execute("SELECT COUNT(*) c FROM hosts WHERE classification='finding'").fetchone()["c"]
                       + conn.execute("SELECT COUNT(*) c FROM resources WHERE classification='finding'").fetchone()["c"],
            "discarded": conn.execute("SELECT COUNT(*) c FROM hosts WHERE classification='discarded'").fetchone()["c"]
                        + conn.execute("SELECT COUNT(*) c FROM resources WHERE classification='discarded'").fetchone()["c"],
            "informational": conn.execute("SELECT COUNT(*) c FROM hosts WHERE classification='informational'").fetchone()["c"]
                            + conn.execute("SELECT COUNT(*) c FROM resources WHERE classification='informational'").fetchone()["c"],
            "operations": conn.execute("SELECT COUNT(*) c FROM resource_operations").fetchone()["c"],
            "http_exchanges": conn.execute("SELECT COUNT(*) c FROM http_exchanges").fetchone()["c"],
        }
        priority = conn.execute(
            """
            SELECT * FROM hosts
            WHERE priority='high' OR classification IN ('lead','finding')
            ORDER BY CASE classification WHEN 'finding' THEN 0 WHEN 'lead' THEN 1 ELSE 2 END,
                     CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                     updated_at DESC
            LIMIT 12
            """
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
            paths = core.ensure_workspace(Path(str(target["workspace"])).expanduser(), domain)
            with _db(paths) as conn:
                item["hosts"] = conn.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"]
                item["resources"] = conn.execute("SELECT COUNT(*) c FROM resources").fetchone()["c"]
                item["leads"] = conn.execute("SELECT COUNT(*) c FROM hosts WHERE classification='lead'").fetchone()["c"] + conn.execute("SELECT COUNT(*) c FROM resources WHERE classification='lead'").fetchone()["c"]
                item["findings"] = conn.execute("SELECT COUNT(*) c FROM hosts WHERE classification='finding'").fetchone()["c"] + conn.execute("SELECT COUNT(*) c FROM resources WHERE classification='finding'").fetchone()["c"]
        except BaseException as exc:
            item["error"] = str(exc)[:180]
        cards.append(item)
    return cards


def _host_rows(paths: dict[str, Path], q: str = "", review: str = "", classification: str = "", priority: str = "", limit: int = 500):
    sql = """
        SELECT h.*, COUNT(r.id) AS resource_count,
               (SELECT COUNT(*) FROM host_inspections i WHERE i.host_id=h.id) AS inspection_count
        FROM hosts h LEFT JOIN resources r ON r.host_id=h.id
        WHERE 1=1
    """
    params: list[Any] = []
    if q:
        sql += " AND lower(h.hostname) LIKE ?"
        params.append(f"%{q.lower()}%")
    if review:
        sql += " AND h.review_state=?"
        params.append(review)
    if classification:
        sql += " AND h.classification=?"
        params.append(classification)
    if priority:
        sql += " AND h.priority=?"
        params.append(priority)
    sql += " GROUP BY h.id ORDER BY CASE h.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, h.hostname LIMIT ?"
    params.append(max(1, min(limit, 2000)))
    with _db(paths) as conn:
        return conn.execute(sql, params).fetchall()


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
            resource_data.append({
                "row": r,
                "sources": _sources(conn, "resource", r["id"]),
                "notes": _notes(conn, "resource", r["id"]),
                "open_url": _external_url(r["url"]),
                "operations": op_data,
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


def create_app(default_domain: str, default_workspace: Path):
    if _WEB_IMPORT_ERROR is not None:
        raise RuntimeError("Faltan dependencias web. Ejecuta ./install-web.sh o instala requirements.txt") from _WEB_IMPORT_ERROR

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
            "targets": core.list_targets(),
            "version": core.VERSION,
            "review_states": core.REVIEW_STATES,
            "classifications": core.CLASSIFICATIONS,
            "priorities": core.PRIORITIES,
            "csrf_token": csrf_token,
        }
        return templates.TemplateResponse(request=request, name=name, context={**base_context, **ctx})

    def verify_csrf(value: str) -> None:
        if not secrets.compare_digest(value or "", csrf_token):
            raise HTTPException(status_code=403, detail="CSRF token inválido")

    @app.get("/")
    def root_redirect():
        data = core.targets_load()
        key = data.get("last_target") or default_key
        if not core.get_target(str(key)):
            key = default_key
        return RedirectResponse(url=f"/t/{key}/", status_code=307)

    @app.post("/targets/create")
    def target_create(request: Request, domain: str = Form(...), workspace: str = Form(""), csrf: str = Form(...)):
        verify_csrf(csrf)
        domain = domain.strip().lower().rstrip(".")
        if domain.startswith("http://") or domain.startswith("https://") or not DOMAIN_RE.fullmatch(domain):
            return templates.TemplateResponse(request=request, name="target_error.html", status_code=400, context={"message":"Usa sólo el dominio, por ejemplo example.com", "version":core.VERSION})
        target_workspace = Path(workspace).expanduser() if workspace.strip() else core.suggested_workspace(domain)
        try:
            core.ensure_workspace(target_workspace, domain)
            key = core.register_target(domain, target_workspace, make_current=True)
        except Exception as exc:
            print(f"[!] No pude crear target {domain}: {exc}")
            return templates.TemplateResponse(request=request, name="target_error.html", status_code=400, context={"message":str(exc), "workspace":str(target_workspace), "version":core.VERSION})
        return RedirectResponse(url=f"/t/{key}/", status_code=303)

    @app.get("/t/{target_key}/settings", response_class=HTMLResponse)
    def settings_page(request: Request, target_key: str):
        import negro_intel as intel
        domain, workspace, _ = _target_context(target_key)
        return render(request, "settings.html", target_key, domain, workspace, settings=intel.load_settings(), secret_status=intel.secret_status(), secrets_path=str(intel.SECRETS_PATH))

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
        values = intel.save_settings({"ai_model":ai_model, "ai_output_tokens":ai_output_tokens, "usd_cop_rate":usd_cop_rate, "usd_cop_rate_date":datetime.now().date().isoformat()})
        return render(request, "settings.html", target_key, domain, workspace, settings=values, secret_status=intel.secret_status(), secrets_path=str(intel.SECRETS_PATH), saved=True)

    @app.get("/t/{target_key}/", response_class=HTMLResponse)
    def dashboard(request: Request, target_key: str):
        domain, workspace, paths = _target_context(target_key)
        core.set_current_target(target_key)
        data = _dashboard_data(paths)
        with JOBS_LOCK:
            jobs = [j for j in JOBS.values() if j.get("target_key") == target_key][-8:][::-1]
        return render(request, "dashboard.html", target_key, domain, workspace, **data, jobs=jobs, target_cards=_target_cards())

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
    def hosts(request: Request, target_key: str, q: str = "", review: str = "", classification: str = "", priority: str = ""):
        domain, workspace, paths = _target_context(target_key)
        rows = _host_rows(paths, q, review, classification, priority)
        return render(request, "hosts.html", target_key, domain, workspace, hosts=rows, q=q, review=review, classification=classification, priority=priority)

    @app.get("/t/{target_key}/tree", response_class=HTMLResponse)
    def tree(request: Request, target_key: str, q: str = "", review: str = "", classification: str = "", priority: str = ""):
        domain, workspace, paths = _target_context(target_key)
        data = _tree_data(paths, q, review, classification, priority)
        return render(request, "tree.html", target_key, domain, workspace, tree=data, q=q, review=review, classification=classification, priority=priority)

    @app.get("/t/{target_key}/host/{host_id}", response_class=HTMLResponse)
    def host_detail(request: Request, target_key: str, host_id: int):
        import negro_intel as intel
        domain, workspace, paths = _target_context(target_key)
        detail = _host_detail(paths, host_id)
        if not detail:
            raise HTTPException(status_code=404, detail="Host no encontrado")
        return render(request, "host.html", target_key, domain, workspace, **detail, intel_settings=intel.load_settings(), secret_status=intel.secret_status(), dependency_status=intel.runtime_dependency_status())

    @app.post("/t/{target_key}/host/{host_id}/state")
    def host_state(target_key: str, host_id: int, review_state: str = Form(...), classification: str = Form(...), priority: str = Form(...), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        with _db(paths) as conn:
            row = conn.execute("SELECT hostname FROM hosts WHERE id=?", (host_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Host no encontrado")
        core.mark_entity(paths, "host", row["hostname"], review_state, classification, priority, None)
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
        return RedirectResponse(url=f"/t/{target_key}/host/{row['host_id']}#resources", status_code=303)

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
        return RedirectResponse(url=f"/t/{target_key}/host/{row['host_id']}#resources", status_code=303)

    @app.post("/t/{target_key}/resource/{resource_id}/send-repeater")
    def resource_send_repeater(target_key: str, resource_id: int, method: str = Form("GET"), csrf: str = Form(...)):
        verify_csrf(csrf)
        _, _, paths = _target_context(target_key)
        method = (method or "GET").upper().strip()[:24]
        with _db(paths) as conn:
            row = conn.execute("SELECT id, url, host_id, path FROM resources WHERE id=?", (resource_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Recurso no encontrado")
            op = conn.execute("SELECT id FROM resource_operations WHERE resource_id=? AND method=?", (resource_id, method)).fetchone()
            request_b64 = None
            if op:
                ex = conn.execute("SELECT request_b64 FROM http_exchanges WHERE operation_id=? AND request_b64 IS NOT NULL ORDER BY last_seen_at DESC LIMIT 1", (op["id"],)).fetchone()
                if ex:
                    request_b64 = ex["request_b64"]
            caption = f"Negro · {method} {row['path']}"
            conn.execute("INSERT INTO burp_repeater_queue(resource_id, method, url, request_b64, caption, status, created_at) VALUES(?,?,?,?,?,'pending',?)", (resource_id, method, row["url"], request_b64, caption, _now()))
        return RedirectResponse(url=f"/t/{target_key}/host/{row['host_id']}#resources", status_code=303)

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
            domain = str(target.get("domain", "")).strip().lower().rstrip(".")
            if host == domain or host.endswith("." + domain):
                candidates.append((len(domain), target))
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
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="JSON inválido")
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
        paths = core.ensure_workspace(Path(str(target["workspace"])).expanduser(), domain)
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
        return {"accepted": True, "target_key": target_key, "target_domain": domain, **result}

    @app.get("/api/bridge/repeater/next", response_class=JSONResponse)
    def bridge_repeater_next():
        pending = []
        for target in core.list_targets():
            try:
                domain = str(target["domain"])
                paths = core.ensure_workspace(Path(str(target["workspace"])).expanduser(), domain)
                with _db(paths) as conn:
                    row = conn.execute("SELECT * FROM burp_repeater_queue WHERE status='pending' ORDER BY created_at, id LIMIT 1").fetchone()
                    if row:
                        pending.append((row["created_at"], str(target["key"]), domain, paths, dict(row)))
            except Exception:
                continue
        if not pending:
            return {"pending": False}
        pending.sort(key=lambda x: x[0])
        _, target_key, domain, paths, item = pending[0]
        with _db(paths) as conn:
            conn.execute("UPDATE burp_repeater_queue SET status='claimed', claimed_at=? WHERE id=? AND status='pending'", (_now(), item["id"]))
            row = conn.execute("SELECT * FROM burp_repeater_queue WHERE id=?", (item["id"],)).fetchone()
            if not row or row["status"] != "claimed":
                return {"pending": False}
            item = dict(row)
        return {"pending": True, "target_key": target_key, "domain": domain, **item}

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
