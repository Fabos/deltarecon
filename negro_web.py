#!/usr/bin/env python3
"""Local web workspace for Negro Recon v0.6.

v0.6 adds a multi-target web workspace while keeping every target isolated in its
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
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _set_job(job_id: str, **values: Any) -> None:
    with JOBS_LOCK:
        if job_id in JOBS:
            JOBS[job_id].update(values)


def _start_job(label: str, target_key: str, fn, *args, **kwargs) -> str:
    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id,
            "target_key": target_key,
            "label": label,
            "status": "running",
            "started_at": _now(),
            "finished_at": None,
            "error": None,
        }

    def runner() -> None:
        try:
            fn(*args, **kwargs)
            _set_job(job_id, status="done", finished_at=_now())
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
            resource_data.append({
                "row": r,
                "sources": _sources(conn, "resource", r["id"]),
                "notes": _notes(conn, "resource", r["id"]),
                "open_url": _external_url(r["url"]),
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
    return {
        "host": host,
        "host_https_url": f"https://{host['hostname']}/",
        "host_http_url": f"http://{host['hostname']}/",
        "sources": host_sources,
        "notes": host_notes,
        "resources": resource_data,
        "inspections": inspection_data,
        "events": event_data,
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
    def target_create(domain: str = Form(...), workspace: str = Form(""), csrf: str = Form(...)):
        verify_csrf(csrf)
        domain = domain.strip().lower().rstrip(".")
        if domain.startswith("http://") or domain.startswith("https://") or not DOMAIN_RE.fullmatch(domain):
            raise HTTPException(status_code=400, detail="Usa sólo el dominio, por ejemplo example.com")
        target_workspace = Path(workspace).expanduser() if workspace.strip() else core.default_workspace(domain)
        core.ensure_workspace(target_workspace, domain)
        key = core.register_target(domain, target_workspace, make_current=True)
        return RedirectResponse(url=f"/t/{key}/", status_code=303)

    @app.get("/t/{target_key}/", response_class=HTMLResponse)
    def dashboard(request: Request, target_key: str):
        domain, workspace, paths = _target_context(target_key)
        core.set_current_target(target_key)
        data = _dashboard_data(paths)
        with JOBS_LOCK:
            jobs = [j for j in JOBS.values() if j.get("target_key") == target_key][-8:][::-1]
        return render(request, "dashboard.html", target_key, domain, workspace, **data, jobs=jobs, target_cards=_target_cards())

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
        domain, workspace, paths = _target_context(target_key)
        detail = _host_detail(paths, host_id)
        if not detail:
            raise HTTPException(status_code=404, detail="Host no encontrado")
        return render(request, "host.html", target_key, domain, workspace, **detail)

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

    @app.post("/t/{target_key}/scan")
    def scan(target_key: str, source: str = Form(...), csrf: str = Form(...)):
        verify_csrf(csrf)
        domain, _, paths = _target_context(target_key)
        allowed = set(core.HOST_SOURCE_ORDER)
        if source not in allowed:
            raise HTTPException(status_code=400, detail="Fuente inválida")
        if source.startswith("gau_"):
            provider = source.removeprefix("gau_")
            _start_job(f"scan {source}", target_key, core.collect_gau_provider, provider, domain, paths, 900)
        else:
            timeout = 7200 if source == "amass" else 900
            _start_job(f"scan {source}", target_key, core.collect_source, source, domain, paths, timeout)
        return RedirectResponse(url=f"/t/{target_key}/?scan=started", status_code=303)

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
