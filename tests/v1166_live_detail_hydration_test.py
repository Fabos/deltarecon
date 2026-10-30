from __future__ import annotations

import base64
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_web

try:
    from fastapi.testclient import TestClient
except Exception:  # pragma: no cover
    TestClient = None


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def setup_project(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(core, "TARGETS_PATH", tmp_path / "targets.json")
    monkeypatch.setenv("NEGRO_TRAFFIC_WORKSPACE", str(tmp_path / "traffic-inbox"))
    ws = tmp_path / "workspace"
    key = core.register_target("live.test", ws, make_current=True, name="Live", scopes=["live.test"])
    core.ensure_workspace(ws, "live.test", scopes=["live.test"], project_name="Live")
    return key, ws


def payload() -> dict:
    req = b"GET /api/new HTTP/1.1\r\nHost: live.test\r\nAccept: application/json\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}"
    return {
        "url": "https://live.test/api/new",
        "method": "GET",
        "tool": "PROXY",
        "status_code": 200,
        "request_b64": b64(req),
        "response_b64": b64(resp),
        "response_content_type": "application/json",
        "burp_in_scope": True,
    }


@pytest.mark.skipif(TestClient is None, reason="FastAPI TestClient unavailable")
def test_workbench_without_initial_selection_keeps_live_detail_shell_mounted(tmp_path, monkeypatch):
    key, ws = setup_project(tmp_path, monkeypatch)
    client = TestClient(negro_web.create_app("live.test", ws))

    # Open the workbench before any event exists: this is the state that used to
    # render only the empty message and left LIVE rows with nowhere to hydrate.
    page = client.get(f"/t/{key}/workbench")
    assert page.status_code == 200
    assert 'data-http-view="request"' in page.text
    assert 'data-http-view="response"' in page.text
    assert 'data-summary-url' in page.text
    assert 'data-context-card="identity"' in page.text
    assert 'data-context-card="objects"' in page.text
    assert 'data-context-card="signals"' in page.text
    assert 'data-context-card="flow"' in page.text
    assert 'data-workbench-inline-context' in page.text

    # A freshly ingested LIVE event must have its detail immediately available;
    # no full page reload is required to materialize request/response bytes.
    ingest = client.post("/api/ingest/http", json=payload())
    assert ingest.status_code == 200, ingest.text
    event_id = int(ingest.json()["capture_event_id"])
    detail = client.get(f"/api/t/{key}/workbench/detail", params={"event_id": event_id})
    assert detail.status_code == 200, detail.text
    data = detail.json()
    assert "GET /api/new HTTP/1.1" in data["request_text"]
    assert "HTTP/1.1 200 OK" in data["response_text"]
    assert data["event_id"] == event_id


def test_live_row_click_hydrates_existing_shell_without_full_reload():
    js = (ROOT / "web/static/app.js").read_text(encoding="utf-8")
    tpl = (ROOT / "web/templates/http_workbench.html").read_text(encoding="utf-8")
    assert "fetchEventDetail" in js
    assert "renderDetail(d)" in js
    assert "data-summary-exchange" in tpl
    assert "data-summary-size" in tpl
    assert "wb-detail-empty" in tpl
