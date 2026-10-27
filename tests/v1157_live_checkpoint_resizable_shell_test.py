from __future__ import annotations

import base64
from pathlib import Path
import re
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_web
import negro_workbench as workbench

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
    key = core.register_target("example.test", ws, make_current=True, name="Example", scopes=["example.test"])
    core.ensure_workspace(ws, "example.test", scopes=["example.test"], project_name="Example")
    return key, ws


def payload(path: str) -> dict:
    req = f"GET {path} HTTP/1.1\r\nHost: example.test\r\n\r\n".encode()
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    return {
        "url": f"https://example.test{path}", "method": "GET", "tool": "PROXY", "status_code": 200,
        "request_b64": b64(req), "response_b64": b64(resp), "burp_in_scope": True,
    }


@pytest.mark.skipif(TestClient is None, reason="FastAPI TestClient unavailable")
def test_checkpoint_live_endpoint_returns_capture_after_cut(tmp_path, monkeypatch):
    key, ws = setup_project(tmp_path, monkeypatch)
    client = TestClient(negro_web.create_app("example.test", ws))
    first = client.post("/api/ingest/http", json=payload("/before")).json()
    cp = workbench.create_checkpoint(label="Cut", target_hint=key)
    page = client.get(f"/t/{key}/workbench", params={"history":"checkpoint", "checkpoint_id":cp["id"], "target":key})
    assert page.status_code == 200
    latest = int(re.search(r'data-latest-event-id="(\d+)"', page.text).group(1))
    assert latest >= first["capture_event_id"]

    second = client.post("/api/ingest/http", json=payload("/after")).json()
    res = client.get(f"/api/t/{key}/workbench/events", params={
        "target": key,
        "since_event_id": cp["cutoff_event_id"],
        "after_event_id": latest,
        "hide_static": 0,
    })
    assert res.status_code == 200
    ids = [int(r["id"]) for r in res.json()["rows"]]
    assert second["capture_event_id"] in ids


def test_live_reads_are_bounded_by_one_snapshot():
    src = (ROOT / "negro_workbench.py").read_text(encoding="utf-8")
    assert 'SELECT COALESCE(MAX(id),0) id FROM workbench_capture_events' in src
    assert 'clauses.append("id<=?")' in src
    assert src.index('SELECT COALESCE(MAX(id),0) id FROM workbench_capture_events') < src.index('clauses.append("id<=?")')


def test_resizable_traffic_and_context_return_affordance_contract():
    tpl = (ROOT / "web/templates/http_workbench.html").read_text(encoding="utf-8")
    css = (ROOT / "web/static/style.css").read_text(encoding="utf-8")
    js = (ROOT / "web/static/app.js").read_text(encoding="utf-8")
    assert 'data-traffic-splitter' in tpl
    assert 'class="wb-context-reopen"' in tpl
    assert 'cursor:row-resize' in css
    assert '.wb-shell.context-hidden .wb-context-reopen{display:flex}' in css
    assert 'trafficHeightKey' in js
    assert 'setTrafficHeight' in js
    assert "ev.clientY-rect.top" in js
    assert 'localStorage.removeItem(trafficHeightKey)' in js
