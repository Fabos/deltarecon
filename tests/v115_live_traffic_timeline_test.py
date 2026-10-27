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


def payload(path: str = "/auth") -> dict:
    req = f"POST {path} HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{{\"x\":1}}".encode()
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"token\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJpYXQiOjE3OTMwNzAwMDAsImV4cCI6MTc5MzA3MzYwMH0.signature\"}"
    return {
        "url": f"https://example.test{path}", "method": "POST", "tool": "PROXY", "status_code": 200,
        "request_content_type": "application/json", "response_content_type": "application/json",
        "request_b64": b64(req), "response_b64": b64(resp), "burp_in_scope": True,
    }


@pytest.mark.skipif(TestClient is None, reason="FastAPI TestClient unavailable")
def test_repeated_exchange_creates_exact_sequential_events(tmp_path, monkeypatch):
    key, ws = setup_project(tmp_path, monkeypatch)
    client = TestClient(negro_web.create_app("example.test", ws))

    a = client.post("/api/ingest/http", json=payload()).json()
    b = client.post("/api/ingest/http", json=payload()).json()
    assert a["exchange_id"] == b["exchange_id"]
    assert a["capture_event_id"] and b["capture_event_id"]
    assert b["capture_event_id"] == a["capture_event_id"] + 1

    traffic = workbench.list_traffic(target=key, hide_static=False, limit=20)
    exact = [r for r in traffic["rows"] if r["path"] == "/auth" and not r.get("synthetic")]
    assert [r["id"] for r in exact] == [a["capture_event_id"], b["capture_event_id"]]
    assert all(r["exchange_id"] == a["exchange_id"] for r in exact)
    assert all(r["is_unread"] for r in exact)

    detail = client.get(f"/api/t/{key}/workbench/detail", params={"event_id": a["capture_event_id"]})
    assert detail.status_code == 200
    assert detail.json()["event_id"] == a["capture_event_id"]
    assert workbench.get_capture_event(a["capture_event_id"])["seen_at"]


@pytest.mark.skipif(TestClient is None, reason="FastAPI TestClient unavailable")
def test_checkpoint_uses_event_sequence_and_flow_preserves_repeated_occurrences(tmp_path, monkeypatch):
    key, ws = setup_project(tmp_path, monkeypatch)
    client = TestClient(negro_web.create_app("example.test", ws))
    first = client.post("/api/ingest/http", json=payload("/same")).json()
    cp = workbench.create_checkpoint(label="Start", target_hint=key)
    second = client.post("/api/ingest/http", json=payload("/same")).json()
    third = client.post("/api/ingest/http", json=payload("/last")).json()

    recent = workbench.list_traffic(target=key, hide_static=False, since_event_id=cp["cutoff_event_id"], limit=20)["rows"]
    assert [r["id"] for r in recent if not r.get("synthetic")] == [second["capture_event_id"], third["capture_event_id"]]

    page = client.get(f"/t/{key}/workbench")
    csrf = re.search(r'data-csrf="([^"]+)"', page.text).group(1)
    flow = client.post(f"/api/t/{key}/workbench/create-flow", json={
        "csrf": csrf, "source_key": key,
        "event_ids": [second["capture_event_id"], first["capture_event_id"], third["capture_event_id"]],
        "name": "Timeline flow",
    })
    assert flow.status_code == 200, flow.text
    paths = core.ensure_workspace(ws, "example.test", scopes=["example.test"], project_name="Example")
    with core.db_connect(paths) as conn:
        steps = [int(r["exchange_id"]) for r in conn.execute("SELECT exchange_id FROM flow_steps WHERE flow_id=? ORDER BY position", (flow.json()["flow_id"],)).fetchall()]
    # event ordering wins; repeated /same occurrence remains a repeated step
    assert steps[0] == first["exchange_id"]
    assert steps[1] == second["exchange_id"]
    assert steps[0] == steps[1]
    assert steps[2] == third["exchange_id"]


def test_live_ui_and_jwt_inspector_contract():
    tpl = (ROOT / "web/templates/http_workbench.html").read_text()
    js = (ROOT / "web/static/app.js").read_text()
    css = (ROOT / "web/static/style.css").read_text()
    for token in ("data-live-url", "data-event-id", "data-unread-badge", "data-new-events-jump", "data-jwt-dialog", "JWT completo"):
        assert token in tpl
    for token in ("pollLive", "loadEvent", "data-jwt-token", "openJwt", "after_event_id", "event_ids"):
        assert token in js
    for token in (".wb-traffic-row.is-unread", ".wb-unread-dot", ".wb-new-events-jump", ".wb-jwt-dialog", ".wb-jwt-claim"):
        assert token in css
