from __future__ import annotations

import base64
from pathlib import Path
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
    paths = core.ensure_workspace(ws, "example.test", scopes=["example.test"], project_name="Example")
    return key, ws, paths


def observe(paths, path: str):
    req = f"GET {path} HTTP/1.1\r\nHost: example.test\r\n\r\n".encode()
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    return core.upsert_http_observation(
        paths, "example.test", url=f"https://example.test{path}", method="GET", source="burp_proxy",
        tool="PROXY", request_b64=b64(req), response_b64=b64(resp), status_code=200,
        response_content_type="application/json", burp_in_scope=True,
    )


def test_checkpoint_is_non_destructive_and_filters_view(tmp_path, monkeypatch):
    key, _ws, paths = setup_project(tmp_path, monkeypatch)
    old = observe(paths, "/before")
    with core.db_connect(paths) as conn:
        conn.execute("UPDATE http_exchanges SET last_seen_at='2026-01-01T00:00:00+00:00' WHERE id=?", (old["exchange_id"],))
        conn.commit()
    cp = workbench.create_checkpoint(label="Login Buyer A", target_hint=key)
    new = observe(paths, "/after")

    all_rows = workbench.list_traffic(target=key, hide_static=False, limit=50)["rows"]
    recent = workbench.list_traffic(target=key, hide_static=False, since=cp["cutoff_at"], limit=50)["rows"]
    assert {r["path"] for r in all_rows} >= {"/before", "/after"}
    assert "/after" in {r["path"] for r in recent}
    assert "/before" not in {r["path"] for r in recent}
    # The exchange still exists: checkpoint changes view, never storage.
    with core.db_connect(paths) as conn:
        assert conn.execute("SELECT 1 FROM http_exchanges WHERE id=?", (old["exchange_id"],)).fetchone()


def test_workbench_comfort_ui_contract():
    tpl = (ROOT / "web/templates/http_workbench.html").read_text()
    js = (ROOT / "web/static/app.js").read_text()
    css = (ROOT / "web/static/style.css").read_text()
    for token in ("Clear view · nuevo checkpoint", "data-mark-toggle", "data-create-flow-marked", "data-message-splitter", "data-focus-toggle", "data-context-toggle"):
        assert token in tpl
    for token in ("markKey=", "createFlowUrl", "header-muted", "smartValue", "setFocus", "setSplit", "mark_scope"):
        assert token in js
    for token in (".wb-traffic-row.marked::before", ".workbench-focus .app-header", ".wb-message-splitter", ".wb-http-line.header-muted", ".wb-shell.context-hidden"):
        assert token in css


@pytest.mark.skipif(TestClient is None, reason="FastAPI TestClient unavailable")
def test_create_flow_from_marked_endpoint(tmp_path, monkeypatch):
    key, ws, paths = setup_project(tmp_path, monkeypatch)
    a = observe(paths, "/one")
    b = observe(paths, "/two")
    app = negro_web.create_app("example.test", ws)
    client = TestClient(app)
    page = client.get(f"/t/{key}/workbench")
    assert page.status_code == 200
    # CSRF is process-local and is embedded in the rendered page.
    import re
    m = re.search(r'data-csrf="([^"]+)"', page.text)
    assert m, page.text[:1000]
    r = client.post(f"/api/t/{key}/workbench/create-flow", json={
        "csrf": m.group(1), "source_key": key,
        "exchange_ids": [b["exchange_id"], a["exchange_id"]],
        "name": "Mental flow",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["step_count"] == 2
    with core.db_connect(paths) as conn:
        flow = conn.execute("SELECT name FROM flows WHERE id=?", (body["flow_id"],)).fetchone()
        steps = conn.execute("SELECT exchange_id FROM flow_steps WHERE flow_id=? ORDER BY position", (body["flow_id"],)).fetchall()
    assert flow["name"] == "Mental flow"
    assert {int(x["exchange_id"]) for x in steps} == {int(a["exchange_id"]), int(b["exchange_id"])}
