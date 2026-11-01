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


def test_out_of_scope_can_only_be_persisted_when_explicitly_allowed(tmp_path, monkeypatch):
    _key, _ws, paths = setup_project(tmp_path, monkeypatch)
    req = b"GET /x HTTP/1.1\r\nHost: other.test\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    with pytest.raises(ValueError):
        core.upsert_http_observation(
            paths, "example.test", url="https://other.test/x", method="GET", source="burp_proxy",
            request_b64=b64(req), response_b64=b64(resp), status_code=200,
        )
    saved = core.upsert_http_observation(
        paths, "example.test", url="https://other.test/x", method="GET", source="burp_proxy",
        request_b64=b64(req), response_b64=b64(resp), status_code=200, allow_out_of_scope=True,
    )
    assert saved["exchange_id"] > 0
    assert saved["resource_url"] == "https://other.test/x"


def test_workbench_aggregates_project_and_passive_inbox(tmp_path, monkeypatch):
    key, _ws, paths = setup_project(tmp_path, monkeypatch)
    req1 = b"GET /orders/ORD-1 HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer t\r\n\r\n"
    resp1 = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"orderId\":\"ORD-1\"}"
    known = core.upsert_http_observation(
        paths, "example.test", url="https://example.test/orders/ORD-1", method="GET", source="burp_proxy",
        tool="PROXY", authenticated=True, request_b64=b64(req1), response_b64=b64(resp1), status_code=200,
        request_content_type="application/json", response_content_type="application/json", burp_in_scope=True,
    )

    inbox_paths = workbench.ensure_inbox_paths()
    req2 = b"POST /telemetry HTTP/1.1\r\nHost: third-party.test\r\nContent-Type: application/json\r\n\r\n{\"event\":\"view\"}"
    resp2 = b"HTTP/1.1 204 No Content\r\n\r\n"
    unknown = core.upsert_http_observation(
        inbox_paths, workbench.INBOX_DOMAIN, url="https://third-party.test/telemetry", method="POST", source="burp_proxy",
        tool="PROXY", request_b64=b64(req2), response_b64=b64(resp2), status_code=204,
        request_content_type="application/json", burp_in_scope=False, allow_out_of_scope=True,
    )

    all_rows = workbench.list_traffic(target="all", hide_static=False, limit=50)["rows"]
    assert {r["hostname"] for r in all_rows} >= {"example.test", "third-party.test"}
    assert any(r["target_key"] == key for r in all_rows)
    assert any(r["target_key"] == workbench.INBOX_KEY for r in all_rows)

    inbox_rows = workbench.list_traffic(target=workbench.INBOX_KEY, hide_static=False, limit=50)["rows"]
    assert len(inbox_rows) == 1
    assert inbox_rows[0]["hostname"] == "third-party.test"

    known_detail = workbench.detail(key, int(known["exchange_id"]))
    unknown_detail = workbench.detail(workbench.INBOX_KEY, int(unknown["exchange_id"]))
    assert known_detail and "GET /orders/ORD-1" in known_detail["request_text"]
    assert unknown_detail and unknown_detail["is_inbox"] is True
    assert "POST /telemetry" in unknown_detail["request_text"]


@pytest.mark.skipif(TestClient is None, reason="FastAPI TestClient unavailable")
def test_burp_ingest_routes_unknown_hosts_to_inbox_and_renders_workbench(tmp_path, monkeypatch):
    key, ws, _paths = setup_project(tmp_path, monkeypatch)
    app = negro_web.create_app("example.test", ws)
    client = TestClient(app)

    unknown_req = b"POST /events HTTP/1.1\r\nHost: other.test\r\nContent-Type: application/json\r\n\r\n{\"x\":1}"
    unknown_resp = b"HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}"
    payload = {
        "url": "https://other.test/events",
        "method": "POST",
        "tool": "PROXY",
        "status_code": 202,
        "authenticated": False,
        "request_content_type": "application/json",
        "response_content_type": "application/json",
        "request_b64": b64(unknown_req),
        "response_b64": b64(unknown_resp),
        "response_body_b64": b64(b'{"ok":true}'),
        "burp_in_scope": False,
    }
    r = client.post("/api/ingest/http", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] is True
    assert body["unassigned"] is True
    assert body["target_key"] == workbench.INBOX_KEY

    known_req = b"GET /me HTTP/1.1\r\nHost: example.test\r\n\r\n"
    known_resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    r2 = client.post("/api/ingest/http", json={
        "url": "https://example.test/me", "method": "GET", "tool": "PROXY", "status_code": 200,
        "request_b64": b64(known_req), "response_b64": b64(known_resp), "burp_in_scope": True,
    })
    assert r2.status_code == 200, r2.text
    assert r2.json()["accepted"] is True and r2.json()["unassigned"] is False
    assert r2.json()["target_key"] == key

    page = client.get(f"/t/{key}/workbench?hide_static=0")
    assert page.status_code == 200, page.text[:500]
    assert "HTTP Workbench" in page.text
    assert "Traffic Inbox" in page.text
    assert "other.test" in page.text
    assert "example.test" in page.text
    assert "Captura global" in page.text

    detail = client.get(f"/api/t/{key}/workbench/detail", params={"source_key": workbench.INBOX_KEY, "exchange_id": body["exchange_id"]})
    assert detail.status_code == 200, detail.text
    assert detail.json()["is_inbox"] is True
    assert "POST /events" in detail.json()["request_text"]
