#!/usr/bin/env python3
from pathlib import Path
import base64
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_flows as flows


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def capture(paths, domain, path):
    req = f"GET {path} HTTP/1.1\r\nHost: api.example.test\r\n\r\n".encode()
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    return core.upsert_http_observation(
        paths, domain, url=f"https://api.example.test{path}", method="GET", source="burp_proxy",
        status_code=200, authenticated=False, tool="PROXY", request_content_type="", response_content_type="application/json",
        request_b64=b64(req), response_b64=b64(resp), query={},
    )


def main():
    with tempfile.TemporaryDirectory(prefix="negro-v106-") as td:
        domain = "api.example.test"
        paths = core.ensure_workspace(Path(td) / "project", domain)
        a = capture(paths, domain, "/a")
        b = capture(paths, domain, "/b")
        c = capture(paths, domain, "/c")
        d = capture(paths, domain, "/d")
        with core.db_connect(paths) as conn:
            fid = flows.start_capture(conn, "Editable journey", source="web")
            flows.capture_observed_exchange(conn, int(a["exchange_id"]))
            flows.capture_observed_exchange(conn, int(b["exchange_id"]))
            first = flows.stop_capture(conn, fid)
            assert first["session_added"] == 2 and first["steps"] == 2, first

            data = flows.get_flow(conn, fid)
            assert data["flow"]["capture_status"] == "stopped"
            # Researcher can edit while capture is paused.
            flows.move_step(conn, fid, int(data["steps"][1]["id"]), 1)

            resumed = flows.resume_capture(conn, fid, source="web")
            assert resumed["baseline_steps"] == 2, resumed
            data = flows.get_flow(conn, fid)
            assert data["flow"]["capture_status"] == "capturing"
            assert int(data["flow"]["capture_session_start_step_count"]) == 2

            flows.capture_observed_exchange(conn, int(c["exchange_id"]))
            second = flows.stop_capture(conn, fid)
            assert second["session_added"] == 1 and second["steps"] == 3, second

            # It can be resumed repeatedly, and existing Steps stay intact.
            flows.resume_capture(conn, fid, source="web")
            flows.capture_observed_exchange(conn, int(d["exchange_id"]))
            third = flows.stop_capture(conn, fid)
            assert third["session_added"] == 1 and third["steps"] == 4, third
            final = flows.get_flow(conn, fid)
            assert len(final["steps"]) == 4
            assert int(final["steps"][0]["exchange_id"]) == int(b["exchange_id"]), final["steps"]

    detail = (ROOT / "web/templates/flow_detail.html").read_text(encoding="utf-8")
    web = (ROOT / "negro_web.py").read_text(encoding="utf-8")
    assert "● Activar captura" in detail
    assert "■ Detener captura" in detail
    assert "/capture/start" in detail
    assert "capture_added={added}" in web
    assert "nueva(s) esta sesión" in detail
    print("[OK] v0.106 Flow Capture can pause/resume repeatedly without resetting the Flow")


if __name__ == "__main__":
    main()
