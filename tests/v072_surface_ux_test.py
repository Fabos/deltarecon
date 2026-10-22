from pathlib import Path
import sqlite3
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_recon as recon
from negro_web import create_app
from fastapi.testclient import TestClient


def test_phase_progress_has_guidance_and_summary():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    recon.init_schema(conn)
    data = recon.surface_data(conn, "example.com")
    assert data["phase_summary"]["total"] == 5
    root = next(p for p in data["phases"] if p["key"] == "root")
    assert root["question"]
    assert root["tool"]
    assert root["checks"]
    assert root["success"]


def test_singleton_families_do_not_inflate_family_summary():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    recon.init_schema(conn)
    recon.import_subfinder_text(conn, "www.example.com\napi.example.com\n", "example.com")
    data = recon.surface_data(conn, "example.com")
    assert data["summary"]["families"] == 0
    recon.import_subfinder_text(conn, "api-dev.example.com\napi-qa.example.com\n", "example.com")
    data = recon.surface_data(conn, "example.com")
    assert data["summary"]["families"] >= 1


def test_surface_has_fullscreen_checklist_and_expandable_phases():
    with tempfile.TemporaryDirectory(prefix="negro-surface-v072-") as td:
        workspace = Path(td) / "workspace"
        core.ensure_workspace(workspace, "example.com")
        old_targets = core.TARGETS_PATH
        try:
            core.TARGETS_PATH = Path(td) / "targets.json"
            key = core.register_target("example.com", workspace, make_current=True, name="Surface UX", scopes=["example.com"])
            client = TestClient(create_app("example.com", workspace))
            page = client.get(f"/t/{key}/surface")
            assert page.status_code == 200
            assert "CHECKLIST DE RECON" in page.text
            assert "data-surface-fullscreen" in page.text
            assert "data-surface-reset-layout" in page.text
            assert "data-phase-detail" in page.text
            assert "Arrastra nodos" in page.text
        finally:
            core.TARGETS_PATH = old_targets


def test_surface_css_respects_hidden_state():
    css = (ROOT / "web" / "static" / "style.css").read_text(encoding="utf-8")
    assert '[data-surface-root] [hidden]{display:none!important}' in css
