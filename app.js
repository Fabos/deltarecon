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


def test_family_heuristics_are_generic_and_cross_target():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    recon.init_schema(conn)
    recon.import_subfinder_text(
        conn,
        "api-dev.example.org\napi-qa.example.org\n"
        "payments-stage.example.org\npayments.example.org\n"
        "visionalpha.example.org\nvisionbeta.example.org\n",
        "example.org",
    )
    data = recon.surface_data(conn, "example.org")
    fam = {h["hostname"]: h["family"] for h in data["hosts"]}
    assert fam["api-dev.example.org"] == fam["api-qa.example.org"] == "api"
    assert fam["payments-stage.example.org"] == fam["payments.example.org"] == "payments"
    assert fam["visionalpha.example.org"] == fam["visionbeta.example.org"] == "vision"
    # No organization-specific vocabulary is required for these groups.
    assert all("terpel" not in x.lower() for x in data["filters"]["families"])


def test_guided_discovery_runs_local_tool_and_ingests_result():
    with tempfile.TemporaryDirectory(prefix="negro-guided-") as td:
        root = Path(td)
        workspace = root / "workspace"
        paths = core.ensure_workspace(workspace, "example.com")
        fake = root / "subfinder"
        fake.write_text("#!/bin/sh\nprintf 'api-dev.example.com\\napi-qa.example.com\\n'\n", encoding="utf-8")
        fake.chmod(0o755)
        old = recon._tool_path
        try:
            recon._tool_path = lambda name: str(fake) if name == "subfinder" else None
            with core.db_connect(paths) as conn:
                result = recon.run_discovery_phase(conn, "example.com", paths, timeout=5)
                data = recon.surface_data(conn, "example.com")
            assert result["records"] == 2
            assert {h["hostname"] for h in data["hosts"]} == {"api-dev.example.com", "api-qa.example.com"}
            assert data["tool_runs"][0]["tool"] == "subfinder"
            assert data["tool_runs"][0]["status"] == "ok"
        finally:
            recon._tool_path = old


def test_surface_page_is_guided_and_import_is_secondary():
    with tempfile.TemporaryDirectory(prefix="negro-guided-web-") as td:
        workspace = Path(td) / "workspace"
        core.ensure_workspace(workspace, "example.com")
        old_targets = core.TARGETS_PATH
        try:
            core.TARGETS_PATH = Path(td) / "targets.json"
            key = core.register_target("example.com", workspace, make_current=True, name="Guided", scopes=["example.com"])
            client = TestClient(create_app("example.com", workspace))
            page = client.get(f"/t/{key}/surface")
            assert page.status_code == 200
            assert "RECON PROGRESIVO" in page.text
            assert "Dominio raíz" in page.text
            assert "Descubrimiento" in page.text
            assert "Validar DNS" in page.text
            assert "Descubrir HTTP" in page.text
            assert "Importar resultados externos" in page.text
            assert "Agrupar familias" in page.text
            assert "Ejecuciones" in page.text
        finally:
            core.TARGETS_PATH = old_targets
