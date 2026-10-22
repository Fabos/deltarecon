from pathlib import Path
import sqlite3
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_recon as recon
from negro_web import create_app
from fastapi.testclient import TestClient


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    recon.init_schema(conn)
    return conn


def test_historical_urls_feed_hostname_candidates_only():
    text = "\n".join([
        "https://www.example.com/old/path",
        "https://api.example.com/v1/users",
        "https://api.example.com/v2/users",
        "https://thirdparty.test/x",
    ])
    assert recon._historical_hosts_from_text(text, "example.com") == ["api.example.com", "www.example.com"]


def test_composite_discovery_runs_available_sources_and_audits_each(monkeypatch, tmp_path):
    conn = _conn()
    outputs = {
        "subfinder": "www.example.com\napi.example.com\n",
        "crt.sh": '[{"name_value":"qa.example.com\\n*.example.com"}]',
        "amass": "stage.example.com\n",
        "gau": "https://old.example.com/login\nhttps://api.example.com/v1\n",
    }
    available = {"subfinder", "curl", "amass", "gau"}
    monkeypatch.setattr(recon, "_tool_path", lambda name: f"/bin/{name}" if name in available else None)

    def fake_run(conn, paths, phase, tool, command, **kwargs):
        stdout = outputs[tool]
        started = recon._now()
        run_dir = Path(paths["raw"]) / "surface-runs"
        run_dir.mkdir(parents=True, exist_ok=True)
        out = run_dir / f"{tool}.out"
        err = run_dir / f"{tool}.err"
        out.write_text(stdout)
        err.write_text("")
        recon._record_tool_run(conn, phase, tool, command, "ok", 0, len(stdout.splitlines()), str(out), str(err), "", started, recon._now(), root_domain="example.com", run_group=kwargs.get("run_group", "g"))
        return {"status":"ok","return_code":0,"stdout":stdout,"stderr":"","command":command,"error":""}

    monkeypatch.setattr(recon, "_run_tool", fake_run)
    paths = {"raw": str(tmp_path / "raw")}
    result = recon.run_discovery_phase(conn, "example.com", paths, run_group="group-1")
    assert result["sources_ok"] == 4
    hosts = recon._first_party_hostnames(conn, "example.com")
    assert {"www.example.com","api.example.com","qa.example.com","stage.example.com","old.example.com"}.issubset(set(hosts))
    detail = recon.phase_detail_data(conn, "example.com", "discovery")
    tools = {r["tool"] for r in detail["runs"]}
    assert {"subfinder","crt.sh","amass","gau"}.issubset(tools)
    summary = {x["source"]: x for x in detail["source_summary"]}
    assert summary["gau_historical"]["normalized_count"] == 2
    assert summary["crtsh"]["normalized_count"] == 1


def test_surface_pages_include_loading_feedback_and_discovery_audit():
    with tempfile.TemporaryDirectory(prefix="negro-v084-") as td:
        workspace = Path(td) / "workspace"
        core.ensure_workspace(workspace, "example.com")
        old_targets = core.TARGETS_PATH
        try:
            core.TARGETS_PATH = Path(td) / "targets.json"
            key = core.register_target("example.com", workspace, make_current=True, name="v084", scopes=["example.com"])
            client = TestClient(create_app("example.com", workspace))
            page = client.get(f"/t/{key}/surface")
            assert page.status_code == 200
            assert "/static/recon_loading.js" in page.text
            assert "Descubrimiento de superficie" in page.text
            detail = client.get(f"/t/{key}/surface/phase/discovery?root=example.com")
            assert detail.status_code == 200
            assert "COBERTURA DE DISCOVERY" in detail.text
            assert "Certificate Transparency" in detail.text
            assert "/static/recon_loading.js" in detail.text
        finally:
            core.TARGETS_PATH = old_targets
