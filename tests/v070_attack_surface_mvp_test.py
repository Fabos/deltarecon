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


def test_recon_ingestion_and_surface_filters():
    with tempfile.TemporaryDirectory(prefix="negro-surface-") as td:
        paths = core.ensure_workspace(Path(td) / "workspace", "example.com")
        with core.db_connect(paths) as conn:
            recon.init_schema(conn)
            recon.import_subfinder_text(conn, "app-dev.example.com\napp.example.com\n", "example.com", "subfinder.txt")
            recon.import_dnsx_text(conn, "app.example.com [A] [203.0.113.10]\napp.example.com [CNAME] [edge.example.net]\n", "example.com", "dnsx.txt")
            recon.import_httpx_jsonl(conn, '{"host":"app-dev.example.com","url":"https://app-dev.example.com","status_code":200,"cdn_name":"cloudflare","cdn_type":"waf","webserver":"nginx","tech":["Node.js","React"],"a":["104.18.1.1"],"location":"https://app.example.com/"}\n', "example.com", "httpx.jsonl")
            data = recon.surface_data(conn, "example.com")
        assert data["summary"]["hosts"] == 2
        dev = next(h for h in data["hosts"] if h["hostname"] == "app-dev.example.com")
        assert dev["environment"] == "DEV"
        assert "Node.js" in dev["technologies"]
        assert "Cloudflare" in dev["providers"]
        assert "nginx" in dev["servers"]
        assert "app.example.com" in dev["redirects"]
        prod = next(h for h in data["hosts"] if h["hostname"] == "app.example.com")
        assert "203.0.113.10" in prod["ips"]
        assert "edge.example.net" in prod["cnames"]
        assert set(data["filters"]["sources"]) >= {"subfinder", "dnsx", "httpx"}


def test_surface_page_and_api_exist():
    with tempfile.TemporaryDirectory(prefix="negro-surface-web-") as td:
        workspace = Path(td) / "workspace"
        paths = core.ensure_workspace(workspace, "example.com")
        with core.db_connect(paths) as conn:
            recon.import_httpx_jsonl(conn, '{"host":"www.example.com","url":"https://www.example.com","status_code":200,"cdn_name":"fastly","cdn_type":"cdn","tech":["PHP","Symfony"],"a":["151.101.1.1"]}\n', "example.com")
        old_targets = core.TARGETS_PATH
        try:
            core.TARGETS_PATH = Path(td) / "targets.json"
            key = core.register_target("example.com", workspace, make_current=True, name="Surface Test", scopes=["example.com"])
            client = TestClient(create_app("example.com", workspace))
            page = client.get(f"/t/{key}/surface")
            assert page.status_code == 200
            assert "Superficie de ataque" in page.text
            assert "Tecnología" in page.text and "Proveedor" in page.text and "Servidor" in page.text
            api = client.get(f"/api/t/{key}/surface")
            assert api.status_code == 200
            body = api.json()
            assert body["summary"]["hosts"] == 1
            assert "PHP" in body["filters"]["technologies"]
        finally:
            core.TARGETS_PATH = old_targets


def test_surface_assets_keep_edge_separate_from_origin():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    recon.init_schema(conn)
    recon.import_httpx_jsonl(conn, '{"host":"www.example.com","url":"https://www.example.com","status_code":200,"cdn_name":"fastly","cdn_type":"cdn","a":["151.101.1.1"]}\n', "example.com")
    data = recon.surface_data(conn, "example.com")
    host = data["hosts"][0]
    assert host["ips"] == ["151.101.1.1"]
    # The canonical model deliberately exposes only OBSERVED_IP; it has no origin relation.
    rels = [dict(r) for r in conn.execute("SELECT relation FROM recon_relationships").fetchall()]
    assert all(r["relation"] != "ORIGIN_IP" for r in rels)
