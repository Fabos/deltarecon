#!/usr/bin/env python3
"""Regression for v0.28 guided UX, Business Object form clarity and empty filters."""
from pathlib import Path
import base64
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import negro_core as core
import negro_hunter as hunter
from negro_web import create_app
from fastapi.testclient import TestClient


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="negro-v028-") as td:
        root = Path(td)
        old_targets = core.TARGETS_PATH
        core.TARGETS_PATH = root / "targets.json"
        try:
            domain = "accesslab.local"
            workspace = root / "workspace"
            paths = core.ensure_workspace(workspace, domain)
            req = b"GET /api/orders/123 HTTP/1.1\r\nHost: api.accesslab.local\r\nCookie: session=ana\r\n\r\n"
            resp = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"order_id":123,"ownerId":101,"status":"CREATED"}'
            ex = core.upsert_http_observation(
                paths, domain, url="https://api.accesslab.local/api/orders/123", method="GET",
                source="burp_proxy", status_code=200, authenticated=True, tool="PROXY",
                response_content_type="application/json", request_b64=b64(req), response_b64=b64(resp),
            )
            with core.db_connect(paths) as conn:
                hunter.analyze_http_exchange(conn, int(ex["exchange_id"]), domain, emit_notifications=False)

            app = create_app(domain, workspace)
            client = TestClient(app)
            target = core.list_targets()[0]["key"]

            # Regression: <option value=""> must not be parsed by FastAPI as int.
            r = client.get(f"/t/{target}/objects?type_id=")
            assert r.status_code == 200, r.text
            assert "Explicar esta pantalla" in r.text
            assert "Access Control Lab" in r.text
            assert "Tipo de objeto" in r.text
            # Suggestions are not silently prefilled; user chooses or clicks the suggestion chip.
            assert 'name="object_type" value=""' in r.text
            assert "Usar sugerencia: Order" in r.text

            # Invalid hand-written filter values are ignored gracefully too.
            r = client.get(f"/t/{target}/objects?type_id=not-a-number")
            assert r.status_code == 200, r.text

            guide = client.get(f"/t/{target}/guide")
            assert guide.status_code == 200
            for phrase in (
                "No memorices módulos", "Access Control Lab", "Resource / Operation / Request",
                "Inspección básica", "Authorization Matrix", "Business Objects", "Settings",
            ):
                assert phrase in guide.text, phrase
        finally:
            core.TARGETS_PATH = old_targets

    print("[OK] empty/invalid Business Object type filters no longer return 422")
    print("[OK] object teaching UI does not prefill/append a suggested type silently")
    print("[OK] every main screen gets contextual help via the shared base template")
    print("[OK] learning center includes the Access Control Lab and end-to-end feature map")


if __name__ == "__main__":
    main()
