from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
web = (ROOT / "negro_web.py").read_text(encoding="utf-8")
detail = (ROOT / "web/templates/flow_detail.html").read_text(encoding="utf-8")
flows = (ROOT / "web/templates/flows.html").read_text(encoding="utf-8")

assert "capture_stopped=1&captured_steps={steps}" in web
assert "CAPTURA ACTIVA" in detail
assert "nueva(s) esta sesión" in detail
assert "CAPTURA DETENIDA" in detail
assert "No llegaron Requests nuevas en esta sesión" in detail
assert "target a través de Burp" in detail
assert "Burp Bridge" in detail
assert "1.</b> Inicia la captura" in flows
print("[OK] Flow Capture makes active/stopped/empty states explicit")
