#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [ ! -x "$ROOT/.venv/bin/python" ]; then
  echo "[+] Creando virtualenv local en $ROOT/.venv"
  python3 -m venv .venv
else
  echo "[+] Reutilizando virtualenv existente en $ROOT/.venv"
fi

"$ROOT/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
"$ROOT/.venv/bin/python" -m pip install -r requirements.txt

echo "[+] Verificando dependencias de Negro..."
"$ROOT/.venv/bin/python" - <<'PY'
import sys
mods = ["fastapi", "uvicorn", "jinja2", "multipart", "openai", "tiktoken", "jsbeautifier"]
failed = []
for name in mods:
    try:
        module = __import__(name)
        version = getattr(module, "__version__", "ok")
        print(f"    ✓ {name}: {version}")
    except Exception as exc:
        failed.append((name, repr(exc)))
        print(f"    ✗ {name}: {exc}")
if failed:
    print("\n[!] Faltan dependencias o alguna no puede importarse:", file=sys.stderr)
    for name, err in failed:
        print(f"    - {name}: {err}", file=sys.stderr)
    print(f"\nReintenta con:\n  {sys.executable} -m pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(1)
print(f"\n[+] Entorno correcto: {sys.executable}")
PY

printf '\n[+] Negro listo. Ejecuta:\n    negro web\n\n'
