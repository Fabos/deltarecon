#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

required_files=(
  "negro.py"
  "negro_core.py"
  "negro_intel.py"
  "negro_hunter.py"
  "negro_rules.py"
  "negro_web.py"
  "negro_http_inspector.py"
  "requirements.txt"
  "web/static/app.js"
  "web/static/style.css"
  "web/templates/base.html"
  "web/templates/dashboard.html"
  "web/templates/host.html"
  "web/templates/hosts.html"
  "web/templates/settings.html"
  "web/templates/detector_rules.html"
  "web/templates/target_error.html"
  "web/templates/tree.html"
  "web/templates/intelligence.html"
)

missing=()
for rel in "${required_files[@]}"; do
  [[ -f "$ROOT/$rel" ]] || missing+=("$rel")
done

if (( ${#missing[@]} )); then
  echo "[!] Instalación incompleta: faltan archivos del proyecto:" >&2
  printf '    - %s\n' "${missing[@]}" >&2
  echo "[!] Usa el ZIP completo de Negro y vuelve a ejecutar ./install-web.sh" >&2
  exit 1
fi

echo "[+] Estructura del proyecto: OK"

if [ ! -x "$ROOT/.venv/bin/python" ]; then
  echo "[+] Creando virtualenv local en $ROOT/.venv"
  python3 -m venv "$ROOT/.venv"
else
  echo "[+] Reutilizando virtualenv existente en $ROOT/.venv"
fi

"$ROOT/.venv/bin/python" -m pip install --upgrade pip setuptools wheel
"$ROOT/.venv/bin/python" -m pip install --upgrade -r "$ROOT/requirements.txt"

echo "[+] Verificando dependencias de Negro..."
"$ROOT/.venv/bin/python" - <<'PY'
import sys
mods = ["fastapi", "uvicorn", "jinja2", "multipart", "openai", "tiktoken", "jsbeautifier", "requests", "dns"]
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

echo "[+] Verificando Python y templates..."
"$ROOT/.venv/bin/python" -m py_compile \
  "$ROOT/negro.py" "$ROOT/negro_core.py" "$ROOT/negro_intel.py" "$ROOT/negro_hunter.py" "$ROOT/negro_rules.py" "$ROOT/negro_web.py" "$ROOT/negro_http_inspector.py"

ROOT="$ROOT" "$ROOT/.venv/bin/python" - <<'PY'
import os
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
root = Path(os.environ["ROOT"])
templates = root / "web" / "templates"
env = Environment(loader=FileSystemLoader(str(templates)))
for path in sorted(templates.glob("*.html")):
    env.get_template(path.name)
print("    ✓ Python compila")
print("    ✓ Templates Jinja cargan")
PY

if command -v node >/dev/null 2>&1; then
  node --check "$ROOT/web/static/app.js"
  echo "    ✓ JavaScript syntax"
fi

# Launcher estable: `negro` siempre usa el Python del .venv de ESTE checkout.
LAUNCHER_CONTENT="$(cat <<LAUNCHER
#!/bin/sh
REPO="$ROOT"
exec "\$REPO/.venv/bin/python" "\$REPO/negro.py" "\$@"
LAUNCHER
)"

install_launcher() {
  local dest="/usr/local/bin/negro"
  rm -f "$dest"
  printf '%s\n' "$LAUNCHER_CONTENT" > "$dest"
  chmod +x "$dest"
}

if [ -w /usr/local/bin ]; then
  install_launcher
elif command -v sudo >/dev/null 2>&1; then
  echo "[+] Actualizando launcher /usr/local/bin/negro (puede pedir sudo)..."
  sudo rm -f /usr/local/bin/negro
  printf '%s\n' "$LAUNCHER_CONTENT" | sudo tee /usr/local/bin/negro >/dev/null
  sudo chmod +x /usr/local/bin/negro
else
  echo "[!] No pude escribir /usr/local/bin/negro." >&2
  echo "    Ejecuta Negro con:" >&2
  echo "    $ROOT/.venv/bin/python $ROOT/negro.py" >&2
  exit 1
fi

echo "[+] Verificando launcher..."
if ! /usr/local/bin/negro --help >/dev/null 2>&1; then
  echo "[!] El launcher se creó, pero la prueba 'negro --help' falló." >&2
  echo "    Contenido actual:" >&2
  sed 's/^/    /' /usr/local/bin/negro >&2 || true
  exit 1
fi

echo "    ✓ /usr/local/bin/negro usa $ROOT/.venv/bin/python"
printf '\n[+] Negro listo. Ejecuta:\n    negro web\n\n'
