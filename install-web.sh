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

# Instala un launcher estable. No dependemos del shebang /usr/bin/env python3:
# `negro` siempre ejecuta el Python del .venv de ESTE checkout.
LAUNCHER_CONTENT="$(cat <<LAUNCHER
#!/bin/sh
REPO=\"$ROOT\"
exec \"\$REPO/.venv/bin/python\" \"\$REPO/negro.py\" \"\$@\"
LAUNCHER
)"

install_launcher() {
  local dest="/usr/local/bin/negro"
  # Importante: si la versión vieja era un symlink a negro.py, elimínalo
  # antes de escribir para no sobrescribir el archivo real del repo.
  rm -f "$dest"
  printf '%s\n' "$LAUNCHER_CONTENT" > "$dest"
  chmod +x "$dest"
}

if [ -w /usr/local/bin ]; then
  install_launcher
  echo "[+] Launcher actualizado: /usr/local/bin/negro -> $ROOT/.venv/bin/python"
elif command -v sudo >/dev/null 2>&1; then
  echo "[+] Actualizando launcher /usr/local/bin/negro (puede pedir sudo)..."
  sudo rm -f /usr/local/bin/negro
  printf '%s\n' "$LAUNCHER_CONTENT" | sudo tee /usr/local/bin/negro >/dev/null
  sudo chmod +x /usr/local/bin/negro
  echo "[+] Launcher actualizado: /usr/local/bin/negro -> $ROOT/.venv/bin/python"
else
  echo "[!] No pude escribir /usr/local/bin/negro. Crea manualmente un launcher que use:"
  echo "    $ROOT/.venv/bin/python $ROOT/negro.py"
fi

printf '\n[+] Negro listo. Ejecuta:\n    negro web\n\n'
