# Reemplazo limpio del repositorio

Esta entrega está pensada para reemplazar el checkout de código completo.

## Antes de borrar el repo viejo

1. Conserva `~/.config/negro/` (especialmente `targets.json`, `config.json` y `secrets.env`).
2. Revisa `~/.config/negro/targets.json`: cada proyecto contiene la ruta de su `workspace`. Si alguno de esos workspaces está físicamente dentro del repo viejo, muévelo o haz backup antes de borrarlo.
3. No copies `.venv`, `__pycache__`, `.pytest_cache`, `javac.*.args` ni notas históricas `V*.md`.

## Reemplazo

```bash
# dentro de la carpeta nueva
chmod +x install-web.sh burp-extension/build-extension.sh
./install-web.sh

# si usas la extensión Burp
cd burp-extension
./build-extension.sh
```

`install-web.sh` crea un `.venv` nuevo y actualiza `/usr/local/bin/negro` para apuntar a este checkout.

## Datos

El código y los workspaces son cosas distintas. Borrar el checkout no debe borrar un workspace externo. Los datos de cada proyecto viven en la ruta `workspace` registrada en `~/.config/negro/targets.json`.

Release: v0.117.9
