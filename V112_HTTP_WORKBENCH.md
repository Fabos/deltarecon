# Negro v0.112 — HTTP Workbench

## Qué cambia

- Burp puede enviar todo el tráfico HTTP observado a Negro.
- Hosts que pertenecen a un proyecto continúan en la base de ese proyecto.
- Hosts desconocidos se guardan en un Traffic Inbox local/passive-only (`__inbox__`) en vez de descartarse.
- Capturar fuera de proyecto no amplía scope ni habilita recon activo.
- Nuevo `HTTP Workbench`: Traffic Inbox + Request/Response + Contexto Negro.
- Filtros por proyecto, host, método, status, Burp scope y herramienta.
- Navegación rápida `↑/↓` o `j/k`, búsqueda con `/`, Pretty/Raw y Copy.
- Contexto reutiliza Identity, Objects, Signals, Flow y Related Requests existentes.
- Quick Actions reutilizan HTTP Inspector, Follow Value, Add to Flow, Replay/Identity y Burp Repeater.

## Archivos principales

- `negro_workbench.py` — agregación global/passive inbox + contexto.
- `negro_web.py` — rutas Workbench y routing de ingest global.
- `negro_core.py` — persistencia explícita fuera de scope sólo para el Inbox.
- `web/templates/http_workbench.html` — interfaz aprobada.
- `web/static/style.css` / `web/static/app.js` — experiencia visual e interacción.
- `burp-extension/.../NegroBurpBridge.java` — UX de captura global y bloqueo de acciones activas para Inbox.
- `tests/v112_http_workbench_test.py` — pruebas nuevas.

## Validación

- `pytest -q`: 116 tests passed.
- `tests/v112_http_workbench_test.py`: 3 passed.
- `node --check web/static/app.js`: OK.
- Tests históricos de HTTP Inspector, Burp Context y scope: OK.

### Burp JAR

El source Java está actualizado. En el entorno donde se preparó este ZIP no fue posible regenerar el JAR porque el build necesita descargar Montoya API desde Maven y ese entorno no tenía resolución de red. Ejecuta `burp-extension/build-extension.sh` (o `.ps1` en Windows) en una máquina con acceso a Maven para generar el JAR actualizado.
