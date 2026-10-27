# Negro v0.114 — Workbench Comfort

Objetivo: convertir HTTP Workbench en una mesa de análisis cómoda para sesiones largas sin perder memoria histórica.

## Checkpoints / Clear view
- `Clear view · nuevo checkpoint` crea un corte visual no destructivo.
- Ningún `http_exchange` se elimina.
- La vista puede alternar entre `Todo el tráfico` y `Desde checkpoint`.
- Los checkpoints son persistentes, seleccionables y renombrables.
- Búsqueda y filtros conservan el contexto de checkpoint activo.

## Marcado mental → Flow
- Cada Request puede marcarse con azul, verde, morado o naranja.
- La selección actual y las marcas usan señales visuales distintas.
- Atajos: `1` azul, `2` verde, `3` morado, `4` naranja, `0` quitar marca.
- Las marcas sobreviven a recargas en el navegador mediante `localStorage`.
- `Crear Flow` permite usar todas las marcas o solo un color.
- Negro valida que las Requests pertenezcan al proyecto actual y crea Steps cronológicamente.

## Calm Security UI
- Contraste suavizado para sesiones largas.
- Pretty reduce peso visual de headers rutinarios (`Accept-*`, `User-Agent`, `sec-ch-*`).
- AUTH/cookies/IDs de contexto conservan mayor jerarquía.
- JWT y valores muy largos se compactan solo visualmente en Pretty; clic copia el valor completo.
- Raw conserva el contenido completo sin compactación.

## Layout de lectura
- Request/Response redimensionables con splitter vertical.
- Doble clic en splitter restaura 50/50.
- Modos `Split`, `Request` y `Response`.
- Context puede ocultarse/mostrarse y recuerda preferencia.
- Related Requests queda como progressive disclosure.
- Focus Mode (`F`) oculta navegación y filtros para concentrarse en Traffic + HTTP + Context.

## Compatibilidad
- No requiere una nueva extensión Burp respecto de v0.112/v0.113.
- Conserva el modelo de scope: Traffic Inbox puede verse pasivamente, pero no habilita acciones activas fuera de proyectos autorizados.
- `core.VERSION` se conserva para compatibilidad con la suite histórica.

## Validación
- Suite completa: 122 tests.
- JavaScript: `node --check web/static/app.js`.
- Python: `py_compile` de `negro_workbench.py` y `negro_web.py`.
