# Negro v0.115.8 · Immersive HTTP + Inline Semantics

## Objetivo
Convertir HTTP Workbench en el centro operativo de análisis sin duplicar los modelos de Identity, Object, Flow o HTTP Inspector.

## Workspace inmersivo
- Pantalla completa usa todo el `wb-grid`, no solamente el visor HTTP.
- Solo quedan Traffic Inbox + Request/Response.
- Traffic conserva su splitter vertical (altura).
- Request/Response conserva su splitter horizontal (ancho).
- Context se oculta al entrar y puede abrirse como drawer flotante con `C` o la pestaña lateral.
- Al salir se restaura el estado de Context anterior al fullscreen.

## Semántica inline
Los valores estructurados detectados por el mismo parser de HTTP Inspector son interactivos directamente en Pretty.

Desde un valor se puede guardar:
- AUTH → Identity
- RESOLVER → Identity
- CONTEXT → Identity
- OBJECT / ENTITY → Business Object type

La escritura usa `http_inspector.save_annotation` a través del endpoint batch existente; no existe una segunda memoria semántica.

Los Business Objects continúan usando el motor existente, incluyendo relaciones `co_observed` cuando dos Objects aparecen en el mismo exchange.

## Navegación simplificada
Primer nivel:
- Inicio
- HTTP
- Flujos
- Escenarios
- Superficie
- Investigaciones
- Hallazgos
- Más

`Más` conserva las vistas globales: Inventario, Buscar, Identidades, Objetos, Mapa, Hipótesis, Recon, Guía y Ajustes.

No se eliminan rutas ni datos; solamente se reduce ruido de navegación.

## Acciones redundantes eliminadas del Context de HTTP
- Inspector avanzado (la enseñanza semántica principal ya ocurre inline)
- Add to Flow (el flujo principal ahora es marcar Traffic → Crear Flow)

Se mantienen:
- Follow Value
- Replay
- Enviar a Burp Repeater

## Validación
- Suite completa: 146 tests.
- `node --check web/static/app.js`.
- `python -m py_compile negro_workbench.py negro_web.py`.
