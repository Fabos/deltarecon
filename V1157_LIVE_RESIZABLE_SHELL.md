# Negro v0.115.7 — Live Checkpoint + Resizable Shell

Esta iteración corrige el polling live para que un Event capturado durante una lectura no pueda quedar detrás del cursor del navegador. El endpoint de eventos fija una ventana consistente (`id <= snapshot_max`) antes de consultar.

## UX

- Traffic Inbox puede redimensionarse verticalmente arrastrando el divisor entre Traffic y Request/Response.
- Doble clic en el divisor restaura el tamaño automático.
- El tamaño se recuerda por proyecto.
- Al cerrar Context queda una pestaña vertical visible en el borde derecho para volver a abrirlo.
- `T`, `C` y `F` siguen disponibles.

## Compatibilidad

No cambia el protocolo de la extensión Burp ni el modelo de Flow/Scenario.

## Validación

144/144 tests.
