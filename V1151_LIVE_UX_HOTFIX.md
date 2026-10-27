# Negro v0.115.1 — Live UX Hotfix

## Cambios

- El Traffic Inbox muestra una previsualización compacta de parámetros de request (query, JSON, form y multipart) usando `value_preview`.
- JWT Inspector abre incluso cuando el header/payload no puede decodificarse completamente; el JWT completo siempre queda disponible.
- El seguimiento del tráfico pasa a ser explícito con `Seguir LIVE`.
- Seleccionar una request congela la posición; las nuevas capturas se acumulan en `↓ N nuevas`.
- `Seguir LIVE` o el botón de nuevas requests devuelve al presente.
- El contador de nuevas refleja la vista filtrada cargada en el Workbench.

La extensión de Burp no cambia.
