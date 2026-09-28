# Negro Recon v0.16.4

## Repeater Bridge: fast poll fix

- `/api/bridge/repeater/next` deja de llamar `ensure_workspace()` cada segundo.
- El poll usa `workspace_paths()` y abre directamente el SQLite ya existente.
- El cleanup de claims vencidos se ejecuta como máximo cada 30 s.
- Se agregan logs `[repeater-next] ... elapsed_ms=...` cuando hay item o el poll es lento.
- El cliente Java amplía el timeout del poll de 3 s a 10 s como margen defensivo.
- Evita `CancelledError`/HTTP 500 observados en workspaces grandes.
