# v0.116.6 — LIVE detail hydration

Corrige un bug del HTTP Workbench donde las filas nuevas sí aparecían en `Traffic Inbox`, pero al hacer clic inmediatamente Request/Response podían quedar vacíos hasta recargar la página.

## Causa

Cuando el Workbench se abría sin una Request seleccionada, el HTML inicial sólo contenía el mensaje de estado vacío. Los contenedores reales de Request, Response y Context no existían todavía, así que el fetch LIVE no tenía dónde renderizar el detalle.

## Ajuste

- El shell de detalle queda montado desde el primer render, incluso sin selección inicial.
- Una fila LIVE puede hidratar Request, Response y Context sin reload.
- El detalle reintenta brevemente respuestas `404` transitorias para cubrir el instante entre captura y disponibilidad del detalle.
- El resumen dinámico también actualiza `exchange #` y tamaño de response.
