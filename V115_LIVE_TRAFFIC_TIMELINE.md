# Negro v0.115 — Live Traffic Timeline

Esta iteración convierte HTTP Workbench de una vista de exchanges deduplicados en una timeline de capturas reales.

## Modelo

- `http_exchanges` sigue siendo la memoria deduplicada/correlacionable de Negro.
- `workbench_capture_events` registra cada ocurrencia real enviada por Burp.
- Cada Capture Event tiene un `event_id` global, secuencial y estable.
- Dos requests idénticas pueden apuntar al mismo exchange pero aparecen como dos eventos distintos.
- El historial previo a v0.115 se migra una sola vez como eventos sintéticos ya vistos. No es posible reconstruir retroactivamente cada repetición histórica que había sido deduplicada.

## Timeline en vivo

- Orden visual: más antiguo arriba, más nuevo abajo.
- Polling local ligero (~700 ms) sin recargar la página.
- Si el operador está al final, la vista sigue el tráfico nuevo.
- Si está leyendo tráfico anterior, el scroll no se mueve y aparece `↓ N nuevas`.
- Los eventos nuevos se marcan como no vistos hasta abrirlos.
- Se puede marcar todo lo capturado hasta el cursor actual como visto.

## Checkpoints

Los checkpoints nuevos guardan `cutoff_event_id`, por lo que “Desde checkpoint” equivale exactamente a `event_id > cutoff_event_id`. Los checkpoints antiguos siguen siendo compatibles mediante su timestamp.

## Flow desde marcas

Las marcas del Workbench ahora referencian Capture Events, no exchanges. Al convertir marcas en Flow se respeta el orden de eventos y se conservan ocurrencias repetidas del mismo exchange.

## JWT Inspector

En Pretty, un JWT compacto abre un visor dedicado con:

- token completo y botón Copiar;
- Header;
- Claims;
- humanización de `iat`, `exp` y `nbf`;
- estado temporal orientativo;
- indicación explícita de que decodificar no verifica la firma;
- indicador de presencia de signature.

Raw continúa mostrando los bytes/texto persistidos sin compactación visual.

## Compatibilidad

No requiere una nueva versión de la extensión Burp posterior a la usada con v0.112. El cambio ocurre en backend/Workbench.
