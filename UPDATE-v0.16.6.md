# Negro Recon v0.16.6

## Repeater bridge — parser robusto para items grandes

Corrige un fallo del bridge al consumir `/api/bridge/repeater/next` cuando `request_b64` contiene varios KB.

### Causa raíz

El bridge parseaba campos JSON con una expresión regular recursiva. Con strings largos (por ejemplo `request_b64` de una request real) el motor regex de Java podía lanzar `StackOverflowError`. Como el poller corre en `ScheduledExecutorService`, una excepción no controlada cancelaba silenciosamente las futuras ejecuciones. El síntoma visible era:

- `pending=true`
- `item pendiente recibido del backend`
- y luego ningún log adicional ni nueva consulta del poller.

### Cambios

- El protocolo local ahora usa un parser iterativo y no recursivo para strings, enteros y booleanos JSON.
- El poller captura también `Throwable` como última barrera de diagnóstico para que una falla inesperada no mate el scheduler en silencio.
- Se conserva el envío exacto del `request_b64` a Repeater y los logs de `claim`, bytes reconstruidos y ACK.
- Bridge/backend etiquetados como v0.16.6.

### Verificación local

Se reprodujo el fallo del regex anterior: con ~3 KB de contenido ya puede disparar `StackOverflowError` en Java. El parser nuevo se probó con un campo de 200 KB sin recursión.
