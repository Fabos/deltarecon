# Negro Recon v0.16.2

Hotfix de observabilidad para el hand-off Negro → Burp Repeater.

## Cambios

- Los botones **Enviar a Repeater** y **Enviar esta solicitud a Repeater** usan un envío AJAX observable en la propia interfaz.
- El usuario ve inmediatamente si la solicitud quedó encolada, el `queue_id` y cuántos bytes de request se enviaron a la cola.
- El backend registra con `flush=True` el inicio del submit, errores CSRF y la creación efectiva del item en la cola.
- El endpoint de envío devuelve JSON cuando la llamada viene desde la UI de Negro, en vez de depender de un redirect silencioso.
- Nuevo endpoint local de diagnóstico: `GET /api/bridge/repeater/status`, con contadores de items `pending/claimed/done/error` y los últimos estados, sin incluir cuerpos HTTP.
- El bridge de Burp registra que el poller está activo, cuándo recibe un item pendiente y qué `queue_id` reclama antes de reconstruir la request.
- Assets estáticos usan `?v=<version>` para evitar que el navegador reutilice JavaScript/CSS de una versión anterior tras una actualización.

## Objetivo

Distinguir claramente entre cuatro fallos posibles: UI que no encola, backend que no crea la cola, bridge que no reclama el item o Montoya que no logra abrir la request en Repeater.
