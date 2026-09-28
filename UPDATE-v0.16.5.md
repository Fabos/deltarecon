# Negro Recon v0.16.5

## Repeater bridge: orphan poller fix

Se corrigió la causa raíz de las solicitudes enviadas desde Negro que quedaban en `claimed` sin aparecer en Burp Repeater.

Las versiones anteriores iniciaban un `ScheduledExecutorService` para consultar `/api/bridge/repeater/next`, pero no registraban un `ExtensionUnloadingHandler`. Al quitar/reemplazar el JAR en Burp, el hilo del bridge anterior podía seguir vivo en segundo plano y reclamar elementos de la cola antes que la extensión visible.

### Cambios

- El bridge registra un `ExtensionUnloadingHandler` y detiene su poller/timer al descargarse.
- Cada instancia del bridge usa un UUID propio (`X-Negro-Bridge-Id`).
- `/api/bridge/repeater/next` rechaza clientes antiguos sin identificador, por lo que pollers huérfanos de v0.16.4 o anteriores ya no pueden consumir la cola.
- El backend mantiene una lease corta de consumidor único para evitar que dos bridges actuales compitan por la misma cola.
- `/api/bridge/repeater/status` muestra la instancia activa y cuándo fue vista por última vez.
- Los logs de Burp incluyen el id corto de la instancia para detectar duplicados.

### Nota de actualización

Después de instalar v0.16.5 se recomienda reiniciar Burp una vez para matar definitivamente cualquier hilo huérfano creado por versiones anteriores. El backend v0.16.5 ya impide que esos hilos reclamen nuevos items incluso antes del reinicio.
