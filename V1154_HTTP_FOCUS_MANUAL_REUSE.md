# Negro v0.115.4 — HTTP Focus + Manual Input Reuse

## HTTP Workbench
- El panel central gana prioridad visual: Traffic Inbox y Context ocupan menos ancho por defecto.
- Traffic Inbox puede ocultarse/restaurarse sin perder el estado.
- Context sigue siendo colapsable.
- Pantalla completa real para Request/Response.
- Pretty mantiene ajuste de línea por defecto y permite alternar `Líneas exactas` / `Ajustar líneas` de forma independiente en Request y Response.
- Raw continúa representando el HTTP exacto.

## Flow data wiring
Una variable ahora se entiende como **origen + uno o varios destinos**.

### Input manual reutilizado
Un parámetro de Request puede:
1. pedirse una sola vez al ejecutar;
2. reemplazar el parámetro del Step actual;
3. opcionalmente reutilizar el mismo valor en un parámetro de la siguiente Request.

### Input manual inyectado
También se puede crear un valor que no venga de Request/Response previos:
1. Negro lo pide al ejecutar;
2. el valor se inyecta directamente en el parámetro elegido del siguiente Step.

Los Escenarios heredan estas conexiones del Flow.
