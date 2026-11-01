# Context Agent v1.4

El Context Agent convierte tráfico HTTP capturado en memoria semántica persistente sin reemplazar el flujo manual de Negro.

## Scope IA híbrido

Un exchange del proyecto puede entrar al análisis si cumple al menos una de estas condiciones:

- el host pertenece a un scope configurado del proyecto;
- coincide con una regla Host/Endpoint añadida explícitamente desde HTTP Workbench;
- Burp lo reporta como `IN_SCOPE`.

`Burp EXCLUDED` sólo actúa como veto cuando el tráfico no está incluido explícitamente por un root/regla de Negro. El scope explícito de Negro es autoritativo.

La estimación muestra cuántas observaciones entraron por cada fuente y los principales hosts que quedaron fuera del gate.

## Semantic Gate

Todas las observaciones permanecen en el ledger local. No todas consumen IA. El gate prioriza señales de negocio, identidad, credenciales, referencias, estados, acciones, propagación response→request, reutilización entre endpoints, Flows, marcas manuales y memoria semántica existente. Ruido de transporte/estáticos puede quedar diferido y despertar en un run posterior si gana evidencia.

## Costos y completitud

- costos y presupuesto se muestran primero en COP;
- el presupuesto es hard-stop, no recorte de contexto;
- no existe cap fijo de candidatos;
- análisis grandes se procesan por batches;
- un run completo debe reportar `coverage = 100%` y `truncated = false`;
- si un batch falla, el costo consumido se registra y la memoria parcial no se presenta como completa.

## Incremental

Los runs normales usan delta + impact graph. Se reenvía tráfico nuevo y el contexto histórico afectado, incluyendo relaciones cercanas, cambios de Flow y marcas manuales, sin reanalizar indiscriminadamente todo el target.
