# Context Agent v1.6

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


## Compresión semántica

El ledger conserva cada instancia concreta. Antes de llamar al modelo, Negro agrupa instancias equivalentes en **concept clusters** usando la key normalizada, la ubicación HTTP y, para campos genéricos como `id`, la familia del endpoint. El LLM interpreta el concepto una vez y Negro proyecta el resultado de vuelta a cada instancia. Esto reduce tokens por redundancia sin eliminar evidencia ni aplicar un cap de candidatos.


## Semantic Preflight v1.6

Antes del LLM, Negro aplica una capa de costo/ruido que **no borra evidencia**:

- endpoints de logging/telemetry/collect/metrics repetitivos pueden quedar dormidos cuando no tienen Flow, propagación, memoria previa ni señales de auth/negocio;
- un valor dormido despierta si posteriormente aparece en otro endpoint, pasa response→request, entra a un Flow, recibe una marca manual o se conecta al grafo;
- aliases contextuales (`fromMemberId`, `toMemberId`, `memberId`) pueden compartir una familia semántica, conservando sus roles y todas las instancias locales;
- campos genéricos (`id`, `status`, etc.) siguen acotados por endpoint/Flow para evitar fusiones peligrosas;
- Flows y valores producidos→consumidos reciben prioridad al seleccionar evidencia representativa.

## Routing de modelos

El modo recomendado es `Luna → Sol selectivo`:

1. **GPT-6 Luna** analiza el 100% de las familias semánticas. Cada familia debe devolver una inferencia; `unknown` es válido y preferible a inventar.
2. **GPT-6.1 Sol** sólo revisa una reserva pequeña de casos ambiguos, conflictos con memoria previa, relaciones inciertas y posibles authorization boundaries.
3. Ninguna familia se elimina para ahorrar costo: Sol es una segunda opinión, no un reemplazo del análisis base.
4. La estimación separa costo Luna, reserva Sol, costo esperado y máximo. El presupuesto sigue siendo un hard-stop.
