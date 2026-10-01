# Negro Recon — Metodología v0.30.0

## Modelo mental

`Rule → Signal → Hipótesis IA → Investigación humana → Finding/cierre`

Negro organiza evidencia y relaciones. No intenta decidir automáticamente qué es vulnerable.

## Cómo no perderse en Negro

Desde v0.28 cada pantalla principal incluye ayuda contextual. Desde v0.30 las Investigation Views usan una visualización distinta según la pregunta: timeline para Flow, grafo focal para Identity/Object, mapa para Surface y bandeja reducida para Attention. La UI llama **Request** a cada llamada HTTP observada (aunque internamente se conserve `exchange_id`). La ruta recomendada es pensar primero en la pregunta, no en el nombre del módulo:

```text
¿Qué existe?              → Inventario / Host tools
¿Dónde aparece esta pista?→ Search / Follow Value / Find Related
¿Quién hizo esto?         → Identity / Authorization Matrix
¿Qué cambió entre A y B?  → Smart Compare
¿Qué secuencia ocurrió?   → Flows / Business State
¿Cuál es la misma cosa?   → Business Objects
¿Qué merece probarse?     → Signals / Hunt
¿Qué confirmé?            → Findings
```

El Access Control Lab se usa como ejemplo común en la guía para separar `Ana` (Identity), `Order 123` (Business Object) y `ownerId=101` (propiedad/ownership).


## Investigation Views / Map 3.0

Responde visualmente distintas preguntas sin duplicar los datos:

```text
Superficie → ¿qué existe y dónde?           → mapa/árbol
Identidad  → ¿quién hizo qué?                → grafo focal
Flow       → ¿qué ocurrió y en qué orden?    → timeline
Objeto     → ¿qué sabemos de esta cosa?      → grafo focal
Atención   → ¿qué merece volver a mirar?     → bandeja corta
```

Los Identity Contexts son dinámicos: el mapa usa los nombres reales definidos en el proyecto. No existe lógica fija para Buyer A/B, seller o admin.

Desde una Request, Identity, Flow, Object o Finding se puede entrar con **Ver en mapa**. Focus Mode reduce la escena al contexto relevante y permite expandir 1 o 2 saltos. **Camino** calcula el trayecto más corto entre dos nodos usando sólo las relaciones observadas en la escena actual.

La visualización es una herramienta de comprensión. No todo conocimiento debe dibujarse: Negro conserva evidencia técnica, pero sólo muestra por defecto lo que ayuda a responder la pregunta actual. Una línea significa relación observada, no causalidad, ownership ni vulnerabilidad.

## Buscar

**Buscar** responde: **¿dónde aparece esto?**

Texto libre encuentra fragmentos en tráfico y conocimiento. Si una coincidencia también existe como observación estructurada, Search ofrece acciones de correlación sin obligarte a entrar primero a Parameter Explorer.

## Follow Value

Responde: **¿dónde reaparece exactamente este valor?**

Seleccionas un valor concreto y Negro sigue su hash exacto por requests, responses, paths, endpoints o hosts. Si `diego@example.test` aparece como `email` en un login y luego en `/me`, Follow Value muestra ambas apariciones.

## Find Related Request

Responde: **¿qué otras Requests comparten evidencia con esta Request completa?**

Toma los valores útiles de request + response de la Request de origen y busca coincidencias exactas en otras Requests. Valores genéricos, booleanos y atributos muy comunes se penalizan; `mismo host` por sí solo no genera una relación. `OPTIONS` se oculta cuando no es relevante.

Una relación no significa “mismo objeto”, “mismo usuario” ni vulnerabilidad. Es una pista de correlación que debe ser interpretada con su path y nombre de campo.

## Smart Compare

Responde dos preguntas distintas:

1. **¿Qué coincide entre A y B?**
2. **¿Qué cambia entre A y B?**

La sección de coincidencias compara observaciones por valor exacto. Si el mismo valor aparece con nombres distintos, Negro lo marca como **posible alias**:

```text
A: response_json:$.user.id · id = 102
B: response_json:$.memberId · memberid = 102
```

Eso es evidencia de igualdad del valor, no de equivalencia semántica. Después, la sección de cambios muestra diferencias de HTTP, query, JSON y headers, priorizando campos de negocio.

## Identity Contexts

Responde: **¿quién hizo este tráfico?**

Negro separa Identity, Context, Auth Material y Resolver. La primera asociación es humana sobre una Request concreta. Auth Material puede rotar; resolvers estables ayudan a reconocer la misma cuenta en sesiones nuevas.

La separación crítica es **actor vs ownership**:

- `/me.id=101`, `/me.email=...`, `jwt:sub=101` pueden resolver al actor;
- `order.ownerId=101` describe el objeto y no demuestra quién hizo la request.

La Authorization Matrix es descriptiva: sólo muestra lo que Burp observó bajo cada identidad. `No observado` significa únicamente ausencia de evidencia.

## Flow Workbench

Responde: **¿qué historia de negocio forman varias Requests?**

Un Flow es una secuencia manual/observada, por ejemplo:

```text
POST /auth/login
POST /cart
POST /checkout
POST /payment
GET  /orders/{id}
```

Puedes capturar un rango de Requests o agregarlos uno por uno. El orden se conserva y cada paso enlaza al HTTP exacto.

### Business states

El hunter enseña una definición ligada a una instancia, por ejemplo `Order = orderId + status`. Negro conserva las observaciones exactas de cada `Order` y puede mostrar `CREATED → PAID → SHIPPED` con sus Requests e identidades. Las pistas adyacentes genéricas siguen existiendo sólo como ayuda hasta que el objeto quede definido.

### Flow Compare

Dos flows se alinean por método + ruta normalizada. La comparación muestra pasos iguales/ausentes/cambiados y, para pasos alineados, reutiliza Smart Compare para exponer coincidencias y cambios de negocio.

Ejemplo de uso:

```text
Flow A: cart → payment → order
Flow B: cart → order
```

La ausencia de `payment` en B es una diferencia de recorrido que merece entenderse, no una vulnerabilidad automática.

## Business Objects

Responde: **¿dónde viaja la misma instancia y qué objetos aparecen relacionados con ella?**

Un tipo puede tener aliases explícitos, por ejemplo `Order: orderId` y `Order: order_id`. Negro unifica instancias por tipo + valor exacto, por lo que `Order 98127` puede aparecer en `api`, `payments` y `shipping` sin perder el hilo. Las relaciones `Order ↔ Payment` o `Order ↔ Shipment` significan únicamente que fueron co-observadas en exchanges; no prueban causalidad.

**Pattern Anomalies** compara sólo contra patrones ya repetidos de status HTTP por Identity + operación normalizada, relaciones, identidades o hosts. Una diferencia sólo significa “esto se comportó distinto de sus pares observados”.

## Mapa mental de módulos

```text
Buscar
  ↓
Follow Value        (un valor exacto)
  ↓
Find Related        (todo un exchange)
  ↓
Smart Compare       (coincidencias + diferencias entre A/B)
  ↓
Identidades         (actor/sesión)
  ↓
Flows               (secuencia de negocio)
  ↓
Business Objects    (instancias + relaciones + cross-host)
  ↓
Signals / IA / Investigaciones
```

## Principios

- Un Signal no es una vulnerabilidad.
- Correlación no es causalidad ni equivalencia semántica.
- La IA no corre por request; el usuario decide cuándo razonar.
- Finding y Discarded siguen siendo decisiones humanas.
- Evidencia histórica y retest actual son conceptos distintos.
- Negro debe reducir ruido y conservar procedencia exacta, no esconder datos útiles del hunter local.
