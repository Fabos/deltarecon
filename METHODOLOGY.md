# Negro Recon — Metodología v0.35.0

## Modelo mental

`Rule → Signal → Hipótesis IA → Investigación humana → Finding/cierre`

Negro organiza evidencia y relaciones. No intenta decidir automáticamente qué es vulnerable.

## Cómo no perderse en Negro

Desde v0.28 cada pantalla principal incluye ayuda contextual. En v0.32 las Investigation Views pasan a un modelo **graph-first cuando la relación visual aporta valor**: Identity compara cuentas/sesiones contra endpoints, Object parte del objeto focal hacia los endpoints donde apareció, Flow permite grafo o timeline, Surface conserva su mapa/árbol y Attention sigue siendo una bandeja reducida. No todas las capas se muestran a la vez: objetos, Requests individuales y métodos pueden activarse sólo cuando hacen falta. La UI llama **Request** a cada llamada HTTP observada (aunque internamente se conserve `exchange_id`). La ruta recomendada es pensar primero en la pregunta, no en el nombre del módulo:

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


## Investigation Views / Map 3.2

Responde visualmente distintas preguntas sin duplicar los datos:

```text
Superficie → ¿qué existe y dónde?           → mapa/árbol; métodos opcionales
Identidad  → ¿qué endpoints tocó cada actor? → grafo Identity ↔ Endpoint
Flow       → ¿qué ocurrió y en qué orden?    → grafo o timeline
Objeto     → ¿dónde apareció este valor?     → grafo Object → Endpoint
Atención   → ¿qué merece volver a mirar?     → bandeja corta
```

Los Identity Contexts son dinámicos: el mapa usa los nombres reales definidos en el proyecto. No existe lógica fija para Buyer A/B, seller o admin.

Desde una Request, Identity, Flow, Object o Finding se puede entrar con **Ver en mapa**. Identity/Object son graph-first cuando la relación visual aporta valor. Focus Mode reduce la escena al contexto relevante y permite expandir 1 o 2 saltos. **Camino** calcula el trayecto más corto entre dos nodos usando sólo las relaciones observadas en la escena actual.

La visualización es una herramienta de comprensión. No todo conocimiento debe dibujarse: Negro conserva evidencia técnica, pero sólo muestra por defecto lo que ayuda a responder la pregunta actual. Una línea significa relación observada, no causalidad, ownership ni vulnerabilidad.

### Lectura rápida de autorización en Identity Compare

Un endpoint compartido puede mostrar el resultado observado por cada Identity directamente en su tarjeta:

```text
/orders/4101
Diego · 200    Ana · 403

/orders/4101/invoice
Diego · 200    Ana · 200
```

La segunda fila merece una segunda mirada si rompe el patrón del resto. Negro muestra el hecho; no concluye IDOR ni bypass.

## Custom Signals

Custom Signals son reglas determinísticas enseñadas por el investigador y conectadas al pipeline existente:

`Custom Rule → Signal → Hunt → Hipótesis/Investigación humana`

Pueden combinar método, status, fragmentos de ruta, nombres de parámetros, contenido de Request/Response, headers, Business Objects e Identity presente/ausente. Todas las secciones configuradas deben coincidir; dentro de una sección basta un valor.

Ejemplo:

```text
Identity presente
parameter name: ownerId, *accountId
path contains: /orders/

Sugerencia:
Comparar identidades y usar Follow Value sobre el identificador.
```

La regla se ejecuta sólo sobre evidencia que Negro ya capturó. Puede aplicarse a historial local y al tráfico nuevo. Una coincidencia conserva procedencia exacta en `signal_occurrences`; nunca crea un Finding automáticamente.

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


## Lectura visual v0.33.0

En vistas semánticas, Negro prioriza tres conceptos: **Identity (quién)**, **Endpoint (qué ruta)** y **Flow (qué historia)**. Business Objects aparecen como contexto y Requests/Métodos se revelan bajo demanda. Cuando se comparan dos identidades, el investigador puede aislar endpoints compartidos o exclusivos; esto es una ayuda de navegación y no una afirmación de vulnerabilidad. Relaciones repetidas se agrupan visualmente, conservando la evidencia original debajo.

## Mapa con inteligencia y Hypothesis Engine 2.0

Una ruta resaltada no significa vulnerable. El mapa sólo indica que Negro ya tiene inteligencia asociada a esa evidencia: un **Signal** determinístico, una **Hypothesis** activa, o ambos. Desde el detalle se debe poder volver a la evidencia exacta en Hunt.

El motor 2.0 intenta formular mejores preguntas combinando capas que antes estaban aisladas: quién hizo la Request (Identity), en qué historia ocurrió (Flow), qué cosa del negocio tocó (Object/State), qué regla hizo match (Signal), qué patrón se desvió (Anomaly) y cómo variaron respuestas entre identidades. La conclusión sigue siendo humana: confirmar manualmente, medir impacto y sólo entonces crear un Finding.
