# Negro Recon — Metodología v0.41.5


## v0.41.5 — El grafo abre preguntas, no cierra conclusiones

Discovery diferencia tres niveles que no deben mezclarse:

```text
Observado       = existe evidencia HTTP concreta.
Contraste       = dos observaciones del mismo contexto difieren de forma relevante.
Rama no probada = existe una operación relacionada, pero aún no fue observada bajo ese actor/contexto.
```

Ejemplo: si Buyer B recibió `403` leyendo una Order de Buyer A y también existe `change-address`, Negro puede recordar que esa escritura todavía no fue comparada bajo B. Sólo cuando haya evidencia real de una mutación 2xx puede mostrar el contraste `lectura denegada / escritura aceptada`. Ninguno de los dos casos crea una vulnerabilidad automáticamente.

La relación **owner observado** exige provenance explícita: un campo owner-like co-observado y una correspondencia única con una Identity/resolver conocido. `Actor` significa quién originó una Request según auth material/resolver aprendido; no implica ownership.

Una Identity se enseña una vez con evidencia confiable. Cookies/tokens/resolvers compatibles deben resolver automáticamente tráfico histórico y futuro para evitar trabajo administrativo; el usuario conserva una acción de recalcular como fallback.

En Discovery, **key** y **value** responden preguntas diferentes:

- seguir una `key` pregunta dónde se usa ese concepto, con cualquier valor;
- seguir un `value` pregunta dónde reaparece la misma pieza, aunque cambie el nombre del campo.

El panel lateral debe conservar siempre provenance a las Requests que justifican cada relación.

---

## v0.41 — Regla → Signal; pregunta elegida → prueba

La semántica queda estricta:

```text
Regla ──match──> Signal

Idea IA ──decisión humana──┐
                           ├─> Hipótesis ─> prueba manual / Runner ─> Finding o nada
Pregunta propia ───────────┘
```

No existe “Signal manual”. Una observación humana que quieres recordar debe convertirse en **Regla** si deseas que Negro la vigile, o en **Hipótesis** si ya es una pregunta que vas a testear. Descartar una Signal conserva su evidencia y decisión humana.

El transporte recomendado del Runner es Burp Bridge: el replay debe recorrer la misma pila de red de Burp siempre que Burp sea la fuente del tráfico original. Un fallo de DNS/TCP/TLS/proxy/timeout es diagnóstico de ejecución, no comportamiento del aplicativo.


## v0.40 — Evidence → AI Idea → decisión humana → prueba válida

La primera prueba real confirma una separación metodológica estricta:

```text
Signal = evidencia observable
  ↓
AI Idea = pregunta sugerida
  ↓
Hypothesis = algo que el humano decide perseguir
  ↓
Runner / Run = prueba
  ↓
Finding / Discarded = decisión humana
```

Una **AI Idea** existe antes de Hypothesis y conserva el contexto que la originó. Guardar, posponer o descartar una idea forma parte de la memoria; la IA debe conocer lo ya propuesto/probado para no repetir automáticamente la misma línea.

Una **Investigation** es el workspace que reúne las piezas sin confundirlas: “Contexto conocido” representa hechos/evidencia; “Qué estoy investigando” representa Hypotheses elegidas; “Pruebas realizadas” representa Runners/Runs; “Ideas de la IA” conserva propuestas; Findings reflejan decisiones finales.

### Transporte no es comportamiento del aplicativo

Un Run sólo cuenta como prueba si llegó al objetivo con una respuesta clasificable como `application_response`. DNS, TLS, timeout, proxy/gateway y errores internos del Runner son **historial de ejecución**, no evidencia de seguridad del aplicativo. Se conservan para diagnóstico y retry, pero no alimentan coverage ni permiten declarar una Hypothesis negativa.

La captura original y el replay pueden recorrer redes distintas. Runner debe declarar su modo de transporte, respetar `Host`/SNI y ofrecer diagnóstico explícito antes de interpretar errores de conectividad como comportamiento de negocio.

### El contexto genera interés compuesto

Negro intenta que evidencia ya observada gane valor cuando aparecen nuevas relaciones, sin afirmar que “nada puede pasar desapercibido”. Contexto y decisiones humanas se conservan; el ruido también puede acumularse, por lo que la UI debe capturar mucho pero destacar poco.

## v0.39 — Flow → pregunta → Hypothesis → Runner → evidencia

El Flow describe el proceso observado. La IA puede ayudar a formular preguntas específicas de lógica de negocio usando el HTTP real sanitizado y el historial de lo ya probado. La IA es un **copiloto de pensamiento**, no un ejecutor: propone preguntas y borradores, pero el investigador decide qué guardar, configurar y ejecutar.

Un **Runner** es un experimento reproducible con alias propio. Parte del Flow normal, modifica sólo lo necesario (omitir/repetir pasos, variar un valor o reutilizar datos de una Response anterior) y registra cada Run. Los outcomes humanos y el HTTP acotado de Runs previos se incluyen en futuros análisis para no repetir ideas negativas y aprovechar nueva evidencia.

```text
Flow baseline
  ↓
Explorar lógica
  ↓
Pregunta / Hypothesis
  ↓
Runner revisado por humano
  ↓
Run secuencial
  ↓
Request/Response → Signals / Objects / memoria
  ↓
Flow resultante → Compare con baseline
```

Runner no es un clon de Intruder: no hace fuzzing masivo, brute force ni concurrencia. Su propósito es quitar trabajo tedioso de experimentos de lógica de negocio manteniendo contexto, trazabilidad y límites explícitos.


## v0.38 — Menos reglas de fábrica, mejor mesa de trabajo HTTP

Negro evita convertir su catálogo en un scanner enciclopédico. Por defecto sólo conserva una Regla integrada como ejemplo pedagógico. El conocimiento de técnicas se incorpora mediante Reglas explícitas cuando el investigador lo necesita, manteniendo la relación simple `Regla → Señal → Hipótesis → validación`.

La página de endpoint es la mesa de trabajo principal: primero la evidencia HTTP completa, luego Signals/Hipótesis y finalmente memoria/hallazgos. Una Request exacta repetida no debe ocupar N tarjetas; se conserva una variante y se agrega su procedencia por herramienta Burp. Intruder puede generar muchas variantes, por lo que la interfaz muestra un resumen y una ventana acotada sin borrar la evidencia persistida.

## v0.37 — Regla, Señal y memoria temporal

El modelo mental principal es:

```text
Regla → coincidencia → Señal → Hipótesis → prueba humana → Hallazgo
```

- **Regla**: algo que Negro debe vigilar o evaluar. Puede ser una key, valor exacto, regex o combinación de contexto.
- **Señal**: hecho observado cuando una Regla coincide; conserva procedencia y no implica vulnerabilidad.
- **Hipótesis**: pregunta/escenario comprobable que el investigador o la IA formula usando una o varias evidencias.
- **Hallazgo**: sólo existe después de validación humana suficiente.

Toda Regla activa cubre tres tiempos: **pasado** (revisión automática de evidencia local existente), **presente** (Señales surgidas de esa reinterpretación) y **futuro** (evaluación incremental de nuevas Requests/JavaScript). Revisar el pasado nunca hace nuevas peticiones al target.

Una Regla puede crearse desde una Request, desde una Hipótesis o desde el catálogo de Reglas. El motivo/notas se conservan para que una coincidencia futura recuerde *por qué* se estaba buscando esa pieza.


## v0.36 — Memoria de investigación y correlación

Negro diferencia cuatro cosas: **memoria** (hechos indexados que no generan alertas por sí solos), **Signal** (una Regla coincidió), **Context Match** (apareció información relacionada con algo pendiente) e **Hypothesis** (una pregunta de investigación). Los identificadores observados se recuerdan por key + valor + Request + host + Identity + Flow y se marcan como `input` u `output` según su ubicación real.

Una Hypothesis puede declarar una pieza pendiente. Si esa pieza aparece más adelante o ya existía en evidencia histórica, Negro crea un **Context Match** y enlaza la evidencia; no afirma que exista una vulnerabilidad. Por compatibilidad histórica, el registro técnico puede reutilizar `signal_occurrences`, pero la UX no lo presenta como Signal. La correlación se procesa incrementalmente y con índices, evitando comparaciones globales O(n²).


## Modelo mental

`Regla → Señal → Hipótesis → Investigación humana → Hallazgo/cierre`

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
Descubrir  → ¿dónde más reaparece esta pieza? → key/valor → endpoints → identidades/Flows/objetos
Atención   → ¿qué merece volver a mirar?     → bandeja corta
```


### Grafo de descubrimiento

Desde v0.41.4 el grafo también puede empezar por una **pieza**, no sólo por una entidad ya entendida. `Descubrir` acepta una key o valor observado y expande únicamente relaciones respaldadas por evidencia persistida. Si un valor sale bajo `orderId` y más tarde entra como `sourceOrderId`, Negro puede mostrar ese puente sin asumir causalidad ni vulnerabilidad. Keys identificadoras vistas cerca se ofrecen como pivotes para abrir otra rama, pero nunca se convierten automáticamente en Entity, Hypothesis o Finding.

La regla visual es: **el grafo debe abrir preguntas, no cerrarlas**. Un nodo seleccionado es una puerta a `dónde más aparece`, `con qué identidades`, `en qué Flows`, `bajo qué aliases` y `qué otros identificadores aparecen alrededor`.

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


## Burp como superficie de contexto · v0.43

Burp sigue siendo la superficie principal de manipulación HTTP; Negro evita obligar al hunter a cambiar de herramienta sólo para conservar memoria. El menú `Negro → Contexto` permite asociar la Request actual a Investigation/Hypothesis, convertir una observación en Entity, seguir key/valor, crear Watches y dejar notas.

Regla conceptual:

- **Signal** sigue naciendo exclusivamente de una Regla.
- **Context Match** nace de un Watch y requiere revisión humana.
- **Hypothesis** sigue siendo una pregunta que el hunter decidió perseguir.
- Las acciones contextuales de Burp **referencian** la evidencia existente; no crean una segunda copia del HTTP.
- Las notas `INV/HYP/CTX/FIND` visibles en Burp son memoria de contexto, no verdicts de seguridad.


## Replay as Identity · v0.44

**Manual cuando importa, automatizado donde ahorra trabajo, siempre preservando contexto.**

Replay as Identity responde una pregunta puntual: “esta Request me genera duda; ¿qué pasa si la ejecuto como otra Identity?”. No es Autorize ni un scanner automático. El hunter elige Request, Identity y momento.

Reglas metodológicas:
- Cambiar auth no significa cambiar el Business Object. `Order 123` debe seguir siendo `Order 123` al usar Identity B.
- Revisar siempre la Request preparada antes de enviarla.
- GET/lectura suele ser replay-safe; POST/PUT/PATCH/DELETE se advierten como state-changing. Operaciones one-shot se tratan como state-dependent.
- `409 already confirmed`, token consumido o estado incompatible = **Estado inválido / Inconcluso**, no “autorización protegida”.
- Runner prepara estado cuando hace falta; Replay ejecuta la prueba manual puntual.
- Replay no entra al discovery normal ni crea Flow Capture de navegación humana.
- Un 2xx no es vulnerabilidad. Ownership, Identity, estado e impacto deben sostener la conclusión.

## Modo de producto después de v0.44

Negro entra en uso real. Nuevas capacidades deben justificar que eliminan trabajo repetitivo o conservan contexto que hoy se pierde. Las reglas/Signals se amplían conforme se estudian vulnerabilidades **sólo cuando existe un patrón observable y automatizable con una tasa de ruido aceptable**. La lógica de negocio que dependa de intención o semántica permanece como Hypothesis/Investigation/Runner.
