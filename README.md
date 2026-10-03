# Negro Recon 🐕 — v0.41.0


## v0.41.0 — Signal desde Regla + Burp-native Runner + HTTP Workbench

La segunda prueba real corrige dos decisiones de modelo y una diferencia de transporte. **Signals no se crean manualmente:** sólo nacen cuando una Regla coincide con evidencia. Desde una Request puedes crear una Regla, Entity, Hipótesis, Runner, adjuntar una Investigación o un Finding. Una Hipótesis es siempre una pregunta que el investigador decidió perseguir; puede nacer directamente del humano o de una Idea IA que el humano convirtió explícitamente.

El flujo operativo queda:

```text
Regla → Signal automático
Idea IA / pregunta propia → Hipótesis humana → prueba manual o Runner → Finding o nada
```

### Runner usa Burp como transporte recomendado

El modo por defecto es `burp_bridge`: Negro entrega la Request exacta al **Negro Burp Bridge v0.27.0+** y Burp la envía con su propia pila DNS/TCP/TLS/upstream proxy. Esto elimina la divergencia `Browser → Burp → target` frente a `Python/container → target` que seguía causando errores de transporte en labs accesibles desde Burp. Los transportes Python directo/entorno/proxy continúan disponibles como fallback explícito.

Un fallo de transporte corta el Run secuencial en el primer punto no válido, se conserva con diagnóstico por intento y nunca cuenta como cobertura o resultado negativo.

### Request Workbench

Request/Response completas siguen siendo el centro. La lectura HTTP añade tipografía monoespaciada más cómoda, números de línea y resaltado ligero de método/ruta/status, headers, keys JSON/form, strings/números y headers sensibles; la búsqueda local mantiene el resaltado sin perder sintaxis.

---

## v0.40.0 — Investigation Workspace + AI Ideas persistentes + transporte confiable

La primera prueba real de `Flow → AI Ideas → Runner` cambió el foco de esta versión: Negro separa con más rigor **evidencia, preguntas, decisiones humanas y ejecución válida**. El modelo operativo queda como `Signal → AI Idea → Hypothesis → Runner/Run → Finding/Discarded`, sin promociones automáticas a vulnerabilidad.

### Request Workbench como punto de decisión

Desde una Request exacta se puede reutilizar el contexto existente para crear una **Entity/Objeto de negocio**, una **Signal manual**, una **Hypothesis**, un **Runner**, adjuntar/crear una **Investigation** y crear/adjuntar un **Finding**. Los candidatos de Entity se sugieren a partir de parámetros y HTTP observado (`userId`, `username`, `email`, `orderId`, etc.); el investigador decide qué representa cada Entity y la observación conserva provenance al exchange original.

### Signal conserva la decisión humana

Una Signal puede marcarse **Interesante**, **Investigar** o **Descartar**. Descartar nunca elimina evidencia: se conserva fecha, motivo humano, provenance y el número de observaciones conocidas al tomar la decisión. Si aparece evidencia posterior, Negro puede indicar que existe información nueva para reconsiderarla.

### Investigation es un workspace propio

Cada Investigation dispone de `/investigations/:id` y separa visualmente:

- **Contexto conocido**: Entities, Identities, Signals, Flows, Requests/Responses y evidencia relacionada.
- **Qué estoy investigando**: Hypotheses activas.
- **Pruebas realizadas**: Runners y Runs.
- **Ideas de la IA**: historial persistente por generaciones.
- **Decisiones finales**: Findings y cierres humanos.

La UI deja de mezclar “lo que sabemos” con “lo que decidimos perseguir”.

### AI Ideas existen antes de Hypothesis

Las ideas generadas por **Explorar lógica** son objetos persistentes con pregunta, explicación, hechos/incógnitas, contexto usado, Flow/Investigation de origen, generación, fecha y estado (`new`, `saved`, `investigating`, `dismissed`, `postponed`, `converted_to_hypothesis`). Una idea descartada sigue siendo memoria y futuras generaciones reciben esa historia para evitar repeticiones exactas salvo que haya nueva evidencia que justifique reconsiderarla.

### Un Run fallido no es evidencia del aplicativo

Runner separa el resultado de transporte del resultado de seguridad: `application_response`, `transport_error`, `timeout`, `dns_error`, `tls_error`, `proxy_error` y `runner_error`. Sólo `application_response` entra como evidencia HTTP canónica y puede contar como prueba. Un Run de transporte fallido permanece en historial, no cubre la Hypothesis, no puede marcarse como negativa y ofrece **Reintentar**.

El transporte del Runner ahora es explícito (`direct`, `environment` o proxy configurado), preserva semántica de `Host`/SNI, permite TLS/CA/timeout configurables y ofrece diagnóstico DNS/TCP/TLS/proxy sin contaminar la evidencia del proyecto.

> **El contexto genera interés compuesto.** Negro conserva contexto amplio, pero sólo promueve atención cuando existe evidencia o una decisión humana que lo justifique.

## v0.39.0 — Flow Intelligence + Runner

Negro puede convertir un **Flujo observado** en una biblioteca de experimentos reproducibles de lógica de negocio. El botón **🧠 Explorar lógica** analiza bajo demanda la secuencia real del Flujo, Requests/Responses sanitizadas, parámetros, Identity, Objetos, estados, Signals, Hypotheses y el historial de Runners ya probados. Los Runs recientes aportan también muestras acotadas de su HTTP real y resultado humano (`Negativa`, `Interesante`, `Retest`, etc.), para evitar repetir ideas y proponer preguntas nuevas con contexto.

La IA sólo propone preguntas y borradores. El investigador decide si guarda una **Hypothesis**, convierte una idea en **Runner** y cuándo ejecuta. Un Runner parte del Flow baseline y permite mantener, omitir o repetir pasos, alternar listas de valores y reutilizar datos extraídos de una Response anterior por key JSON o Regex. Puede ejecutarse bajo una Identity Context concreta.

Cada Run es secuencial y deliberadamente acotado (30 Requests por defecto, 100 máximo; 20 repeticiones máximas por paso; sin concurrencia). Cada Request/Response resultante vuelve a Negro como evidencia normal y alimenta Signals, Objetos, memoria y Search. Además, cada Run genera un **Flujo resultante** que puede compararse con el baseline usando Flow Compare. Runner no pretende reemplazar Intruder, fuzzers ni scanners: automatiza experimentos de proceso tediosos y contextuales.


## v0.38.0 — Reglas mínimas + Request Workbench

Esta versión reduce deliberadamente el ruido. Negro incluye **una sola Regla integrada de ejemplo** (`Errores con detalles internos`) y deja las demás técnicas para Reglas creadas por el investigador a medida que aprende o las necesita. Las Reglas propias se pueden activar, pausar y eliminar; la Regla integrada se puede activar/desactivar y quitar/restaurar por proyecto.

La vista de endpoint se convierte en **Request Workbench**: Request y Response completos son el centro de la investigación diaria, con búsqueda local, copiar, ajuste de líneas, pantalla completa, Repeater, comparación inteligente y Requests relacionadas. Capturas HTTP idénticas ya no se presentan como tarjetas repetidas: Negro conserva la variante exacta una sola vez y agrupa procedencia por herramienta Burp (`Proxy ×N`, `Repeater ×N`, `Intruder ×N`).

Se retiraron de la vista del endpoint la guía opcional de pruebas, recordatorios de pruebas y ejecución CORS. Signals e Hipótesis permanecen porque aportan contexto directo sobre la evidencia.

> Compatibilidad: los motores históricos siguen en el código para leer workspaces antiguos, pero v0.38 los retira del catálogo activo. Las señales automáticas históricas de esas reglas se archivan/deseleccionan de la bandeja activa sin borrar la evidencia original.

## v0.37.0 — Reglas que recuerdan por ti

Negro formaliza el modelo **Regla → Señal → Hipótesis → validación humana**. Una Regla expresa qué quieres que Negro recuerde o detecte; una Señal es una coincidencia real con evidencia. Las Reglas pueden vigilar una key, un valor exacto, regex o condiciones de contexto, y pueden crearse desde una Request, una Hipótesis o el editor general.

### Pasado, presente y futuro

Al guardar, editar o activar una Regla, Negro revisa automáticamente la evidencia local que ya posee (Requests y JavaScript analizado) sin volver a tocar el objetivo. Desde ese mismo momento la Regla queda activa para nueva evidencia de Burp y nuevos JavaScript analizados. Una edición vuelve a interpretar el historial y sustituye solamente las Señales generadas por esa Regla.

### Proyecto ≠ host

`/projects` administra investigaciones completas. Un proyecto puede contener muchos hosts y alcances del mismo programa; el Inicio del proyecto muestra únicamente métricas y trabajo de ese proyecto. Los hosts viven en Inventario/Surface, no como proyectos hermanos.

### Idioma

La UX es español-first. Se mantienen en inglés únicamente términos técnicos donde traducirlos resta claridad: Request, Response, Burp, HTTP, API, JWT, CORS, OAuth/OIDC y nombres propios de herramientas/protocolos.

## v0.36.0 — Investigation Memory / Correlation Engine

Negro ya no sólo guarda lo que viste: mantiene un índice incremental de identificadores observados, distingue si un valor entró a la aplicación o salió de ella, recuerda piezas que faltan en una hipótesis y genera **Correlation Signals** cuando evidencia posterior puede completar esa investigación o conectar APIs/hosts distintos.

Principios de esta versión:

- reutiliza Objects, Signals, Hypotheses, Search, Hunt y Map; no crea un segundo sistema paralelo;
- `order_id`, `cardId`, `shipment_id`, etc. se indexan como memoria, no como Signals por cada aparición;
- una hipótesis puede declarar piezas pendientes como `order_id bajo otra Identity`;
- si esa pieza aparece después —o ya existía en el historial— Negro crea una correlación explicable y persistente;
- output/input se basa en dónde se observó el dato, no en inferir causalidad;
- las correlaciones heurísticas nunca se llaman vulnerabilidades;
- el procesamiento nuevo es incremental e indexado; no compara todos los Requests contra todos los Requests;
- Search, Object y Hunt muestran la memoria relacionada sin crear pantallas nuevas;
- Map resalta de forma persistente Signal / Correlation / Hypothesis y puede aislar **Sólo con inteligencia**.


---

## v0.35.0 — mapa con inteligencia + Hypothesis Engine 2.0

El mapa ya no sólo muestra relaciones: una ruta o Request con **Signal** o **Hypothesis** queda visualmente marcada y su detalle enlaza directamente a la inteligencia asociada en Hunt. Hypothesis Engine 2.0 cruza el contexto ya construido por Negro (Identity, Flow, Object, State, Signals, anomalías y resultados HTTP por identidad) para producir hipótesis específicas y comprobables. La IA se ejecuta únicamente cuando el investigador la solicita y nunca promueve una hipótesis a Finding por sí sola.

Negro es una capa local de inteligencia, memoria y organización encima de Burp Suite. No pretende reemplazar Burp ni decidir vulnerabilidades por el usuario.

## Modelo central

`Regla → Señal → Hipótesis → Investigación / prueba humana → Hallazgo`

- **Reglas**: condiciones observables configurables; pueden ser integradas o creadas por el investigador.
- **Signals**: observaciones automáticas con procedencia exacta; no son vulnerabilidades.
- **Hipótesis IA**: aparecen únicamente cuando el usuario ejecuta IA y separan hechos, inferencia, incógnitas y próxima prueba.
- **Investigaciones**: las crea el usuario al promover una hipótesis.
- **Findings / estados humanos**: siguen bajo control del hacker.

## v0.34.0 — Identity outcomes + Custom Signals

Esta versión cierra la **Fase 7 — Custom Signals** y sigue puliendo la lectura del grafo.

- En Identity Compare, cada endpoint puede mostrar dentro de su tarjeta el resultado observado por Identity, por ejemplo `Diego · 200` y `Ana · 403`. Esto permite detectar visualmente endpoints que rompen el patrón de autorización sin declarar automáticamente un IDOR.
- Superficie adopta también la gramática visual semántica: proyecto, host, endpoint y método dejan de depender de bolitas indistinguibles.
- El tráfico de Identity queda ordenado explícitamente de **más reciente a más antiguo**.
- Flow Detail prioriza objetos de negocio con significado y pliega `111 101`, `Object 7`, `owner 101` y equivalentes como **identificadores sin clasificar**.
- **Custom Signals** permite crear reglas locales por método, status, ruta, nombre de parámetro, contenido de request/response, headers, Business Object e Identity presente/ausente. Todas las condiciones configuradas se combinan con AND; dentro de una condición varios valores se combinan con OR.
- Las Custom Rules escriben en el mismo `signal_occurrences` usado por Hunt. No generan findings ni un motor paralelo; producen Signals con Request exacta, explicación del match y una sugerencia opcional de siguiente prueba.
- Cada regla se aplica automáticamente al tráfico nuevo y puede **reinterpretar historial** de forma local sin tocar el target.

Ejemplo:

```text
Rule: Object ID bajo otra identidad
Identity: presente
Parameter: ownerId, *accountId

→ Signal
→ Request exacta
→ sugerencia: comparar identidades + Follow Value
```

## v0.33.0 — Semantic graph polish: iconos, relaciones legibles y comparación A/B

Esta iteración no añade otro motor de detección. Hace que el grafo explique mejor la evidencia que Negro ya conoce.

- Los nodos semánticos dejan de ser círculos indistinguibles: **Identity** usa tarjeta/persona, **Endpoint** una pill persistente con la ruta, **Flow** una tarjeta de proceso, **Object** un hexágono, **Request** documento, **State** rombo y **Anomaly** triángulo.
- En vistas Identity/Object/Flow, Identity, Endpoint y Flow mantienen tamaño/label legible al cambiar zoom; Superficie conserva su comportamiento conocido.
- El panel de un endpoint agrupa relaciones por significado. Repeticiones como `id=102` o dos Flows con el mismo nombre ya no aparecen como líneas idénticas: se condensan con contador y la evidencia ambigua queda separada como “identificadores sin clasificar”.
- Identity Compare añade una lectura rápida **Compartidos / Sólo A / Sólo B**, con filtros directos sobre el grafo y líneas visuales diferenciadas para cada identidad.
- La navegación superior elimina `Entender` / `Más` y deja accesos directos a Identidades, Flows, Objetos, Mapa, Recon, Guía y Ajustes.
- Nuevos Flows creados desde la selección por defecto de Burp reciben un nombre contextual basado en el primer/último endpoint, evitando listas de `Flow from Burp selection` indistinguibles.

La regla visual sigue siendo: **Identity + Endpoint + Flow explican la historia; Object añade contexto; Request/Method son detalle progresivo.**

## v0.32.0 — Graph-first semantic views: Identidades, endpoints y objetos legibles

Esta iteración corrige el exceso de simplificación de v0.31: el grafo vuelve a ser la vista principal cuando realmente ayuda a comparar relaciones, pero con una jerarquía visual explícita.

- **Identidad**: una o dos Identity Contexts quedan a los lados y los **endpoints** aparecen en el centro. Un endpoint compartido converge visualmente; uno exclusivo queda conectado sólo a la identidad que lo observó. Flows, objetos, Requests individuales y métodos son capas opcionales.
- **Objeto**: el objeto focal conecta directamente con los endpoints donde apareció. Identidades y Flows relacionados quedan como contexto lateral; objetos secundarios y Requests individuales se pueden activar si hacen falta.
- **Flow**: ofrece dos lecturas del mismo dato, **Grafo** y **Línea de tiempo**. El grafo conserva la secuencia entre Requests; la línea de tiempo mantiene la lectura paso a paso que ya funcionaba bien.
- **Superficie**: conserva el comportamiento conocido; los métodos HTTP siguen visibles por defecto, pero ahora pueden ocultarse con un check.
- **Endpoints**: sus labels nunca se suprimen por nivel de zoom en las vistas semánticas importantes. El detalle del endpoint muestra siempre los métodos soportados, aunque la capa de métodos esté apagada.
- Jerarquía visual estable: **Identity = azul**, **Flow = ámbar**, **Endpoint = azul/cian**, **Object = verde y menor peso**.

La idea no es mostrar más nodos: es que el grafo responda visualmente preguntas como “¿qué endpoints comparten estas dos sesiones?” o “¿en qué rutas apareció Order 4101?”.

## v0.30.0 — Investigation Views / Map 3.0 + UX simplification

Esta iteración no añade nuevas detecciones. Reduce ruido y cambia el mapa desde un grafo universal hacia **vistas que responden preguntas concretas**.

- **Superficie** sigue usando mapa/árbol para responder qué existe.
- **Identidad** usa un grafo focal alrededor de una cuenta/sesión elegida dinámicamente.
- **Flow** deja de ser un grafo: ahora es una **línea de tiempo de Requests**, con método, endpoint, HTTP status, identidad, objetos y estados visibles sin abrir detalle.
- **Objeto** obliga a elegir una cosa concreta antes de mostrar relaciones. Tipos ambiguos como `111`, `Object`, `id` o `reference` se conservan, pero quedan ocultos por defecto.
- **Atención** deja de mostrar toda la superficie y se convierte en una bandeja corta de anomalías, hipótesis activas y hallazgos.

La navegación principal también se simplifica: Identidades, Flows y Objetos se agrupan bajo **Entender**; Recon/Guía/Ajustes quedan en **Más**. Todas las páginas mantienen ayuda contextual, pero ahora la pregunta que responde la pantalla es la pieza visible principal.

La regla de UX oficial pasa a ser: **guardado no significa protagonista**. Negro puede conservar evidencia técnica sin obligar al investigador a verla en cada pantalla.

La terminología visible sigue siendo **Request**; `exchange_id` permanece únicamente como compatibilidad interna.

## v0.28.0 — Guided UX + Learning Center

Esta iteración no añade otra capa de detección. Reduce complejidad cognitiva. Cada pantalla principal incluye una ayuda contextual con cuatro respuestas: **qué pregunta responde**, **cuándo usarla**, **ejemplo del Access Control Lab** y **qué no debe inferirse**.

La sección **Guía** pasa a ser un Centro de Aprendizaje por intención: inventario/enumeración, búsqueda y correlación, identidades/autorización, flows/estados, Business Objects/anomalías e Intelligence/Hunt/Findings. Incluye un walkthrough con Ana/Diego y el modelo `Identity → Business Object → propiedad` para evitar mezclar actores con objetos.

Business Objects también corrige el filtro vacío `type_id`, elimina el prellenado confuso del campo de tipo y clasifica candidatos como `Buen candidato`, `Revisar contexto` o `Genérico`. Una sugerencia nunca se activa sola.

## v0.27.0 — Business Objects + cross-host correlation + Pattern Anomalies

Negro ahora puede aprender tipos de objeto como `Order`, `Payment`, `Shipment`, `Account` o cualquier concepto propio del target. Un tipo acepta varios identifiers/aliases, por ejemplo `Order: orderId` y `Order: order_id`; las instancias se unifican por **tipo + valor exacto**.

Una instancia muestra en una sola vista:

- hosts y endpoints donde apareció;
- identidades observadas;
- Flows donde participó;
- estados ya aprendidos;
- objetos co-observados;
- timeline HTTP cross-host.

Pattern Anomalies compara únicamente contra patrones que ya se repitieron varias veces. Puede señalar un status HTTP distinto para la misma Identity + operación normalizada, un conjunto diferente de objetos relacionados, una cobertura de identidades distinta o una huella de hosts diferente. Siempre se presenta como **diferencia observada**, nunca como IDOR, bypass o vulnerabilidad confirmada.

Business State Tracks enseñan automáticamente su identificador al modelo de Business Objects, por lo que `Order = orderId + status` no crea dos sistemas paralelos. Flow Detail muestra objetos observados y Flow Compare añade diferencias por tipos de objeto.

## v0.26.0 — Burp-native Flows + Identity + Business States

Esta iteración cierra Flow Capture/Compare y lleva las acciones principales al sitio donde ocurre la investigación: Burp.

### Flow Capture desde Burp o Negro

Desde Burp, clic derecho → **Negro → Flow**:

- `Start Flow from here…`
- `Add to current Flow…`
- `End Flow here…`
- `Create Flow from selected exchanges…`

Desde la web, **Start Flow** abre una Capture Window y **Stop Flow** guarda todo lo observado como candidatos. Negro puede marcar tráfico repetido como `possible background`, pero nunca lo borra ni lo excluye solo. En el editor decides `Include`, `Ignore`, `Set as Start` y `Set as End`.

### Identity Contexts directamente en Burp

Clic derecho → **Negro → Identity** permite:

- asignar el exchange a una Identity existente;
- crear una Identity desde la request seleccionando su auth material;
- declarar el auth actual cuando rota una sesión/token;
- `Send / Re-send as Identity` hacia el Repeater existente;
- enviar como `Anonymous`, removiendo sólo auth conocida por Negro.

El resend conserva método, path/query, body y headers ajenos a autenticación. Negro maneja Cookie, Authorization/Bearer y headers de auth comunes.

### Business State Observations

Los estados ya no son sólo campos adyacentes. El investigador enseña una definición real, por ejemplo:

```text
Order = orderId + status
```

A partir de ahí Negro observa instancias concretas:

```text
Order orderId=98127
CREATED → PAID → SHIPPED
```

Cada nodo conserva el exchange y la Identity observada. Flow Compare puede mostrar una variante `CREATED → SHIPPED`, pero lo presenta como **secuencia diferente observada**, nunca como bypass o vulnerabilidad confirmada.

### Smart Compare sigue siendo el diff de detalle

Flow Compare trabaja un nivel arriba. Cuando dos pasos alineados cambian, el detalle continúa abriéndose en **Smart Compare**; no existe un segundo motor de diff paralelo.

## Identity Contexts

Negro separa:

- **Identity**: cuenta estable (`Buyer A`, `Seller A`).
- **Context**: rol/tenant opcional.
- **Auth Material**: cookie/Bearer/JWT concreto que puede rotar.
- **Resolver**: valor estable que identifica al actor (`/me.id`, `/me.email`, `jwt:sub`).

`ownerId`, `orderId`, `tenantId` y otros identificadores de objeto/contexto no se usan como resolvers del actor. La Authorization Matrix sigue mostrando sólo tráfico observado y `No observado` no se interpreta como permitido o denegado.

## Buscar

Buscar sigue siendo la entrada universal:

```text
4101
ownerId
1223
AIza
host:api.example.com method:GET ownerId
```

El texto libre usa coincidencia parcial. Cuando hay observaciones estructuradas, Search ofrece acciones de `HTTP`, `Follow Value`, `Find Related Exchange`, `Smart Compare` e Identity.

En un workspace antiguo usa una vez **Buscar → Actualizar datos** para reconstruir búsqueda y parámetros históricos.

## Arranque

```bash
chmod +x negro.py install-web.sh burp-extension/build-extension.sh
./install-web.sh
negro web
```

## Extensión Burp

**v0.41 requiere Negro Burp Bridge v0.27.0+ para ejecutar Runners mediante Burp.** Las acciones anteriores de Flow/Identity siguen disponibles, pero un Bridge v0.26.x no puede consumir trabajos `execute` del Runner y Negro lo mostrará como extensión desactualizada.

Compila el JAR en la misma máquina donde vas a usar Burp:

```bash
cd burp-extension
./build-extension.sh
```

Carga `build/libs/negro-burp-bridge-0.27.0.jar` desde **Burp → Extensions → Installed → Add → Java** y elimina/deshabilita la versión anterior para evitar dos pollers compitiendo por la cola. Con Burp abierto, entra al Runner y usa **Diagnosticar transporte**: debe mostrar `runner_transport_ready: true`.

El modo recomendado es **Burp Bridge** porque Burp realiza la conexión al target con su propia ruta DNS/TCP/TLS/upstream proxy. Los modos Python Directo/Entorno/Proxy explícito quedan como fallback.

Consulta `METHODOLOGY.md` para el modelo mental, `ROADMAP.md` para lo siguiente y `CHANGELOG.md` para el historial.