# CHANGELOG

Historial consolidado de Negro Recon. Desde v0.20.1 ya no se distribuyen archivos `UPDATE-vX.Y.Z.md` separados.

## v0.20.1

- Corrige el highlight **CYAN** automático de Burp usando los `Signal Occurrences` realmente persistidos y pendientes de revisión.
- Los Signals pasan a describir **hechos observados**; las hipótesis se presentan al usuario como **Investigaciones** (preguntas de prueba).
- La vista **Hunt** reúne Signals pendientes + Investigaciones sin fusionar sus modelos de datos, y añade un primer Learning Backlog por categoría.
- Mejora la pestaña Negro de Burp con una leyenda visual y estado de conexión que se recupera tras un ingest exitoso.
- Mantiene `Signal = observación automática`, `Investigación = pregunta a validar`, `Estado = decisión humana`.
- Consolida el historial de releases en este único `CHANGELOG.md`.


---

# Negro Recon v0.20.0 — Signals ≠ State · Evidence Memory · Burp Workflow

Esta versión cambia la semántica central de Negro: **una detección automática no es una decisión humana**.

## 1. Signals automáticos separados de estados humanos

Negro persiste cada indicio automático en `signal_occurrences`, ligado al exchange exacto que lo originó. Un Signal conserva categoría, severidad orientativa, explicación (`why_json`), evidencia/provenance y si ya fue revisado.

Estados humanos disponibles:

- `normal`
- `learning` — Pendiente aprendizaje
- `review_later` — Revisar luego
- `interesting` — Interesante
- `correlate` — Correlacionar
- `finding` — Finding confirmado por el investigador
- `discarded` — Descartado por decisión humana

Negro **no** asigna automáticamente `interesting`, `correlate`, `finding` ni `discarded`.

## 2. Evidencia histórica vs retest vivo

Marcar un exchange como `interesting`, `correlate` o `finding` crea un `evidence_snapshot` con:

- request/response exactos comprimidos;
- hashes del request/response;
- tamaño;
- timestamp de la observación;
- estado humano y nota.

La UI diferencia esa evidencia histórica de un envío a Repeater. Repeater vuelve a ejecutar el request y la respuesta actual puede no coincidir con la observada originalmente.

## 3. Base para Follow Value / Parameter Explorer

`parameter_observations` normaliza parámetros observados en query/form/JSON/multipart y conserva:

- nombre y ubicación;
- hash del valor;
- preview limitado;
- masking para material sensible;
- relación exacta con exchange/operation/resource.

Esta capa será la base de Parameter Explorer, Follow Value e Identity Contexts sin tener que volver a parsear todos los blobs HTTP en cada consulta.

## 4. Burp Bridge v0.20.0

La extensión ahora:

- resalta **cyan** cuando Negro detecta Signals automáticos nuevos;
- añade una nota `NEGRO · 🩵 SIGNAL ...`;
- permite cambiar estados humanos desde `Negro → State`;
- sincroniza highlights: blue/yellow/orange/magenta/red/green;
- añade notas legibles para conservar el significado aunque se olvide el color;
- soporta selección múltiple para estados/notas cuando aplica.

El panel de la extensión incluye la leyenda de colores y recuerda que Signal y State son conceptos diferentes.

## 5. UI de Resource / Exchange

El detalle del Resource incorpora:

- panel de Signals automáticos con provenance;
- estado humano separado;
- conteo de Signals sin revisar;
- banner de evidencia histórica;
- aviso cuando el visor HTTP está mostrando sólo una vista truncada;
- acción explícita `Reprobar ahora en Repeater`.

La compatibilidad con los estados históricos v0.19 (`review_state` / `classification`) se conserva en una sección secundaria para no romper workspaces existentes.

## 6. Polling local

El frontend deja de consultar `/notifications` con un `setInterval` rígido. Ahora evita requests solapados, usa backoff y reduce la frecuencia cuando la pestaña está oculta o no hay cambios.

## 7. Base de datos

No se migra a PostgreSQL en esta versión. SQLite sigue siendo el backend recomendado para un workspace local de un solo investigador. v0.20 activa WAL cuando es posible, `busy_timeout`, índices nuevos y persistencia estructurada.

El siguiente riesgo de escala no es SQLite sino guardar payloads HTTP grandes como Base64 dentro de la propia base. La evolución prevista es mantener SQLite para metadata/FTS/relaciones y mover blobs HTTP a un almacén comprimido y content-addressed (`sha256 → blob`) sin romper los IDs existentes.

## Migración

La migración es aditiva. Al abrir un workspace v0.19, `init_db()` crea las tablas nuevas sin eliminar resources, exchanges, findings, leads, reglas ni estados previos.

Antes de sustituir una instalación productiva conserva una copia del workspace, especialmente `inventory/negro.db`.


---

# Negro Recon v0.19.3 — Exact Evidence Provenance

Esta versión corrige el problema observado al investigar una Google Maps API key: Negro sabía que el detector había coincidido en un exchange, pero la UI enviaba al recurso genérico y podía mostrar otro exchange o truncar el body antes de la coincidencia.

## Cambios

- Cada coincidencia de `secret_candidate` persiste y/o reconstruye:
  - exchange exacto, método y URL;
  - request/response (`surface`);
  - valor enmascarado y fingerprint;
  - regex que coincidió;
  - offset, línea y columna dentro del body;
  - contexto cercano con secretos enmascarados;
  - pista educativa para Google Maps cuando el contexto lo indica.
- Hipótesis muestra “¿De dónde salió esta coincidencia?” con contexto verificable.
- “Abrir evidencia” apunta a `?exchange=<id>#exchange-<id>`.
- Resource detail fuerza la inclusión del exchange solicitado aunque no esté en los 30 más recientes.
- El exchange enfocado muestra la coincidencia que llevó hasta él.
- Las hipótesis históricas pueden reconstruir provenance desde el SQLite actual; no exige volver a enumerar.

## Seguridad de evidencia

Negro no persiste la credencial completa en `evidence_json` ni en el snippet. Los valores que coinciden con detectores de secretos se enmascaran antes de mostrarse o persistirse.


---

# Negro Recon v0.19.2 — Fullscreen Map + Local Intelligence Recalculation

## Objetivo

Hacer el mapa utilizable como superficie principal de investigación y permitir que una Knowledge Base cambiante reinterprete evidencia histórica sin repetir recon.

## Mapa

- botón `Pantalla completa` usando Fullscreen API;
- el workspace ocupa todo el viewport en fullscreen;
- las rutas se convierten en carrusel horizontal compacto;
- `Ocultar ideas` libera todavía más altura para el canvas;
- al cambiar de tamaño Negro vuelve a ajustar el grafo.

## Recalcular inteligencia

La acción vuelve a procesar localmente:

- todos los `http_exchanges` guardados;
- Resources y parámetros históricos;
- análisis JavaScript ya almacenados;
- source maps ya procesados;
- crawls, observaciones e inspecciones existentes.

No ejecuta discovery, crawler, HTTP recon, descarga de JavaScript ni OpenAI.

## Vigencia

`leads_v2.rule_active` separa la decisión humana de la coincidencia actual de reglas. Recalcular pone temporalmente las hipótesis deterministas en no-vigentes y reactiva sólo las que siguen cumpliendo la Knowledge Base actual. Estados y `result_notes` se conservan.

La pantalla Hipótesis permite ver `Vigentes`, `Ya no coinciden` o `Todas`. El mapa y las rutas usan únicamente hipótesis vigentes.

## Notificaciones

El recálculo crea una sola notificación resumen y marca como leídas las notificaciones pendientes de hipótesis que dejaron de coincidir. Esto evita inundar un bounty grande al reinterpretar miles de requests históricos.

## Compatibilidad

Migración SQLite aditiva. No cambia el protocolo Burp ↔ Negro.


---

# Negro Recon v0.19.1 — Route Canvas Hydration Fix

## Problema

En v0.19.0 el endpoint `scope=overview` cargaba intencionalmente sólo Proyecto + Hosts para mantener fluidez en targets grandes. Sin embargo, `_investigation_routes()` podía devolver tarjetas que apuntaban a `resource:*`, `operation:*`, `exchange:*` y `lead:*` que todavía no estaban presentes en `graph.nodes`. El resultado visible era contradictorio: **Ideas para continuar** tenía hipótesis válidas, pero el canvas decía **No hay nodos para esta vista**.

## Corrección

- nueva proyección `scope=routes`;
- materializa sólo los Host → Resource → Operation → Exchange → Hypothesis necesarios para las rutas prioritarias;
- al abrir **Qué probar ahora**, el frontend solicita esa proyección automáticamente;
- las tarjetas siguen siendo el selector de ruta, pero ya no es necesario hacer clic en una para que aparezca el grafo;
- mantiene progressive disclosure: no carga todo el target.

## Validación

El test de Access Control ahora verifica que cada ruta materializa sus nodos esenciales (`host`, `resource`, `operation`, `lead`) y que el canvas puede dibujar las hipótesis existentes desde el primer render.


---

# Negro Recon v0.19.0 — Guided Rule Knowledge Base

## Objetivo

Convertir los detectores de Negro en conocimiento ofensivo **visible, explicable, editable y heredable**. El investigador debe poder aprender por qué existe una señal, entender exactamente qué regla la disparó y adaptar esa regla a la terminología real de cada aplicación.

## Modelo de conocimiento

```text
Negro built-in
      ↓
Biblioteca personal
      ↓
Proyecto
```

- **Negro built-in**: reglas base incluidas con la herramienta.
- **Biblioteca personal**: términos y ajustes aprendidos que se heredan en futuros proyectos.
- **Proyecto**: adiciones/exclusiones locales que no contaminan otros targets.

Ejemplo: `memberId` puede añadirse globalmente como identificador de objeto y luego excluirse sólo en un proyecto donde sea telemetría o un parámetro ubicuo sin relación con ownership.

## Editor guiado por detector

Cada detector incorpora una guía en español con:

- qué es la vulnerabilidad;
- cómo suele aparecer en aplicaciones reales;
- ejemplo mental;
- qué evidencia puede observar Negro;
- falsos positivos habituales;
- cómo validarla manualmente sin confundir señal con finding.

Después de la explicación aparecen las reglas efectivas y sus controles: listas de nombres/patrones, ubicaciones, condiciones y exclusiones. Cada término muestra su procedencia (`Negro`, `personal`, `proyecto`).

## Rule Match trazable

Las hipótesis generadas por reglas guardan la coincidencia concreta que las originó, por ejemplo:

```text
Detector: IDOR / autorización horizontal
Ubicación: query.memberId
Regla: exact:memberId
Valor observado: 83921
Origen: Biblioteca personal
```

La pantalla Hipótesis expone esta información y enlaza de vuelta al editor del detector.

## Detectores migrados

La Knowledge Base cubre Access Control, CORS, JavaScript, Open Redirect, URL-fetch/SSRF, secrets/config, respuestas sensibles, secretos en URL, source maps, API docs y error disclosure.

En Access Control, IDOR/BOLA, Mass Assignment, HTTP Method, redirect-body leakage, proxy/path discrepancies y Referer usan reglas editables. El motor CORS usa scopes del proyecto para evitar confundir comunicación first-party con un origin externo.

## Herencia y seguridad operacional

- Las reglas personales se guardan en la configuración global de Negro.
- Las reglas del proyecto se guardan en su SQLite/meta.
- Desactivar un detector no elimina evidencia histórica.
- Excluir un término en un proyecto no lo borra de la biblioteca personal.
- Los resultados positivos/negativos **no auto-promueven ni auto-eliminan reglas**; el investigador decide.
- Una señal sigue siendo una hipótesis. Sólo evidencia de impacto debe convertirse en Finding.

## Compatibilidad

Los workspaces v0.18 migran de forma conservadora. Los estados enabled/disabled previos se respetan cuando existen. El protocolo Burp ↔ Negro no cambia, por lo que el Bridge v0.16.7 continúa siendo compatible.


---

# Negro Recon v0.18.0 — Projects, Detector Lab & Investigation Map

## Objetivo

Reducir ruido y convertir Negro en una memoria de investigación más clara: una prueba puede contener varios scopes, cada proyecto puede ajustar sus detectores y el mapa debe responder preguntas concretas en lugar de mostrar un grafo decorativo.

## Proyecto → múltiples scopes

Negro deja de asumir que una prueba equivale a un solo dominio. Cada proyecto tiene:

- nombre legible;
- scope principal;
- scopes adicionales;
- un único workspace/SQLite;
- inventario, Burp, JavaScript, hipótesis, hallazgos, notificaciones y mapa compartidos.

Burp enruta cada request al proyecto cuyo scope coincida de forma más específica con el host.

Ejemplo del lab:

```text
Proyecto: Access Control Lab
Scopes:
  app.accesslab.local
  api.accesslab.local
```

`score.accesslab.local` no se agrega y permanece fuera de scope.

Al agregar scopes que antes Negro consideraba targets distintos, las hipótesis CORS first-party históricas entre esos scopes se marcan como negativas y sus alertas quedan leídas.

## Detector Lab por proyecto

Ajustes incorpora un panel explicativo para los motores de alerta. Cada detector permite:

- activar/desactivar;
- sensibilidad `Estricto / Equilibrado / Permisivo`;
- ver qué observa Negro;
- entender qué condición dispara cada modo;
- ver hipótesis activas y alertas históricas generadas en el proyecto.

La configuración se guarda por proyecto. Los defaults globales se conservan únicamente como fallback.

Motores configurables en v0.18.0 incluyen Access Control, CORS, JavaScript, Open Redirect, URL-fetch/SSRF, secrets/config, respuestas sensibles, secretos en URL, source maps, API docs y error disclosure.

Una señal sigue siendo una hipótesis: desactivar un detector impide nuevas alertas, pero no borra evidencia/histórico.

## CORS con contexto de proyecto

CORS ahora distingue `cross-origin` de `external-to-project`.

Una relación como:

```text
app.target.com → api.target.com
```

no se eleva automáticamente si ambos hosts pertenecen a los scopes del mismo proyecto. En modo Estricto, el motor exige contexto mucho más fuerte antes de alertar.

## Mapa de investigación

La pantalla aprovecha mejor el viewport y elimina la sensación de un bloque inferior separado del mapa.

Las perspectivas se redefinen como preguntas:

- **Superficie** — ¿Qué existe?
- **Pendientes** — ¿Qué no he revisado?
- **Interesante** — ¿Dónde hay señales?
- **Burp** — ¿Qué observé realmente?
- **Qué probar ahora** — evidencia → hipótesis → siguiente prueba.

El panel de siguientes pasos vive dentro del workspace del mapa, puede filtrarse por estado/tipo/prioridad y reutiliza el mismo estado + `Resultado / qué pasó` de Hipótesis.

El nodo raíz muestra el nombre del proyecto en vez de fingir que un único dominio representa toda la prueba.

## JavaScript y notificaciones

Se conserva el flujo v0.17.1: `Analizar local` crea Resources para rutas in-scope, relaciones `JavaScript → Resource` y una notificación agregada. Con múltiples scopes, un JS de `app.*` puede descubrir correctamente rutas en `api.*` del mismo proyecto.

## Compatibilidad

- Los targets/workspaces anteriores migran conservadoramente: su dominio existente se convierte en el primer scope.
- No se borra inventario ni evidencia.
- El protocolo Burp ↔ Negro no cambia; el Bridge v0.16.7 sigue siendo compatible.
- Para unir datos históricos que ya viven en dos workspaces separados se recomienda crear/usar un proyecto nuevo y recapturar o importar explícitamente; agregar un scope no fusiona mágicamente dos SQLite históricos.


---

# Negro Recon v0.17.1 — Signal UX + JavaScript Surface

## Objetivo

Hacer que Access Control Intelligence sea usable durante una investigación real: menos ruido, filtros claros, estados editables desde el mapa, notificaciones accionables y JavaScript conectado de verdad con Resources.

## Cambios

### Mapa

- `Interesante`, `Burp` y `Rutas de investigación` ahora responden preguntas distintas:
  - **Interesante:** dónde existen señales, hipótesis o hallazgos.
  - **Burp:** tráfico observado (`Resource → Operation → Request`) sin mezclar hipótesis.
  - **Rutas de investigación:** sólo caminos respaldados por evidencia hacia una hipótesis y su siguiente prueba.
- filtros de hipótesis por **estado**, **prioridad** y **tipo**;
- las tarjetas de rutas respetan esos mismos filtros;
- una hipótesis puede cambiar de estado y guardar `Resultado / qué pasó` directamente desde su nodo del mapa;
- ese estado/comentario es el mismo registro de `leads_v2` usado por la pantalla Hipótesis; no existe memoria duplicada;
- relaciones visualmente diferenciadas:
  - evidencia observada;
  - rutas descubiertas por JavaScript;
  - relación hipotética;
  - hipótesis confirmada;
  - ruta seleccionada.

### Notificaciones

- las nuevas hipótesis determinísticas de Access Control generan una notificación **sólo cuando nacen**;
- la notificación enlaza a evidencia, Hipótesis y Mapa;
- se mantiene deduplicación por hipótesis;
- el análisis local de JavaScript genera una notificación agregada con rutas in-scope, nuevas e interesantes.

### CORS

- `app.target → api.target` deja de elevarse automáticamente como CORS sospechoso cuando ambos hosts pertenecen al mismo target/workspace;
- si v0.17.0 había creado una candidata CORS para esa relación y vuelve a observarse, Negro la retira como `negative` con una nota explicativa;
- Origins externos reflejados siguen entrando al flujo normal de investigación.

### JavaScript

`Analizar local` ahora convierte las rutas encontradas en una señal visible:

```text
JavaScript
   ↓ discovered
Resource
```

- las URLs in-scope siguen convirtiéndose en Resources;
- el grafo conecta el bundle con esos recursos;
- las relaciones funcionan también cuando un JS de `app.target` descubre endpoints de `api.target`;
- rutas con términos como `admin`, `internal`, `approve`, `audit`, `export`, `ops`, `role`, `permission`, etc. generan una única hipótesis de **superficie JavaScript**, no una vulnerabilidad confirmada;
- una notificación resume el análisis en vez de emitir una alerta por cada ruta.

## Filosofía

```text
Señal ≠ vulnerabilidad
Hipótesis ≠ finding
Ruta de investigación ≠ exploit chain confirmado
```

La v0.17.1 mejora dónde mirar y conserva al investigador como quien valida impacto.

## Compatibilidad

No cambia el protocolo Burp ↔ Negro. El bridge/JAR de v0.16.7/v0.17.0 continúa funcionando.

## Tests

```bash
PYTHONPATH=. python tests/smoke_test.py
PYTHONPATH=. python tests/access_control_intelligence_test.py
node --check web/static/graph.js
```

El test de Access Control cubre también reducción de ruido CORS, notificaciones de hipótesis y `JavaScript → Resource` cross-host.


---

# Negro Recon v0.17.0 — Access Control Intelligence + Rutas de investigación

## Objetivo

Convertir las lecciones aprendidas manualmente sobre **Broken Access Control** en memoria operativa de Negro sin transformarlo en un vulnerability scanner. Negro observa tráfico que ya pasó por Burp, correlaciona señales y ayuda a responder dos preguntas:

1. **¿Qué merece revisión en este recurso?**
2. **¿Por dónde conviene seguir investigando en el mapa?**

Una señal o ruta nunca equivale por sí sola a una vulnerabilidad confirmada.

## Inteligencia de Access Control

El análisis pasivo de exchanges puede crear hipótesis para:

- **Autorización horizontal / IDOR**: IDs/UUIDs controlados por el cliente en operaciones autenticadas.
- **Mass assignment**: campos de rol/estado/ownership visibles en la respuesta pero ausentes de una operación de edición observada.
- **Control de acceso por método HTTP**: mismo recurso observado con varios verbos, especialmente cuando alguno cambia estado.
- **Redirect con body**: respuestas `3xx` que todavía transportan contenido significativo o campos sensibles.
- **Discrepancia proxy/backend**: un `403` cuyo fingerprint difiere de un `404` normal del mismo host.
- **Referer en acción sensible**: quick check de baja prioridad; la presencia del header no se considera vulnerabilidad.

Las pruebas propuestas son manuales y minimizan impacto. Negro no prueba IDs de terceros, no cambia roles, no falsifica sesiones y no dispara acciones administrativas automáticamente.

## Resources — “Qué merece revisión aquí”

El detalle de cada Resource agrega una tabla que reúne hipótesis activas y recordatorios de pruebas contextuales:

```text
Posible / indicio | Por qué llamó la atención | Prueba sugerida | Estado
```

La tabla reutiliza `leads_v2` y el coverage de operaciones existente; no introduce una entidad duplicada.

## Rutas de investigación

El mapa agrega **Por dónde seguir**. Cada ruta se calcula con evidencia persistida y prioriza:

```text
Host → Resource → Operation → Exchange → Hypothesis
```

cuando esas piezas existen.

Las hipótesis generadas por IA participan de la misma forma porque ya viven en `leads_v2`. La ruta muestra la siguiente prueba y puede abrir/enfocar el recurso correspondiente.

Importante: una ruta es una **secuencia de investigación**, no un “attack path” confirmado. Una futura cadena multi-step sólo debería presentarse como tal cuando sus relaciones estén respaldadas por pruebas/hallazgos confirmados.

## Mapa

- mayor contraste y grosor de conexiones en dark mode;
- highlight más claro para relaciones interesantes;
- ruta activa en verde con mayor grosor;
- nodos que forman parte de la ruta reciben un borde destacado.

## Compatibilidad

- No cambia el esquema de comunicación Burp ↔ Negro.
- El **Burp Bridge v0.16.7** sigue siendo compatible; no necesitas recompilar/reinstalar el JAR por esta actualización.
- Workspaces anteriores conservan findings, leads, coverage y evidencia. `generate-leads` puede backfillear las nuevas señales sobre exchanges existentes.

## Validación offline

```bash
PYTHONPATH=. python tests/smoke_test.py
PYTHONPATH=. python tests/access_control_intelligence_test.py
```

El test nuevo valida señales de Access Control, ayudas por Resource, rutas de investigación y que no se creen Findings automáticamente.


---

# Negro Recon v0.16.7

Hotfix de compilación del Burp Bridge.

## Corregido

- Restaura el helper `unescapeJson(...)` usado por el selector de Findings del menú contextual.
- El helper es iterativo y no reintroduce el parser regex recursivo que se eliminó en v0.16.6 para `request_b64`.
- Bridge, backend y scripts de build quedan etiquetados como v0.16.7.
- Corrige el error de compilación `cannot find symbol: unescapeJson(String)`.

No cambia el protocolo Burp ↔ Negro ni el modelo de datos.


---

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


---

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


---

# Negro Recon v0.16.4

## Repeater Bridge: fast poll fix

- `/api/bridge/repeater/next` deja de llamar `ensure_workspace()` cada segundo.
- El poll usa `workspace_paths()` y abre directamente el SQLite ya existente.
- El cleanup de claims vencidos se ejecuta como máximo cada 30 s.
- Se agregan logs `[repeater-next] ... elapsed_ms=...` cuando hay item o el poll es lento.
- El cliente Java amplía el timeout del poll de 3 s a 10 s como margen defensivo.
- Evita `CancelledError`/HTTP 500 observados en workspaces grandes.


---

# Negro Recon v0.16.3

Hotfix de entrega Negro → Burp Repeater.

- El poller del bridge usa una llamada HTTP síncrona en su hilo dedicado para evitar futures fallidos sin observar.
- Logs de cada poll: status HTTP, longitud de body y bandera pending.
- Items `claimed` sin ACK expiran a `error` tras 30 segundos para evitar reenvíos y pestañas duplicadas; basta pulsar Enviar de nuevo.
- Logs seguros de claims del backend.
- No se registran cuerpos HTTP ni secretos en los logs.


---

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


---

# Negro Recon v0.16.1 — Repeater hand-off hotfix

## Qué corrige

- `Enviar a Repeater` ya no selecciona intercambios con `request_b64` vacío o `request_size=0`.
- Desde cada exchange HTTP aparece **Enviar esta solicitud a Repeater**, que conserva exactamente esa evidencia en lugar de elegir otra observación del mismo método.
- Si un workspace histórico no tiene bytes de solicitud, Negro genera una solicitud HTTP/1.1 mínima y válida en lugar de abrir una pestaña vacía.
- El bridge normaliza únicamente la línea de request de evidencia HTTP/2 (`HTTP/2` → `HTTP/1.1`) al reconstruir el mensaje para el editor de Repeater. Headers y body permanecen intactos. Burp podrá negociar HTTP/2 al enviarla según su configuración.
- El bridge valida el tamaño del request reconstruido antes de entregarlo a Repeater y usa un fallback seguro si el resultado queda vacío.
- Logs de diagnóstico:
  - backend: `[repeater-queue] ... request_bytes=...`
  - Burp Output: `Negro → Repeater: queue=... raw=...B reconstructed=...B h2_normalized=...`

## Por qué

Los requests observados por Burp pueden almacenarse en forma textual HTTP/2. El hand-off previo reconstruía siempre esos bytes con el constructor genérico de `HttpRequest`, y además permitía elegir históricos sin bytes. En determinadas combinaciones esto podía terminar en una pestaña de Repeater vacía.

## Compatibilidad

Requiere recompilar/reimportar el JAR del bridge `v0.16.1` para obtener la corrección completa del lado Burp.


---

# Negro Recon v0.16.0 — Burp Passive Intelligence + Progressive Map

## Objetivo

Cerrar la versión previa al bounty real haciendo que el tráfico que ya ve Burp se convierta en pistas accionables sin pedir trabajo manual adicional y evitando que el mapa se bloquee con targets grandes.

## Burp como fuente de inteligencia

Cada exchange HTTP nuevo puede producir, sin enviar tráfico adicional:

- **Open Redirect** desde parámetros reales observados en query, form o JSON (`next`, `return_url`, `redirect_uri`, etc.). La evidencia guarda método, ruta, parámetro, ubicación y exchange exacto.
- **Superficies URL/SSRF** cuando parámetros como `url`, `endpoint`, `webhook`, `fetch`, `image`, etc. reciben URLs absolutas.
- **Secretos/config de alto valor** con firmas conocidas: Google API keys, AWS access keys, GitHub tokens, Stripe live secrets, Slack tokens y private keys. Negro guarda sólo valor enmascarado + fingerprint.
- **Campos sensibles en respuestas JSON** como `password`, `pwd`, `client_secret`, `api_key`, `private_key`, `secret`, tokens, etc.; eleva señal cuando aparecen junto a identidad (`username`, `email`, `user_id`, ...).
- **Secretos en URL**, diferenciados porque pueden propagarse a logs, historial o Referer.
- **CORS observado** en requests/responses reales.
- **Source maps**, documentación OpenAPI/Swagger y señales de errores internos/stack/SQL/path disclosure.

La correlación es pasiva: no explota ni genera requests. Cada pista sigue siendo una hipótesis/lead que requiere validación manual.

## Notificaciones

- Nueva campana persistente por target.
- Toaster en tiempo real para severidad media/alta/crítica.
- Página de notificaciones con historial, deduplicación, número de ocurrencias y vínculo directo al recurso/evidencia.
- La primera carga establece baseline y no dispara cientos de toasts históricos.

## Inteligencia

La página Inteligencia explica y muestra explícitamente qué detectó Negro desde Burp. `Generar señales` también puede hacer backfill de exchanges existentes, pero sin inundar las notificaciones históricas.

## Mapa escalable

El mapa deja de intentar dibujar todo el workspace al abrir:

- **overview:** Target + hosts relevantes y grupos de pendientes/revisados/descartados.
- **host:** un host + un conjunto acotado/priorizado de sus recursos, operaciones y evidencia.
- **resource:** un solo recurso + sus métodos, requests, señales, hipótesis y findings.

El doble click/drill-down y los botones de detalle cambian de capa. Para IA se conserva una proyección server-side completa/estructurada, independiente de la visualización progresiva.

## Dashboard

- Progreso separado para Hosts y Recursos.
- Pendientes excluyen descartados.
- Revisados, en revisión y descartados se muestran por separado.
- Barra de avance = revisados + descartados sobre total.
- Métricas de tráfico, métodos, hipótesis, findings y alertas nuevas.

## Compatibilidad Burp

El protocolo de ingestión sigue siendo compatible con el bridge v0.15.x. No es obligatorio recompilar el JAR para usar las nuevas capacidades server-side. Si se compila desde este paquete, el artefacto se etiqueta `v0.16.0`.

## Usabilidad adicional

- Inventario mantiene una sola búsqueda para host/endpoint/URL/query y agrega filtro de **estado de recursos** dentro del listado de hosts.
- Desde Dashboard, “Recursos pendientes” abre directamente hosts que contienen recursos pendientes.
- Las notificaciones enlazan al **exchange exacto** dentro del detalle del recurso (`#exchange-ID`) para no perder dónde apareció la señal.
- El contador “Interesantes” y el bloque de foco del Dashboard consideran también leads persistentes creados por el motor pasivo de Burp, no sólo clasificaciones manuales.
- Etiquetas nuevas y severidades se muestran en español; se conservan en inglés únicamente términos técnicos de seguridad.


---

# Negro Recon v0.15.0 — UX Polish / Bounty Pilot

Última iteración antes del piloto real de bug bounty. No cambia el modelo de datos ni el protocolo Burp → Negro: reorganiza la experiencia para que la herramienta sea más rápida de leer y requiera menos mantenimiento manual.

## Cambios principales

- UI unificada en español (manteniendo términos técnicos estándar cuando aportan).
- Navegación reducida a Inicio, Inventario, Mapa, Inteligencia, Hipótesis, Hallazgos y Ajustes.
- Inventario unificado: la búsqueda de Hosts también encuentra recursos por path, URL o query y muestra las coincidencias dentro del host.
- Dashboard rediseñado para priorizar contexto, pendientes, hipótesis y hallazgos.
- Host: acciones reorganizadas en una caja de herramientas contextual en vez de una fila saturada.
- Resource detail: tráfico Burp y acciones contextuales son protagonistas.
- La antigua checklist de vulnerabilidades queda como **Guía opcional de pruebas**, cerrada por defecto. No es requisito completar checks ni mantenerlos manualmente. Sólo las pruebas que el investigador realmente toca (o que un motor registra) alimentan la memoria de IA. Los checks automáticos pendientes no se convierten en tareas ni sesgan “Dame ideas”.
- Hallazgos, retests, hipótesis, mapa y ajustes reciben nomenclatura y jerarquía visual coherentes.
- El mapa mantiene drag, perspectivas y memoria de layout; las perspectivas se muestran en español.

## Compatibilidad

- Bases/workspaces de v0.14.x: compatibles.
- Bridge v0.14.x: compatible; no es necesario recompilarlo para usar v0.15.0. Si se recompila desde este paquete, el JAR se etiqueta v0.15.0.


---

# Negro Recon v0.14.5 — Robust Graph AI Responses + Diagnostics

Esta versión endurece `Give me ideas` para Responses API y evita diagnosticar como “JSON inválido” una respuesta que en realidad quedó incompleta.

## Cambios

- Presupuesto propio para Graph AI: 6000 tokens de salida y reintento automático a 9000 si OpenAI devuelve `status=incomplete` por `max_tokens`/`max_output_tokens`.
- `reasoning=low` por defecto para reservar más presupuesto a la salida estructurada accionable.
- Negro inspecciona `response.status`, `incomplete_details.reason`, `error`, refusals y usage antes de intentar parsear JSON.
- Una respuesta incompleta, fallida o rechazada nunca se guarda como resultado válido ni entra al cache.
- El segundo intento exploratorio de 0 hipótesis se conserva y también usa la estrategia de reintento por límite de salida.
- Logs seguros en terminal con prefijo `[AI graph]`: modelo, intento, presupuesto, status, razón de incompletitud, caracteres de salida y conteos de tokens. Nunca se imprimen prompts, cookies, cuerpos HTTP ni texto generado.
- UI distingue `incomplete`, `refusal`, `api_error` y Structured Output inválido.
- La estimación previa contempla el peor caso: retry por tokens + retry exploratorio.

Ejemplo de logs:

```text
[AI graph] request · model=gpt-6-luna · attempt=1 · budget=6000 · reasoning=low · payload_chars=...
[AI graph] response · status=incomplete · incomplete_reason=max_output_tokens · output_tokens=6000 · reasoning_tokens=...
[AI graph] retry_larger_budget · from_budget=6000 · to_budget=9000
[AI graph] response · status=completed · output_tokens=... · output_chars=...
```

El protocolo Burp Bridge no cambia.


---

# Negro Recon v0.14.4 — Endpoint Test Coverage + Exploratory AI Retry

## Test Coverage por método

Negro añade memoria explícita de pruebas sobre cada `resource_operation`. La misma ruta puede tener resultados distintos por método, por eso la checklist vive en `GET/POST/PUT/PATCH/DELETE`, no como una única marca genérica del Resource.

Estados: `pending`, `testing`, `negative`, `interesting`, `confirmed`, `not_applicable`. `negative` significa que la prueba se realizó y no dio; no es información perdida.

La checklist se recomienda según evidencia real: método, autenticación observada, Content-Type, query params, ruta y tipo de recurso. CORS actualiza automáticamente su check después de ejecutar el probe.

## IA

`Give me ideas` recibe ahora `test_coverage` como memoria estructurada. Las pruebas negativas/no aplicables no deben repetirse sin evidencia nueva. Si la primera respuesta estructurada devuelve cero hipótesis, Negro hace una única segunda pasada exploratoria enfocada en checks pendientes, diferencias de sesión, métodos alternativos, client-side trust, parámetros reales y lógica de negocio. Si tampoco encuentra algo defendible, lo dice explícitamente.

La estimación muestra el costo máximo posible de dos llamadas; la segunda sólo se ejecuta cuando la primera produce cero hipótesis válidas.

## Burp

El protocolo del Bridge no cambia. El JAR ya cargado sigue siendo compatible; sólo necesitas recompilar si quieres que Burp muestre la versión 0.14.4.


---

# Negro Recon v0.14.3 — AI Cache Reliability Hotfix

- Los resultados de `Give me ideas` que no puedan validarse como JSON estructurado ya no se guardan con estado `done` ni se reutilizan desde cache.
- Los cache entries inválidos heredados se ignoran y se marcan `invalid` automáticamente.
- Se elimina el fallback silencioso a texto libre cuando el SDK no soporta Structured Outputs: Negro ahora pide actualizar dependencias en lugar de contaminar el cache.
- `install-web.sh` actualiza dependencias y `requirements.txt` exige una versión moderna del SDK OpenAI.
- La UI diferencia entre “0 hipótesis válidas” y “respuesta inválida/reintentable”.
- Se incrementó `GRAPH_AI_PROMPT_VERSION` para invalidar cache anterior.


---

# Negro Recon v0.14.3 — Offensive Hypothesis Prioritization

## Objetivo

Hacer que `Give me ideas` sea una mano derecha de pentesting: menos comprobaciones genéricas y más pruebas accionables, priorizadas y conectadas con evidencia real.

## Cambios

- Prioridad de investigación independiente: `high`, `medium`, `quick`.
- Razones trazables sin probabilidades falsas (`backend enforcement unknown`, `new attack surface possible`, etc.).
- `Prueba esto ahora` aparece antes de la explicación.
- Feature flags: response tampering → observar nueva UI/tráfico → probar enforcement server-side.
- Business logic: buscar la operación sensible que consume `state/until/regional/limit/...` y verificar validación en backend.
- Checks simples/probablemente públicos se degradan a `QUICK CHECK`.
- Operaciones state-changing permitidas sólo sobre cuentas/datos autorizados y minimizando impacto; no se bloquean genéricamente POST/PUT/DELETE.
- Hypotheses muestra evidencia humana (`METHOD /path`, status, Burp request) en vez de IDs internos.
- Acciones directas: abrir request/evidence, Send to Repeater, Open Resource, View on Graph.
- El resultado/nota de prueba continúa alimentando futuras rondas de IA.
- `prompt_version` forma parte del evidence hash, evitando reutilizar cache generado con prompts anteriores.

## Compatibilidad

No cambia el protocolo Burp ↔ Negro. El JAR ya cargado sigue funcionando; recompilar sólo es necesario si quieres que el bridge muestre la misma versión del paquete.


---

# Negro Recon v0.14.1 — Structured AI Output hotfix

- `Give me ideas` usa Structured Outputs (`json_schema`, strict) para evitar JSON malformado.
- El parser de respaldo ya no propaga `JSONDecodeError` a la UI.
- Si un SDK antiguo no soporta `text.format`, Negro conserva compatibilidad y falla de forma segura sin perder el workspace.
- No cambia el protocolo Burp Bridge.


---

# Negro Recon v0.14.0 — Hypothesis Workbench

- Dashboard: eliminar target + workspace con confirmación por dominio.
- Nueva página Hypotheses persistente con filtros, estados y notas de resultado.
- IA de mapa más concreta: explicación simple, pasos manuales, qué cambiar y qué observar.
- Contexto IA incluye previews JSON estructurales/sanitizados de exchanges relevantes, no dumps completos.
- Hipótesis enlazables al mapa y resources.
- Estados negativos/descartados permanecen como memoria para evitar repetir ideas.


---

# Negro Recon v0.13.0 — Bug Bounty Pilot

Esta versión cierra el primer ciclo operativo para usar Negro durante un bounty real: Burp alimenta la investigación, los Findings son entidades persistentes, los retests conservan evidencia y el workspace puede respaldarse/restaurarse completo.

## Burp → Negro desde el menú contextual

Sobre una request/response en Proxy, Repeater u otra vista HTTP compatible:

- **Open in Negro** — ingesta/sincroniza y abre el Resource.
- **Mark as Interesting** — marca el Resource como señal interesante y conserva el exchange.
- **Create Finding…** — crea un Finding confirmado y enlaza Resource, Operation y Exchange.
- **Attach to existing Finding…** — agrega la request a una cadena/hallazgo existente.
- **Attach as Retest evidence…** — registra resultado de retest y usa el exchange actual como evidencia.

El bridge sigue enviando tráfico observado en tiempo real y conserva Negro → Burp Repeater.

## Findings como fuente de verdad

Un Host o Resource no deja de ser un asset por tener una vulnerabilidad. El Finding es una entidad separada y puede relacionar múltiples:

- hosts;
- resources;
- operations/métodos;
- HTTP exchanges;
- evidencia visual;
- observaciones.

Marcar manualmente un Host/Resource con la clasificación legacy `finding` crea un Finding real si todavía no existe, para mantener compatibilidad con workspaces anteriores.

## Retest con evidencia

Cada retest conserva resultado, notas, fecha y opcionalmente el HTTP Exchange exacto usado para reproducirlo:

- `still_vulnerable`
- `fixed`
- `fix_verified`
- `inconclusive`

La vista del Finding muestra esa evidencia navegable dentro del timeline.

## Coverage ≠ Signal

Negro deja de mezclar progreso y hallazgo en un único color:

**Coverage**
- `untested`
- `testing`
- `tested`

**Signal**
- `normal`
- `interesting`
- `finding`

El Knowledge Graph muestra ambas dimensiones. El color principal prioriza la señal; un indicador secundario muestra coverage.

## Backup / Restore

Desde Dashboard:

- **Backup ↓** exporta el workspace completo como ZIP con `manifest.json`.
- **Restaurar backup** recupera DB, evidencia, notas, raw data, análisis y estado del target en un workspace nuevo.

El restore valida rutas del ZIP antes de extraerlas y no pisa silenciosamente un workspace con contenido.

## Validación incluida

- smoke test offline v0.13;
- migración aditiva de schema;
- HTTP model + findings + retest evidence;
- API Burp context actions;
- backup + restore de workspace;
- render de Resource/Finding/Graph sobre modelos existentes.


---

# Negro Recon v0.12.2 — Interactive Graph + AI Hypotheses

- Fix de selección: click/tap en nodo abre siempre el panel lateral; drag sigue funcionando.
- Navegación por teclado (Enter/Espacio) en nodos.
- Perspectivas reordenables por drag & drop; el orden se recuerda por target.
- `🧠 Give me ideas` desde todo el target o desde un nodo seleccionado.
- Estimación de costo antes de ejecutar IA, igual que el resto de Negro.
- Contexto estructurado: nodos/edges, cobertura, findings e hipótesis anteriores; no se envían cuerpos HTTP completos.
- La IA devuelve 3–5 hipótesis investigables, nunca findings automáticos ni probabilidades falsas.
- Hipótesis AI persistentes reutilizando `leads_v2`, con estados `candidate/testing/interesting/negative/postponed/confirmed`.
- `Negative` permanece como conocimiento y entra al contexto de futuras sugerencias para evitar repeticiones.
- `View on Graph` cambia a Interesting y enfoca la hipótesis con sus nodos de evidencia.


---

# Negro Recon v0.12.1 — Knowledge Graph UX

Esta iteración no agrega nuevas entidades de seguridad. Reorganiza la proyección visual existente para que el mapa ayude a pensar en lugar de simplemente dibujar filas de la base de datos.

## Cambios

- `Attack Surface` es la perspectiva inicial: Target → Host → Resource → Operation.
- Layout semántico horizontal en lanes, con reducción de cruces por barycentric passes.
- `Burp` agrupa exchanges por operación y permite expandirlos a demanda.
- Observaciones repetidas y JavaScript se agrupan para reducir ruido.
- `Interesting` y `Attack Paths` aíslan relaciones que llevan a señales, leads o findings sin afirmar automáticamente que exista una vulnerabilidad.
- `Untested` reduce el mapa a elementos cuyo estado todavía está pendiente.
- Labels progresivos: requests/observaciones no dominan el canvas hasta que se seleccionan o se hace zoom.
- Panel lateral con métodos, requests, pruebas y señales registradas para Resources/Operations.
- Focus de 1 y 2 hops.
- Nodos arrastrables. La posición manual se persiste por target y perspectiva en el navegador.
- `Auto ordenar` elimina la disposición manual de la perspectiva actual y vuelve al layout semántico.
- El target deja de usar el verde principal como relleno; los colores se reservan principalmente para estado y selección.

## Principio de UX

El mapa aplica progressive disclosure: Negro conserva toda la evidencia, pero no obliga a verla toda simultáneamente. Los detalles siguen disponibles mediante expansión, focus y navegación a la entidad real.


---

# Negro Recon v0.12.1 — Attack Knowledge Graph V1

Esta versión agrega una nueva proyección visual de la investigación sin duplicar el modelo de datos existente.

## Mapa
- Nueva sección `Mapa` por target.
- Nodos derivados de Target, Hosts, Resources, Operations, HTTP Exchanges, JavaScript, Observations, Leads, Findings y Sources.
- Edges semánticos: `contains`, `supports`, `observed_in`, `discovered`, `observed`, `tested_by`, `produced_lead` y relaciones persistidas por Negro.
- Panel lateral con metadata, relaciones y navegación a entidades reales.
- Búsqueda, filtros por tipo y perspectivas rápidas: All, Untested, Leads/Findings, Burp y Resources.
- Focus de 1 hop con doble click o botón contextual.
- Zoom, pan y centrado.
- Provenance visible al seleccionar relaciones.

## Performance
- El grafo es una proyección read-only del modelo actual.
- Exchanges y observaciones se limitan inicialmente para evitar renderizar miles de nodos.
- La arquitectura queda preparada para progressive disclosure/clusterización en siguientes iteraciones.

## Compatibilidad
- No cambia el protocolo del Burp Bridge.
- No elimina Árbol, Hosts, Resources, Findings o Intelligence.


---

# Negro Recon v0.11.3

Hotfix del Burp Bridge para ingestión HTTP local.

## Corrección

El bridge ahora fuerza `java.net.http.HttpClient.Version.HTTP_1_1` al comunicarse con Negro. Java HttpClient puede intentar un upgrade h2c/HTTP2 sobre `http://127.0.0.1:8765`; Uvicorn no necesita ese upgrade y, en las pruebas, el request llegaba a `/api/ingest/http` con `body_len=0` aunque el bridge había construido un payload JSON válido.

También se sincronizaron los números de versión de los scripts de build (`build-extension.sh`, PowerShell y Gradle), que todavía podían producir un JAR con nombre 0.11.1 aunque el código fuera posterior.

## Resultado esperado

En Burp > Extensions > Output:

```text
Negro → ingest: PROXY GET https://... | payload=... bytes | first=0x7b('{')
Negro ← ingest HTTP 200 accepted=true
```

Y en la terminal de Negro ya no deben aparecer `Unsupported upgrade request` relacionados con el bridge ni `body_len=0` para esos POST.


---

# Negro v0.11.3

Hotfix de diagnóstico y transporte para Burp Bridge.

- El bridge envía `/api/ingest/http` como bytes UTF-8 explícitos (`ofByteArray`).
- Output de Burp muestra cada envío, tamaño de payload, primer byte y resultado HTTP.
- Se ignora el tráfico dirigido al propio backend de Negro para evitar realimentación.
- El backend reporta `body_len` y `first_byte` cuando falla el parseo JSON, sin exponer contenido sensible.
- No cambia el modelo de datos ni el protocolo lógico de ingestión.


---

# Negro Recon v0.11.3 — Burp ingest JSON hardening

Hotfix para el bridge Burp → Negro detectado durante pruebas reales.

- El bridge ahora serializa strings JSON como ASCII seguro, escapando cualquier carácter no ASCII y todos los controles JSON.
- Evita payloads inválidos producidos por valores de headers/URLs/metadatos entregados por Burp.
- El API `/api/ingest/http` devuelve errores de parseo con posición/causa sin reflejar el contenido sensible del request.
- No cambia el modelo de ingestión ni el protocolo funcional de Resources/Operations/Exchanges.

Después de actualizar, recompilar `burp-extension` y volver a cargar el JAR en Burp.


---

# Negro Recon v0.11.0 — Investigation Workspace

## Qué cambia

- Cada Resource tiene una pantalla propia con URL, provenance, estado, herramientas y evidencia.
- Los exchanges capturados por Burp se pueden inspeccionar como request/response lado a lado, preservando método, status, fuente, tamaño, timestamps y seen count.
- Las herramientas se contextualizan por Resource; CORS queda asociado al endpoint que se probó.
- `Send to Repeater` continúa disponible por método observado.
- Nueva entidad persistente `Finding` con severidad, estado, descripción, impacto y remediación.
- Un Finding puede relacionar múltiples Resources/Hosts/Exchanges/etc., permitiendo documentar cadenas entre servicios.
- Retests persistentes: `still_vulnerable`, `fixed`, `fix_verified`, `inconclusive`.
- Evidencia visual y notas también pueden vivir a nivel Finding.
- Hosts/Resources/Findings usan estados visuales más claros sin cambiar el estilo sobrio de Negro.
- Tooltips contextuales explican qué hace una prueba, qué señal busca y cómo interpretar un resultado.
- `uvicorn[standard]` sustituye a `uvicorn` para habilitar soporte WebSocket estándar y evitar warnings de upgrade cuando una dependencia intenta usarlo.

## Modelo añadido

```text
Finding
  ├── finding_entities -> resource / host / exchange / operation / js_asset / observation
  ├── finding_retests
  ├── notes
  └── evidence_attachments
```

Esto prepara el modelo para el Knowledge Graph posterior sin duplicar Host/Resource/Operation/Exchange.

## Flujo recomendado

1. Navega con Burp y deja que Negro capture el tráfico.
2. Abre el Resource desde el Host.
3. Revisa exchanges HTTP y ejecuta pruebas contextuales.
4. Documenta notas/evidencia mientras investigas.
5. Si una hipótesis se confirma, crea un Finding y asocia todos los Resources involucrados.
6. Cuando llegue un retest, registra el resultado en el mismo Finding.


---

# Negro Recon v0.10.3

- CORS por recurso reutiliza el contexto HTTP más reciente observado por Burp (cookies/Authorization y headers útiles), reemplazando únicamente `Origin` por el origen controlado de Negro.
- El resultado CORS queda visible dentro del propio recurso: status, ACAO, credentials y si la señal parece interesante.
- El popup de finalización muestra el resultado concreto de CORS en vez de limitarse al delta de inventario.
- Se corrigió un caso donde la UI podía quedarse en “Terminado. Actualizando resultados…” si `sessionStorage` rechazaba el payload del job.


---

# Negro Recon v0.10.2

- CORS check ahora puede ejecutarse sobre un Resource concreto, no sólo sobre la raíz del host.
- La procedencia del Resource se muestra directamente en su resumen y conserva todas las fuentes.
- Tooltips contextuales en herramientas principales: qué buscan y qué representa un resultado útil.
- Evidencia visual por Resource (PNG/JPG/WEBP/GIF, hasta 8 MB) con descripción y timestamp.
- Mantiene el flujo Burp → Negro → Repeater de v0.10.1.


---

# Negro Recon v0.10.2

Parche de instalación de la integración Burp.

## Cambios

- La extensión Burp ya no requiere Gradle global.
- Nuevo `burp-extension/build-extension.sh` para Linux/macOS/Kali.
- Nuevo `burp-extension/build-extension.ps1` para Windows.
- El build descarga Montoya API 2026.7 automáticamente en la primera ejecución.
- Compila con cualquier JDK >= 21 y genera bytecode Java 21 (`--release 21`).
- `build.gradle` se mantiene como opción para desarrollo, pero ya no intenta exigir un JDK 21 separado mediante toolchains.

## Build rápido

```bash
cd burp-extension
./build-extension.sh
```

Salida esperada:

```text
build/libs/negro-burp-bridge-0.10.2.jar
```


---

# Upgrade a Negro v0.10.0 — Burp Bridge + HTTP Operations

## Qué cambia

Negro v0.10 introduce un modelo HTTP orientado al trabajo real de bug bounty:

```text
Target
  └── Host
       └── Resource
            └── Operation (GET/POST/PUT/DELETE/...)
                 └── HTTP Exchange
```

El mismo recurso no se duplica por método. Cada método observado mantiene `seen_count`, status más reciente, si fue visto autenticado, Content-Type y procedencia (`burp_proxy`, `burp_repeater`, etc.). Requests/responses idénticos se deduplican sin perder first/last seen.

## Burp en tiempo real

Se incluye `burp-extension/` con **Negro Burp Bridge** basado en Montoya API 2026.7.

- Captura tráfico HTTP observado por Burp sin filtrar por tipo de asset.
- Negro auto-enruta cada host al target más específico ya creado.
- Conserva request/response completos en Base64 y headers.
- JS observados por Burp entran automáticamente al pipeline JavaScript de Negro.
- Desde un Resource de Negro se puede usar **Send to Repeater →**. Si existe una request real observada para ese método, se reutiliza; si no, Burp construye una request base desde la URL.

> Seguridad: esta versión conserva evidencia HTTP completa localmente, incluyendo cookies o Authorization si estaban presentes. Mantén Negro escuchando en localhost y protege el workspace.

## Notificaciones de jobs

Los jobs ahora guardan snapshot antes/después y la UI muestra un toast al finalizar, por ejemplo:

```text
Web recon terminado
+5 resources · +2 JS · +1 observaciones
```

Si no hubo cambios: `Sin elementos nuevos`.

## API local

```text
GET  /api/ingest/health
POST /api/ingest/http
GET  /api/bridge/repeater/next
POST /api/bridge/repeater/{target_key}/{queue_id}/ack
```

## Build de la extensión Burp

Requiere Java 21 y Gradle:

```bash
cd burp-extension
gradle jar
```

Carga `build/libs/negro-burp-bridge-0.10.0.jar` desde **Burp → Extensions → Installed → Add → Java**.

Por defecto conecta a `http://127.0.0.1:8765`. La pestaña **Negro** dentro de Burp permite cambiar la URL y ver contadores.

## Flujo de prueba recomendado

1. Instalación limpia de Negro v0.10.
2. Repetir NegroLab para validar regresión del flujo v0.9.
3. Crear el target del lab de PortSwigger CORS.
4. Cargar Negro Burp Bridge.
5. Navegar autenticado con el navegador de Burp.
6. Abrir `My account` y confirmar que `/accountDetails` aparece automáticamente en Negro como Resource.
7. Confirmar que GET aparece como Operation y que el exchange indica `auth`.
8. Desde Negro, enviar `/accountDetails` a Repeater.
9. Ejecutar/practicar el CORS check con el endpoint ya conocido.


---

# Upgrade a Negro v0.9.0

La migración de SQLite es aditiva: conserva hosts/resources/notes/inspections de v0.8.x y crea `relationships`, `leads_v2` y `ai_tasks`.

## Recomendado

Haz copia del repo antes de sobrescribir código. Los workspaces (`~/recon/...`) y configuración (`~/.config/negro/`) viven fuera del repo y no deben borrarse.

```bash
cd ~/Documents/recon/tools
cp -a deltarecon deltarecon.backup-v081

# Extrae el ZIP en /tmp y copia su contenido sobre el checkout actual:
unzip ~/Downloads/negro-recon-v0.9.0-full.zip -d /tmp/negro-v090
cp -a /tmp/negro-v090/negro-recon-v0.9.0/. ~/Documents/recon/tools/deltarecon/

cd ~/Documents/recon/tools/deltarecon
chmod +x negro.py negro_hunter.py install-web.sh
./install-web.sh
PYTHONPATH=. python tests/smoke_test.py
negro web
```

No uses `rsync --delete` sobre tu checkout si quieres conservar `.git`.

## Primer perfil

Para HTB/lab:

```bash
negro target.htb -w ~/recon/target policy --profile lab
```

Para Mercado Libre:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre policy --profile mercadolibre
```

La v0.9 no cambia automáticamente tu perfil existente a `lab`; el default es conservador.


---

# Negro Recon v0.8.1 — instalación limpia

Este paquete es **completo**. No depende de archivos de versiones anteriores.

## Instalación recomendada

```bash
cd ~/Documents/recon/tools
rm -rf deltarecon
git clone https://github.com/Fabos/deltarecon.git
cd deltarecon
```

Copia **todo el contenido** de este ZIP sobre el checkout, reemplazando archivos. Luego:

```bash
chmod +x install-web.sh
./install-web.sh
negro web
```

`install-web.sh` falla antes de modificar el launcher si falta cualquier archivo crítico de `web/`, compila los módulos Python y carga todos los templates Jinja. El launcher generado usa siempre el `.venv` de este checkout.


---

# Actualización a Negro v0.8.0

## Antes de reemplazar archivos

```bash
cd ~/Documents/recon/tools/deltarecon
git add .
git commit -m "Backup before Negro v0.8.0"
```

## Reemplazar archivos y reinstalar entorno/launcher

```bash
chmod +x negro.py install-web.sh
./install-web.sh
```

El instalador reutiliza `.venv`, verifica dependencias y reemplaza de forma segura cualquier launcher/symlink viejo de `/usr/local/bin/negro` por un wrapper que siempre usa:

```text
<repo>/.venv/bin/python <repo>/negro.py
```

## Verificación rápida

```bash
which negro
cat /usr/local/bin/negro
negro --help
```

Al ejecutar `negro web`, el proceso debe usar el Python de `.venv`.

## Workspaces existentes

La migración de SQLite es conservadora: añade campos de análisis de Source Map sin borrar hosts, resources, estados, notas ni análisis previos.

Un `.map` descargado por v0.7.x puede reutilizarse localmente al estimar/ejecutar IA. Para mostrar todas las métricas nuevas en la tarjeta Source Map, también puedes pulsar **Reprocesar Source Map**.
