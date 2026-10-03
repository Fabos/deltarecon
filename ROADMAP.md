## v0.39 — Flow Intelligence + Runner ✅

- IA on-demand sobre Flow con HTTP sanitizado y memoria de Runners/Runs previos.
- Preguntas de lógica específicas al proceso, sin ejecutar automáticamente.
- Conversión de idea → Hypothesis o idea → Runner draft.
- Runner con alias, keep/omit/repeat, listas de valores y extracción desde Responses.
- Identity Context opcional, ejecución secuencial y límites duros anti-fuzzing.
- Cada Run vuelve a Negro como evidencia y crea un Flow resultante comparable con baseline.

## v0.38 — Request Workbench + reducción de ruido ✅
- Una sola Regla integrada de ejemplo; el resto del conocimiento se agrega bajo demanda.
- Activar/desactivar/eliminar/restaurar Reglas desde una UX directa.
- Request/Response completos como centro de la vista de endpoint.
- Búsqueda, copiar, wrap y pantalla completa por mensaje HTTP.
- Provenance agregado por Proxy / Repeater / Intruder para capturas exactas repetidas.
- Ventana visual limitada para grandes cantidades de variantes sin perder evidencia persistida.
- Se retiran guía de pruebas, recordatorios y ejecución CORS de la vista principal del endpoint.

# Roadmap

## v0.37 — Reglas como memoria de investigación ✅
- Regla → Señal → Hipótesis como modelo explícito.
- Reglas desde Request, Hipótesis o configuración.
- Condiciones por key, valor exacto, regex y contexto HTTP/Identidad/Objeto.
- Cobertura automática del pasado + evaluación incremental del futuro.
- Requests y JavaScript analizado participan en el backfill local.
- Reglas integradas y personalizadas reunidas en una UX única.
- Administración de Proyectos separada del dashboard activo; un proyecto agrupa múltiples hosts/scopes.
- UX español-first.

## Siguiente paso
Usar Negro en Bug Bounty/labs reales y priorizar únicamente problemas observados: ruido, rendimiento, señales que falten y fricción de investigación. Evitar nuevas fases por inventario de funciones.


## v0.13 — Bug Bounty Pilot ✅
- Burp contextual actions: Open / Interesting / Create Finding / Attach / Retest evidence
- Real multi-entity Findings as source of truth
- Coverage and Signal as independent visual dimensions
- Workspace backup + restore
- Pilot-ready workflow for real targets

## Next — learn from real bounty usage
- Identities / roles and cross-account coverage
- Parameters and per-operation test coverage
- Business objects and richer attack paths
- Scale/performance tuning from large real targets

## v0.12 — Attack Knowledge Graph V1 ✅
- Graph projection over existing entities
- Semantic edges + provenance
- Semantic lane layout + progressive disclosure
- Perspectives: Superficie / Pendientes / Interesante / Burp / Rutas de investigación
- Search / filters / 1-hop / 2-hop focus
- Draggable nodes with per-perspective saved layout
- Interactive visual investigation map

# Negro Recon — Roadmap posterior a v0.9.0

## Implementado en v0.19.2

- mapa con Fullscreen API y más viewport útil;
- panel de siguientes pasos plegable;
- recálculo local de toda la evidencia almacenada con las reglas actuales;
- vigencia de regla separada del estado humano de la hipótesis;
- retiro/reactivación automática sin borrar notas ni resultados;
- filtro de hipótesis vigentes / históricas;
- comando `recalculate-intel`;
- notificación resumen del recálculo, sin inundar con alertas históricas.

## Implementado en v0.19.1

- `Qué probar ahora` materializa automáticamente el subgrafo de las rutas prioritarias; las tarjetas y el canvas ya no pueden quedar desacoplados por progressive disclosure.

## Implementado en v0.19.0

- Knowledge Base de detectores guiada por aprendizaje;
- reglas exactas, sufijos/patrones, ubicaciones, condiciones y exclusiones visibles;
- herencia `built-in → biblioteca personal → proyecto`;
- procedencia de cada regla (`Negro`, `personal`, `proyecto`);
- evidencia `rule_match` para explicar exactamente por qué nació una hipótesis;
- exclusiones por proyecto sin borrar conocimiento global;
- configuración de detectores sin presets opacos de sensibilidad.

## Implementado en v0.18.0

- Proyecto → múltiples scopes con un solo workspace;
- auto-routing de Burp por scope más específico;
- detectores configurables por proyecto (base sobre la que v0.19 añade reglas transparentes);
- reducción/limpieza de CORS first-party;
- mapa de investigación más grande y perspectivas orientadas a preguntas;
- siguientes pasos integrados al mapa;
- JS cross-scope → Resources/relaciones/notificaciones.

## Implementado en el Hunter Intelligence MVP

- policy profiles;
- DNS infrastructure + PTR;
- AXFR;
- Smart DNS + wildcard detection;
- Smart VHost + baseline;
- CT intelligence;
- fingerprinting + passive WAF/CDN hints;
- robots.txt;
- selected `.well-known` + OIDC relationships;
- bounded crawler + sitemap XML + forms/comments/docs;
- Search Intelligence query generator;
- Wayback historical intelligence;
- JS/source maps/secrets/config;
- Correlation Engine;
- actionable leads;
- Target AI triage;
- JS/Target AI cost estimate + actual cost + evidence-hash cache;
- offline smoke test;
- conservative DB migration from v0.8.x.

## Próximas mejoras después de probar v0.9 en labs

### 1. Temporal diff v2

- comparar contenido JS histórico vs actual;
- detectar endpoints/hosts/config removidos;
- validación explícita y bounded de una shortlist histórica;
- snapshot diff visual.

### 2. Document Intelligence

- PDF/DOCX/XLSX local extraction;
- metadata + URLs/hosts/config;
- AI triage sólo sobre texto relevante;
- costo/cache igual al pipeline JS.

### 3. Code Intelligence v2

- AST JavaScript/TypeScript;
- data-flow más preciso para DOM XSS/Open Redirect;
- correlation entre bundles/chunks;
- GraphQL operations;
- HTTP method/body extraction.

### 4. Lead validation helpers

Sólo helpers de una prueba mínima y reversible, siempre explícitos:

- Open Redirect controlled-domain check;
- CORS browser-readable evidence;
- provider-specific dangling DNS confirmation;
- public storage anonymous-read check.

No auto-exploitation.

### 5. Better relationships UI

- grafo Host → Page → Resource → Endpoint → Host;
- auth clusters;
- legacy clusters;
- provenance timeline;
- “why this lead exists” interactivo.

## Criterio de éxito

No medir Negro por cantidad de módulos. Medirlo por:

> ¿redujo cientos/miles de observaciones a pocos leads que llevaron a una validación útil más rápido que el análisis manual?


## Implementado en v0.19.3
- Proveniencia exacta para secrets/config: exchange, surface, masked value, fingerprint, regex, offset/línea/columna y contexto enmascarado.
- “Abrir evidencia” salta al exchange real que produjo la hipótesis.
- Un exchange histórico se carga aunque ya no esté entre los 30 más recientes del recurso.
- Evidencia histórica obtiene contexto al abrirse sin recapturar tráfico.

## Implementado en v0.20.0

- Signals automáticos separados de estados humanos.
- Signal provenance por exchange (`signal_occurrences`).
- Estados humanos `normal / learning / review_later / interesting / correlate / finding / discarded`.
- Evidence Snapshots para `interesting / correlate / finding`.
- Burp colors + notes + context menu de estados.
- Parameter observations como base de Follow Value / Parameter Explorer / Identity Contexts.
- Diferenciación UX entre evidencia histórica y retest actual en Repeater.
- Polling de notificaciones local con backoff y sin solapamiento.

## Siguientes fases de la nueva visión

1. Global Search + FTS5 + Saved Searches + guía “Aprende a buscar como hacker”.
2. Parameter Explorer + Follow Value + Find Related + Smart Diff.
3. Identity Contexts + auth material rotatorio + actor resolvers + Authorization Matrix. ✅ v0.23.2
4. Correlation clarity: Find Related con paths completos + Smart Compare con coincidencias/alias por valor. ✅ v0.25.0
5. Flow Capture + Flow Compare + Burp-native Identity/Flows + object-bound business-state observations. ✅ v0.26.0
6. Pattern anomalies + cross-host correlation + business objects. ✅ v0.27.0
6.5. Guided UX + Learning Center + contextual help + Business Object clarity. ✅ v0.28.0
6.6. Investigation Experience / Map 2.0 + Focus Mode + Path Finder + lenguaje Request-first. ✅ v0.29.0
6.7. Investigation Views / Map 3.0 + simplificación global + timeline de Flow + evidencia ambigua fuera del foco. ✅ v0.30.0
6.8. Evidence-first UX: Identity/Object Request-first, objetos ambiguos como key=value, Flow Compare sin ruido y navegación corregida. ✅ v0.32.0
6.9. Semantic graph polish: iconos por tipo, relaciones deduplicadas, compare Shared/Only y navegación directa. ✅ v0.33.0
6.10. Identity HTTP outcomes + iconografía de Superficie + Flow object cleanup. ✅ v0.35.0
7. Custom Signals sobre la Knowledge Base existente, sin crear un segundo motor paralelo. ✅ v0.35.0

## Implementado en v0.20.3 — separación definitiva del razonamiento

- `Rule → Signal → Hipótesis IA → Investigación humana` como modelo oficial.
- Hunt deja de presentar los `ENGINE leads` determinísticos como hipótesis.
- Las hipótesis visibles provienen únicamente de una ejecución explícita de IA.
- Cada hipótesis IA separa hechos, inferencia, incógnitas y siguiente prueba.
- Promoción manual `Hipótesis → Investigación` con evidencia/Signals relacionados.
- Revisión de un Signal sin obligar a marcar el recurso como descartado.

## Implementado en v0.21.0 — Search Everything + mapa observable

- SQLite FTS5 sobre tráfico y conocimiento normalizado.
- Búsqueda libre y filtros `host:`, `method:`, `status:`, `state:`, `signal:`, `param:`, `cookie:`, `header:`, `body:`, `request:`, `response:`, `path:`, `type:` y `contains:`.
- Saved Searches + ayuda integrada “Aprende a buscar como hacker”.
- Backfill explícito de workspaces existentes con “Indexar historial”; tráfico nuevo se indexa al ingerirlo.
- Mapa de proyectos pequeños con relaciones determinísticas antes de IA.
- Perspectiva Burp con proyección real de exchanges observados, independiente de las Hipótesis IA.

## Implementado en v0.22.0 — búsqueda parcial + Parameter Explorer

- búsqueda por fragmentos con FTS5 trigram (`1223` encuentra `3001112233`, `AIza` encuentra cadenas mayores);
- ayuda de búsqueda simplificada y documentación normal en README/Metodología;
- Parameter Explorer por nombre, superficie, host y operación;
- extracción histórica/nueva de query, IDs de path, request body y response JSON;
- Follow Value por hash exacto con previews sensibles enmascarados;
- Find Related con razones transparentes de correlación;
- Smart Diff priorizando campos de negocio y enmascarando headers sensibles.

## Implementado en v0.23.0 — Search unificado + Identity Contexts

- Search es la entrada universal para texto, valores y parámetros;
- resultados estructurados muestran Follow Value, Find Related, Smart Diff e Identity actions sin cambiar de módulo;
- Parameter Explorer queda como drill-down técnico y corrige el contador `values`;
- Identity separada de Auth Material rotatorio y de Context (role/tenant);
- asignación manual de identidad a un exchange conocido;
- aprendizaje local de cookie/Bearer fingerprints;
- resolvers automáticos de claims JWT estables (`sub`, `userId`, `accountId`, email);
- resolvers manuales desde observaciones de parámetros estables;
- una sesión/token rotado puede resolverse a la misma Identity y luego enseñar su nuevo auth material;
- `Unknown` se conserva si no hay coincidencia única;
- Authorization Matrix basada **solo en tráfico observado**, con `No observado` explícito y sin inferir acceso.

## Implementado en v0.25.0 — correlación + flows

- Smart Compare separa coincidencias de diferencias y detecta posibles alias por valor aunque cambie el nombre/path del campo;
- Find Related conserva path/nombre de ambos lados y penaliza valores genéricos;
- Guía integrada por módulo;
- Flow Workbench con captura por exchange o rango;
- Business-state observations;
- Flow Compare por método + ruta normalizada, con pasos ausentes/cambiados y Smart Compare por paso.

## Implementado en v0.32.0 — Graph-first semantic views

- Identity compare con identidades laterales y endpoints centrales.
- Object focal conectado directamente a endpoints, Identity y Flow como contexto.
- Flow con selector Grafo / Línea de tiempo.
- Capas opcionales para métodos, objetos y Requests individuales.
- Labels de endpoint persistentes al cambiar zoom y métodos soportados en el detalle.
- Jerarquía visual consistente por tipo de nodo.

## Implementado en v0.33.0 — Semantic graph polish

- Iconografía SVG por tipo de nodo sin depender de emojis.
- Endpoints persistentes y legibles en vistas semánticas.
- Relaciones del detalle agrupadas y evidencia ambigua plegada.
- Identity Compare con Shared / Only A / Only B.
- Navegación superior directa, sin categorías opacas.
- Nombres contextuales para Flows Burp creados con el nombre por defecto.

## Implementado en v0.34.0 — Custom Signals + Identity outcomes

- Identity Compare muestra resultados HTTP por Identity dentro del endpoint.
- Superficie reutiliza iconografía semántica para proyecto/host/endpoint/método.
- Identity history queda newest-first explícito.
- Flow Detail pliega Business Objects ambiguos como identificadores sin clasificar.
- Custom Signals configurables por evidencia HTTP/params/Identity/Object.
- Las Custom Rules reutilizan `signal_occurrences` y Hunt; no crean un segundo modelo de Signal.
- Reinterpretación local del historial por regla, sin requests nuevas al target.

## Ciclo siguiente: uso real y endurecimiento

Las fases funcionales principales ya están completas. A partir de aquí el foco es usar Negro en targets reales y mejorar **ruido, rendimiento, ergonomía, explicabilidad y flujos repetitivos**, especialmente en workspaces con miles de endpoints/Requests. Nuevas capacidades se añaden sólo cuando resuelvan un problema observado durante investigación real.

## v0.35.0 — última fase funcional del roadmap base ✅

- [x] Mapa intelligence-aware: Signal/Hypothesis visibles sobre Endpoint/Request y navegación directa a Hunt.
- [x] Hypothesis Engine 2.0 con fusión de Identity + Flow + Object + State + Signal + Anomaly + authorization outcomes.
- [x] Hipótesis explicables con fuentes de contexto y evidencia navegable.
- [x] Sin promoción automática a vulnerabilidad/Finding.

Con esta entrega quedan completas las fases funcionales principales planteadas. El siguiente ciclo es **uso real, reducción de ruido, rendimiento, ergonomía y ajustes derivados de Bug Bounty**, no añadir features por añadir.

## v0.36.0 — Investigation Memory / Correlation Engine ✅

- Identifier memory index over stored parameter observations.
- Input/output observations across hosts, identities and flows.
- Hypothesis pending pieces (`needed pieces`) with retrospective matching.
- Correlation Signals reusing the existing Signal/Hunt pipeline.
- Produced→consumed cross-context correlations with aggressive deduplication.
- Search/Object/Hunt/Map integration.
- Prominent intelligence markers + “Sólo con inteligencia” in the map.
- Retrospective technique coverage architecture prepared; full checklist system intentionally deferred.
