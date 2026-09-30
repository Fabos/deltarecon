# Roadmap

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
