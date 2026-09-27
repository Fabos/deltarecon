# Roadmap

## v0.12 — Attack Knowledge Graph V1 ✅
- Graph projection over existing entities
- Semantic edges + provenance
- Semantic lane layout + progressive disclosure
- Perspectives: Attack Surface / Untested / Interesting / Burp / Attack Paths
- Search / filters / 1-hop / 2-hop focus
- Draggable nodes with per-perspective saved layout
- Interactive visual investigation map

## Next
- Persistent Hypothesis lifecycle
- AI Give me ideas / I'm stuck using structured graph context
- Identities / roles
- Business objects and richer attack paths

# Negro Recon — Roadmap posterior a v0.9.0

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
