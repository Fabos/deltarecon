# Negro Recon — Roadmap

## Implementado

### v0.1–v0.4 — Recon engine

- crt.sh;
- Subfinder;
- Amass passive;
- GAU por provider;
- RAW / normalized / delta / provenance;
- SQLite;
- Host → Resources;
- estados, notas y Basic Inspect.

### v0.5 — Web Foundation

- FastAPI + Jinja;
- dashboard;
- inventario/árbol;
- cambio de estados;
- notas;
- jobs background;
- ejecución explícita de discovery e inspect.

### v0.6 — Multi-target + Live Workflow

- varios targets en el mismo servidor web;
- selector y creación de targets;
- workspaces/DB aislados por target;
- auto-refresh al terminar Basic Inspect;
- contadores live del dashboard;
- abrir hosts/resources en pestaña nueva;
- compatibilidad con config v0.5.

## Próxima fase: mejorar señal, no cantidad

### P1 — Wayback/CDX directo

Objetivo: separar `provider unavailable` de `0 resultados` y conservar timestamps/metadata histórica en vez de depender sólo de GAU.

### P1 — URLScan directo

Objetivo: relacionar host, página observada, requests/resources, dominios hermanos y fecha de observación.

### P1 — Passive DNS

Objetivo: descubrir relaciones históricas no visibles en CT actual y registrar `first_seen / last_seen` cuando la fuente lo permita.

### P1 — TLS SAN pivoting

Objetivo: desde un host seleccionado obtener SANs del certificado y asociar sólo nombres relevantes al target.

### P2 — GitHub / public code search

Objetivo: arquitectura pública: `API_URL`, hosts, WebSockets, GraphQL, Swagger, buckets y nombres de ambientes. Mantener source/provenance y revisión humana.

### P2 — JavaScript / source maps

Objetivo: importar scripts observados, extraer endpoints/hosts/rutas y asociarlos al árbol. No asumir que una cadena encontrada sea un finding.

### P2 — Snapshot diff

Comparar inspecciones del mismo host:

```text
DNS changed
CNAME changed
TLS SAN changed
HTTP status changed
Server/Location changed
```

Esto convierte recon periódico en señal accionable sin volver a revisar todo manualmente.

### P3 — Content discovery dirigido

Primero aprender/configurar manualmente. Después Negro debe permitir ejecutar/importar una enumeración **sobre un host explícitamente seleccionado**, con límites/rate claros, nunca como scanner masivo por defecto.

## UX / organización

### Cola de trabajo

Añadir `next_action` y vistas como:

```text
Hoy
- revisar /wf en url8202...
- validar provider de snoopy...

Bloqueado
- necesita cuenta de test
- necesita respuesta de triage
```

### Evidencia

Adjuntar por lead/finding:

- request/response;
- captura;
- comando/PoC;
- URL;
- nota;
- timestamp.

### Diffs

Mostrar visualmente qué cambió entre dos inspecciones.

### Global overview

Vista transversal entre targets:

- leads abiertos;
- findings;
- pendientes high priority;
- última actividad.

### Report builder

Convertir un finding seleccionado en borrador Markdown:

```text
Title
Asset
Summary
Steps to reproduce
Impact
Evidence
```

Sin inventar severidad/impacto: sólo reutilizar evidencia ya registrada.

## Regla permanente

> aprender manualmente → entender señal/ruido → integrar al modelo de Negro.
