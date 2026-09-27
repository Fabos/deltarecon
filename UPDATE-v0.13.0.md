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
