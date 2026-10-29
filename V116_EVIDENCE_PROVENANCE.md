# Negro v0.116 — Evidence & Provenance

Esta fase separa tres niveles que antes podían mezclarse:

1. **Capture Event** — lo que ocurrió en Burp/Negro y de dónde vino.
2. **Evidence** — qué demostró un experimento sobre un Object concreto.
3. **Knowledge Relation** — conocimiento observado o confirmado respaldado por evidencia.

## Provenance

Los Capture Events pueden conservar `provenance_source`, `interaction_kind`, `parent_event_id`, `parent_confidence`, `mutation_diff`, `bridge_message_id` y `request_hash`.

Fuentes iniciales relevantes:

- `PROXY` → comportamiento observado normalmente.
- `PROXY_MANUAL_MUTATION` → Request editada durante Intercept; `EXPERIMENT`.
- `REPEATER` → `EXPERIMENT` por defecto.
- `NEGRO_REPLAY` / `RUNNER` → experimentos controlados.

Un experimento **no se convierte en tráfico legítimo** porque responda HTTP 200. El Capture Event sigue siendo `EXPERIMENT`; lo que puede convertirse en conocimiento confirmado es la relación sustentada por su evidencia.

## Resultado separado del HTTP status

Evidence conserva por separado:

- `transport_status` — por ejemplo 422.
- `semantic_result` — `ALLOWED`, `DENIED`, `PARTIAL`, `UNKNOWN`.
- `object_evidence` — `RETURNED`, `NOT_RETURNED`, `MODIFIED`, `CREATED`, `DELETED`, `UNKNOWN`.
- `outcome` — `CONFIRMED`, `BLOCKED`, `INCONCLUSIVE`.

Esto permite representar, por ejemplo, `HTTP 422 + DENIED + Order data RETURNED` sin confundir autorización con exposición de datos.

## Parent y mutaciones

Proxy Intercept usa el mismo `messageId` de Montoya para correlacionar la Request original y la finalmente enviada. Negro calcula un diff semántico de path/query/headers/body.

Repeater intenta enlazar un parent exacto únicamente cuando existe una Request observada previa con el mismo hash. Si no hay certeza, el parent queda desconocido; v0.116 no inventa relaciones fuzzy.

## Knowledge

`knowledge_relations` conserva relaciones sustentadas por evidencia, por ejemplo:

- `owns`
- `references`
- `accessed`
- `modified`
- `returned_by`
- `leaked_from`

Cada relación puede llevar `status` (`OBSERVED` / `CONFIRMED`) y `expectedness` (`EXPECTED` / `UNEXPECTED` / `UNKNOWN`).

La intención es que el futuro Mapa consuma **knowledge**, no cada Request capturada ni cada experimento fallido.

## Burp Bridge v0.40.0 en Kali

Compilar desde Kali:

```bash
cd burp-extension
sh build-extension.sh
```

El script está escrito para POSIX `sh` (Kali normalmente ejecuta `/bin/sh` con `dash`) y no depende de sintaxis exclusiva de Bash.

Requisitos:

- JDK 21+
- `curl` o `wget`
- Internet en la primera compilación para descargar Montoya API 2026.7

Salida:

```text
build/libs/negro-burp-bridge-0.40.0.jar
```

Luego carga ese JAR en Burp → Extensions → Installed → Add → Java.

## Compatibilidad

v0.116 se construye encima de v0.115.8. El Workbench inmersivo, Traffic Timeline, JWT Inspector, Checkpoints, Inline Semantics, Flow wiring y Runner existentes se mantienen.
