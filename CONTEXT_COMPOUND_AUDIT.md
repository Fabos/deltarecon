# Contexto compuesto — auditoría de arquitectura y plan incremental

> **Lema:** El contexto genera interés compuesto.
>
> **Principio:** Negro no debe pensar por el hunter. Debe evitar que el hunter pierda el contexto de lo que ya pensó.

Este documento describe el estado real de Negro v0.41.0 antes de ampliar el Investigation Workspace y deja registrado el primer incremento seguro de la evolución.

## Diagnóstico ejecutivo

Negro **no necesita un segundo sistema de investigaciones**. La base adecuada ya existe:

- `investigations` representa el workspace humano.
- `investigation_links` ya es un grafo genérico de pertenencia/contexto y admite relaciones many-to-many.
- `leads_v2` contiene las Hypotheses humanas y conserva `promoted_investigation_id` como puntero histórico/primario.
- `signal_occurrences` mantiene Signals producidas por Reglas y su decisión humana.
- `flows`, `runners`, `runner_runs` y `runner_run_requests` ya modelan experimentos reproducibles sobre Flows completos.
- `business_objects`, `business_object_observations` y las tablas de estado ya sirven como memoria de Entities y transiciones observadas.
- `identities` + `identity_contexts` ya separan cuenta/persona del contexto de sesión/rol/tenant.
- `findings` + `finding_entities` ya permiten evidencia multi-entidad.
- `notes` y `events` en core son una base reutilizable para Notes/Timeline; hoy el workspace todavía usa además `investigations.notes` como texto libre.
- Search/Follow Value y Smart Compare ya existen, pero son principalmente operaciones transitorias y aún no tienen un registro persistente propio ligado a Investigation.
- La extensión Burp ya dispone de bridge, menú contextual, estados, notas, Findings, Identities y Flows; faltan las acciones contextuales de Investigation/Hypothesis/Entity/Follow Value/Watch.

La consecuencia de arquitectura es clara: **migrar y conectar**, no rehacer.

## Modelo actual que se conserva

### Signal

`signal_occurrences` sigue siendo la fuente de Signals. Fase 1 no permite Signals manuales ni cambia el principio Regla → Signal. Las Correlation Signals existentes también reutilizan esta tabla.

### Hypothesis

Las preguntas que el hunter decide probar continúan en `leads_v2`. No se crea una segunda tabla de Hypotheses.

Existe ya `hypothesis_requirements`, que persiste piezas faltantes (`key_pattern`, identidad, estado pending/matched y evidencia encontrada). El motor actual busca esas piezas retrospectivamente y en tráfico nuevo mediante el índice de identificadores. Esto es la semilla del futuro modelo de **Hypothesis bloqueada + Watch + Context Match**.

### Investigation

`investigations` sigue siendo el workspace. `investigation_links` se formaliza como el **grafo canónico de asociaciones many-to-many**, mientras los campos históricos de una sola Investigation se conservan como punteros de origen/compatibilidad.

No se copia Request, Flow, Signal, Entity, Hypothesis, Runner o Finding dentro de la Investigation: sólo se referencia el objeto existente.

### Runner

Runner continúa ejecutando **Flows completos**. Fase 5 añadirá intención experimental y trayectoria, no convertirá Runner en un simple repetidor de Requests.

### Finding

`findings` y `finding_entities` siguen siendo source of truth. La futura trayectoria de un Finding deberá registrar provenance hacia la investigación y eventos que condujeron a él, no crear otro modelo de hallazgo.

## Fase 1 implementada — relaciones canónicas

### Cambio 1: `investigation_links` es la relación canónica

Se añadieron helpers centrales:

- `link_investigation_entity(...)`
- `unlink_investigation_entity(...)`
- `list_investigation_links(...)`
- `backfill_investigation_links(...)`

La escritura valida que Investigation y entidad existan. Un `unlink` sólo elimina la asociación; nunca elimina la evidencia fuente.

### Cambio 2: backfill aditivo y compatible

Al abrir/inicializar un workspace se materializan en `investigation_links`, mediante `INSERT OR IGNORE`, relaciones históricas provenientes de:

- `investigations.source_hypothesis_id`;
- `leads_v2.promoted_investigation_id`;
- `runners.investigation_id`;
- `finding_entities` cuando la entidad es una Investigation;
- `ai_ideas.investigation_id`.

Los campos originales **no se eliminan ni se reescriben**. Esto permite que código antiguo siga funcionando mientras el workspace nuevo consume un grafo uniforme.

La migración tiene stamps separados para base y Runner porque el schema de Runner puede inicializarse después del schema Hunter. Las referencias huérfanas se ignoran por JOIN contra ambos extremos, de modo que un workspace viejo inconsistente no bloquea el arranque.

### Cambio 3: Identity Context como contexto first-class

`identity_context` se incorpora a los tipos asociables. Esto permite que una Investigation recuerde no sólo “Buyer A” sino, por ejemplo, “Buyer A · sesión principal/tenant/rol”.

### Cambio 4: navegación coherente

- Investigation abre una Identity asociada mediante `/identities/view/:id`.
- Search abre una Investigation directamente en `/investigations/:id`, en vez del ancla histórica dentro de Hypotheses.
- El workspace renderiza `identity_context` como contexto conocido.

## Migraciones propuestas por fase

### Fase 2 — Workspace + Notes + Timeline

No crear una segunda tabla de notas de inmediato. Evolucionar la tabla core `notes` de forma aditiva para soportar edición/borrado/provenance cuando haga falta, usando `entity_type='investigation'`. Reutilizar `events` como journal para Timeline y añadir sólo los índices/metadatos estrictamente necesarios. `investigations.notes` se conserva como resumen/nota legacy durante la transición.

Las asociaciones seguirán usando `investigation_links`. La UI debe ofrecer selectores rápidos y acciones contextuales, no formularios administrativos.

### Fase 3 — bloqueos + dependencias + Watches + Context Match

No crear otro motor desde cero. Generalizar `hypothesis_requirements` y el correlation engine existente. Se propone evolucionar el requirement con tipos explícitos (parameter/key/entity/endpoint/value/regex), lifecycle y provenance. Un Watch será una **dependencia humana pendiente**, no una Signal: cuando haga match, el resultado será un evento/context match y, si se conserva la Signal de correlación para visibilidad, ésta seguirá siendo salida de una regla/motor y no una conclusión de seguridad.

### Fase 4 — Follow Value + Smart Compare persistentes

`parameter_observations`/identifier memory siguen siendo la fuente para Follow Value. `smart_diff` y Flow Compare siguen haciendo el cálculo. Hace falta persistir la **exploración** (consulta, momento, selección/resultados relevantes y notas) y la **comparación** (inputs, snapshot/resumen), ligándolas con Investigation sin duplicar Requests.

### Fase 5 — Runner experimental

Conservar `runners.investigation_id`, `runners.hypothesis_id`, Flow y Runs por compatibilidad. Añadir, si la UX lo exige, una capa ligera de “Experiment”/intent o metadata del Run para expresar: “este Run existe para responder esta Hypothesis dentro de esta Investigation”. El resultado continúa siendo evidencia del Runner y Flow resultante.

### Fase 6 — Burp ↔ Negro

Extender el bridge y menú contextual actuales. No crear un segundo canal. Acciones candidatas: Add to Investigation, Create/Attach Hypothesis, Create Entity from selection, Follow Value, Watch parameter, Add Note y Open in Negro. Los badges/highlights deben reutilizar annotations/metadata ya disponibles en la extensión.

### Fase 7 — memoria + IA + trayectoria

Construir Dashboard y AI contextual sobre Investigation, `events`, Links, Runs, búsquedas/comparaciones persistidas, Matches y Findings. La IA propone preguntas y explica evidencia; no confirma vulnerabilidades ni crea Findings automáticamente.

## Ajuste del roadmap de siete fases

El orden general se mantiene, pero Fase 3 y Fase 5 son más pequeñas de lo previsto porque ya existe infraestructura útil:

| Fase | Estado real tras auditoría | Ajuste |
|---|---|---|
| 1. Auditoría y relaciones | **Implementada en este incremento** | Formalizar `investigation_links`, backfill y compatibilidad |
| 2. Workspace + Notes + Timeline | Parcial | Reusar workspace actual + `notes` + `events` |
| 3. Bloqueos + Watches + Context Match | Parcial desde v0.36 | Evolucionar `hypothesis_requirements` + correlation memory |
| 4. Follow Value + Smart Compare | Herramientas existentes, memoria faltante | Persistir exploraciones/comparaciones y asociarlas |
| 5. Runner experimental | Parcial desde v0.39/v0.40 | Añadir intención/trayectoria; no rehacer Runner |
| 6. Burp contextual | Bridge sólido, acciones faltantes | Extender API/menú existentes |
| 7. Dashboard + IA + trayectoria | Bases dispersas existentes | Componer memoria, no crear otro datastore |

## Compatibilidad

Fase 1 es intencionalmente aditiva:

- no elimina columnas;
- no renombra tablas existentes;
- no mueve evidencia;
- no cambia el contrato de Runner;
- no cambia el origen de Signals;
- no obliga a que todo pertenezca a una Investigation;
- conserva las rutas/relaciones históricas razonables y sólo corrige navegación claramente obsoleta.

## Validación

Se añadió `tests/v042_context_compound_phase1_test.py` para cubrir:

- backfill Hypothesis/Runner/Finding → `investigation_links`;
- many-to-many real entre Hypothesis e Investigations;
- asociación de Identity Context;
- idempotencia del link;
- rechazo de IDs inexistentes;
- unlink sin borrar evidencia;
- tolerancia a referencias legacy huérfanas;
- render del contexto y navegación directa de Investigation.

Además permanecen verdes las regresiones v0.39, v0.40 y v0.41.
