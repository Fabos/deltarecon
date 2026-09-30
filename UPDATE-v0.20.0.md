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
