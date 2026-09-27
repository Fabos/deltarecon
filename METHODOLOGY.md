# Negro Recon — Metodología v0.8.0

## Filosofía

```text
ASSET → OBSERVATION → LEAD → MANUAL VALIDATION → FINDING / DISCARDED
```

## Capa 1 — superficie pasiva

1. crt.sh — CT/SANs públicos.
2. Subfinder — agregador multi-source.
3. Amass passive — correlación OSINT.
4. GAU providers — URLs históricas/observadas.
5. Wayback CDX direct — snapshots + timestamp/MIME/status.
6. URLScan direct — scans y requests observados.
7. SecurityTrails — subdominios/DNS histórico (si hay key).
8. GitHub code search — arquitectura pública (si hay token).

## Capa 2 — un host que decidimos investigar

```text
Basic Inspect
  A / AAAA / CNAME
  TLS subject / issuer / dates / SAN
  HTTP / HTTPS headers
```

Luego, según señal:

- TLS SAN pivot;
- Passive DNS history;
- JavaScript discovery;
- recursos históricos ya asociados.

## Capa 3 — aplicación / JavaScript

Primero determinístico/local:

- guardar RAW;
- calcular SHA-256;
- beautify cuando la dependencia está disponible;
- extraer URLs/rutas/WebSockets;
- detectar `sourceMappingURL`;
- contar señales de auth, roles, feature flags, admin/internal, etc.;
- recortar sólo contextos relevantes.

Después IA opcional:

- se estima tokens/costo antes de enviar;
- se envían extracción + chunks, no el bundle completo por defecto;
- la IA reconstruye comportamiento y propone validaciones manuales;
- no puede declarar finding ni inventar endpoints/impacto.

## Source maps

Si el JS declara un source map público:

1. descarga explícita;
2. conserva `.map` en RAW;
3. lista `sources`;
4. si existe `sourcesContent`, analiza sólo un límite local;
5. endpoints in-scope derivados se asocian con provenance `sourcemap`.

## Estados

Review:

- `pending`
- `in_progress`
- `reviewed`

Classification:

- `unknown`
- `informational`
- `lead`
- `discarded`
- `finding`

Priority:

- `none`
- `low`
- `medium`
- `high`

## Límites

Negro sigue siendo passive-first. Content discovery/fuzzing activo no se ejecuta sobre todo el inventario. Cuando se integre, será sólo sobre un host seleccionado y con rate explícito.


## Progreso de tareas largas

Cuando una herramienta no expone progreso determinista, Negro muestra actividad indeterminada y tiempo transcurrido. No se presenta un porcentaje ficticio. El job termina en `done` o `error` y la ficha se refresca automáticamente.

## Costos de IA

La estimación debe leerse como un máximo presupuestado: entrada estimada + tope de salida. La UI muestra COP de forma explícita, USD como referencia y la tasa usada. La llamada facturable sólo ocurre tras confirmación del usuario.


## JavaScript v0.8 — lectura por capas

1. **Discovery**: inventariar scripts cargados por una página.
2. **Local Analysis**: extraer URLs, rutas, WebSockets, `sourceMappingURL` y contexto.
3. **Secrets & Client Config**: clasificar candidatos sin asumir vulnerabilidad; los valores se enmascaran.
4. **Source Map**: separar código de aplicación de dependencias/runtime y analizar `sourcesContent` cuando esté disponible.
5. **AI Analysis**: correlacionar únicamente evidencia seleccionada; salida en español; nunca auto-promover a finding.

Una Google API key, Firebase config, OAuth Client ID, Sentry DSN o Stripe publishable key puede ser intencionalmente pública. La pregunta útil es si su configuración/restricciones producen impacto dentro del scope, no si el valor aparece en JavaScript. Negro no usa automáticamente tokens/keys detectados.
