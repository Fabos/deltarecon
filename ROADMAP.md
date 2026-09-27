# Negro Recon — Roadmap

## Implementado hasta v0.8.1

- crt.sh
- Subfinder
- Amass passive
- GAU por provider
- Wayback CDX direct
- URLScan direct
- SecurityTrails subdomains + DNS history opcional
- TLS SAN pivot
- GitHub public code search opcional
- Basic Inspect
- multi-target Web UI
- states/notes/provenance/tree
- JavaScript discovery
- local JS extraction
- source maps
- OpenAI JS analysis con estimación previa USD/COP
- Secrets & Client Config con valores enmascarados
- Source Map app/dependencies/runtime + sourcesContent
- correlación Source Map + bundle antes de IA
- IA en español con términos técnicos preservados
- launcher fijo sobre `.venv`

## Siguiente aprendizaje antes de automatizar más

### Content discovery dirigido

Aprender manualmente `ffuf` / `feroxbuster` y reglas/rates por programa. Luego integrar sólo ejecución dirigida/importación por host.

### Análisis JavaScript v2

- AST real / separación más precisa de módulos webpack/Vite;
- correlación entre múltiples bundles;
- operaciones GraphQL;
- detección de métodos HTTP con contexto;
- cache por SHA-256 para no pagar dos veces por el mismo JS;
- segunda pasada IA sólo cuando la primera marque señal alta.

### Passive DNS providers adicionales

Adaptadores opcionales según cuentas disponibles, sin acoplar Negro a un único proveedor.

### Snapshot diffs

Comparar DNS/TLS/HTTP entre inspecciones.


### v0.7.2 — UX del análisis JS/IA

- costo IA claro en COP/USD;
- barra de actividad + tiempo transcurrido para jobs largos;
- tarjetas JS más legibles;
- verificación/diagnóstico del SDK `openai`;
- hotfix consolidado de source maps inline Base64.


### Después de v0.8.0

- Job Center persistente con cola y límite de concurrencia configurable;
- progreso por etapas cuando una herramienta exponga progreso real;
- validadores dirigidos y explícitos para client config sólo cuando el programa lo permita (nunca uso automático de credenciales);
- correlación entre múltiples bundles/source maps por aplicación.
