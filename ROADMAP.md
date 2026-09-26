# Negro Recon — Roadmap

## Implementado hasta v0.7

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

## Siguiente aprendizaje antes de automatizar más

### Content discovery dirigido

Aprender manualmente `ffuf` / `feroxbuster` y reglas/rates por programa. Luego integrar sólo ejecución dirigida/importación por host.

### Análisis JavaScript v2

- AST real / separación de módulos webpack/Vite;
- correlación entre múltiples bundles;
- operaciones GraphQL;
- detección de métodos HTTP con contexto;
- cache por SHA-256 para no pagar dos veces por el mismo JS;
- segunda pasada IA sólo cuando la primera marque señal alta.

### Passive DNS providers adicionales

Adaptadores opcionales según cuentas disponibles, sin acoplar Negro a un único proveedor.

### Snapshot diffs

Comparar DNS/TLS/HTTP entre inspecciones.
