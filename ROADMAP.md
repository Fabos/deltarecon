# Negro Recon — Roadmap

## v0.5 — Web Foundation

Implementado:

- CLI + Web UI sobre la misma SQLite;
- dashboard;
- inventario de hosts;
- árbol host → resources → sources;
- estados `pending / in_progress / reviewed`;
- clasificación `unknown / informational / lead / discarded / finding`;
- prioridad `none / low / medium / high`;
- notas;
- auditoría de cambios de estado;
- Basic Inspect desde web;
- lanzamiento explícito de crt.sh, Subfinder, Amass y GAU;
- jobs locales en background.

## Próximo — sólo después de usar v0.5 en casos reales

- mejorar timeline y provenance visual;
- vistas de recursos más grandes/paginación;
- comparación entre snapshots de inspección;
- export/import de leads;
- tags personalizados;
- detección de cambios de DNS/TLS/HTTP entre inspecciones.

## Técnicas por aprender antes de automatizar

- Passive DNS;
- TLS SAN pivoting;
- GitHub/public code search;
- análisis de JavaScript/source maps;
- content discovery dirigido;
- fingerprints de SaaS/takeover basados en hipótesis.

Regla permanente:

> aprender manualmente → entender señal/ruido → integrar al modelo de Negro.
