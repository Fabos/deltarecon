# Negro Recon v0.12.1 — Attack Knowledge Graph V1

Esta versión agrega una nueva proyección visual de la investigación sin duplicar el modelo de datos existente.

## Mapa
- Nueva sección `Mapa` por target.
- Nodos derivados de Target, Hosts, Resources, Operations, HTTP Exchanges, JavaScript, Observations, Leads, Findings y Sources.
- Edges semánticos: `contains`, `supports`, `observed_in`, `discovered`, `observed`, `tested_by`, `produced_lead` y relaciones persistidas por Negro.
- Panel lateral con metadata, relaciones y navegación a entidades reales.
- Búsqueda, filtros por tipo y perspectivas rápidas: All, Untested, Leads/Findings, Burp y Resources.
- Focus de 1 hop con doble click o botón contextual.
- Zoom, pan y centrado.
- Provenance visible al seleccionar relaciones.

## Performance
- El grafo es una proyección read-only del modelo actual.
- Exchanges y observaciones se limitan inicialmente para evitar renderizar miles de nodos.
- La arquitectura queda preparada para progressive disclosure/clusterización en siguientes iteraciones.

## Compatibilidad
- No cambia el protocolo del Burp Bridge.
- No elimina Árbol, Hosts, Resources, Findings o Intelligence.
