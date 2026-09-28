# Negro Recon v0.15.0 — UX Polish / Bounty Pilot

Última iteración antes del piloto real de bug bounty. No cambia el modelo de datos ni el protocolo Burp → Negro: reorganiza la experiencia para que la herramienta sea más rápida de leer y requiera menos mantenimiento manual.

## Cambios principales

- UI unificada en español (manteniendo términos técnicos estándar cuando aportan).
- Navegación reducida a Inicio, Inventario, Mapa, Inteligencia, Hipótesis, Hallazgos y Ajustes.
- Inventario unificado: la búsqueda de Hosts también encuentra recursos por path, URL o query y muestra las coincidencias dentro del host.
- Dashboard rediseñado para priorizar contexto, pendientes, hipótesis y hallazgos.
- Host: acciones reorganizadas en una caja de herramientas contextual en vez de una fila saturada.
- Resource detail: tráfico Burp y acciones contextuales son protagonistas.
- La antigua checklist de vulnerabilidades queda como **Guía opcional de pruebas**, cerrada por defecto. No es requisito completar checks ni mantenerlos manualmente. Sólo las pruebas que el investigador realmente toca (o que un motor registra) alimentan la memoria de IA. Los checks automáticos pendientes no se convierten en tareas ni sesgan “Dame ideas”.
- Hallazgos, retests, hipótesis, mapa y ajustes reciben nomenclatura y jerarquía visual coherentes.
- El mapa mantiene drag, perspectivas y memoria de layout; las perspectivas se muestran en español.

## Compatibilidad

- Bases/workspaces de v0.14.x: compatibles.
- Bridge v0.14.x: compatible; no es necesario recompilarlo para usar v0.15.0. Si se recompila desde este paquete, el JAR se etiqueta v0.15.0.
