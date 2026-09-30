# Negro Recon v0.19.2 — Fullscreen Map + Local Intelligence Recalculation

## Objetivo

Hacer el mapa utilizable como superficie principal de investigación y permitir que una Knowledge Base cambiante reinterprete evidencia histórica sin repetir recon.

## Mapa

- botón `Pantalla completa` usando Fullscreen API;
- el workspace ocupa todo el viewport en fullscreen;
- las rutas se convierten en carrusel horizontal compacto;
- `Ocultar ideas` libera todavía más altura para el canvas;
- al cambiar de tamaño Negro vuelve a ajustar el grafo.

## Recalcular inteligencia

La acción vuelve a procesar localmente:

- todos los `http_exchanges` guardados;
- Resources y parámetros históricos;
- análisis JavaScript ya almacenados;
- source maps ya procesados;
- crawls, observaciones e inspecciones existentes.

No ejecuta discovery, crawler, HTTP recon, descarga de JavaScript ni OpenAI.

## Vigencia

`leads_v2.rule_active` separa la decisión humana de la coincidencia actual de reglas. Recalcular pone temporalmente las hipótesis deterministas en no-vigentes y reactiva sólo las que siguen cumpliendo la Knowledge Base actual. Estados y `result_notes` se conservan.

La pantalla Hipótesis permite ver `Vigentes`, `Ya no coinciden` o `Todas`. El mapa y las rutas usan únicamente hipótesis vigentes.

## Notificaciones

El recálculo crea una sola notificación resumen y marca como leídas las notificaciones pendientes de hipótesis que dejaron de coincidir. Esto evita inundar un bounty grande al reinterpretar miles de requests históricos.

## Compatibilidad

Migración SQLite aditiva. No cambia el protocolo Burp ↔ Negro.
