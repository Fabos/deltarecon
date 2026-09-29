# Negro Recon v0.17.1 — Signal UX + JavaScript Surface

## Objetivo

Hacer que Access Control Intelligence sea usable durante una investigación real: menos ruido, filtros claros, estados editables desde el mapa, notificaciones accionables y JavaScript conectado de verdad con Resources.

## Cambios

### Mapa

- `Interesante`, `Burp` y `Rutas de investigación` ahora responden preguntas distintas:
  - **Interesante:** dónde existen señales, hipótesis o hallazgos.
  - **Burp:** tráfico observado (`Resource → Operation → Request`) sin mezclar hipótesis.
  - **Rutas de investigación:** sólo caminos respaldados por evidencia hacia una hipótesis y su siguiente prueba.
- filtros de hipótesis por **estado**, **prioridad** y **tipo**;
- las tarjetas de rutas respetan esos mismos filtros;
- una hipótesis puede cambiar de estado y guardar `Resultado / qué pasó` directamente desde su nodo del mapa;
- ese estado/comentario es el mismo registro de `leads_v2` usado por la pantalla Hipótesis; no existe memoria duplicada;
- relaciones visualmente diferenciadas:
  - evidencia observada;
  - rutas descubiertas por JavaScript;
  - relación hipotética;
  - hipótesis confirmada;
  - ruta seleccionada.

### Notificaciones

- las nuevas hipótesis determinísticas de Access Control generan una notificación **sólo cuando nacen**;
- la notificación enlaza a evidencia, Hipótesis y Mapa;
- se mantiene deduplicación por hipótesis;
- el análisis local de JavaScript genera una notificación agregada con rutas in-scope, nuevas e interesantes.

### CORS

- `app.target → api.target` deja de elevarse automáticamente como CORS sospechoso cuando ambos hosts pertenecen al mismo target/workspace;
- si v0.17.0 había creado una candidata CORS para esa relación y vuelve a observarse, Negro la retira como `negative` con una nota explicativa;
- Origins externos reflejados siguen entrando al flujo normal de investigación.

### JavaScript

`Analizar local` ahora convierte las rutas encontradas en una señal visible:

```text
JavaScript
   ↓ discovered
Resource
```

- las URLs in-scope siguen convirtiéndose en Resources;
- el grafo conecta el bundle con esos recursos;
- las relaciones funcionan también cuando un JS de `app.target` descubre endpoints de `api.target`;
- rutas con términos como `admin`, `internal`, `approve`, `audit`, `export`, `ops`, `role`, `permission`, etc. generan una única hipótesis de **superficie JavaScript**, no una vulnerabilidad confirmada;
- una notificación resume el análisis en vez de emitir una alerta por cada ruta.

## Filosofía

```text
Señal ≠ vulnerabilidad
Hipótesis ≠ finding
Ruta de investigación ≠ exploit chain confirmado
```

La v0.17.1 mejora dónde mirar y conserva al investigador como quien valida impacto.

## Compatibilidad

No cambia el protocolo Burp ↔ Negro. El bridge/JAR de v0.16.7/v0.17.0 continúa funcionando.

## Tests

```bash
PYTHONPATH=. python tests/smoke_test.py
PYTHONPATH=. python tests/access_control_intelligence_test.py
node --check web/static/graph.js
```

El test de Access Control cubre también reducción de ruido CORS, notificaciones de hipótesis y `JavaScript → Resource` cross-host.
