# v0.117.1 · Context Agent — Complete Batching + COP

Esta versión elimina el cap fijo de 120 candidatos del Context Agent v1.0.

## Principio

La optimización de costo puede reducir redundancia, nunca contexto semántico relevante.

- Todos los candidatos que pasan el filtro determinístico de ruido entran al plan de análisis.
- Si son muchos, se reparten en batches correlacionados por exchange/Flow.
- El presupuesto no reduce candidatos: actúa como hard-stop antes de llamar al modelo.
- El output se calcula automáticamente por batch.
- Un run exitoso exige `coverage_pct = 100` y `truncated = false`.

## Costos en COP

La UI usa COP como moneda principal para presupuesto, estimación y costo real.
La referencia incluida en esta release es `1 USD ≈ COP $3.160,05` (2026-11-01) y puede seguir configurándose mediante `usd_cop_rate` en settings.

La estimación muestra:

- costo esperado en COP;
- costo máximo estimado en COP;
- USD sólo como referencia secundaria;
- número de batches;
- input estimado total;
- output reservado total.

## Batching

El tamaño base es 48 candidatos. Negro intenta conservar juntos candidatos que comparten exchanges o Flows para proteger relaciones semánticas.

No se persisten resultados parciales si un batch falla. El costo consumido sí queda registrado y el run queda marcado como incompleto.

## Incrementalidad

Se mantiene Delta + Impact Graph:

- tráfico nuevo;
- cambios manuales;
- cambios de Flow;
- vecinos del grafo histórico hasta dos saltos.

El batching no cambia el watermark ni la memoria semántica persistente.
