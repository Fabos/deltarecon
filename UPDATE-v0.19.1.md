# Negro Recon v0.19.1 — Route Canvas Hydration Fix

## Problema

En v0.19.0 el endpoint `scope=overview` cargaba intencionalmente sólo Proyecto + Hosts para mantener fluidez en targets grandes. Sin embargo, `_investigation_routes()` podía devolver tarjetas que apuntaban a `resource:*`, `operation:*`, `exchange:*` y `lead:*` que todavía no estaban presentes en `graph.nodes`. El resultado visible era contradictorio: **Ideas para continuar** tenía hipótesis válidas, pero el canvas decía **No hay nodos para esta vista**.

## Corrección

- nueva proyección `scope=routes`;
- materializa sólo los Host → Resource → Operation → Exchange → Hypothesis necesarios para las rutas prioritarias;
- al abrir **Qué probar ahora**, el frontend solicita esa proyección automáticamente;
- las tarjetas siguen siendo el selector de ruta, pero ya no es necesario hacer clic en una para que aparezca el grafo;
- mantiene progressive disclosure: no carga todo el target.

## Validación

El test de Access Control ahora verifica que cada ruta materializa sus nodos esenciales (`host`, `resource`, `operation`, `lead`) y que el canvas puede dibujar las hipótesis existentes desde el primer render.
