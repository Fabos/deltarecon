# Negro Recon — Metodología v0.23.2

## Modelo mental: Rule → Signal → Hipótesis IA → Investigación

Negro no intenta reemplazar Burp ni decidir vulnerabilidades por el hacker.

1. **Rule**: conocimiento determinístico configurable. Define patrones observables.
2. **Signal**: hecho que una Rule encontró en evidencia real. Debe explicar WHY y apuntar al exchange exacto.
3. **Hipótesis IA**: inferencia generada únicamente cuando el usuario ejecuta IA. Debe separar hechos, inferencia, incógnitas y próxima prueba.
4. **Investigación**: línea de trabajo creada/promovida por decisión humana. Puede agrupar múltiples Signals, exchanges, recursos y notas.
5. **Finding**: vulnerabilidad confirmada por el humano. La IA y las Rules nunca lo asignan automáticamente.

## Buscar

**Buscar** es la entrada universal. Texto libre encuentra fragmentos en tráfico y conocimiento; si además coincide con una observación estructurada, la misma pantalla ofrece acciones de Parameter Explorer. Ejemplos:

```text
4101
ownerId
AIza
host:api.example.com method:GET ownerId
```

Filtros disponibles: `host:`, `method:`, `status:`, `state:`, `signal:`, `param:`, `cookie:`, `header:`, `body:`, `request:`, `response:`, `path:`, `type:` y `contains:`.

Parameter Explorer queda como vista de detalle: **Search responde dónde aparece algo; Parameter Explorer responde cómo se comporta ese nombre/valor a lo largo del sistema.**

### Follow Value / Find Related / Smart Diff

`parameter_observations` deriva escalares de query, path, request JSON/form y response JSON. Cada observación conserva nombre normalizado, superficie, exchange, recurso, hash del valor, preview y valor local completo (`value_raw`). El hash sirve para correlación; el valor completo permanece disponible en el workspace local para análisis manual.

- **Follow Value**: mismo valor exacto por hash.
- **Find Related**: exchanges relacionados por valores exactos o el mismo recurso. “Mismo host” o un nombre genérico compartido no bastan; OPTIONS queda fuera del resultado normal. Las etiquetas fuerte/media/débil describen evidencia compartida, no severidad.
- **Smart Diff**: diferencias relevantes entre dos exchanges antes del ruido de headers.

## Identity Contexts

Negro separa **Identity**, **Context** y **Auth Material**. La identidad representa a la cuenta/persona; el contexto representa rol/tenant; el auth material representa la credencial concreta que puede rotar.

La primera asociación es humana y se hace sobre un **exchange**, no sobre una ruta completa. Ejemplo: el `GET /me` concreto que sabes que pertenece a Buyer A. Antes de guardarlo, Negro muestra el HTTP exacto y los valores observados. A partir de ese ancla recuerda fingerprints y valores locales de cookies/Bearer y, si el token es JWT, resolvers de claims estables como `sub`, `userId` o `accountId`. Si un resolver estable identifica una sesión nueva, Negro aprende el auth material rotado de esa sesión para siguientes requests.

También se puede enseñar un resolver desde una observación de parámetro estable. La separación clave es **actor vs ownership**: `/me.id=101`, `/me.email=...` o `jwt:sub=101` pueden resolver quién hace la request; `order.ownerId=101` describe el dueño de un objeto y no debe atribuir el tráfico a esa persona. Al asignar manualmente un `/me`, Negro propone candidatos y deja la selección bajo control humano. Si no hay una coincidencia única, la identidad permanece **desconocida**; Negro no adivina. `Context` es opcional y pertenece siempre a una sola Identity.

### Authorization Matrix

La matriz es descriptiva, no conclusiva. Agrupa rutas observadas y muestra qué status/cantidad de exchanges existen para cada identidad. Una celda vacía se representa como **No observado**; no se infiere acceso, bloqueo ni vulnerabilidad.

## Mapa

El mapa distingue inventario determinístico de rutas de investigación:

- `Superficie`: relaciones conocidas por inventario/HTTP.
- `Burp`: tráfico observado realmente por Burp, cargado de forma explícita y acotada.
- `Qué probar ahora`: rutas respaldadas por Hipótesis/Investigaciones; esta perspectiva sí puede crecer después del razonamiento IA.

Que una Hipótesis añada una ruta de investigación no significa que haya creado las relaciones básicas del inventario.

## Principios

- Un Signal no es una vulnerabilidad.
- Una Rule no crea automáticamente una Hipótesis visible.
- La IA no corre por request; el usuario decide cuándo y sobre qué evidencia razonar.
- Una Hipótesis IA no se convierte sola en Investigación.
- `Finding` y `Discarded` siguen siendo decisiones humanas.
- Evidencia histórica y retest actual son conceptos distintos.
- El conocimiento útil descubierto con IA puede terminar convertido, después de revisión humana, en una nueva Rule determinística.

## Flujo recomendado

Burp captura tráfico → Negro normaliza evidencia → Rules producen Signals → el hacker revisa/organiza → Search ayuda a recuperar/correlacionar evidencia → cuando tiene suficiente contexto ejecuta IA → la IA propone Hipótesis → el hacker promueve sólo las que merecen trabajo → Investigación → validación manual → Finding o cierre.
