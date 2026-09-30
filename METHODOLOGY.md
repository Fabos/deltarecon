# Negro Recon — Metodología v0.22.0

## Modelo mental: Rule → Signal → Hipótesis IA → Investigación

Negro no intenta reemplazar Burp ni decidir vulnerabilidades por el hacker.

1. **Rule**: conocimiento determinístico configurable. Define patrones observables.
2. **Signal**: hecho que una Rule encontró en evidencia real. Debe explicar WHY y apuntar al exchange exacto.
3. **Hipótesis IA**: inferencia generada únicamente cuando el usuario ejecuta IA. Debe separar hechos, inferencia, incógnitas y próxima prueba.
4. **Investigación**: línea de trabajo creada/promovida por decisión humana. Puede agrupar múltiples Signals, exchanges, recursos y notas.
5. **Finding**: vulnerabilidad confirmada por el humano. La IA y las Rules nunca lo asignan automáticamente.

## Buscar

La búsqueda es local y sirve para localizar texto o fragmentos en la memoria de Negro. Para términos de 3 o más caracteres usa un índice trigram, por lo que una consulta parcial puede coincidir dentro de un valor mayor:

```text
1223
AIza
response:ownerId
param:tenant
```

Filtros disponibles:

```text
host:api.example.com
method:POST
status:403
state:learning
signal:authorization
param:userId
cookie:session
header:X-Tenant-Id
body:ownerId
request:redirect_uri
response:roleId
path:/orders/
type:investigation
contains:redirect_uri
```

Los filtros pueden combinarse. Saved Searches guarda la consulta, no cambia estados ni crea hallazgos.

## Parameter Explorer / Follow Value

`parameter_observations` es una capa derivada de la evidencia HTTP. Extrae escalares de query, IDs probables del path, JSON/form del request y JSON del response. Cada observación guarda nombre normalizado, superficie, exchange, recurso, hash del valor y un preview; valores sensibles se enmascaran.

- **Parameter Explorer** responde “¿dónde aparece este nombre?”.
- **Follow Value** responde “¿dónde vuelve a aparecer exactamente este valor?”.
- **Find Related** usa evidencia compartida para sugerir exchanges cercanos y explica los motivos.
- **Smart Diff** compara dos exchanges y ordena primero campos de negocio; no declara vulnerabilidades.

Esta capa será la base de Identity Contexts: antes de resolver identidades necesitamos saber dónde viajan `userId`, `accountId`, `ownerId`, `tenantId`, tokens y otros identificadores.

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
