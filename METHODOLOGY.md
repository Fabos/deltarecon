# Negro Recon — Metodología v0.21.0

## Modelo mental: Rule → Signal → Hipótesis IA → Investigación

Negro no intenta reemplazar Burp ni decidir vulnerabilidades por el hacker.

1. **Rule**: conocimiento determinístico configurable. Define patrones observables.
2. **Signal**: hecho que una Rule encontró en evidencia real. Debe explicar WHY y apuntar al exchange exacto.
3. **Hipótesis IA**: inferencia generada únicamente cuando el usuario ejecuta IA. Debe separar hechos, inferencia, incógnitas y próxima prueba.
4. **Investigación**: línea de trabajo creada/promovida por decisión humana. Puede agrupar múltiples Signals, exchanges, recursos y notas.
5. **Finding**: vulnerabilidad confirmada por el humano. La IA y las Rules nunca lo asignan automáticamente.

## Search Everything: buscar evidencia, no “vulnerabilidades”

Search permite volver sobre tráfico histórico cuando aprendes una técnica nueva o quieres correlacionar una superficie grande. La búsqueda se apoya en SQLite FTS5 y filtros estructurados.

Sintaxis principal:

```text
host:api.example.com
method:POST
status:403
state:learning
signal:authorization
param:userId
cookie:session
header:X-Tenant-Id
body:"ownerId"
request:"redirect_uri"
response:"roleId"
path:/orders/
type:investigation
contains:redirect_uri
```

Los filtros se pueden combinar, por ejemplo:

```text
host:api.example.com method:POST param:userId status:200
cookie:session response:ownerId
signal:authorization status:200
```

Una **Saved Search** sirve como pregunta repetible; no altera estado ni declara hallazgos.

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
