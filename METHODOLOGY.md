# Negro Recon — Metodología v0.25.0

## Modelo mental

`Rule → Signal → Hipótesis IA → Investigación humana → Finding/cierre`

Negro organiza evidencia y relaciones. No intenta decidir automáticamente qué es vulnerable.

## Buscar

**Buscar** responde: **¿dónde aparece esto?**

Texto libre encuentra fragmentos en tráfico y conocimiento. Si una coincidencia también existe como observación estructurada, Search ofrece acciones de correlación sin obligarte a entrar primero a Parameter Explorer.

## Follow Value

Responde: **¿dónde reaparece exactamente este valor?**

Seleccionas un valor concreto y Negro sigue su hash exacto por requests, responses, paths, endpoints o hosts. Si `diego@example.test` aparece como `email` en un login y luego en `/me`, Follow Value muestra ambas apariciones.

## Find Related Exchange

Responde: **¿qué otros exchanges comparten evidencia con este exchange completo?**

Toma los valores útiles de request + response del exchange de origen y busca coincidencias exactas en otros exchanges. Valores genéricos, booleanos y atributos muy comunes se penalizan; `mismo host` por sí solo no genera una relación. `OPTIONS` se oculta cuando no es relevante.

Una relación no significa “mismo objeto”, “mismo usuario” ni vulnerabilidad. Es una pista de correlación que debe ser interpretada con su path y nombre de campo.

## Smart Compare

Responde dos preguntas distintas:

1. **¿Qué coincide entre A y B?**
2. **¿Qué cambia entre A y B?**

La sección de coincidencias compara observaciones por valor exacto. Si el mismo valor aparece con nombres distintos, Negro lo marca como **posible alias**:

```text
A: response_json:$.user.id · id = 102
B: response_json:$.memberId · memberid = 102
```

Eso es evidencia de igualdad del valor, no de equivalencia semántica. Después, la sección de cambios muestra diferencias de HTTP, query, JSON y headers, priorizando campos de negocio.

## Identity Contexts

Responde: **¿quién hizo este tráfico?**

Negro separa Identity, Context, Auth Material y Resolver. La primera asociación es humana sobre un exchange concreto. Auth Material puede rotar; resolvers estables ayudan a reconocer la misma cuenta en sesiones nuevas.

La separación crítica es **actor vs ownership**:

- `/me.id=101`, `/me.email=...`, `jwt:sub=101` pueden resolver al actor;
- `order.ownerId=101` describe el objeto y no demuestra quién hizo la request.

La Authorization Matrix es descriptiva: sólo muestra lo que Burp observó bajo cada identidad. `No observado` significa únicamente ausencia de evidencia.

## Flow Workbench

Responde: **¿qué historia de negocio forman varios exchanges?**

Un Flow es una secuencia manual/observada, por ejemplo:

```text
POST /auth/login
POST /cart
POST /checkout
POST /payment
GET  /orders/{id}
```

Puedes capturar un rango de exchanges o agregarlos uno por uno. El orden se conserva y cada paso enlaza al HTTP exacto.

### Business states

Negro extrae campos cuyo nombre sugiere estado (`status`, `state`, `paymentStatus`, `orderStatus`, etc.) y muestra cambios vistos entre pasos consecutivos. Sólo documenta transiciones observadas; no afirma que una transición ausente sea inválida.

### Flow Compare

Dos flows se alinean por método + ruta normalizada. La comparación muestra pasos iguales/ausentes/cambiados y, para pasos alineados, reutiliza Smart Compare para exponer coincidencias y cambios de negocio.

Ejemplo de uso:

```text
Flow A: cart → payment → order
Flow B: cart → order
```

La ausencia de `payment` en B es una diferencia de recorrido que merece entenderse, no una vulnerabilidad automática.

## Mapa mental de módulos

```text
Buscar
  ↓
Follow Value        (un valor exacto)
  ↓
Find Related        (todo un exchange)
  ↓
Smart Compare       (coincidencias + diferencias entre A/B)
  ↓
Identidades         (actor/sesión)
  ↓
Flows               (secuencia de negocio)
  ↓
Signals / IA / Investigaciones
```

## Principios

- Un Signal no es una vulnerabilidad.
- Correlación no es causalidad ni equivalencia semántica.
- La IA no corre por request; el usuario decide cuándo razonar.
- Finding y Discarded siguen siendo decisiones humanas.
- Evidencia histórica y retest actual son conceptos distintos.
- Negro debe reducir ruido y conservar procedencia exacta, no esconder datos útiles del hunter local.
