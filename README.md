# Negro Recon 🐕 — v0.33.0

Negro es una capa local de inteligencia, memoria y organización encima de Burp Suite. No pretende reemplazar Burp ni decidir vulnerabilidades por el usuario.

## Modelo central

`Rule → Signal → Hipótesis IA → Investigación humana`

- **Rules**: conocimiento determinístico configurable.
- **Signals**: observaciones automáticas con procedencia exacta; no son vulnerabilidades.
- **Hipótesis IA**: aparecen únicamente cuando el usuario ejecuta IA y separan hechos, inferencia, incógnitas y próxima prueba.
- **Investigaciones**: las crea el usuario al promover una hipótesis.
- **Findings / estados humanos**: siguen bajo control del hacker.

## v0.33.0 — Semantic graph polish: iconos, relaciones legibles y comparación A/B

Esta iteración no añade otro motor de detección. Hace que el grafo explique mejor la evidencia que Negro ya conoce.

- Los nodos semánticos dejan de ser círculos indistinguibles: **Identity** usa tarjeta/persona, **Endpoint** una pill persistente con la ruta, **Flow** una tarjeta de proceso, **Object** un hexágono, **Request** documento, **State** rombo y **Anomaly** triángulo.
- En vistas Identity/Object/Flow, Identity, Endpoint y Flow mantienen tamaño/label legible al cambiar zoom; Superficie conserva su comportamiento conocido.
- El panel de un endpoint agrupa relaciones por significado. Repeticiones como `id=102` o dos Flows con el mismo nombre ya no aparecen como líneas idénticas: se condensan con contador y la evidencia ambigua queda separada como “identificadores sin clasificar”.
- Identity Compare añade una lectura rápida **Compartidos / Sólo A / Sólo B**, con filtros directos sobre el grafo y líneas visuales diferenciadas para cada identidad.
- La navegación superior elimina `Entender` / `Más` y deja accesos directos a Identidades, Flows, Objetos, Mapa, Recon, Guía y Ajustes.
- Nuevos Flows creados desde la selección por defecto de Burp reciben un nombre contextual basado en el primer/último endpoint, evitando listas de `Flow from Burp selection` indistinguibles.

La regla visual sigue siendo: **Identity + Endpoint + Flow explican la historia; Object añade contexto; Request/Method son detalle progresivo.**

## v0.32.0 — Graph-first semantic views: Identidades, endpoints y objetos legibles

Esta iteración corrige el exceso de simplificación de v0.31: el grafo vuelve a ser la vista principal cuando realmente ayuda a comparar relaciones, pero con una jerarquía visual explícita.

- **Identidad**: una o dos Identity Contexts quedan a los lados y los **endpoints** aparecen en el centro. Un endpoint compartido converge visualmente; uno exclusivo queda conectado sólo a la identidad que lo observó. Flows, objetos, Requests individuales y métodos son capas opcionales.
- **Objeto**: el objeto focal conecta directamente con los endpoints donde apareció. Identidades y Flows relacionados quedan como contexto lateral; objetos secundarios y Requests individuales se pueden activar si hacen falta.
- **Flow**: ofrece dos lecturas del mismo dato, **Grafo** y **Línea de tiempo**. El grafo conserva la secuencia entre Requests; la línea de tiempo mantiene la lectura paso a paso que ya funcionaba bien.
- **Superficie**: conserva el comportamiento conocido; los métodos HTTP siguen visibles por defecto, pero ahora pueden ocultarse con un check.
- **Endpoints**: sus labels nunca se suprimen por nivel de zoom en las vistas semánticas importantes. El detalle del endpoint muestra siempre los métodos soportados, aunque la capa de métodos esté apagada.
- Jerarquía visual estable: **Identity = azul**, **Flow = ámbar**, **Endpoint = azul/cian**, **Object = verde y menor peso**.

La idea no es mostrar más nodos: es que el grafo responda visualmente preguntas como “¿qué endpoints comparten estas dos sesiones?” o “¿en qué rutas apareció Order 4101?”.

## v0.30.0 — Investigation Views / Map 3.0 + UX simplification

Esta iteración no añade nuevas detecciones. Reduce ruido y cambia el mapa desde un grafo universal hacia **vistas que responden preguntas concretas**.

- **Superficie** sigue usando mapa/árbol para responder qué existe.
- **Identidad** usa un grafo focal alrededor de una cuenta/sesión elegida dinámicamente.
- **Flow** deja de ser un grafo: ahora es una **línea de tiempo de Requests**, con método, endpoint, HTTP status, identidad, objetos y estados visibles sin abrir detalle.
- **Objeto** obliga a elegir una cosa concreta antes de mostrar relaciones. Tipos ambiguos como `111`, `Object`, `id` o `reference` se conservan, pero quedan ocultos por defecto.
- **Atención** deja de mostrar toda la superficie y se convierte en una bandeja corta de anomalías, hipótesis activas y hallazgos.

La navegación principal también se simplifica: Identidades, Flows y Objetos se agrupan bajo **Entender**; Recon/Guía/Ajustes quedan en **Más**. Todas las páginas mantienen ayuda contextual, pero ahora la pregunta que responde la pantalla es la pieza visible principal.

La regla de UX oficial pasa a ser: **guardado no significa protagonista**. Negro puede conservar evidencia técnica sin obligar al investigador a verla en cada pantalla.

La terminología visible sigue siendo **Request**; `exchange_id` permanece únicamente como compatibilidad interna.

## v0.28.0 — Guided UX + Learning Center

Esta iteración no añade otra capa de detección. Reduce complejidad cognitiva. Cada pantalla principal incluye una ayuda contextual con cuatro respuestas: **qué pregunta responde**, **cuándo usarla**, **ejemplo del Access Control Lab** y **qué no debe inferirse**.

La sección **Guía** pasa a ser un Centro de Aprendizaje por intención: inventario/enumeración, búsqueda y correlación, identidades/autorización, flows/estados, Business Objects/anomalías e Intelligence/Hunt/Findings. Incluye un walkthrough con Ana/Diego y el modelo `Identity → Business Object → propiedad` para evitar mezclar actores con objetos.

Business Objects también corrige el filtro vacío `type_id`, elimina el prellenado confuso del campo de tipo y clasifica candidatos como `Buen candidato`, `Revisar contexto` o `Genérico`. Una sugerencia nunca se activa sola.

## v0.27.0 — Business Objects + cross-host correlation + Pattern Anomalies

Negro ahora puede aprender tipos de objeto como `Order`, `Payment`, `Shipment`, `Account` o cualquier concepto propio del target. Un tipo acepta varios identifiers/aliases, por ejemplo `Order: orderId` y `Order: order_id`; las instancias se unifican por **tipo + valor exacto**.

Una instancia muestra en una sola vista:

- hosts y endpoints donde apareció;
- identidades observadas;
- Flows donde participó;
- estados ya aprendidos;
- objetos co-observados;
- timeline HTTP cross-host.

Pattern Anomalies compara únicamente contra patrones que ya se repitieron varias veces. Puede señalar un status HTTP distinto para la misma Identity + operación normalizada, un conjunto diferente de objetos relacionados, una cobertura de identidades distinta o una huella de hosts diferente. Siempre se presenta como **diferencia observada**, nunca como IDOR, bypass o vulnerabilidad confirmada.

Business State Tracks enseñan automáticamente su identificador al modelo de Business Objects, por lo que `Order = orderId + status` no crea dos sistemas paralelos. Flow Detail muestra objetos observados y Flow Compare añade diferencias por tipos de objeto.

## v0.26.0 — Burp-native Flows + Identity + Business States

Esta iteración cierra Flow Capture/Compare y lleva las acciones principales al sitio donde ocurre la investigación: Burp.

### Flow Capture desde Burp o Negro

Desde Burp, clic derecho → **Negro → Flow**:

- `Start Flow from here…`
- `Add to current Flow…`
- `End Flow here…`
- `Create Flow from selected exchanges…`

Desde la web, **Start Flow** abre una Capture Window y **Stop Flow** guarda todo lo observado como candidatos. Negro puede marcar tráfico repetido como `possible background`, pero nunca lo borra ni lo excluye solo. En el editor decides `Include`, `Ignore`, `Set as Start` y `Set as End`.

### Identity Contexts directamente en Burp

Clic derecho → **Negro → Identity** permite:

- asignar el exchange a una Identity existente;
- crear una Identity desde la request seleccionando su auth material;
- declarar el auth actual cuando rota una sesión/token;
- `Send / Re-send as Identity` hacia el Repeater existente;
- enviar como `Anonymous`, removiendo sólo auth conocida por Negro.

El resend conserva método, path/query, body y headers ajenos a autenticación. Negro maneja Cookie, Authorization/Bearer y headers de auth comunes.

### Business State Observations

Los estados ya no son sólo campos adyacentes. El investigador enseña una definición real, por ejemplo:

```text
Order = orderId + status
```

A partir de ahí Negro observa instancias concretas:

```text
Order orderId=98127
CREATED → PAID → SHIPPED
```

Cada nodo conserva el exchange y la Identity observada. Flow Compare puede mostrar una variante `CREATED → SHIPPED`, pero lo presenta como **secuencia diferente observada**, nunca como bypass o vulnerabilidad confirmada.

### Smart Compare sigue siendo el diff de detalle

Flow Compare trabaja un nivel arriba. Cuando dos pasos alineados cambian, el detalle continúa abriéndose en **Smart Compare**; no existe un segundo motor de diff paralelo.

## Identity Contexts

Negro separa:

- **Identity**: cuenta estable (`Buyer A`, `Seller A`).
- **Context**: rol/tenant opcional.
- **Auth Material**: cookie/Bearer/JWT concreto que puede rotar.
- **Resolver**: valor estable que identifica al actor (`/me.id`, `/me.email`, `jwt:sub`).

`ownerId`, `orderId`, `tenantId` y otros identificadores de objeto/contexto no se usan como resolvers del actor. La Authorization Matrix sigue mostrando sólo tráfico observado y `No observado` no se interpreta como permitido o denegado.

## Buscar

Buscar sigue siendo la entrada universal:

```text
4101
ownerId
1223
AIza
host:api.example.com method:GET ownerId
```

El texto libre usa coincidencia parcial. Cuando hay observaciones estructuradas, Search ofrece acciones de `HTTP`, `Follow Value`, `Find Related Exchange`, `Smart Compare` e Identity.

En un workspace antiguo usa una vez **Buscar → Actualizar datos** para reconstruir búsqueda y parámetros históricos.

## Arranque

```bash
chmod +x negro.py install-web.sh burp-extension/build-extension.sh
./install-web.sh
negro web
```

## Extensión Burp

Para las acciones de Flow/Identity sigue siendo compatible **Negro Burp Bridge v0.26.0**; v0.27 no requiere cambios en el JAR.

Para compilarla:

```bash
cd burp-extension
./build-extension.sh
```

Carga `build/libs/negro-burp-bridge-0.26.0.jar` desde Burp → Extensions.

Consulta `METHODOLOGY.md` para el modelo mental, `ROADMAP.md` para lo siguiente y `CHANGELOG.md` para el historial.
