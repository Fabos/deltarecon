# Negro Recon 🐕 — v0.29.0

Negro es una capa local de inteligencia, memoria y organización encima de Burp Suite. No pretende reemplazar Burp ni decidir vulnerabilidades por el usuario.

## Modelo central

`Rule → Signal → Hipótesis IA → Investigación humana`

- **Rules**: conocimiento determinístico configurable.
- **Signals**: observaciones automáticas con procedencia exacta; no son vulnerabilidades.
- **Hipótesis IA**: aparecen únicamente cuando el usuario ejecuta IA y separan hechos, inferencia, incógnitas y próxima prueba.
- **Investigaciones**: las crea el usuario al promover una hipótesis.
- **Findings / estados humanos**: siguen bajo control del hacker.

## v0.29.0 — Investigation Experience / Map 2.0

Esta iteración no añade otro scanner. Convierte el mapa en una **lente visual de investigación** sobre los datos que Negro ya conoce. La misma evidencia puede verse como **Superficie**, **Identidades**, **Flows**, **Objetos** o **Inteligencia**.

Las identidades son completamente dinámicas: Negro usa exactamente los Identity Contexts creados por el investigador y nunca presupone `buyer`, `seller`, `admin` ni una cantidad fija de cuentas. Desde la lente Identidades se puede seleccionar una identidad y compararla visualmente con cualquier otra.

`View in Map` / **Ver en mapa** está disponible desde Request, Identity, Flow, Business Object y Finding. El foco carga sólo el contexto relevante y puede expandirse a **1 salto** o **2 saltos**. El nuevo **Path Finder** permite seleccionar dos nodos y mostrar el camino más corto respaldado por relaciones observadas.

La UI adopta **Request** como término humano en lugar de Exchange. Los nombres internos `http_exchanges` / `exchange_id` se conservan para compatibilidad de base de datos y APIs, pero el usuario ya no necesita conocer ese término.

El mapa sigue siendo descriptivo: una arista indica evidencia almacenada o correlación registrada; no demuestra causalidad ni una vulnerabilidad.

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
