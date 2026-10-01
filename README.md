# Negro Recon 🐕 — v0.26.0

Negro es una capa local de inteligencia, memoria y organización encima de Burp Suite. No pretende reemplazar Burp ni decidir vulnerabilidades por el usuario.

## Modelo central

`Rule → Signal → Hipótesis IA → Investigación humana`

- **Rules**: conocimiento determinístico configurable.
- **Signals**: observaciones automáticas con procedencia exacta; no son vulnerabilidades.
- **Hipótesis IA**: aparecen únicamente cuando el usuario ejecuta IA y separan hechos, inferencia, incógnitas y próxima prueba.
- **Investigaciones**: las crea el usuario al promover una hipótesis.
- **Findings / estados humanos**: siguen bajo control del hacker.

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

Para usar las acciones de Flow/Identity de esta versión, carga **Negro Burp Bridge v0.26.0**.

Para compilarla:

```bash
cd burp-extension
./build-extension.sh
```

Carga `build/libs/negro-burp-bridge-0.26.0.jar` desde Burp → Extensions.

Consulta `METHODOLOGY.md` para el modelo mental, `ROADMAP.md` para lo siguiente y `CHANGELOG.md` para el historial.
