# Negro Recon 🐕 — v0.25.0

Negro es una capa local de inteligencia, memoria y organización encima de Burp Suite. No pretende reemplazar Burp ni decidir vulnerabilidades por el usuario.

## Modelo central

`Rule → Signal → Hipótesis IA → Investigación humana`

- **Rules**: conocimiento determinístico configurable.
- **Signals**: observaciones automáticas con procedencia exacta; no son vulnerabilidades.
- **Hipótesis IA**: aparecen únicamente cuando el usuario ejecuta IA y separan hechos, inferencia, incógnitas y próxima prueba.
- **Investigaciones**: las crea el usuario al promover una hipótesis.
- **Findings / estados humanos**: siguen bajo control del hacker.

## v0.25.0 — Smart Compare + Flow Workbench

Esta versión junta dos bloques que necesitaban trabajar juntos antes de seguir con anomalías.

### 1. Smart Compare entiende coincidencias, no sólo diferencias

El antiguo `Smart Diff` ahora se presenta como **Smart Compare**. Sigue mostrando diferencias entre dos exchanges, pero primero muestra **valores exactos compartidos**, incluso cuando aparecen con nombres o rutas JSON distintas.

Ejemplo:

```text
Exchange A                  Exchange B
$.user.id = 102            $.memberId = 102
$.user.email = diego@...   $.email = diego@...
```

Negro muestra `102` como un **posible alias por valor** entre `id` y `memberId`. Eso significa únicamente que el mismo valor observado conecta ambos campos; no afirma que tengan la misma semántica. Valores triviales como `ok=true`, booleanos o atributos muy reutilizados se penalizan o se ocultan de las correlaciones útiles.

**Find Related Exchange** también conserva el path completo de cada coincidencia y deja de decir “mismo objeto” sin evidencia. Toma el exchange completo, busca valores exactos compartidos y separa correlaciones fuertes, medias y débiles. `Follow Value` continúa siguiendo un único valor seleccionado.

### 2. Guía de módulos integrada

La navegación incluye **Guía**. Cada módulo explica qué pregunta responde, cuándo usarlo y qué NO concluye:

- Buscar → ¿dónde aparece esto?
- Follow Value → ¿dónde reaparece exactamente este valor?
- Find Related Exchange → ¿qué otros exchanges comparten evidencia con éste?
- Smart Compare → ¿qué coincide y qué cambia entre A y B?
- Identidades → ¿quién hizo este tráfico?
- Flows → ¿qué historia de negocio forman varios exchanges?

### 3. Flow Workbench

**Flows** agrupa exchanges observados en una secuencia de negocio real:

```text
login → cart → checkout → payment → order
```

Puedes crear un flow vacío, agregar exchanges uno por uno o capturar un rango de IDs. Al capturar rangos, Negro ignora `OPTIONS` por defecto.

Cada paso conserva:

- exchange exacto;
- método, host, path y status HTTP;
- Identity observada cuando exista;
- valores de negocio relevantes (`orderId`, `total`, `status`, etc.);
- etiqueta, estado manual y nota opcionales.

Negro también muestra **business-state observations** cuando ve campos como `status`, `state`, `paymentStatus`, `orderStatus`, etc. Las transiciones representan únicamente tráfico observado.

### 4. Flow Compare

Dos flows se alinean por `método + ruta normalizada` y se comparan paso a paso. La vista muestra:

- pasos presentes sólo en A o sólo en B;
- pasos equivalentes por estructura;
- coincidencias de valores entre exchanges alineados;
- cambios de negocio relevantes;
- acceso directo a Smart Compare completo.

Esto permite comparar, por ejemplo:

```text
Compra normal Buyer A
vs
Compra Buyer B
```

u observar que un recorrido tiene `POST /payment` y otro no.

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

**No necesitas actualizar la extensión para v0.25.0.** Sigue siendo compatible con **Negro Burp Bridge v0.20.3**.

Si necesitas recompilarla:

```bash
cd burp-extension
./build-extension.sh
```

Carga `build/libs/negro-burp-bridge-0.20.3.jar` desde Burp → Extensions.

Consulta `METHODOLOGY.md` para el modelo mental, `ROADMAP.md` para lo siguiente y `CHANGELOG.md` para el historial.
