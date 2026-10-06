# Negro Burp Bridge v0.36.0

Extensión Burp (Montoya API) para alimentar Negro en tiempo real y recibir solicitudes para Repeater.

## Compilar — Linux/macOS/Kali (recomendado)

No necesitas Gradle instalado.

```bash
cd burp-extension
./build-extension.sh
```

La primera compilación descarga `montoya-api-2026.7.jar` desde Maven Central y lo deja en `.deps/`. Las siguientes compilaciones reutilizan esa copia.

Resultado:

```text
build/libs/negro-burp-bridge-0.36.0.jar
```

Requisitos: JDK 21 o superior y `curl` o `wget`. Con JDK 25 funciona: se compila bytecode compatible con Java 21 mediante `javac --release 21`.

## Windows PowerShell

```powershell
cd burp-extension
.\build-extension.ps1
```

## Gradle (opcional)

El proyecto conserva `build.gradle` para desarrollo. Si ya tienes Gradle puedes usar:

```bash
gradle jar
```

Gradle ya no es requisito para instalar la extensión.

## Cargar en Burp

1. `Extensions` → `Installed` → `Add`.
2. Tipo: `Java`.
3. Selecciona `build/libs/negro-burp-bridge-0.36.0.jar`.
4. Abre la pestaña `Negro` y verifica la conexión con la API local.

Mantén Negro escuchando solo en localhost durante estas pruebas, ya que la integración puede almacenar request/response completos.


## Transporte de Runner v0.27

Desde v0.27 la misma extensión también puede ejecutar trabajos del **Runner**. Negro entrega la Request exacta al Bridge y Burp la envía mediante Montoya, reutilizando la pila de red y configuración de Burp (DNS/TCP/TLS/upstream proxy). La Response vuelve a Negro y sólo entonces se incorpora como evidencia si alcanzó válidamente al aplicativo.

Esto evita que el Runner dependa de una segunda ruta de red desde Python/container. Mantén Burp abierto y la extensión cargada mientras ejecutas Runners. En Negro puedes verificarlo desde **Runner → Transporte → Diagnosticar transporte**.

## Menú contextual v0.28

Haz clic derecho sobre una Request/Response en Burp y abre **Negro**.

### Contexto

- `Abrir en Negro`
- `Contexto → Añadir a Investigation…`
- `Contexto → Crear Investigation desde esta Request…`
- `Contexto → Crear Hypothesis…`
- `Contexto → Adjuntar a Hypothesis…`
- `Contexto → Crear Entity desde key/valor…`
- `Contexto → Seguir key / valor…`
- `Contexto → Watch de key / valor…`
- `Contexto → Agregar nota…`

Cuando hay texto seleccionado en el editor Request/Response, Entity / Follow Value / Watch pueden partir de esa selección exacta. Cuando no hay selección, la extensión usa las keys/values estructuradas que Negro extrajo del exchange.

### Acciones existentes

- `Flow` → iniciar, añadir, terminar o crear Flow desde una selección.
- `Identidad` → asignar, crear, actualizar auth material y reenviar como Identity.
- `Estado` → estados humanos de revisión.
- `Finding` → crear, adjuntar evidencia y registrar Retest.

`Send as Identity` usa el Repeater existente: conserva método/path/query/body y cambia únicamente material de autenticación conocido por Negro. `Anonymous` remueve esa auth conocida.

### Contexto visible en Burp

Los **Signals automáticos** continúan separados de los estados humanos y pueden resaltar una response en cyan. Además, cuando una Request ya participa en memoria persistente, la extensión añade una nota compacta como:

```text
NEGRO · CONTEXTO · INV 1 · HYP 1 · CTX 1 · FIND 0
```

Las acciones contextuales añaden notas `INV`, `HYP`, `ENTITY`, `WATCH`, `FIND` o `RETEST`. No se cambia el highlight sólo por pertenecer a una Investigation/Hypothesis, evitando llenar Burp de colores.

> Las acciones contextuales v0.28 requieren Bridge v0.28+. El transporte del Runner mantiene compatibilidad con v0.27+.

## v0.36.0 · Negro Context en editores HTTP

Burp añade una pestaña de solo lectura `Negro Context` tanto en Request como Response. Consulta de forma asíncrona el contexto exacto ya aprendido en Negro (Identity, AUTH/RESOLVER/CONTEXT, Objects, Environment y Scope). Si no hay evidencia exacta, la pestaña lo indica sin bloquear el editor. La clasificación se sigue editando únicamente en HTTP Inspector.

## v0.33.0 · Replay as Identity

Desde cualquier Request/Response: `Negro → Replay as Identity` carga los Identity Contexts del target. Elegir una Identity o `Sin autenticación` **sólo prepara** el Replay y abre Negro para revisar la Request; no la envía automáticamente.

`Compare Identity…` abre el mismo Workbench sin preseleccionar Identity. Cuando pulses `Enviar prueba controlada` en Negro, Bridge v0.29 consume `job_kind=replay_execute` y devuelve status, HTTP completo y tiempo. Esa ejecución se excluye del ingest pasivo para no contaminar discovery/Flow Capture.

El menú antiguo `Identidad → Enviar a Repeater con Identity…` se mantiene por compatibilidad como utilidad de Repeater; no sustituye el nuevo Authorization Replay persistente.
