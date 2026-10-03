# Negro Burp Bridge v0.27.0

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
build/libs/negro-burp-bridge-0.27.0.jar
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
3. Selecciona `build/libs/negro-burp-bridge-0.27.0.jar`.
4. Abre la pestaña `Negro` y verifica la conexión con la API local.

Mantén Negro escuchando solo en localhost durante estas pruebas, ya que la integración puede almacenar request/response completos.


## Transporte de Runner v0.27

Desde v0.27 la misma extensión también puede ejecutar trabajos del **Runner**. Negro entrega la Request exacta al Bridge y Burp la envía mediante Montoya, reutilizando la pila de red y configuración de Burp (DNS/TCP/TLS/upstream proxy). La Response vuelve a Negro y sólo entonces se incorpora como evidencia si alcanzó válidamente al aplicativo.

Esto evita que el Runner dependa de una segunda ruta de red desde Python/container. Mantén Burp abierto y la extensión cargada mientras ejecutas Runners. En Negro puedes verificarlo desde **Runner → Transporte → Diagnosticar transporte**.

## Menú contextual v0.27

Haz click derecho sobre una o varias request/response en Burp y abre **Negro**:

- `Flow → Start Flow from here / Add to current Flow / End Flow here / Create Flow from selected exchanges`
- `Identity → Assign / Create from this request / Update auth material / Send as Identity`
- `State → Pending Learning / Review Later / Interesting / Correlate / Finding / Discarded / Normal`
- `Open in Negro`, notas, Findings y Retest.

`Send as Identity` usa el Repeater existente: conserva método/path/query/body y cambia únicamente material de autenticación conocido por Negro. `Anonymous` remueve esa auth conocida.

Los **Signals automáticos** no son estados humanos. Una response con signals nuevos puede quedar resaltada en cyan; al elegir un estado humano el highlight cambia al color correspondiente y Negro añade una nota legible. La acción sincroniza primero la evidencia con Negro para obtener su `Resource → Operation → Exchange`.
