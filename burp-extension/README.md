# Negro Burp Bridge v0.16.1

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
build/libs/negro-burp-bridge-0.16.1.jar
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
3. Selecciona `build/libs/negro-burp-bridge-0.16.1.jar`.
4. Abre la pestaña `Negro` y verifica la conexión con la API local.

Mantén Negro escuchando solo en localhost durante estas pruebas, ya que la integración puede almacenar request/response completos.

## Menú contextual v0.13

Haz click derecho sobre una request/response en Burp y abre **Negro**:

- `Open in Negro`
- `Mark as Interesting`
- `Create Finding…`
- `Attach to existing Finding…`
- `Attach as Retest evidence…`

La acción sincroniza primero la request/response seleccionada con Negro para obtener su `Resource → Operation → Exchange`; después enlaza la acción al objeto correcto. Las requests fuera de scope no se convierten en Findings por accidente: Negro las rechaza durante el auto-route.
