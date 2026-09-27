# Negro Burp Bridge v0.11.0

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
build/libs/negro-burp-bridge-0.11.0.jar
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
3. Selecciona `build/libs/negro-burp-bridge-0.11.0.jar`.
4. Abre la pestaña `Negro` y verifica la conexión con la API local.

Mantén Negro escuchando solo en localhost durante estas pruebas, ya que la integración puede almacenar request/response completos.
