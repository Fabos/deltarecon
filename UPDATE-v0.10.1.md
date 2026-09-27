# Negro Recon v0.10.2

Parche de instalación de la integración Burp.

## Cambios

- La extensión Burp ya no requiere Gradle global.
- Nuevo `burp-extension/build-extension.sh` para Linux/macOS/Kali.
- Nuevo `burp-extension/build-extension.ps1` para Windows.
- El build descarga Montoya API 2026.7 automáticamente en la primera ejecución.
- Compila con cualquier JDK >= 21 y genera bytecode Java 21 (`--release 21`).
- `build.gradle` se mantiene como opción para desarrollo, pero ya no intenta exigir un JDK 21 separado mediante toolchains.

## Build rápido

```bash
cd burp-extension
./build-extension.sh
```

Salida esperada:

```text
build/libs/negro-burp-bridge-0.10.2.jar
```
