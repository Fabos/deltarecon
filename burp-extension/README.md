# Negro Burp Bridge v0.10

Extensión Java/Montoya para alimentar Negro con el tráfico HTTP que Burp observa en tiempo real.

## Qué envía

- URL, método y herramienta de Burp (`PROXY`, `REPEATER`, etc.)
- Status code y Content-Type
- Indicador de request autenticada (Cookie/Authorization presentes)
- Headers completos
- Request/response completos en Base64
- Response body por separado para promover `.js` al pipeline JavaScript de Negro

No descarta JS, imágenes, fuentes ni otros assets por tipo. Negro auto-enruta únicamente hosts que estén dentro de un target ya creado; el resto se responde como `host_out_of_scope`.

## Compilar

Requiere Java 21 y Gradle. El proyecto usa Montoya API `2026.7`.

```bash
gradle jar
```

El JAR queda en:

```text
build/libs/negro-burp-bridge-0.10.0.jar
```

En Burp: **Extensions → Installed → Add → Java → selecciona el JAR**.

Por defecto conecta a `http://127.0.0.1:8765`. La pestaña **Negro** dentro de Burp permite cambiar esa URL y muestra contadores de tráfico aceptado/fuera de scope/errores.

## Negro → Repeater

La extensión consulta una cola local una vez por segundo. En Negro, abre un host → Resource → **Send to Repeater →**. Si Negro ya vio ese método en Burp, reutiliza la request real más reciente; para recursos descubiertos por otras fuentes crea una request base desde la URL.

## Nota de seguridad

v0.10 prioriza no perder evidencia: request/response completos pueden contener cookies, tokens o Authorization. El API de Negro debe mantenerse en localhost salvo que deliberadamente agregues una capa de autenticación/red segura.
