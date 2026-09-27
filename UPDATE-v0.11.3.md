# Negro Recon v0.11.3

Hotfix del Burp Bridge para ingestión HTTP local.

## Corrección

El bridge ahora fuerza `java.net.http.HttpClient.Version.HTTP_1_1` al comunicarse con Negro. Java HttpClient puede intentar un upgrade h2c/HTTP2 sobre `http://127.0.0.1:8765`; Uvicorn no necesita ese upgrade y, en las pruebas, el request llegaba a `/api/ingest/http` con `body_len=0` aunque el bridge había construido un payload JSON válido.

También se sincronizaron los números de versión de los scripts de build (`build-extension.sh`, PowerShell y Gradle), que todavía podían producir un JAR con nombre 0.11.1 aunque el código fuera posterior.

## Resultado esperado

En Burp > Extensions > Output:

```text
Negro → ingest: PROXY GET https://... | payload=... bytes | first=0x7b('{')
Negro ← ingest HTTP 200 accepted=true
```

Y en la terminal de Negro ya no deben aparecer `Unsupported upgrade request` relacionados con el bridge ni `body_len=0` para esos POST.
