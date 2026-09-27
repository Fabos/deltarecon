# Negro v0.11.3

Hotfix de diagnóstico y transporte para Burp Bridge.

- El bridge envía `/api/ingest/http` como bytes UTF-8 explícitos (`ofByteArray`).
- Output de Burp muestra cada envío, tamaño de payload, primer byte y resultado HTTP.
- Se ignora el tráfico dirigido al propio backend de Negro para evitar realimentación.
- El backend reporta `body_len` y `first_byte` cuando falla el parseo JSON, sin exponer contenido sensible.
- No cambia el modelo de datos ni el protocolo lógico de ingestión.
