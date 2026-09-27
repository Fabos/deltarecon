# Negro Recon v0.11.1 — Burp ingest JSON hardening

Hotfix para el bridge Burp → Negro detectado durante pruebas reales.

- El bridge ahora serializa strings JSON como ASCII seguro, escapando cualquier carácter no ASCII y todos los controles JSON.
- Evita payloads inválidos producidos por valores de headers/URLs/metadatos entregados por Burp.
- El API `/api/ingest/http` devuelve errores de parseo con posición/causa sin reflejar el contenido sensible del request.
- No cambia el modelo de ingestión ni el protocolo funcional de Resources/Operations/Exchanges.

Después de actualizar, recompilar `burp-extension` y volver a cargar el JAR en Burp.
