# Negro Recon v0.16.0 — Burp Passive Intelligence + Progressive Map

## Objetivo

Cerrar la versión previa al bounty real haciendo que el tráfico que ya ve Burp se convierta en pistas accionables sin pedir trabajo manual adicional y evitando que el mapa se bloquee con targets grandes.

## Burp como fuente de inteligencia

Cada exchange HTTP nuevo puede producir, sin enviar tráfico adicional:

- **Open Redirect** desde parámetros reales observados en query, form o JSON (`next`, `return_url`, `redirect_uri`, etc.). La evidencia guarda método, ruta, parámetro, ubicación y exchange exacto.
- **Superficies URL/SSRF** cuando parámetros como `url`, `endpoint`, `webhook`, `fetch`, `image`, etc. reciben URLs absolutas.
- **Secretos/config de alto valor** con firmas conocidas: Google API keys, AWS access keys, GitHub tokens, Stripe live secrets, Slack tokens y private keys. Negro guarda sólo valor enmascarado + fingerprint.
- **Campos sensibles en respuestas JSON** como `password`, `pwd`, `client_secret`, `api_key`, `private_key`, `secret`, tokens, etc.; eleva señal cuando aparecen junto a identidad (`username`, `email`, `user_id`, ...).
- **Secretos en URL**, diferenciados porque pueden propagarse a logs, historial o Referer.
- **CORS observado** en requests/responses reales.
- **Source maps**, documentación OpenAPI/Swagger y señales de errores internos/stack/SQL/path disclosure.

La correlación es pasiva: no explota ni genera requests. Cada pista sigue siendo una hipótesis/lead que requiere validación manual.

## Notificaciones

- Nueva campana persistente por target.
- Toaster en tiempo real para severidad media/alta/crítica.
- Página de notificaciones con historial, deduplicación, número de ocurrencias y vínculo directo al recurso/evidencia.
- La primera carga establece baseline y no dispara cientos de toasts históricos.

## Inteligencia

La página Inteligencia explica y muestra explícitamente qué detectó Negro desde Burp. `Generar señales` también puede hacer backfill de exchanges existentes, pero sin inundar las notificaciones históricas.

## Mapa escalable

El mapa deja de intentar dibujar todo el workspace al abrir:

- **overview:** Target + hosts relevantes y grupos de pendientes/revisados/descartados.
- **host:** un host + un conjunto acotado/priorizado de sus recursos, operaciones y evidencia.
- **resource:** un solo recurso + sus métodos, requests, señales, hipótesis y findings.

El doble click/drill-down y los botones de detalle cambian de capa. Para IA se conserva una proyección server-side completa/estructurada, independiente de la visualización progresiva.

## Dashboard

- Progreso separado para Hosts y Recursos.
- Pendientes excluyen descartados.
- Revisados, en revisión y descartados se muestran por separado.
- Barra de avance = revisados + descartados sobre total.
- Métricas de tráfico, métodos, hipótesis, findings y alertas nuevas.

## Compatibilidad Burp

El protocolo de ingestión sigue siendo compatible con el bridge v0.15.x. No es obligatorio recompilar el JAR para usar las nuevas capacidades server-side. Si se compila desde este paquete, el artefacto se etiqueta `v0.16.0`.

## Usabilidad adicional

- Inventario mantiene una sola búsqueda para host/endpoint/URL/query y agrega filtro de **estado de recursos** dentro del listado de hosts.
- Desde Dashboard, “Recursos pendientes” abre directamente hosts que contienen recursos pendientes.
- Las notificaciones enlazan al **exchange exacto** dentro del detalle del recurso (`#exchange-ID`) para no perder dónde apareció la señal.
- El contador “Interesantes” y el bloque de foco del Dashboard consideran también leads persistentes creados por el motor pasivo de Burp, no sólo clasificaciones manuales.
- Etiquetas nuevas y severidades se muestran en español; se conservan en inglés únicamente términos técnicos de seguridad.
