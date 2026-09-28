# Negro Recon v0.16.1 — Repeater hand-off hotfix

## Qué corrige

- `Enviar a Repeater` ya no selecciona intercambios con `request_b64` vacío o `request_size=0`.
- Desde cada exchange HTTP aparece **Enviar esta solicitud a Repeater**, que conserva exactamente esa evidencia en lugar de elegir otra observación del mismo método.
- Si un workspace histórico no tiene bytes de solicitud, Negro genera una solicitud HTTP/1.1 mínima y válida en lugar de abrir una pestaña vacía.
- El bridge normaliza únicamente la línea de request de evidencia HTTP/2 (`HTTP/2` → `HTTP/1.1`) al reconstruir el mensaje para el editor de Repeater. Headers y body permanecen intactos. Burp podrá negociar HTTP/2 al enviarla según su configuración.
- El bridge valida el tamaño del request reconstruido antes de entregarlo a Repeater y usa un fallback seguro si el resultado queda vacío.
- Logs de diagnóstico:
  - backend: `[repeater-queue] ... request_bytes=...`
  - Burp Output: `Negro → Repeater: queue=... raw=...B reconstructed=...B h2_normalized=...`

## Por qué

Los requests observados por Burp pueden almacenarse en forma textual HTTP/2. El hand-off previo reconstruía siempre esos bytes con el constructor genérico de `HttpRequest`, y además permitía elegir históricos sin bytes. En determinadas combinaciones esto podía terminar en una pestaña de Repeater vacía.

## Compatibilidad

Requiere recompilar/reimportar el JAR del bridge `v0.16.1` para obtener la corrección completa del lado Burp.
