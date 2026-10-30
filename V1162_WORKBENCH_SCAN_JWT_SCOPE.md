# v0.116.2 · Workbench scanability + JWT claims + analysis scope

- Traffic Inbox prioriza **Host → URL → Status** como lectura primaria, con contexto y parámetros de menor peso visual.
- JWT Inspector vuelve a exponer los claims como observaciones interactivas: la llave `jwt.sub` puede enseñar semántica de campo y el valor puede marcarse como RESOLVER/CONTEXT/AUTH/OBJECT usando la misma memoria del HTTP Workbench.
- Traffic Inbox permite **Incluir host completo** o **solo endpoint (método + path)** dentro del proyecto. Esta regla es un **scope de análisis** persistente y separado de `target.scopes`: organiza tráfico histórico/futuro pero nunca amplía Recon activo.
- Al incluir tráfico histórico desde Inbox, Negro copia la evidencia HTTP al workspace del proyecto con `allow_out_of_scope=True`, conserva la timeline y refresca contexto pasivo local.
