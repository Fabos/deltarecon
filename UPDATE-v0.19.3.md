# Negro Recon v0.19.3 — Exact Evidence Provenance

Esta versión corrige el problema observado al investigar una Google Maps API key: Negro sabía que el detector había coincidido en un exchange, pero la UI enviaba al recurso genérico y podía mostrar otro exchange o truncar el body antes de la coincidencia.

## Cambios

- Cada coincidencia de `secret_candidate` persiste y/o reconstruye:
  - exchange exacto, método y URL;
  - request/response (`surface`);
  - valor enmascarado y fingerprint;
  - regex que coincidió;
  - offset, línea y columna dentro del body;
  - contexto cercano con secretos enmascarados;
  - pista educativa para Google Maps cuando el contexto lo indica.
- Hipótesis muestra “¿De dónde salió esta coincidencia?” con contexto verificable.
- “Abrir evidencia” apunta a `?exchange=<id>#exchange-<id>`.
- Resource detail fuerza la inclusión del exchange solicitado aunque no esté en los 30 más recientes.
- El exchange enfocado muestra la coincidencia que llevó hasta él.
- Las hipótesis históricas pueden reconstruir provenance desde el SQLite actual; no exige volver a enumerar.

## Seguridad de evidencia

Negro no persiste la credencial completa en `evidence_json` ni en el snippet. Los valores que coinciden con detectores de secretos se enmascaran antes de mostrarse o persistirse.
