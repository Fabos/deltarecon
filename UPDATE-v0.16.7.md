# Negro Recon v0.16.7

Hotfix de compilación del Burp Bridge.

## Corregido

- Restaura el helper `unescapeJson(...)` usado por el selector de Findings del menú contextual.
- El helper es iterativo y no reintroduce el parser regex recursivo que se eliminó en v0.16.6 para `request_b64`.
- Bridge, backend y scripts de build quedan etiquetados como v0.16.7.
- Corrige el error de compilación `cannot find symbol: unescapeJson(String)`.

No cambia el protocolo Burp ↔ Negro ni el modelo de datos.
