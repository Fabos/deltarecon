# Negro Recon v0.14.1 — Structured AI Output hotfix

- `Give me ideas` usa Structured Outputs (`json_schema`, strict) para evitar JSON malformado.
- El parser de respaldo ya no propaga `JSONDecodeError` a la UI.
- Si un SDK antiguo no soporta `text.format`, Negro conserva compatibilidad y falla de forma segura sin perder el workspace.
- No cambia el protocolo Burp Bridge.
