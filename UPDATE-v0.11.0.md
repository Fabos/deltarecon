# Negro Recon v0.11.0 — Investigation Workspace

## Qué cambia

- Cada Resource tiene una pantalla propia con URL, provenance, estado, herramientas y evidencia.
- Los exchanges capturados por Burp se pueden inspeccionar como request/response lado a lado, preservando método, status, fuente, tamaño, timestamps y seen count.
- Las herramientas se contextualizan por Resource; CORS queda asociado al endpoint que se probó.
- `Send to Repeater` continúa disponible por método observado.
- Nueva entidad persistente `Finding` con severidad, estado, descripción, impacto y remediación.
- Un Finding puede relacionar múltiples Resources/Hosts/Exchanges/etc., permitiendo documentar cadenas entre servicios.
- Retests persistentes: `still_vulnerable`, `fixed`, `fix_verified`, `inconclusive`.
- Evidencia visual y notas también pueden vivir a nivel Finding.
- Hosts/Resources/Findings usan estados visuales más claros sin cambiar el estilo sobrio de Negro.
- Tooltips contextuales explican qué hace una prueba, qué señal busca y cómo interpretar un resultado.
- `uvicorn[standard]` sustituye a `uvicorn` para habilitar soporte WebSocket estándar y evitar warnings de upgrade cuando una dependencia intenta usarlo.

## Modelo añadido

```text
Finding
  ├── finding_entities -> resource / host / exchange / operation / js_asset / observation
  ├── finding_retests
  ├── notes
  └── evidence_attachments
```

Esto prepara el modelo para el Knowledge Graph posterior sin duplicar Host/Resource/Operation/Exchange.

## Flujo recomendado

1. Navega con Burp y deja que Negro capture el tráfico.
2. Abre el Resource desde el Host.
3. Revisa exchanges HTTP y ejecuta pruebas contextuales.
4. Documenta notas/evidencia mientras investigas.
5. Si una hipótesis se confirma, crea un Finding y asocia todos los Resources involucrados.
6. Cuando llegue un retest, registra el resultado en el mismo Finding.
