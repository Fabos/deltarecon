# Negro Recon v0.17.0 — Access Control Intelligence + Rutas de investigación

## Objetivo

Convertir las lecciones aprendidas manualmente sobre **Broken Access Control** en memoria operativa de Negro sin transformarlo en un vulnerability scanner. Negro observa tráfico que ya pasó por Burp, correlaciona señales y ayuda a responder dos preguntas:

1. **¿Qué merece revisión en este recurso?**
2. **¿Por dónde conviene seguir investigando en el mapa?**

Una señal o ruta nunca equivale por sí sola a una vulnerabilidad confirmada.

## Inteligencia de Access Control

El análisis pasivo de exchanges puede crear hipótesis para:

- **Autorización horizontal / IDOR**: IDs/UUIDs controlados por el cliente en operaciones autenticadas.
- **Mass assignment**: campos de rol/estado/ownership visibles en la respuesta pero ausentes de una operación de edición observada.
- **Control de acceso por método HTTP**: mismo recurso observado con varios verbos, especialmente cuando alguno cambia estado.
- **Redirect con body**: respuestas `3xx` que todavía transportan contenido significativo o campos sensibles.
- **Discrepancia proxy/backend**: un `403` cuyo fingerprint difiere de un `404` normal del mismo host.
- **Referer en acción sensible**: quick check de baja prioridad; la presencia del header no se considera vulnerabilidad.

Las pruebas propuestas son manuales y minimizan impacto. Negro no prueba IDs de terceros, no cambia roles, no falsifica sesiones y no dispara acciones administrativas automáticamente.

## Resources — “Qué merece revisión aquí”

El detalle de cada Resource agrega una tabla que reúne hipótesis activas y recordatorios de pruebas contextuales:

```text
Posible / indicio | Por qué llamó la atención | Prueba sugerida | Estado
```

La tabla reutiliza `leads_v2` y el coverage de operaciones existente; no introduce una entidad duplicada.

## Rutas de investigación

El mapa agrega **Por dónde seguir**. Cada ruta se calcula con evidencia persistida y prioriza:

```text
Host → Resource → Operation → Exchange → Hypothesis
```

cuando esas piezas existen.

Las hipótesis generadas por IA participan de la misma forma porque ya viven en `leads_v2`. La ruta muestra la siguiente prueba y puede abrir/enfocar el recurso correspondiente.

Importante: una ruta es una **secuencia de investigación**, no un “attack path” confirmado. Una futura cadena multi-step sólo debería presentarse como tal cuando sus relaciones estén respaldadas por pruebas/hallazgos confirmados.

## Mapa

- mayor contraste y grosor de conexiones en dark mode;
- highlight más claro para relaciones interesantes;
- ruta activa en verde con mayor grosor;
- nodos que forman parte de la ruta reciben un borde destacado.

## Compatibilidad

- No cambia el esquema de comunicación Burp ↔ Negro.
- El **Burp Bridge v0.16.7** sigue siendo compatible; no necesitas recompilar/reinstalar el JAR por esta actualización.
- Workspaces anteriores conservan findings, leads, coverage y evidencia. `generate-leads` puede backfillear las nuevas señales sobre exchanges existentes.

## Validación offline

```bash
PYTHONPATH=. python tests/smoke_test.py
PYTHONPATH=. python tests/access_control_intelligence_test.py
```

El test nuevo valida señales de Access Control, ayudas por Resource, rutas de investigación y que no se creen Findings automáticamente.
