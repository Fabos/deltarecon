# Negro Recon v0.14.5 — Robust Graph AI Responses + Diagnostics

Esta versión endurece `Give me ideas` para Responses API y evita diagnosticar como “JSON inválido” una respuesta que en realidad quedó incompleta.

## Cambios

- Presupuesto propio para Graph AI: 6000 tokens de salida y reintento automático a 9000 si OpenAI devuelve `status=incomplete` por `max_tokens`/`max_output_tokens`.
- `reasoning=low` por defecto para reservar más presupuesto a la salida estructurada accionable.
- Negro inspecciona `response.status`, `incomplete_details.reason`, `error`, refusals y usage antes de intentar parsear JSON.
- Una respuesta incompleta, fallida o rechazada nunca se guarda como resultado válido ni entra al cache.
- El segundo intento exploratorio de 0 hipótesis se conserva y también usa la estrategia de reintento por límite de salida.
- Logs seguros en terminal con prefijo `[AI graph]`: modelo, intento, presupuesto, status, razón de incompletitud, caracteres de salida y conteos de tokens. Nunca se imprimen prompts, cookies, cuerpos HTTP ni texto generado.
- UI distingue `incomplete`, `refusal`, `api_error` y Structured Output inválido.
- La estimación previa contempla el peor caso: retry por tokens + retry exploratorio.

Ejemplo de logs:

```text
[AI graph] request · model=gpt-6-luna · attempt=1 · budget=6000 · reasoning=low · payload_chars=...
[AI graph] response · status=incomplete · incomplete_reason=max_output_tokens · output_tokens=6000 · reasoning_tokens=...
[AI graph] retry_larger_budget · from_budget=6000 · to_budget=9000
[AI graph] response · status=completed · output_tokens=... · output_chars=...
```

El protocolo Burp Bridge no cambia.
