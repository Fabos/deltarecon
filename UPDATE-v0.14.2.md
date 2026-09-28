# Negro Recon v0.14.2 — Offensive Hypothesis Prioritization

## Objetivo

Hacer que `Give me ideas` sea una mano derecha de pentesting: menos comprobaciones genéricas y más pruebas accionables, priorizadas y conectadas con evidencia real.

## Cambios

- Prioridad de investigación independiente: `high`, `medium`, `quick`.
- Razones trazables sin probabilidades falsas (`backend enforcement unknown`, `new attack surface possible`, etc.).
- `Prueba esto ahora` aparece antes de la explicación.
- Feature flags: response tampering → observar nueva UI/tráfico → probar enforcement server-side.
- Business logic: buscar la operación sensible que consume `state/until/regional/limit/...` y verificar validación en backend.
- Checks simples/probablemente públicos se degradan a `QUICK CHECK`.
- Operaciones state-changing permitidas sólo sobre cuentas/datos autorizados y minimizando impacto; no se bloquean genéricamente POST/PUT/DELETE.
- Hypotheses muestra evidencia humana (`METHOD /path`, status, Burp request) en vez de IDs internos.
- Acciones directas: abrir request/evidence, Send to Repeater, Open Resource, View on Graph.
- El resultado/nota de prueba continúa alimentando futuras rondas de IA.
- `prompt_version` forma parte del evidence hash, evitando reutilizar cache generado con prompts anteriores.

## Compatibilidad

No cambia el protocolo Burp ↔ Negro. El JAR ya cargado sigue funcionando; recompilar sólo es necesario si quieres que el bridge muestre la misma versión del paquete.
