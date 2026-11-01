# v0.117.2 · Context Agent — Scope + Semantic Gate

## Objetivo

Reducir drásticamente el costo del Context Agent sin volver a introducir un cap arbitrario ni perder evidencia que pueda ser importante más adelante.

## Scope Gate

El agente sólo construye candidatos IA desde exchanges que cumplan al menos una de estas condiciones:

- `burp_scope_status = IN_SCOPE`; o
- el hostname pertenece a los scopes configurados del proyecto.

`EXCLUDED` nunca entra. Un host externo copiado al proyecto sólo para análisis no consume Context Agent mientras no esté dentro del scope autorizado.

## Semantic Gate

El ledger local sigue registrando path/query, headers, cookies, JWT claims, bodies y responses. Pero una observación no se convierte automáticamente en un candidato IA.

Se priorizan señales como:

- manual ground truth;
- memoria semántica previa;
- vecino del impact graph;
- JWT/auth/context detectado;
- key semántica + evidencia suficiente;
- reference-like + evidencia suficiente;
- valor producido en response y consumido después;
- reutilización entre endpoints;
- pertenencia a Flow.

Assets estáticos, metadata de transporte, trace IDs, request IDs y valores aislados sin contexto quedan diferidos.

## “Dormido”, no eliminado

Un candidato diferido sigue en `semantic_observations`. Puede despertar en un run posterior si aparece nueva evidencia. Esto permite ahorrar tokens hoy sin perder la relación mañana.

## Estimación

La UI muestra:

- observaciones in-scope;
- observaciones fuera de scope ignoradas;
- candidatos tocados antes del Semantic Gate;
- candidatos diferidos;
- candidatos realmente enviados;
- batches;
- costo esperado/máximo en COP.

No existe cap fijo de candidatos. El presupuesto sigue siendo un hard-stop y nunca un recorte silencioso.
