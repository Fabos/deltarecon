# v0.116.4 · Exploration Focus, reversible target y checkpoints

## Modelo de visibilidad

- **Todo**: todo el tráfico con peso visual normal.
- **Focus**: el proyecto actual permanece nítido; el resto sigue visible, atenuado y seleccionable.
- **Solo target**: únicamente eventos pertenecientes al proyecto actual.

El viejo Focus de layout se llama ahora **Inmersivo**.

## Target de análisis reversible

`Incluir host` / `Incluir endpoint` continúa siendo routing pasivo de análisis. No modifica scopes autorizados de Recon. Una Request incluida por estas reglas muestra su membresía en Context → Actions y permite **Retirar**. Al retirar, la regla deja de enrutar tráfico futuro y el histórico asociado vuelve a Traffic Inbox; la evidencia HTTP ya utilizada por Flows/Findings no se elimina.

## Checkpoints

Los checkpoints son cortes de vista, no evidencia permanente. Pueden eliminarse de forma individual o todos desde el administrador. El timeline HTTP y sus Capture Events se conservan.

## Contraste

Traffic Inbox usa un deck claro/neutro para lectura tabular rápida de método, host, URL y status. Request/Response conservan el tema oscuro y semántico.
