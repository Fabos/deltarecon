# v0.116.3 · Bearer JWT UX

Flujo esperado en HTTP Workbench:

1. `Authorization: Bearer <JWT>` conserva el click semántico del valor completo.
2. Junto al valor aparece `JWT`; ese botón abre el JWT Inspector.
3. JWT Inspector muestra Header + Claims.
4. Click en `sub`/`role`/etc. enseña la llave de claim como regla reusable.
5. Click en el valor de un claim permite asociar el valor concreto a Identity/Context/Object/Auth.

Scope de análisis: sólo Requests `Sin proyecto` muestran `Context > Actions > Incluir en este proyecto…`, con `Host completo` o `Solo este endpoint`. Esto no modifica el scope autorizado de Recon.
