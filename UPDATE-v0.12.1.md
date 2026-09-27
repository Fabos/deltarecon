# Negro Recon v0.12.1 — Knowledge Graph UX

Esta iteración no agrega nuevas entidades de seguridad. Reorganiza la proyección visual existente para que el mapa ayude a pensar en lugar de simplemente dibujar filas de la base de datos.

## Cambios

- `Attack Surface` es la perspectiva inicial: Target → Host → Resource → Operation.
- Layout semántico horizontal en lanes, con reducción de cruces por barycentric passes.
- `Burp` agrupa exchanges por operación y permite expandirlos a demanda.
- Observaciones repetidas y JavaScript se agrupan para reducir ruido.
- `Interesting` y `Attack Paths` aíslan relaciones que llevan a señales, leads o findings sin afirmar automáticamente que exista una vulnerabilidad.
- `Untested` reduce el mapa a elementos cuyo estado todavía está pendiente.
- Labels progresivos: requests/observaciones no dominan el canvas hasta que se seleccionan o se hace zoom.
- Panel lateral con métodos, requests, pruebas y señales registradas para Resources/Operations.
- Focus de 1 y 2 hops.
- Nodos arrastrables. La posición manual se persiste por target y perspectiva en el navegador.
- `Auto ordenar` elimina la disposición manual de la perspectiva actual y vuelve al layout semántico.
- El target deja de usar el verde principal como relleno; los colores se reservan principalmente para estado y selección.

## Principio de UX

El mapa aplica progressive disclosure: Negro conserva toda la evidencia, pero no obliga a verla toda simultáneamente. Los detalles siguen disponibles mediante expansión, focus y navegación a la entidad real.
