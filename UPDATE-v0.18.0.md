# Negro Recon v0.18.0 — Projects, Detector Lab & Investigation Map

## Objetivo

Reducir ruido y convertir Negro en una memoria de investigación más clara: una prueba puede contener varios scopes, cada proyecto puede ajustar sus detectores y el mapa debe responder preguntas concretas en lugar de mostrar un grafo decorativo.

## Proyecto → múltiples scopes

Negro deja de asumir que una prueba equivale a un solo dominio. Cada proyecto tiene:

- nombre legible;
- scope principal;
- scopes adicionales;
- un único workspace/SQLite;
- inventario, Burp, JavaScript, hipótesis, hallazgos, notificaciones y mapa compartidos.

Burp enruta cada request al proyecto cuyo scope coincida de forma más específica con el host.

Ejemplo del lab:

```text
Proyecto: Access Control Lab
Scopes:
  app.accesslab.local
  api.accesslab.local
```

`score.accesslab.local` no se agrega y permanece fuera de scope.

Al agregar scopes que antes Negro consideraba targets distintos, las hipótesis CORS first-party históricas entre esos scopes se marcan como negativas y sus alertas quedan leídas.

## Detector Lab por proyecto

Ajustes incorpora un panel explicativo para los motores de alerta. Cada detector permite:

- activar/desactivar;
- sensibilidad `Estricto / Equilibrado / Permisivo`;
- ver qué observa Negro;
- entender qué condición dispara cada modo;
- ver hipótesis activas y alertas históricas generadas en el proyecto.

La configuración se guarda por proyecto. Los defaults globales se conservan únicamente como fallback.

Motores configurables en v0.18.0 incluyen Access Control, CORS, JavaScript, Open Redirect, URL-fetch/SSRF, secrets/config, respuestas sensibles, secretos en URL, source maps, API docs y error disclosure.

Una señal sigue siendo una hipótesis: desactivar un detector impide nuevas alertas, pero no borra evidencia/histórico.

## CORS con contexto de proyecto

CORS ahora distingue `cross-origin` de `external-to-project`.

Una relación como:

```text
app.target.com → api.target.com
```

no se eleva automáticamente si ambos hosts pertenecen a los scopes del mismo proyecto. En modo Estricto, el motor exige contexto mucho más fuerte antes de alertar.

## Mapa de investigación

La pantalla aprovecha mejor el viewport y elimina la sensación de un bloque inferior separado del mapa.

Las perspectivas se redefinen como preguntas:

- **Superficie** — ¿Qué existe?
- **Pendientes** — ¿Qué no he revisado?
- **Interesante** — ¿Dónde hay señales?
- **Burp** — ¿Qué observé realmente?
- **Qué probar ahora** — evidencia → hipótesis → siguiente prueba.

El panel de siguientes pasos vive dentro del workspace del mapa, puede filtrarse por estado/tipo/prioridad y reutiliza el mismo estado + `Resultado / qué pasó` de Hipótesis.

El nodo raíz muestra el nombre del proyecto en vez de fingir que un único dominio representa toda la prueba.

## JavaScript y notificaciones

Se conserva el flujo v0.17.1: `Analizar local` crea Resources para rutas in-scope, relaciones `JavaScript → Resource` y una notificación agregada. Con múltiples scopes, un JS de `app.*` puede descubrir correctamente rutas en `api.*` del mismo proyecto.

## Compatibilidad

- Los targets/workspaces anteriores migran conservadoramente: su dominio existente se convierte en el primer scope.
- No se borra inventario ni evidencia.
- El protocolo Burp ↔ Negro no cambia; el Bridge v0.16.7 sigue siendo compatible.
- Para unir datos históricos que ya viven en dos workspaces separados se recomienda crear/usar un proyecto nuevo y recapturar o importar explícitamente; agregar un scope no fusiona mágicamente dos SQLite históricos.
