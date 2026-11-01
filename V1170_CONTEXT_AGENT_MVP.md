# v0.117.0 · Context Agent MVP

El primer agente persistente de Negro convierte tráfico HTTP capturado en contexto semántico reutilizable sin reemplazar el flujo manual.

## Qué hace

`HTTP / Flows → Observation Ledger → Delta + Impact Graph → Context Agent → Semantic Memory → HTTP Workbench`

El agente **no busca vulnerabilidades y no ejecuta Requests**. Su trabajo en esta versión es aprender actores, credenciales, objetos de negocio, referencias, estados, acciones/contexto, posibles fronteras de autorización y relaciones a partir de evidencia ya capturada.

### Observation Ledger

Negro extrae determinísticamente observaciones desde:

- path params y query params;
- headers;
- cookies;
- JWT + claims;
- JSON y `application/x-www-form-urlencoded`;
- `multipart/form-data` (campos de texto; no envía el contenido de archivos);
- XML escalar;
- request y response;
- pertenencia a Flows.

Cada observación conserva `exchange`, lado request/response, ubicación exacta, key, hash del valor, endpoint y Flow. Las inferencias de IA apuntan de vuelta a esas observaciones.

## Manual + IA

El comportamiento manual existente no cambia. Sin ejecutar Context Agent, Negro funciona como antes y consume **$0 de IA**.

Cuando ejecutas el agente:

- alta confianza (`>= 0.90` final) puede aparecer automáticamente en HTTP Workbench;
- confianza media (`0.70–0.89`) aparece como `Suggested` de forma tenue;
- baja confianza queda como candidato interno y no ensucia el HTTP;
- una marca manual exacta siempre tiene prioridad sobre el overlay de IA;
- confirmar/rechazar una inferencia queda en la memoria semántica del target.

El confidence final no es el número que declara el LLM. Negro guarda:

- `model_confidence`;
- `evidence_confidence` determinística;
- `confidence` final conservadora.

## Análisis incremental

El modo normal es **Inteligente · incremental**.

Después del primer run, Negro guarda un watermark y en el siguiente análisis prioriza:

1. observaciones nuevas;
2. candidatos cuyo contexto manual cambió;
3. candidatos afectados por Flows creados/editados después;
4. vecinos del grafo semántico previo (hasta dos saltos);
5. valores/fields co-observados en los exchanges afectados.

Esto evita volver a enviar toda la historia como raw traffic, pero conserva el contexto anterior necesario para descubrir relaciones nuevas. `Reanalizar todo` sigue disponible explícitamente.

## Estados

Negro deriva localmente transiciones conservadoras cuando el mismo identificador aparece asociado al mismo campo de estado en diferentes exchanges, por ejemplo:

`OrderCandidate -> status PENDING → PAID`

La transición se envía al agente con IDs de observación reales como evidencia.

## Cost control

Antes de ejecutar debes usar **Calcular antes de ejecutar**. Esta acción construye el bundle local y estima tokens/costo, pero **no llama a OpenAI**.

La pantalla muestra:

- observaciones nuevas;
- contexto modificado;
- vecinos recuperados del grafo;
- candidatos impactados y enviados;
- input tokens estimados;
- output token budget;
- costo máximo estimado;
- watermark anterior/nuevo.

`Límite por ejecución · USD` es un hard limit: el endpoint vuelve a recalcular la estimación justo antes del run y bloquea la llamada si supera el presupuesto.

El ledger registra tokens y costo real de runs completados. Si OpenAI devuelve una respuesta incompleta/estructuralmente inválida pero reporta usage, Negro registra también ese costo en el run fallido.

## Modelos del MVP

- `GPT-6.1 Sol`: default para calibrar precisión.
- `GPT-6 Luna`: alternativa económica.

## Configurar OpenAI

Negro sigue usando su archivo local de secretos:

```bash
mkdir -p ~/.config/negro
nano ~/.config/negro/secrets.env
```

Agregar:

```text
OPENAI_API_KEY=tu_key
```

También puede usarse la variable de entorno `OPENAI_API_KEY`; las variables de entorno tienen prioridad.

## Qué se envía al modelo

No se envía el raw traffic indiscriminadamente. El modelo recibe candidatos estructurados y contexto correlacionado.

Antes de construir el payload se redactan valores de Authorization/Bearer, cookies/session y campos que parecen token/secret/password/API key. Los JWT claims sí pueden formar observaciones independientes porque son parte del contexto semántico. Otros identificadores/valores de negocio necesarios para clasificar relaciones pueden formar parte del payload.

## HTTP Workbench

Después del run puedes volver a HTTP Workbench y seguir trabajando manualmente. Las inferencias relevantes aparecen:

- directamente sobre keys/values como annotations `AI` / `Suggested`;
- en `Context → AI Context` con tipo, rol, confidence, explicación y relaciones;
- sin reemplazar las marcas manuales.

## Fuera del alcance de este MVP

- generar hipótesis de vulnerabilidad;
- ejecutar escenarios/ataques;
- Runner Agent;
- Pentest Manager / supervisor multi-agente;
- reescribir automáticamente ground truth manual.

Esas capas consumirán la memoria semántica producida por Context Agent en fases posteriores.
