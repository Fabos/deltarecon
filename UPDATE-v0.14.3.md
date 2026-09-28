# Negro Recon v0.14.3 — AI Cache Reliability Hotfix

- Los resultados de `Give me ideas` que no puedan validarse como JSON estructurado ya no se guardan con estado `done` ni se reutilizan desde cache.
- Los cache entries inválidos heredados se ignoran y se marcan `invalid` automáticamente.
- Se elimina el fallback silencioso a texto libre cuando el SDK no soporta Structured Outputs: Negro ahora pide actualizar dependencias en lugar de contaminar el cache.
- `install-web.sh` actualiza dependencias y `requirements.txt` exige una versión moderna del SDK OpenAI.
- La UI diferencia entre “0 hipótesis válidas” y “respuesta inválida/reintentable”.
- Se incrementó `GRAPH_AI_PROMPT_VERSION` para invalidar cache anterior.
