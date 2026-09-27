# Negro Recon v0.12.2 — Interactive Graph + AI Hypotheses

- Fix de selección: click/tap en nodo abre siempre el panel lateral; drag sigue funcionando.
- Navegación por teclado (Enter/Espacio) en nodos.
- Perspectivas reordenables por drag & drop; el orden se recuerda por target.
- `🧠 Give me ideas` desde todo el target o desde un nodo seleccionado.
- Estimación de costo antes de ejecutar IA, igual que el resto de Negro.
- Contexto estructurado: nodos/edges, cobertura, findings e hipótesis anteriores; no se envían cuerpos HTTP completos.
- La IA devuelve 3–5 hipótesis investigables, nunca findings automáticos ni probabilidades falsas.
- Hipótesis AI persistentes reutilizando `leads_v2`, con estados `candidate/testing/interesting/negative/postponed/confirmed`.
- `Negative` permanece como conocimiento y entra al contexto de futuras sugerencias para evitar repeticiones.
- `View on Graph` cambia a Interesting y enfoca la hipótesis con sus nodos de evidencia.
