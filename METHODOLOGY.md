# Negro Recon — Metodología v0.20.3

## Modelo mental: Rule → Signal → Hipótesis IA → Investigación

Negro no intenta reemplazar Burp ni decidir vulnerabilidades por el hacker.

1. **Rule**: conocimiento determinístico configurable. Define patrones observables.
2. **Signal**: hecho que una Rule encontró en evidencia real. Debe explicar WHY y apuntar al exchange exacto.
3. **Hipótesis IA**: inferencia generada únicamente cuando el usuario ejecuta IA. Debe separar hechos, inferencia, incógnitas y próxima prueba.
4. **Investigación**: línea de trabajo creada/promovida por decisión humana. Puede agrupar múltiples Signals, exchanges, recursos y notas.
5. **Finding**: vulnerabilidad confirmada por el humano. La IA y las Rules nunca lo asignan automáticamente.

## Principios

- Un Signal no es una vulnerabilidad.
- Una Rule no crea automáticamente una Hipótesis visible.
- La IA no corre por request; el usuario decide cuándo y sobre qué evidencia razonar.
- Una Hipótesis IA no se convierte sola en Investigación.
- `Finding` y `Discarded` siguen siendo decisiones humanas.
- Evidencia histórica y retest actual son conceptos distintos.
- El conocimiento útil descubierto con IA puede terminar convertido, después de revisión humana, en una nueva Rule determinística.

## Flujo recomendado

Burp captura tráfico → Negro normaliza evidencia → Rules producen Signals → el hacker revisa/organiza → cuando tiene suficiente contexto ejecuta IA → la IA propone Hipótesis → el hacker promueve sólo las que merecen trabajo → Investigación → validación manual → Finding o cierre.
