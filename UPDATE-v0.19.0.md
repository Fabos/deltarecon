# Negro Recon v0.19.0 — Guided Rule Knowledge Base

## Objetivo

Convertir los detectores de Negro en conocimiento ofensivo **visible, explicable, editable y heredable**. El investigador debe poder aprender por qué existe una señal, entender exactamente qué regla la disparó y adaptar esa regla a la terminología real de cada aplicación.

## Modelo de conocimiento

```text
Negro built-in
      ↓
Biblioteca personal
      ↓
Proyecto
```

- **Negro built-in**: reglas base incluidas con la herramienta.
- **Biblioteca personal**: términos y ajustes aprendidos que se heredan en futuros proyectos.
- **Proyecto**: adiciones/exclusiones locales que no contaminan otros targets.

Ejemplo: `memberId` puede añadirse globalmente como identificador de objeto y luego excluirse sólo en un proyecto donde sea telemetría o un parámetro ubicuo sin relación con ownership.

## Editor guiado por detector

Cada detector incorpora una guía en español con:

- qué es la vulnerabilidad;
- cómo suele aparecer en aplicaciones reales;
- ejemplo mental;
- qué evidencia puede observar Negro;
- falsos positivos habituales;
- cómo validarla manualmente sin confundir señal con finding.

Después de la explicación aparecen las reglas efectivas y sus controles: listas de nombres/patrones, ubicaciones, condiciones y exclusiones. Cada término muestra su procedencia (`Negro`, `personal`, `proyecto`).

## Rule Match trazable

Las hipótesis generadas por reglas guardan la coincidencia concreta que las originó, por ejemplo:

```text
Detector: IDOR / autorización horizontal
Ubicación: query.memberId
Regla: exact:memberId
Valor observado: 83921
Origen: Biblioteca personal
```

La pantalla Hipótesis expone esta información y enlaza de vuelta al editor del detector.

## Detectores migrados

La Knowledge Base cubre Access Control, CORS, JavaScript, Open Redirect, URL-fetch/SSRF, secrets/config, respuestas sensibles, secretos en URL, source maps, API docs y error disclosure.

En Access Control, IDOR/BOLA, Mass Assignment, HTTP Method, redirect-body leakage, proxy/path discrepancies y Referer usan reglas editables. El motor CORS usa scopes del proyecto para evitar confundir comunicación first-party con un origin externo.

## Herencia y seguridad operacional

- Las reglas personales se guardan en la configuración global de Negro.
- Las reglas del proyecto se guardan en su SQLite/meta.
- Desactivar un detector no elimina evidencia histórica.
- Excluir un término en un proyecto no lo borra de la biblioteca personal.
- Los resultados positivos/negativos **no auto-promueven ni auto-eliminan reglas**; el investigador decide.
- Una señal sigue siendo una hipótesis. Sólo evidencia de impacto debe convertirse en Finding.

## Compatibilidad

Los workspaces v0.18 migran de forma conservadora. Los estados enabled/disabled previos se respetan cuando existen. El protocolo Burp ↔ Negro no cambia, por lo que el Bridge v0.16.7 continúa siendo compatible.
