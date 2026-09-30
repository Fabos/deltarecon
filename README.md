# Negro Recon 🐕 — v0.20.3

Negro es una capa local de inteligencia, memoria y organización encima de Burp Suite. No pretende ser un vulnerability scanner ni hacer el hacking por el usuario.

## v0.20.3 — Rule → Signal → AI Hypothesis → Human Investigation

Esta versión consolida el modelo de producto:

- **Rules**: conocimiento determinístico configurable.
- **Signals**: observaciones automáticas con procedencia exacta.
- **Hipótesis IA**: sólo aparecen tras una ejecución explícita de IA; separan hechos, inferencia, incógnitas y prueba sugerida.
- **Investigaciones**: las crea el usuario al promover una hipótesis que considera valiosa.
- **Estados humanos / Findings**: siguen bajo control del hacker.

El Hunt ya no muestra los `ENGINE leads` históricos como si fueran hipótesis. Se preservan internamente por compatibilidad con workspaces anteriores, pero el flujo visible evita la duplicación Signal=Hipótesis.

También se mantiene la integración Burp v0.20.3 con colores de estado y cyan para Signals pendientes, Evidence Snapshots, Parameter Observations, Learning Backlog y la separación entre evidencia histórica y retest.

## Arranque

```bash
chmod +x negro.py install-web.sh burp-extension/build-extension.sh
./install-web.sh
negro web
```

## Extensión Burp

```bash
cd burp-extension
./build-extension.sh
```

Carga `build/libs/negro-burp-bridge-0.20.3.jar` desde Burp → Extensions.

Consulta `METHODOLOGY.md` para el modelo mental y `CHANGELOG.md` para el historial consolidado.
