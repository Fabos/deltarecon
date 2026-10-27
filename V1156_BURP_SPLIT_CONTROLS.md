# v0.115.6 · Burp Split View + Reliable Controls

## Objetivo

Priorizar la lectura HTTP: Traffic arriba para navegar, Request a la izquierda, Response a la derecha y Context como apoyo plegable.

## Layout

- Traffic Inbox: deck superior, `T` para plegar/desplegar.
- Request: panel izquierdo.
- Response: panel derecho.
- Divisor vertical: arrastrable; doble click vuelve a 50/50.
- Context: panel derecho externo, `C` para plegar/desplegar.
- Focus: `F`.
- Pantalla completa: expande Request/Response como área principal.

## Controles HTTP

- Pretty / Raw independientes por lado.
- Líneas exactas / Ajustar líneas independientes por lado.
- Copiar HTTP original.
- Split / Request / Response.
- Pantalla completa.

## Bugs corregidos

1. `wrapKey` se consultaba antes de declararse. Ese error detenía la inicialización del Workbench.
2. `closest('[data-pane-layout]')` también encontraba el atributo `data-pane-layout` del contenedor raíz, por lo que clicks en Pretty/Raw/Traffic/Context podían retornar prematuramente como si fueran clicks de Split. Ahora sólo `button[data-pane-layout]` activa esa rama.

## Validación

- Chromium real: Pretty/Raw, wrap, Split/Request/Response, Traffic, Context, `T/C/F` y fullscreen.
- Suite completa: 141/141 tests.
