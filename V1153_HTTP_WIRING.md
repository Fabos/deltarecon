# v0.115.3 — HTTP Reading + Flow Data Wiring

Esta iteración une dos objetivos que salieron del uso real de Negro.

## 1. HTTP Workbench con el lenguaje visual de Inventario

El modo **Pretty** reutiliza la misma gramática visual del visor HTTP de Inventario:

- número de línea;
- método y status con jerarquía fuerte;
- path/target en azul;
- headers en violeta;
- Authorization/Cookie y material sensible diferenciados;
- JSON con keys, strings, números y literales en colores consistentes;
- JSON compacto se formatea con indentación;
- líneas largas se ajustan al ancho disponible, sin obligar a hacer scroll horizontal.

`Raw` sigue siendo el wire-format exacto y mantiene scroll horizontal cuando sea necesario.

## 2. Flow: conexiones de datos por intención

La UI deja de pedir al usuario que piense primero en `variables`, `extractors` y `bindings`.
Desde **Ver HTTP** de un Step, cada valor útil expone directamente lo que se puede hacer con él.

### Valor que viene de Request

- **Pedir al ejecutar**: crea/reutiliza un `MANUAL_INPUT` y reemplaza ese valor cuando se ejecuta el Flow.
- **Pasar al siguiente Step**: usa el valor observado como fuente y permite seleccionar exactamente qué parámetro de la siguiente Request reemplazar.

### Valor que viene de Response

- **Pasar al siguiente Step**: crea/reutiliza un extractor (`PREVIOUS_RESPONSE`) y permite seleccionar el parámetro destino de la siguiente Request.

La UI sólo permite conectar con la **siguiente Request activa del Flow**, para que el encadenamiento sea predecible y fácil de leer.

## 3. Flow y Escenario cuentan la misma historia

El Flow muestra las conexiones como:

- **ENTRA**: valores que ese Step recibe/reemplaza.
- **SALE**: valores de Request/Response que alimentan Steps posteriores.

El Escenario **hereda el wiring del Flow**. No existe un segundo sistema de parámetros para la prueba: el Escenario modifica la variante de prueba, pero conserva el movimiento de datos definido por el Flow.

## Compatibilidad

- No cambia el protocolo del Burp Bridge.
- No requiere actualizar la extensión de Burp desde v0.112+.
- `negro_core.VERSION` permanece en `0.52.3` para conservar compatibilidad histórica interna.
