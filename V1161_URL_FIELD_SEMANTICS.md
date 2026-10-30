# v0.116.1 — URL Parameters + Field Semantics

## Objetivo
Extender Inline Semantics del HTTP Workbench para que la URL participe del mismo modelo semántico que headers/body y separar claramente **valor** de **campo**.

## Valor vs campo
- Clic en un **valor**: enseña el significado de esa instancia concreta. Ej.: `84329 -> RESOLVER -> Buyer A`.
- Clic en una **llave/campo**: enseña el rol recurrente del campo. Ej.: `customerId -> RESOLVER field` o `orderId -> OBJECT field: Order`.
- Una regla de campo RESOLVER/AUTH/CONTEXT nunca asigna automáticamente futuros valores a una misma Identity.
- Una regla OBJECT sí reutiliza `business_object_identifiers`, por lo que futuros valores del mismo campo se convierten en nuevas instancias del tipo enseñado.

## URL
- Query string: llave y valor son seleccionables (`?orderId=ORD-1`).
- Path: segmentos identificador-like son seleccionables (`/orders/ORD-1`) y reutilizan la misma inferencia de parámetros (`order_id`) que Parameter Memory.
- Valores URL encoded se enlazan al valor decodificado para correlación, conservando Raw como fuente exacta.

## Compatibilidad
No requiere una nueva versión del Bridge. `burp-extension/build-extension.sh` continúa generando `negro-burp-bridge-0.40.0.jar` con `sh build-extension.sh` en Kali.
