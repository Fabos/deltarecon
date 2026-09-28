# Negro Recon v0.14.4 — Endpoint Test Coverage + Exploratory AI Retry

## Test Coverage por método

Negro añade memoria explícita de pruebas sobre cada `resource_operation`. La misma ruta puede tener resultados distintos por método, por eso la checklist vive en `GET/POST/PUT/PATCH/DELETE`, no como una única marca genérica del Resource.

Estados: `pending`, `testing`, `negative`, `interesting`, `confirmed`, `not_applicable`. `negative` significa que la prueba se realizó y no dio; no es información perdida.

La checklist se recomienda según evidencia real: método, autenticación observada, Content-Type, query params, ruta y tipo de recurso. CORS actualiza automáticamente su check después de ejecutar el probe.

## IA

`Give me ideas` recibe ahora `test_coverage` como memoria estructurada. Las pruebas negativas/no aplicables no deben repetirse sin evidencia nueva. Si la primera respuesta estructurada devuelve cero hipótesis, Negro hace una única segunda pasada exploratoria enfocada en checks pendientes, diferencias de sesión, métodos alternativos, client-side trust, parámetros reales y lógica de negocio. Si tampoco encuentra algo defendible, lo dice explícitamente.

La estimación muestra el costo máximo posible de dos llamadas; la segunda sólo se ejecuta cuando la primera produce cero hipótesis válidas.

## Burp

El protocolo del Bridge no cambia. El JAR ya cargado sigue siendo compatible; sólo necesitas recompilar si quieres que Burp muestre la versión 0.14.4.
