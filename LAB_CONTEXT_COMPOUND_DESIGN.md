# Lab propio — Contexto compuesto / Investigation Workspace

Este documento **diseña** el laboratorio. El Vagrantfile y la aplicación vulnerable se implementarán en un incremento separado para no mezclar infraestructura de lab con la Fase 1 del core de Negro.

## Objetivo

Validar la experiencia de hunting real, no sólo endpoints aislados:

`Buyer A crea Order → B cambia dirección → Investigation → Follow Value → cancel → refund bloqueado por returnId → Watch → otra funcionalidad revela returnId → Context Match → retomar → Runner refund cross-account → verificar estado → Finding → trayectoria completa.`

La métrica principal no es “cuántas features usamos”, sino si el hunter siente que sigue trabajando normalmente mientras Negro conserva el contexto.

## Topología propuesta

### Host del hunter

- navegador;
- Burp Community + Negro Burp Bridge;
- Negro web/core;
- Vagrant/VirtualBox.

Flujo de tráfico:

`Browser → Burp → VM vulnerable`

Runner, cuando llegue su fase, seguirá usando el transporte `burp_bridge`, de forma que la reproducción también pase por Burp y pueda verse en el historial.

### VM Vagrant

Una VM Ubuntu aislada por `private_network`, sin publicar la aplicación a Internet. Dentro corre una pequeña aplicación de ecommerce deliberadamente vulnerable con base SQLite y seed determinista.

Propuesta de hostname de laboratorio: `shop.negro.lab`.

La VM sólo representa el **target**. Negro y Burp permanecen en el host para probar exactamente el flujo cotidiano de la herramienta.

## Datos semilla

- Buyer A: `buyer.a@negro.lab`
- Buyer B: `buyer.b@negro.lab`
- credenciales exclusivamente de laboratorio, visibles en la portada;
- catálogo con uno o dos productos;
- una cuenta no puede leer por GET las órdenes ajenas, para que lectura y escritura tengan controles distintos.

## Modelo vulnerable intencional

### Crear Order

`POST /api/orders`

Buyer A crea una orden. Response devuelve `orderId` y estado `CREATED`.

### Consultar Order

`GET /api/orders/{orderId}`

**Valida ownership correctamente.** Buyer B recibe 403 para la orden de A.

### Change address

`POST /api/orders/{orderId}/change-address`

**Vulnerable:** exige sesión pero no ownership. Buyer B puede modificar dirección de la orden de A.

### Cancel

`POST /api/orders/{orderId}/cancel`

**Vulnerable:** misma familia de fallo de autorización en operación write. Cambia estado a `CANCELLED` o a un estado preparado para devolución, según el guion final.

### Refund

`POST /api/refunds`

Body requiere al menos:

```json
{
  "orderId": 8932,
  "returnId": 5591
}
```

La operación tiene el fallo cross-account deliberado, pero no puede probarse aún porque el hunter desconoce `returnId`.

### Devoluciones / funcionalidad lateral

La aplicación debe tener otra sección que el hunter explorará después, por ejemplo **Mis devoluciones** / **Crear devolución** / **Historial de actividad**.

Un Flow posterior genera o expone:

```json
{
  "returnId": 5591,
  "orderId": 8932
}
```

La aparición está controlada por una acción posterior, no por un temporizador real. Esto hace el lab determinista pero reproduce la sensación “la pieza apareció después en otro contexto”.

### Verificación final

Buyer A consulta su orden y observa estado `REFUNDED`. Esa Request/Response es evidencia final del impacto.

## Guion de validación UX

El lab se ejecutará en checkpoints. En cada checkpoint se evaluarán **web**, **Burp** y **Negro** por separado.

| Checkpoint | Web | Burp | Negro | Qué valida |
|---|---|---|---|---|
| 1. Baseline | Login A, crear Order | Capturar create + GET propio | Identity A, Entity Order, Flow baseline | Captura de contexto sin burocracia |
| 2. Cross-account write | Login B, intentar change-address sobre Order A | Repetir/manipular `orderId` | Hypothesis + Investigation sólo cuando “hay tema” | Diferencia entre pista, pregunta e investigación |
| 3. Follow Value | Seguir usando app | Observar endpoints con mismo `orderId` | Follow Value guardado en Investigation | Correlación sin copiar Requests |
| 4. Cancel | B cancela Order A | Evidencia 200 + verificación | Adjuntar evidencia / actualizar hipótesis | Rama nueva sobre el mismo objeto |
| 5. Refund bloqueado | Intentar refund | Ver requisito `returnId` | Hypothesis “B puede refund A” → Bloqueada; Watch `returnId` | Memoria de pieza faltante |
| 6. Cambiar de contexto | Explorar otra funcionalidad | Capturar tráfico normalmente | No administrar manualmente la Investigation | Negro no interrumpe el hunting |
| 7. Context Match | Crear/ver devolución | Response revela `returnId` | Aviso: nueva evidencia puede desbloquear Hypothesis | Interés compuesto del contexto |
| 8. Retomar | Volver al caso original | Preparar Flow completo | Abrir Investigation con contexto recuperado | Continuidad después del cambio de contexto |
| 9. Runner | Ninguna acción manual extra salvo observar | Ver replay vía Bridge | Runner: A crea → B obtiene/usa return → refund → A verifica | Experimento reproducible ligado a pregunta |
| 10. Finding | Ver estado final | Conservar request final | Crear Finding y “Cómo llegamos aquí” | Trayectoria completa |

## Experiencia guiada futura

Cuando el lab esté implementado, la guía no dirá simplemente “explota el IDOR”. Será secuencial y operacional. Ejemplo de formato:

**Paso Web:** inicia sesión como Buyer A y crea una orden. No navegues aún a devoluciones.

**Paso Burp:** en Proxy History localiza `POST /api/orders`; envíala/ábrela en Negro y marca el contexto de Buyer A si Negro no lo resolvió automáticamente.

**Paso Negro:** no crees Investigation todavía. Confirma que Order aparece como Entity/valor correlacionable y crea/guarda el Flow baseline sólo si resulta natural en la UX.

Después de cada checkpoint se responderán tres preguntas:

1. ¿Negro recordó algo que de otro modo tendríamos que recordar nosotros?
2. ¿Nos obligó a registrar información que ya podía inferir/reutilizar?
3. ¿El siguiente paso surgió del trabajo de hunting o de “alimentar la herramienta”?

Cualquier paso que falle la pregunta 2 se considera fricción de producto y debe rediseñarse.

## Criterios de aceptación del lab

El laboratorio estará completo cuando podamos cerrar una sesión tras el refund bloqueado, continuar explorando tráfico no relacionado y, al aparecer `returnId`, recuperar en pocos clics:

- Investigation correcta;
- Hypothesis bloqueada correcta;
- dependencia que faltaba;
- Request/Response donde apareció la pieza;
- identidades implicadas;
- experimentos previos;
- Runner final;
- verificación de estado;
- Finding y trayectoria.

No debe ser necesario copiar/pegar IDs entre módulos de Negro ni volver a reconstruir mentalmente el caso.
