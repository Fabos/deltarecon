# Negro v0.48.1 · Executable Flow MVP

## Arquitectura

El Flow es la definición estable del proceso. El Run contiene el estado temporal de una ejecución. El transporte de red sigue reutilizando las primitivas existentes de `negro_runners`; no existe una segunda configuración de proxy/TLS/Burp.

```text
FLOW
  steps
  variables
  bindings
  extractors
  prerequisites
        ↓
FLOW RUN
  isolated context
  manual inputs
  per-step overrides
  evidence used/produced
        ↓
Runner transport / Burp Bridge
```

### Tablas nuevas

- `flow_variables`
- `flow_step_variable_bindings`
- `flow_prerequisites`
- `flow_runs`
- `flow_run_steps`
- `flow_run_overrides`

Son aditivas. Los Flows y Runners existentes no se migran ni se reescriben.

## Flow Variables

Sources soportados:

- `CONSTANT`
- `MANUAL_INPUT`
- `PREVIOUS_RESPONSE`
- `IDENTITY`
- `OBJECT`
- `GENERATED` (token/UUID/email básico)

Una variable conoce producer, extractor, consumers, `sensitive`, `required` y `exported`.

## Manual Input OTP

1. Flow → **+ Crear Flow Variable**.
2. `name=otp`, `source=MANUAL_INPUT`, prompt `Código OTP recibido`, Sensitive.
3. En **Marcar un valor de un Step como variable**, selecciona el Step de verify, la variable `otp` y el valor OTP de la captura baseline.
4. Ejecuta el Flow.
5. Runner ejecuta los Steps previos hasta llegar al consumidor de `otp`, cambia el Run a `waiting_input` y no envía el Step incompleto.
6. Ingresa OTP y **Continuar Run**. Los Steps previos no se repiten.

## Extraer JWT

1. Crea `jwt` con `source=PREVIOUS_RESPONSE`.
2. Producer Step = verify/login.
3. Extractor `JSON path`.
4. Expression por ejemplo `$.token` o `$.accessToken`.
5. Marca Sensitive y, si otros Flows lo necesitarán, **Export**.
6. Crea bindings de `jwt` sobre el token/header baseline de los Steps siguientes.

Extractores adicionales MVP: header, Set-Cookie, Location y regex.

## Per-Step Override

1. Desde el Flow pulsa **Ejecutar Flow**. Esto prepara el Run; no lo ejecuta todavía.
2. Abre el Run y en **Security Overrides** crea un override.
3. Selecciona Step + Variable.
4. Source `IDENTITY`, `OBJECT` o `CONSTANT`.
5. Para Identity, por ejemplo `auth:Authorization`.
6. Pulsa **Iniciar Run**.

El override sólo existe en `flow_run_overrides`. No modifica el Flow ni el valor global del Run. El Step siguiente vuelve a resolver la variable normal.

## Reusable prerequisite Flows

Un Flow puede requerir otro Flow guardado sin copiar sus Steps.

```text
Login Vive Terpel
  exports: jwt, userId

Consultar Puntos
  requires: Login Vive Terpel
```

Al ejecutar `Consultar Puntos`, Negro crea un child Run para `Login Vive Terpel`. Si Login necesita OTP, el parent queda `waiting_prerequisite`. Al completar Login, únicamente las variables marcadas **Export** se incorporan al contexto del parent.

Esto deja preparado el camino para `Purchase Abuse requires Login`, sin duplicar autenticación en cada escenario.

## Evidencia del Run

Cada Step conserva:

- Request/Response RAW del Run.
- HTTP status y error.
- Variables `Used` (sensibles enmascaradas en UI).
- Variables `Produced`.
- Exchange canónico cuando hubo respuesta válida.

## Límites deliberados del MVP

Todavía no se implementan:

- creación de variable seleccionando directamente un rango dentro de HTTP Inspector/Burp (hoy el binding se crea desde Flow pegando el valor baseline);
- Variants persistentes; por ahora existe Run Override;
- fallback manual automático después de extractor fallido;
- branches, loops, wait conditions, browser automation, CAPTCHA o agentes;
- grafo visual grande producer→consumers;
- ejecución asíncrona/polling de Flows largos.

La prioridad de v0.48.1 es que los dos benchmarks básicos sean modelables sin romper Flow/Runner existentes: OTP pause/resume + JWT chaining, y override de Identity en un único Step con restauración automática.
