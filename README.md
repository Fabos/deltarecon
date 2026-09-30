# Negro Recon 🐕 — v0.21.0

Negro es una capa local de inteligencia, memoria y organización encima de Burp Suite. No pretende ser un vulnerability scanner ni hacer el hacking por el usuario.

## Modelo central

`Rule → Signal → Hipótesis IA → Investigación humana`

- **Rules**: conocimiento determinístico configurable.
- **Signals**: observaciones automáticas con procedencia exacta; no son vulnerabilidades.
- **Hipótesis IA**: aparecen únicamente cuando el usuario ejecuta IA; separan hechos, inferencia, incógnitas y próxima prueba.
- **Investigaciones**: las crea el usuario al promover una hipótesis que considera valiosa.
- **Estados humanos / Findings**: siguen bajo control del hacker.

## v0.21.0 — Search Everything + mapa observable

La nueva vista **Buscar** permite consultar la memoria acumulada de Negro sin recorrer miles de requests manualmente. Usa SQLite FTS5 e índices estructurados sobre tráfico, metadata y conocimiento.

Ejemplos:

```text
redirect_uri
host:api.example.com method:POST
status:403
state:learning
signal:authorization
param:userId
cookie:session
header:X-Tenant-Id
response:ownerId
request:redirect_uri
body:"roleId"
path:/orders/
type:investigation
```

La página incorpora ayuda **“Aprende a buscar como hacker”**, ejemplos ejecutables y **Saved Searches**. Al actualizar un workspace anterior, pulsa una vez **Indexar historial**; el tráfico Burp nuevo se indexa durante la ingesta.

El mapa también cambia:

- los proyectos pequeños materializan relaciones `Target → Host → Resource → Operation` aun sin Hipótesis IA;
- la perspectiva **Burp** carga una proyección propia de exchanges observados, por lo que ya no depende del grafo superficial ni de que exista una hipótesis;
- generar una Hipótesis IA ya no cambia automáticamente la perspectiva inicial del mapa.

## Arranque

```bash
chmod +x negro.py install-web.sh burp-extension/build-extension.sh
./install-web.sh
negro web
```

## Extensión Burp

**No necesitas actualizar la extensión al pasar de Negro v0.20.3 a v0.21.0.** La aplicación v0.21.0 sigue siendo compatible con **Negro Burp Bridge v0.20.3**.

Si necesitas recompilarla:

```bash
cd burp-extension
./build-extension.sh
```

Carga `build/libs/negro-burp-bridge-0.20.3.jar` desde Burp → Extensions.

Consulta `METHODOLOGY.md` para el modelo mental, `ROADMAP.md` para las siguientes fases y `CHANGELOG.md` para el historial consolidado.
