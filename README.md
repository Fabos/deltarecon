# Negro Recon 🐕 — v0.5

> **Olfatea donde otros no miran.**

Negro es un workspace local para organizar recon de **Bug Bounty**. Mantiene el CLI para ejecutar y automatizar, y agrega una interfaz web para revisar, clasificar, priorizar y documentar activos sin perder contexto.

## Arquitectura

```text
                    NEGRO
                      │
              ┌───────┴────────┐
              │                │
          CLI / Engine       Web UI
              │                │
    discovery / inspect     review / notes
              │                │
              └───────┬────────┘
                      │
                  SQLite DB
```

El mismo `inventory/negro.db` es usado por terminal y web.

## Fuentes automatizadas

- `crt.sh`
- Subfinder
- Amass passive
- GAU / OTX
- GAU / URLScan
- GAU / Wayback
- GAU / Common Crawl

Negro conserva `raw/`, `normalized/` y `delta/`, pero SQLite es la fuente de verdad para hosts, resources, estados, notas e historial.

## Estados

Cada host y resource tiene tres dimensiones independientes:

```text
Revisión:
  pending       todavía no revisado
  in_progress   investigación abierta
  reviewed      análisis terminado

Clasificación:
  unknown
  informational
  lead
  discarded
  finding

Prioridad:
  none
  low
  medium
  high
```

Ejemplos:

```text
reviewed + discarded       revisado y cerrado sin finding
in_progress + lead + high  señal prometedora; volver pronto
reviewed + finding         impacto demostrado
```


## Actualizar desde v0.4

Haz backup/commit de tu repo antes de reemplazar archivos. La v0.5 migra `inventory/negro.db` de forma conservadora: agrega `priority` y `events`, sin borrar hosts, resources, notas, inspecciones ni estados existentes.

Después de copiar los archivos nuevos:

```bash
cd ~/Documents/recon/tools/deltarecon
chmod +x negro.py install-web.sh
./install-web.sh
```

Si `/usr/local/bin/negro` ya apunta a `negro.py`, no tienes que recrear el symlink.

## Web UI

La UI está diseñada para correr **sólo en localhost**. No tiene autenticación.

### Instalar dependencias web

Desde el repo:

```bash
./install-web.sh
```

Esto crea `.venv/` e instala FastAPI, Uvicorn, Jinja2 y `python-multipart`.

### Ejecutar

Primero asegúrate de tener un target configurado. Por ejemplo:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre init
```

Luego:

```bash
negro web
```

Abre:

```text
http://127.0.0.1:8765
```

Puerto alternativo:

```bash
negro web --port 9000
```

> No uses `--host 0.0.0.0` salvo que sepas exactamente lo que haces y tengas una capa de autenticación/proxy delante. Negro Web no implementa auth en v0.5.

## Qué permite la UI

- dashboard del target;
- hosts y resources asociados;
- árbol Host → Resources → Sources;
- filtros por revisión, clasificación y prioridad;
- cambiar estados desde formularios;
- agregar notas;
- lanzar `crt.sh`, Subfinder, Amass y providers de GAU de forma explícita;
- ejecutar Basic Inspect sobre un único host;
- ver DNS / TLS / HTTP de la última inspección;
- historial de inspecciones;
- auditoría de cambios de estado desde v0.5.

Las tareas largas se ejecutan en threads locales y el dashboard muestra su estado. Si el proceso web se apaga, los jobs en memoria se pierden, aunque los resultados ya persistidos en SQLite/RAW permanecen.

## CLI sigue disponible

Dashboard:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre status
```

Fuentes:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre run --sources crtsh subfinder
negro mercadolibre.com -w ~/Documents/recon/mercadolibre run --sources amass
negro mercadolibre.com -w ~/Documents/recon/mercadolibre gau --provider otx
```

Basic Inspect:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre inspect url8202.mercadolibre.com
```

Árbol:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre tree
```

Pendientes/en revisión:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre queue
```

Cambiar estado desde CLI:

```bash
negro mercadolibre.com \
  -w ~/Documents/recon/mercadolibre \
  mark host url8202.mercadolibre.com \
  --review in_progress \
  --classification lead \
  --priority high \
  --note "OTX encontró /wf; falta completar triage."
```

Cerrar un activo:

```bash
negro mercadolibre.com \
  -w ~/Documents/recon/mercadolibre \
  mark host url8202.mercadolibre.com \
  --review reviewed \
  --classification discarded \
  --priority none \
  --note "DNS/TLS/HTTP revisados. Sin impacto demostrable."
```

## Basic Inspect

Sobre un host seleccionado explícitamente, Negro recopila:

```text
DNS: A / AAAA / CNAME
TLS :443: subject / issuer / dates / SAN / handshake error
HTTP /: status / Server / Location / Content-Type / Via / X-Powered-By
HTTPS /: mismos headers, usando -k sólo para observar respuesta aunque el certificado sea inválido
```

No sigue redirecciones automáticamente.

## Workspace

```text
target/
├── raw/
│   └── inspect/<hostname>/<timestamp>.json
├── normalized/
├── delta/
├── inventory/
│   ├── all-hosts.txt
│   ├── provenance.json
│   ├── state.json
│   └── negro.db
└── notes/
```

## Estructura del repo

```text
deltarecon/
├── negro.py              launcher
├── negro_core.py         motor CLI / DB / discovery / inspect
├── negro_web.py          aplicación FastAPI
├── web/
│   ├── templates/
│   └── static/
├── requirements.txt
├── install-web.sh
├── METHODOLOGY.md
└── ROADMAP.md
```

## Regla metodológica

```text
DISCOVER → ASSOCIATE → INSPECT → ANALYZE → CLASSIFY → REMEMBER
```

Negro no decide que algo sea vulnerable por tener `admin`, un CNAME externo o TLS roto. Organiza evidencia; el investigador decide y documenta el impacto.

## Uso responsable

Úsalo sólo sobre activos autorizados. Respeta scope, restricciones de automatización, rate limits y reglas del programa. Negro v0.5 no incluye port scanning, brute force, directory fuzzing, credential attacks ni explotación automática.
