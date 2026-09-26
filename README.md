# Negro Recon 🐕 — v0.6

> **Olfatea donde otros no miran.**

Negro es un workspace local de recon para **Bug Bounty**. El CLI ejecuta discovery/inspecciones y la Web UI organiza la investigación: targets, hosts, resources, provenance, estados, prioridad, notas e historial.

## Qué cambia en v0.6

- **Multi-target Web UI**: varios programas/targets desde un solo `negro web`.
- selector de target en la barra superior;
- agregar un target nuevo desde el dashboard;
- cada target conserva su workspace y su propia `inventory/negro.db`;
- migración automática del target único de v0.5 a `~/.config/negro/targets.json`;
- **Basic Inspect live**: al lanzarlo desde un host se muestra el progreso y la página se actualiza sola al terminar;
- dashboard actualiza contadores mientras corren jobs;
- botón **Abrir** para hosts desde inventario/árbol/dashboard;
- botones **Abrir HTTPS / HTTP** en la ficha del host;
- botón **Abrir recurso** para URLs/endpoints HTTP(S).

## Arquitectura

```text
                         NEGRO
                           │
                ┌──────────┴──────────┐
                │                     │
           CLI / Engine            Web UI
                │                     │
   discovery / inspect       review / targets / notes
                │                     │
                └──────────┬──────────┘
                           │
               un SQLite por target
```

Los RAW siguen siendo evidencia/reproducibilidad. SQLite es la fuente de verdad para el estado de la investigación.

## Targets

La lista local vive en:

```text
~/.config/negro/targets.json
```

Cada entrada apunta a un workspace independiente:

```text
mercadolibre.com -> ~/Documents/recon/mercadolibre
example.com      -> ~/recon/example.com
```

La v0.6 importa automáticamente el target anterior guardado en `config.json`.

### Agregar desde CLI

Cualquier `init` registra el target:

```bash
negro example.com -w ~/Documents/recon/example init
```

### Agregar desde Web

```bash
negro web
```

En el dashboard abre **+ Agregar target**, escribe el dominio y opcionalmente el workspace. Después puedes cambiar de target desde el selector superior sin reiniciar el servidor.

## Web UI

Instala las dependencias si aún no lo hiciste:

```bash
chmod +x install-web.sh
./install-web.sh
```

Arranca:

```bash
negro web
```

Abre:

```text
http://127.0.0.1:8765
```

La UI no tiene autenticación. Por defecto escucha únicamente en localhost.

## Discovery integrado

- `crt.sh`
- Subfinder
- Amass passive
- GAU / OTX
- GAU / URLScan
- GAU / Wayback
- GAU / Common Crawl

GAU asocia automáticamente cada URL a su host/resource y conserva provenance.

## Estados

Cada host/resource conserva tres dimensiones:

```text
Review:
  pending
  in_progress
  reviewed

Classification:
  unknown
  informational
  lead
  discarded
  finding

Priority:
  none
  low
  medium
  high
```

Ejemplos:

```text
reviewed + discarded
  investigado y cerrado sin finding

in_progress + lead + high
  investigación prometedora que debemos retomar

reviewed + finding
  impacto demostrado/documentado
```

## Basic Inspect

Sólo se ejecuta sobre un host seleccionado explícitamente:

```text
DNS
  A
  AAAA
  CNAME

TLS :443
  subject
  issuer
  dates
  SAN
  handshake/error

HTTP /
HTTPS /
  status
  Server
  Location
  Content-Type
  Via
  X-Powered-By
```

No sigue redirecciones automáticamente y no marca el host como revisado.

Desde Web, al pulsar **Inspección básica**:

```text
inicia job
   ↓
UI consulta estado
   ↓
termina
   ↓
la ficha se actualiza automáticamente
```

## Abrir activos en navegador

Desde la UI puedes abrir una pestaña nueva para revisar manualmente:

- Host → HTTPS;
- Host → HTTP;
- Resource → URL exacta encontrada por la fuente histórica.

Negro sólo genera botones para resources con esquema `http` o `https`.

## Modelo de trabajo

```text
DISCOVER
   ↓
ASSOCIATE
   ↓
INSPECT
   ↓
ANALYZE
   ↓
CLASSIFY
   ↓
REMEMBER
```

Negro organiza la evidencia; no decide que un activo sea vulnerable.

## CLI sigue disponible

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre status
negro mercadolibre.com -w ~/Documents/recon/mercadolibre run --sources crtsh subfinder
negro mercadolibre.com -w ~/Documents/recon/mercadolibre run --sources amass
negro mercadolibre.com -w ~/Documents/recon/mercadolibre gau --provider otx
negro mercadolibre.com -w ~/Documents/recon/mercadolibre inspect url8202.mercadolibre.com
negro mercadolibre.com -w ~/Documents/recon/mercadolibre queue
negro mercadolibre.com -w ~/Documents/recon/mercadolibre leads
```

## Lo siguiente

No queremos integrar herramientas por cantidad. La próxima etapa debe añadir **señal distinta** y encajar en el modelo Host → Resource → Observation → Lead/Finding.

Prioridades técnicas:

1. Wayback/CDX directo, independiente de GAU;
2. URLScan directo con metadata y recursos relacionados;
3. Passive DNS;
4. TLS SAN pivoting;
5. GitHub/public code search;
6. extracción de endpoints desde JavaScript/source maps;
7. comparación automática de snapshots DNS/TLS/HTTP;
8. content discovery dirigido e importable, nunca masivo por defecto.

Prioridades de comodidad/orden:

- cola de trabajo / “next action”;
- tags personalizados;
- evidencia/adjuntos por lead;
- timeline más rico;
- diffs entre inspecciones;
- vista global de leads/findings entre targets;
- export de finding a Markdown/HackerOne;
- saved searches/filtros;
- relaciones entre hosts, providers, IPs y resources.

## Uso responsable

Usa Negro sólo sobre activos autorizados y respeta scope, rate limits y reglas de cada programa. La v0.6 no incluye port scanning, brute force, fuzzing masivo, credential attacks ni explotación automática.
