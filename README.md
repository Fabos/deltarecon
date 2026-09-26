# Negro Recon 🐕

> **Olfatea donde otros no miran.**

Negro es una herramienta personal de enumeración y organización de superficie de ataque para **Bug Bounty autorizado**.

El objetivo no es ser un scanner automático de vulnerabilidades. La idea es aprender una técnica manualmente, entender qué aporta y luego automatizar únicamente la parte repetitiva.

## v0.3 — Qué cambia

Automatizado:

- `crt.sh`
- `Subfinder`
- `Amass passive`
- `GAU` (`OTX`, `URLScan`, `Wayback`, `Common Crawl`)
- inspección básica dirigida por host (`DNS`, `TLS`, `HTTP/HTTPS`)
- `Amass passive`
- `GAU / OTX`
- `GAU / URLScan`
- `GAU / Wayback`
- `GAU / Common Crawl`

Nuevo modelo de datos:

```text
TARGET
└── HOST
    ├── RESOURCE / endpoint
    ├── SOURCE / provenance
    ├── REVIEW STATE
    ├── CLASSIFICATION
    └── NOTES
```

Negro conserva también:

```text
RAW -> NORMALIZED -> DELTA -> INVENTORY
```

La base SQLite se guarda en:

```text
inventory/negro.db
```

## Estados

Cada host y recurso tiene dos dimensiones separadas.

### Review state

```text
pending   = todavía no se revisó
reviewed  = ya se revisó manualmente
```

### Classification

```text
unknown        = todavía sin conclusión
informational  = aporta contexto/arquitectura, pero no hay vulnerabilidad
lead           = sospechoso; requiere seguimiento
 discarded      = revisado y sin interés de seguridad
finding        = impacto de seguridad confirmado
```

Esto evita mezclar “ya lo miré” con “es vulnerable”.

## Iconos del árbol

```text
[ ][?] pendiente / unknown
[x][i] revisado / informational
[x][-] revisado / discarded
[ ][!] pendiente / lead
[x][F] revisado / finding
```

---

# Instalación

Requisitos:

- Python 3
- Subfinder
- Amass (para su módulo)
- GAU moderno (para fuentes históricas)
- `dig`, `openssl` y `curl` para `inspect`
- OWASP Amass
- GAU moderno recomendado (`~/go/bin/gau`)

En Kali, Amass 5 puede instalar `/usr/bin/amass` como wrapper. Negro prefiere automáticamente:

```text
/usr/lib/amass/amass
```

Para GAU, Negro busca primero:

```text
~/go/bin/gau
```

Luego `gau` en `PATH`, y como fallback `getallurls`.

Dar permisos:

```bash
chmod +x negro.py
```

Instalar el comando global desde este repo:

```bash
sudo ln -sf \
/home/kali/Documents/recon/tools/deltarecon/negro.py \
/usr/local/bin/negro
```

Después:

```bash
negro
```

---

# Modo interactivo

```bash
negro
```

Menú principal:

```text
[1] Dashboard / estado
[2] Ejecutar crt.sh
[3] Ejecutar Subfinder
[4] Ejecutar Amass passive
[5] Ejecutar GAU (elegir provider)
[6] Ver árbol de assets
[7] Ver pendientes
[8] Marcar / revisar asset
[9] Ver leads / findings
[10] Buscar
[11] Ver fuentes
[12] Cambiar target
[0] Salir
```

---

# Modo CLI

Todos los comandos pueden usarse sin menú.

## Inicializar / migrar workspace

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
init
```

La migración es conservadora: importa el inventario v0.2 existente a SQLite sin borrar archivos ni estados.

## crt.sh

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
run --sources crtsh
```

## Subfinder

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
run --sources subfinder
```

## Amass passive

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
run --sources amass
```

Amass puede tardar bastante. Negro usa el flujo v5:

```text
amass enum -passive
        ↓
amass subs -names
        ↓
hosts normalizados
```

## GAU / OTX

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
gau --provider otx
```

Otros providers:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre gau --provider urlscan
negro mercadolibre.com -w ~/Documents/recon/mercadolibre gau --provider wayback
negro mercadolibre.com -w ~/Documents/recon/mercadolibre gau --provider commoncrawl
```

Negro diferencia:

```text
OK     = provider respondió y produjo datos
EMPTY  = provider respondió correctamente con cero resultados
ERROR  = timeout, error TLS, conexión, etc.
```

Un `ERROR` nunca se interpreta como cero resultados.

GAU alimenta dos niveles:

```text
URL histórica
    ↓
HOST
    ↓
RESOURCE / path / query
```

Ejemplo conceptual:

```text
api.example.com
├── /oauth/token       [gau_otx]
├── /orders/           [gau_otx]
└── /config            [gau_urlscan]
```

## Dashboard

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
status
```

Muestra hosts, recursos, pendientes, leads, findings y últimas ejecuciones.

## Árbol

Vista general:

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
tree
```

Un host específico:

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
tree --host api.mercadolibre.com
```

Más recursos por host:

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
tree --host api.mercadolibre.com --resource-limit 50
```

## Cola de pendientes

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
queue
```

## Marcar un host

Ejemplo: revisado y descartado.

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
mark host artifacts.mercadolibre.com \
--review reviewed \
--classification discarded \
--note "Nexus público revisado; artefactos parecen intencionalmente públicos."
```

Ejemplo: dejar un lead pendiente.

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
mark host url8202.mercadolibre.com \
--review pending \
--classification lead \
--note "Certificado no coincide con hostname; falta revisar DNS/TLS/HTTP y /wf."
```

## Marcar un recurso

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
mark resource 'https://api.mercadolibre.com/errorux/config' \
--review reviewed \
--classification informational \
--note "Configuración pública revisada; sin impacto demostrado."
```

## Leads / findings

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
leads
```

## Buscar

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
search session-replay
```

Busca tanto hostnames como URLs/resources.

---

# Workspace v0.3

```text
mercadolibre/
├── raw/
│   ├── crtsh.json
│   ├── subfinder.txt
│   ├── amass-enum.txt
│   ├── amass-subs.txt
│   ├── gau_otx.txt
│   └── ...stderr.txt
│
├── normalized/
│   ├── crtsh.txt
│   ├── subfinder.txt
│   ├── amass.txt
│   ├── gau_otx-hosts.txt
│   ├── gau_otx-urls.txt
│   └── ...
│
├── delta/
│   ├── crtsh-new.txt
│   ├── subfinder-new.txt
│   ├── amass-new.txt
│   └── gau_otx-new.txt
│
├── inventory/
│   ├── all-hosts.txt
│   ├── provenance.json
│   ├── state.json
│   └── negro.db
│
└── notes/
```

---

# Regla metodológica

```text
DISCOVERED
    ↓
PENDING
    ↓
REVIEWED
    ├── DISCARDED
    ├── INFORMATIONAL
    ├── LEAD
    └── FINDING
```

Un hostname raro no es una vulnerabilidad. Un certificado roto no es automáticamente un finding. Un CNAME externo no implica takeover. Un endpoint `admin` no implica acceso indebido.

Ver `METHODOLOGY.md` para el checklist manual.

## Uso responsable

Usa Negro exclusivamente sobre activos autorizados. Respeta scope, rate limits y restricciones del programa. Negro v0.3 sigue siendo **passive-first** y no hace brute force, fuzzing ni explotación automática.
