# Negro Recon 🐕

> **Olfatea donde otros no miran.**

Negro es una herramienta personal de enumeración para **Bug Bounty**.

El nombre viene de Negro, un perrito criollo que no pierde oportunidad para buscar comida en la cocina, la basura o cualquier rincón. La filosofía es la misma: **buscar superficie que otros pasan por alto**.

La prioridad inicial es descubrir subdominios actuales e históricos, hosts olvidados, infraestructura legacy, servicios externos, rutas/endpoints históricos y activos que no aparecen en la navegación normal.

## Filosofía

```text
RAW -> NORMALIZED -> DELTA -> INVENTORY -> PROVENANCE
```

- **RAW:** salida original de cada fuente; no se modifica.
- **NORMALIZED:** hostnames limpios, minúsculas y sin duplicados.
- **DELTA:** hosts que una fuente aporta y las anteriores no habían descubierto.
- **INVENTORY:** unión de todos los hosts conocidos.
- **PROVENANCE:** qué fuentes conocen cada host y cuál lo aportó primero.

## Estado actual — v0.2

Automatizado:

- `crt.sh`
- `Subfinder`

Pendiente de **aprender manualmente antes de automatizar**:

- Amass passive
- GAU
- Wayback / CDX
- URLScan
- Passive DNS
- TLS SAN discovery
- GitHub / public code search

Esto es intencional: **aprender -> entender -> automatizar**. Negro no debe convertirse en una caja negra.

Por ahora Negro no hace port scanning, HTTP probing masivo, fuzzing, vulnerability scanning ni explotación.

---

## Instalación

Requisitos actuales:

- Python 3
- Subfinder

```bash
chmod +x negro.py
```

Desde el repo:

```bash
./negro.py
```

Sin argumentos abre el modo interactivo.

### Instalar el comando `negro`

Si el repo está en:

```text
/home/kali/Documents/recon/tools/deltarecon
```

crea un enlace:

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

## Modo interactivo

```bash
negro
```

Menú:

```text
[1] Dashboard / estado
[2] Ejecutar crt.sh
[3] Ejecutar Subfinder
[4] Ejecutar todas las fuentes automatizadas
[5] Ver hosts nuevos por fuente
[6] Ver inventario
[7] Buscar en inventario
[8] Ver fuentes y roadmap
[9] Cambiar target
[0] Salir
```

El último target se guarda en:

```text
~/.config/negro/config.json
```

---

## Modo CLI / no interactivo

El modo interactivo es cómodo, pero todos los comandos siguen disponibles para scripting y reproducibilidad.

### Inicializar target

```bash
negro mercadolibre.com init
```

Con workspace manual:

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
init
```

### Ejecutar crt.sh

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
run --sources crtsh
```

### Ejecutar Subfinder

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
run --sources subfinder
```

### Ejecutar todas las fuentes implementadas

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
run
```

Actualmente el orden es:

```text
crt.sh -> Subfinder
```

### Dashboard

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
status
```

### Sólo lo nuevo que aportó Subfinder

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
new subfinder
```

### Inventario

Primeros 50:

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
inventory
```

Todos:

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
inventory --limit 0
```

### Buscar patrones

```bash
negro mercadolibre.com \
-w ~/Documents/recon/mercadolibre \
search internal
```

También:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre search dev
negro mercadolibre.com -w ~/Documents/recon/mercadolibre search stage
negro mercadolibre.com -w ~/Documents/recon/mercadolibre search auth
```

### Ver fuentes y roadmap

```bash
negro mercadolibre.com sources
```

---

## Workspace

```text
mercadolibre/
├── raw/
│   ├── crtsh.json
│   ├── subfinder.txt
│   └── subfinder.stderr.txt
├── normalized/
│   ├── crtsh.txt
│   └── subfinder.txt
├── delta/
│   ├── crtsh-new.txt
│   └── subfinder-new.txt
├── inventory/
│   ├── all-hosts.txt
│   ├── provenance.json
│   └── state.json
└── notes/
```

---

## Metodología que iremos incorporando

### 01 — Certificate Transparency
Fuente: `crt.sh`

### 02 — Multi-source passive enumeration
Herramienta: `Subfinder`

### 03 — Amass passive
Primero se aprenderá manualmente. Luego se integra como fuente #3.

### 04 — Historical URL archaeology
Fuentes: `GAU`, `Wayback / CDX`.

Buscará hosts históricos, rutas antiguas, endpoints, parámetros y APIs legacy.

### 05 — URLScan
Hosts observados en navegaciones públicas, recursos JS y APIs.

### 06 — Passive DNS
Relaciones DNS históricas que pueden no existir actualmente en CT.

### 07 — TLS SAN pivoting
Usar certificados de hosts conocidos para descubrir hermanos.

### 08 — GitHub / public code search
Buscar arquitectura pública: `BASE_URL`, `API_URL`, dominios, WebSockets, GraphQL, Swagger, buckets y nombres de ambientes.

---

## Regla metodológica

```text
ASSET -> LEAD -> FINDING
```

Un hostname raro no es una vulnerabilidad. Un CNAME abandonado no implica automáticamente takeover. Código fuente accesible no implica automáticamente fuga. Hay que demostrar impacto.

---

## Roadmap tentativo

```text
v0.3  Amass passive
v0.4  GAU + Wayback
v0.5  URLScan
v0.6  Passive DNS
v0.7  TLS SAN pivots
v0.8  GitHub/code-derived assets
```

## Uso responsable

Usa Negro sólo sobre activos autorizados y respeta scope, rate limits, reglas del programa y restricciones de automatización.
