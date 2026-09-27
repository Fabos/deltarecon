# Negro Recon 🐕 — v0.8.0

> **Olfatea donde otros no miran.**

Negro es un workspace local de recon para Bug Bounty. El CLI ejecuta discovery/inspecciones y la Web UI organiza targets, hosts, resources, provenance, estados, notas, JavaScript y análisis asistido por IA.


## v0.8.0 — Secrets & Client Config + Source Map intelligence

Esta versión convierte el pipeline JavaScript en cinco fases visibles: **Discovery → Local Analysis → Secrets & Config → Source Map → AI Analysis**.

Cambios principales:

- detector local de credenciales/configuración con valores **enmascarados** y deduplicados por fingerprint;
- antes de enviar contextos a OpenAI, Negro vuelve a enmascarar candidatos sensibles; el valor completo permanece sólo en el archivo JS/source map local original;
- categorías separadas: `potential_secret`, `public_client_config` y `surface_config`;
- reconoce familias de alta señal como Google API key, AWS keys, GitHub/GitLab/npm/SendGrid tokens, Slack/Discord webhooks, JWT, OAuth `client_secret`, Bearer literal, private keys, database URLs, signed URLs, Stripe/Mapbox/Sentry/Firebase y storage endpoints;
- detectar una key/config **no la convierte en vulnerabilidad** y Negro no prueba credenciales automáticamente;
- Source Map muestra fuentes totales, código de aplicación, `node_modules`, runtime, `sourcesContent` y muestra de archivos de aplicación;
- el análisis de Source Map filtra `node_modules`/Webpack runtime antes de extraer señales, endpoints y candidatos;
- la IA recibe el análisis local **más el Source Map confirmado** cuando existe; los workspaces v0.7.x pueden reutilizar el `.map` ya guardado sin nueva descarga al estimar/ejecutar IA;
- prompt de IA en español, manteniendo términos técnicos útiles en inglés;
- la UI usa `Prioridad de revisión` en vez de presentar `high/medium/low` como severidad de vulnerabilidad;
- TLS SAN muestra en la ficha el último conjunto de nombres in-scope observado;
- `install-web.sh` instala un launcher `/usr/local/bin/negro` que fuerza el Python de `.venv`, evitando que Web use por accidente el Python global.
- la Web limita a **3 jobs simultáneos**; los adicionales quedan en cola para evitar lanzar demasiados análisis a la vez sobre el mismo target/equipo.

### Qué significa Secrets & Config

`public_client_config` incluye valores que muchas aplicaciones necesitan exponer al navegador (por ejemplo una Google API key para Maps, Firebase config, OAuth Client ID o Sentry DSN). Su presencia es una pista para revisar restricciones/configuración, **no un finding por sí sola**.

`potential_secret` indica material que merece revisión manual porque podría actuar como credencial. Negro lo muestra enmascarado y no lo usa automáticamente.


## v0.7.2 — JS/AI UX + dependency hardening + source-map hotfix

Esta versión consolida los ajustes de v0.7.1 y los nuevos cambios de UX:

- source maps inline Base64 toleran padding omitido y se prueban todos los candidatos;
- presentación de JavaScript más legible: URL, tamaño, hash, métricas y señales con tipografía/tarjetas mayores;
- la estimación IA muestra primero el valor **COP** de forma inequívoca (por ejemplo `COP $9,70 ≈ 10 pesos colombianos`) y después USD/tokens;
- el costo mostrado es un **máximo estimado** según el presupuesto de salida; el costo real puede ser menor;
- jobs como Descubrir JS, análisis local, Source Map, TLS SAN, Passive DNS e IA muestran una barra de actividad indeterminada y tiempo transcurrido; no se inventa un porcentaje cuando la operación no expone progreso real;
- `install-web.sh` reutiliza/repara `.venv`, actualiza pip/setuptools/wheel, instala requirements y verifica explícitamente `openai`, `tiktoken`, `jsbeautifier` y dependencias Web;
- si el SDK OpenAI no está disponible, la ficha JS lo avisa antes de lanzar IA y el error indica el Python exacto que está ejecutando Negro.

## v0.7 — Intelligence + JavaScript + AI

Novedades:

- corrige/hardening de creación de targets desde Web: un error de workspace ya no termina en un `Internal Server Error`; se muestra la causa exacta;
- los targets nuevos se crean como hermanos del workspace actual cuando es posible;
- Wayback CDX directo;
- URLScan directo, con scans históricos y requests observados;
- SecurityTrails opcional para subdominios y DNS histórico;
- TLS SAN pivot dirigido desde un host;
- GitHub public code search opcional;
- discovery de JavaScript por host;
- análisis local de bundles minificados/grandes;
- detección y análisis de source maps;
- OpenAI opcional sobre sólo los chunks relevantes del JS;
- estimación de tokens y costo **antes** de ejecutar IA;
- estimación en USD y COP;
- ningún resultado de IA se convierte automáticamente en finding ni en recurso verificado.

## Instalación / actualización

```bash
cd ~/Documents/recon/tools/deltarecon
chmod +x negro.py install-web.sh
./install-web.sh
```

`negro.py` usará automáticamente `.venv` para CLI y Web cuando exista.

## Web

```bash
negro web
```

Abre:

```text
http://127.0.0.1:8765
```

No expongas la UI a Internet: no tiene autenticación.

## Targets

Registro global:

```text
~/.config/negro/targets.json
```

Cada target tiene su workspace independiente. Por ejemplo Mercado Libre:

```text
~/Documents/recon/mercadolibre/
├── raw/
├── normalized/
├── delta/
├── inventory/
│   └── negro.db
└── notes/
```

La DB es la fuente de verdad para estado/provenance. RAW conserva evidencia reproducible.

## API keys

Negro **no guarda las keys en el repo ni en SQLite**.

Crea:

```bash
mkdir -p ~/.config/negro
nano ~/.config/negro/secrets.env
chmod 600 ~/.config/negro/secrets.env
```

Formato:

```dotenv
OPENAI_API_KEY=sk-...
URLSCAN_API_KEY=...
SECURITYTRAILS_API_KEY=...
GITHUB_TOKEN=...
```

También puedes usar variables de entorno; tienen prioridad sobre `secrets.env`.

Desde Web abre **Settings**: Negro sólo muestra `configurada/falta`, nunca el valor de la key.

## Costos de IA

Configuración local:

```text
~/.config/negro/settings.json
```

Defaults de v0.8:

```text
model = gpt-6-luna
max output = 3000 tokens
USD/COP = 3344.62
fecha FX = 2026-09-26
```

La tasa COP es editable desde Settings. Es sólo una aproximación visual; OpenAI factura en USD.

El flujo obligatorio en Web es:

```text
Análisis local JS
      ↓
Estimar IA
      ↓
ver tokens + USD + COP
      ↓
Confirmar costo y analizar
```

El botón billable no aparece hasta haber calculado una estimación.

### Modelos configurados

- `gpt-6-luna`: primera pasada económica;
- `gpt-6-sol`: análisis más profundo cuando el bundle/contexto lo amerita.

La tabla local de precios está fechada en el código. Si OpenAI cambia precios, actualizar `OPENAI_PRICING` en `negro_intel.py`.

## Discovery integrado

### Host / domain discovery

- crt.sh
- Subfinder
- Amass passive
- GAU / OTX
- GAU / URLScan
- GAU / Wayback
- GAU / Common Crawl
- Wayback CDX direct
- URLScan direct
- SecurityTrails subdomains (API key)
- GitHub public code search (token)

### Investigación dirigida de un host

- Basic Inspect: A / AAAA / CNAME / TLS / HTTP / HTTPS
- TLS SAN pivot
- SecurityTrails DNS history
- JavaScript discovery

### JavaScript

Negro primero trabaja localmente:

```text
HTML del host
   ↓
Discovery de <script src=...>
   ↓
JS in-scope
   ↓
Local Analysis
   ├── URLs / rutas / WebSockets
   ├── sourceMappingURL
   └── señales/chunks
   ↓
Secrets & Client Config
   ├── potential_secret
   ├── public_client_config
   └── surface_config
   ↓
Source Map
   ├── separa app / node_modules / runtime
   └── analiza sourcesContent de aplicación
   ↓
AI opcional (evidencia consolidada)
```

Scripts de terceros se registran como observación, pero Negro no los descarga automáticamente como objetivo de análisis.

## Wayback CDX directo

CLI:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre wayback-cdx
```

Valor adicional frente a GAU: conserva metadata como `timestamp`, `statuscode`, `mimetype`, `digest` y `length` de capturas históricas.

## URLScan directo

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre urlscan
```

Busca scans históricos y, para un conjunto pequeño, consulta el resultado y extrae requests in-scope observados. `URLSCAN_API_KEY` mejora/asegura cuotas; sin key pueden existir cuotas muy limitadas.

## SecurityTrails

Subdominios:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre securitytrails
```

DNS histórico de un host:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre passive-dns api.mercadolibre.com
```

Requiere `SECURITYTRAILS_API_KEY`.

## TLS SAN pivot

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre tls-san api.mercadolibre.com
```

Sólo importa SANs que pertenezcan al target. No considera un SAN una vulnerabilidad; es una nueva pista de asset discovery.

## GitHub public code search

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre github-code
```

Busca referencias públicas al dominio. Extrae URLs in-scope de los fragmentos devueltos y conserva repo/path/URL como observación. Requiere `GITHUB_TOKEN`.

## JavaScript CLI

Descubrir scripts de un host:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre js-discover ux.mercadolibre.com
```

Luego la Web muestra IDs de assets; también puedes analizarlos por CLI:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre js-analyze 1
negro mercadolibre.com -w ~/Documents/recon/mercadolibre js-sourcemap 1
```

Estimar IA sin enviar nada:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre ai-estimate 1 --model gpt-6-luna
```

Sólo después, si aceptas el costo:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre ai-analyze 1 --model gpt-6-luna
```

## Modelo de seguridad / metodología

```text
DISCOVER
  ↓
ASSOCIATE
  ↓
INSPECT
  ↓
LOCAL EXTRACT
  ↓
AI ASSIST (optional)
  ↓
HUMAN VALIDATION
  ↓
CLASSIFY
```

Reglas permanentes:

- una URL, SAN, keyword o salida de IA es una observación, no una vulnerabilidad;
- IA nunca marca automáticamente `finding`;
- contenido activo/fuzzing no se ejecuta masivamente;
- herramientas externas con costo o cuota se disparan explícitamente;
- respetar scope y reglas del programa.
