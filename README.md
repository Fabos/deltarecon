# Negro Recon 🐕 — v0.20.2


## v0.20.2 — Signals ≠ State · Evidence Memory · Burp Workflow

Negro separa formalmente **lo que el motor observa** de **lo que el hacker decide**. Los `Signal Occurrences` son automáticos, trazables por exchange y nunca convierten por sí solos una superficie en Interesting/Finding/Discarded. Los estados humanos son `Normal`, `Pending Learning`, `Review Later`, `Interesting`, `Correlate`, `Finding` y `Discarded`.

La integración Burp v0.20.2 sincroniza colores/notas, expone estados desde el menú contextual y resalta en cyan los Signals persistidos que siguen sin revisión. La vista **Hunt** reúne Signals e Investigaciones en un único flujo sin confundir sus significados y mantiene la filosofía **Signal = observación; State = decisión humana**. Los estados importantes congelan un `Evidence Snapshot` del request/response histórico para distinguirlo de un retest posterior en Repeater.

También incorpora la vista **Hunt** con Signals pendientes, Investigaciones y un primer **Learning Backlog** agrupado por categoría. Se mantiene la base de `Parameter Observations` para futuras funciones `Follow Value`, Parameter Explorer e Identity Contexts, además de un polling de notificaciones con backoff para no golpear innecesariamente la API local.

Consulta `CHANGELOG.md`.


## v0.19.3 — Exact Evidence Provenance

Las hipótesis de secretos/configuración ahora explican exactamente de qué exchange y superficie salió la coincidencia, muestran el valor enmascarado, fingerprint, patrón, offset/línea/columna y una ventana de contexto enmascarada. Los botones abren el exchange exacto, incluso si quedó fuera de los 30 más recientes. Evidencia histórica se resuelve al abrirla, sin repetir enumeración.

Consulta `CHANGELOG.md`.

## v0.19.2 — Fullscreen Map + Local Intelligence Recalculation

El mapa incorpora **pantalla completa real** y un control para plegar las tarjetas de siguientes pasos, de modo que el grafo pueda usar prácticamente todo el viewport incluso con zoom alto.

La Knowledge Base ahora puede **recalcular toda la inteligencia local** sobre evidencia ya almacenada: requests/responses de Burp, Resources, análisis JavaScript guardados, crawls e inspecciones. No vuelve a enumerar, no descarga JS otra vez y no llama a OpenAI. Las hipótesis deterministas conservan estados/notas humanos, pero obtienen una vigencia separada (`rule_active`): si una regla deja de coincidir desaparecen de las vistas activas sin borrar el historial; si vuelve a coincidir se reactivan.

Comando equivalente:

```bash
negro TARGET -w WORKSPACE recalculate-intel
```

Consulta `CHANGELOG.md`.

## v0.19.1 — Route Canvas Hydration Fix

Corrige la perspectiva **Qué probar ahora**: en v0.19.0 las tarjetas de rutas podían existir mientras el canvas quedaba vacío, porque el overview cargaba sólo hosts y las tarjetas referenciaban recursos/métodos/requests/hipótesis todavía no materializados. v0.19.1 añade una proyección compacta `scope=routes` que carga únicamente los nodos necesarios para las rutas prioritarias y la activa automáticamente al entrar en esa perspectiva.

No cambia el modelo de reglas, proyectos ni el protocolo de Burp. Consulta `CHANGELOG.md`.

## v0.19.0 — Guided Rule Knowledge Base

Negro reemplaza la sensibilidad abstracta de detectores por un **motor de reglas transparente, editable e heredable**. Cada detector enseña primero la vulnerabilidad —qué es, cómo aparece, qué observa Negro, falsos positivos y cómo validarla manualmente— y después expone exactamente los nombres, patrones, ubicaciones, condiciones y exclusiones que generan sus señales.

La resolución de reglas sigue `Negro built-in → Biblioteca personal → Proyecto`: puedes enseñar a Negro términos como `memberId`, heredarlos en futuros proyectos y excluirlos sólo donde generen ruido. Las hipótesis guardan además **qué regla coincidió** (`query.memberId`, `exact:memberId`, UUID en path, etc.) para poder explicar por qué nacieron y volver desde la hipótesis al editor del detector. No se promueven reglas automáticamente por resultados; el investigador conserva el control sobre qué conocimiento pasa a su biblioteca personal.

Consulta `CHANGELOG.md`.

## v0.18.0 — Projects, Detector Lab & Investigation Map

Negro agrupa una prueba como **Proyecto → múltiples scopes**, enruta Burp/JS/hipótesis al mismo workspace y usa ese contexto para reducir falsos positivos first-party como CORS entre `app.*` y `api.*`. Ajustes incorpora un **Detector Lab por proyecto** con on/off, sensibilidad Estricto/Equilibrado/Permisivo, explicación del trigger y métricas de ruido. El mapa ocupa mejor el viewport y separa perspectivas por pregunta: qué existe, qué falta revisar, dónde hay señales, qué observó Burp y qué conviene probar ahora.

Consulta `CHANGELOG.md`.

## v0.17.1 — Signal UX + JavaScript Surface

Refina Access Control Intelligence con filtros por estado/tipo/prioridad en el mapa, edición de estado + resultado desde la propia hipótesis visual, perspectivas claramente separadas, notificaciones para nuevas hipótesis, reducción de ruido CORS first-party y relaciones `JavaScript → Resource` (incluido cross-host). `Analizar local` ahora avisa cuando el bundle amplía superficie y destaca rutas sensibles sin convertirlas automáticamente en findings.

Consulta `CHANGELOG.md`.

## v0.17.0 — Access Control Intelligence + Rutas de investigación

Negro convierte lo aprendido en el módulo de **Access Control** en ayudas pasivas sobre tráfico que ya capturaste con Burp. No explota automáticamente ni convierte indicios en Findings: crea hipótesis trazables para revisión manual.

- **Resources → Qué merece revisión aquí**: tabla por recurso con indicio, razón, prueba sugerida, prioridad y estado.
- Señales pasivas para autorización horizontal/IDOR, campos privilegiados y mass assignment, métodos HTTP alternativos, redirects con body, discrepancias `403` proxy/backend y acciones sensibles dependientes de `Referer`.
- El check de métodos recuerda preservar la semántica: al convertir `POST`/JSON a `GET`, los parámetros equivalentes pueden necesitar ir en query string.
- **Mapa → Rutas de investigación**: prioriza caminos `evidencia → recurso/operación → hipótesis → siguiente prueba`, incluyendo hipótesis de IA ya persistidas. Son rutas para investigar, **no cadenas de explotación confirmadas**.
- Las rutas se pueden abrir desde el mapa; Negro carga el recurso, enfoca el vecindario y resalta el camino.
- Mejor contraste de líneas y resaltado especial para la ruta activa en el mapa oscuro.
- Los workspaces existentes pueden regenerar estas señales con el flujo normal de `generate-leads`; no se borra estado previo.
- El protocolo Burp ↔ Negro **no cambió**: el Burp Bridge v0.16.7 existente sigue siendo compatible y no necesita recompilarse.

Consulta `CHANGELOG.md`.

## v0.16.7 — Hotfix de compilación Burp Bridge

Corrige el helper `unescapeJson(...)` faltante en v0.16.6, que impedía compilar el JAR. No cambia el protocolo ni la lógica de Repeater. Ver `CHANGELOG.md`.

## v0.16.7 — Repeater bridge parser fix

Corrige el hand-off Negro → Burp Repeater para requests grandes: el parser regex del bridge podía lanzar `StackOverflowError` al leer `request_b64` y matar silenciosamente el poller justo después de `pending=true`. Ahora usa un parser iterativo y mantiene logs/ACK robustos. Ver `CHANGELOG.md`.


## v0.16.7 — Repeater Bridge orphan-poller fix

Corrige la causa raíz de items que quedaban en `claimed`: bridges antiguos podían seguir ejecutando su poller después de retirar el JAR. La extensión ahora detiene sus hilos al descargarse y el backend exige un id único de bridge/lease de consumidor. Tras actualizar, reinicia Burp una vez. Ver `CHANGELOG.md`.


> **Olfatea donde otros no miran.**

Negro es un workspace local de recon para Bug Bounty. El CLI ejecuta discovery/inspecciones y la Web UI organiza targets, hosts, resources, provenance, estados, notas, JavaScript y análisis asistido por IA.







## v0.16.7 — Repeater Bridge fast poll fix

Negro ahora correlaciona **cada exchange nuevo de Burp** de forma pasiva y en tiempo real: parámetros de redirección/URL en query, form y JSON; candidatos SSRF; API keys y secretos con firma; credenciales/campos sensibles devueltos por APIs; secretos en URL; CORS observado; source maps; documentación API y errores internos. Los valores sensibles se enmascaran antes de persistirlos. Las pistas crean señales accionables con provenance exacto y notificaciones persistentes/toasts.

Para targets grandes, el Mapa pasa a **progressive disclosure**: la vista inicial ya no renderiza miles de recursos. Empieza en Target → hosts relevantes/grupos, permite entrar a un host y luego a un recurso, con límites por capa. Dashboard agrega progreso de revisión para hosts/recursos, descartados separados y alertas nuevas. Ver `CHANGELOG.md`.

## v0.15.0 — UX final para piloto de bounty

Rework visual y de usabilidad: Inventario busca hosts + recursos, navegación/UI centralizadas en español y el checklist por endpoint pasa a una guía opcional cerrada por defecto y sus checks automáticos pendientes dejan de sesgar la IA. El foco queda en Burp → recursos → evidencia → hipótesis → hallazgos, sin obligar al investigador a mantener una matriz manual. Ver `CHANGELOG.md`.

## v0.14.5 — Robust Graph AI Responses + Diagnostics

`Give me ideas` ahora comprueba el estado real de Responses API antes de parsear Structured Outputs. Usa un presupuesto propio de 6000 tokens, reintenta a 9000 cuando la respuesta queda `incomplete` por límite de salida y deja logs seguros `[AI graph]` con status/usage sin exponer tráfico sensible. Ver `CHANGELOG.md`.

## v0.14.4 — Endpoint Test Coverage + Exploratory AI Retry

Cada método observado (`GET`, `POST`, `PUT`, etc.) tiene ahora una checklist persistente de pruebas recomendadas: Authorization/IDOR, acceso sin sesión, CORS, parámetros, métodos alternativos, Content-Type, CSRF, lógica de negocio, cache, rate limiting, client-side trust y checks contextuales. Los estados `pending / testing / negative / interesting / confirmed / not_applicable` quedan guardados, aparecen en el detalle del Resource y alimentan `Give me ideas` para no repetir pruebas ya descartadas. Si la primera llamada estructurada de IA devuelve 0 hipótesis, Negro ejecuta una sola segunda pasada exploratoria acotada; la estimación de costo muestra el máximo de dos llamadas. Consulta `CHANGELOG.md`.

## v0.14.3 — Offensive Hypothesis Prioritization

`Give me ideas` prioriza superficies ofensivas nuevas y backend enforcement desconocido, separa `ALTA / MEDIA / QUICK CHECK`, pone **Prueba esto ahora** antes de la explicación, convierte lógica de negocio en validaciones server-side y muestra evidencia HTTP con acciones directas a Resource/Repeater/Mapa. El cache de IA incluye versión de prompt para no reutilizar recomendaciones antiguas. Consulta `CHANGELOG.md`.

## v0.14.1 — Structured AI Output Hotfix

`Give me ideas` usa Structured Outputs con JSON Schema estricto y un parser de respaldo seguro para que una respuesta malformada del modelo no rompa el job ni deje la UI en error. Consulta `CHANGELOG.md`.

## v0.14.0 — Bug Bounty Pilot

Negro ya puede acompañar una investigación de punta a punta: menú contextual en Burp para abrir/marcar/crear Findings/adjuntar evidencia/retests, Findings reales multi-entidad, separación visual **Coverage vs Signal** y backup/restore completo del workspace. El objetivo de esta versión es empezar un piloto real de bug bounty sin perder contexto ni evidencia. Consulta `CHANGELOG.md`.

## v0.12.2 — Interactive Graph + AI Hypotheses

El mapa ahora responde de forma fiable a click/tap, mantiene drag manual, permite reordenar las perspectivas según el flujo personal del investigador y añade **🧠 Give me ideas**. La IA recibe contexto estructurado del grafo (sin cuerpos HTTP completos), propone 3–5 hipótesis investigables, las persiste sobre `leads_v2`, conecta sus evidencias al mapa y conserva estados negativos para no repetir pruebas descartadas. Consulta `CHANGELOG.md`.

## v0.11.3 — Investigation Workspace

La v0.11 convierte Resources en unidades de investigación: detalle HTTP estilo proxy con request/response, herramientas contextuales, provenance, evidencia, Findings persistentes multi-entidad y ciclo de retest. La navegación y los estados visuales se refuerzan para usar Negro como memoria operativa durante pentests y bug bounty. Consulta `CHANGELOG.md`.

## v0.10.0 — Burp Bridge + HTTP Operations

La v0.10 conecta el trabajo manual de Burp con la memoria de Negro. El tráfico observado se organiza como `Host → Resource → Operation → Exchange`, conserva métodos y evidencia, promueve JavaScript al pipeline local y permite enviar recursos desde Negro hacia Burp Repeater. También añade resúmenes visuales al terminar jobs. Consulta `CHANGELOG.md`.

## v0.9.0 — Hunter Intelligence MVP

Esta versión convierte lo aprendido en **HTB Information Gathering - Web Edition** en un pipeline de recon con memoria, policy y leads accionables. La meta no es "escanear todo": es **reducir ruido y decirte qué merece una prueba manual y por qué**.

### Nuevo pipeline

```text
DISCOVERY / HISTORY
        ↓
INVENTORY + PROVENANCE
        ↓
DNS / HTTP / CRAWL / JS
        ↓
EVIDENCE + RELATIONSHIPS
        ↓
CORRELATION ENGINE
        ↓
ACTIONABLE LEADS
        ↓
AI TRIAGE opcional
        ↓
SAFE MANUAL VALIDATION
```

### Intelligence + policy

La nueva vista **Intelligence** añade:

- perfiles `conservative`, `mercadolibre` y `lab`;
- límites de candidatos y tráfico activo por target;
- DNS infrastructure (`A/AAAA/NS/MX/SOA/TXT/SRV/PTR`);
- AXFR dirigido por nameserver;
- Smart DNS con naming observado + wildcard detection;
- Smart VHost con baseline aleatorio para reducir falsos positivos;
- Certificate Transparency intelligence (`first_seen`, `last_seen`, cert count, issuer, wildcard);
- Search Intelligence: genera pocas queries/dorks contextuales, **no automatiza búsquedas masivas**;
- Wayback como historical intelligence;
- Correlation Engine y Target AI Triage.

### HTTP intelligence por host

- redirect chain;
- fingerprinting por headers/content;
- fingerprints pasivos de WAF/CDN cuando hay evidencia;
- `robots.txt` parseado;
- selected `.well-known`: `security.txt`, `openid-configuration`, `assetlinks.json`, `change-password`, `mta-sts.txt`;
- OIDC endpoints/hosts importados con relaciones;
- crawler BFS controlado con scope estricto, `robots.txt`, sitemap XML, links, JS, documents, forms, comments, emails y hosts relacionados;
- forms se descubren, **nunca se envían automáticamente**;
- CORS probe único y explícito;
- Smart VHost permite base URL/puerto manual para labs.

### Correlation Engine — lead families

La v0.9 genera hipótesis, no findings automáticos:

- Open Redirect (parámetros/forms + JS navigation sinks);
- exposed Source Maps;
- Secrets / API keys / client config;
- OAuth/OIDC surface;
- CORS candidates;
- directory listing / exposed files surface;
- cloud storage endpoints;
- dangling DNS / Subdomain Takeover candidates;
- DOM XSS source→sink candidates;
- SSRF URL-fetch surfaces;
- IDOR/BOLA object-authorization surfaces.

Cada lead incluye:

```text
confidence
review_priority
evidence
why_interesting
next_test
confirm_if
discard_if
```

`confidence` y `review_priority` **no son severidad**. Un finding sólo existe después de validación humana con impacto.

### IA como motor de análisis, no chatbot

Negro mantiene análisis determinístico/local primero. La IA recibe sólo evidencia reducida y enmascarada.

Antes de ejecutar IA muestra:

```text
input tokens estimados
output budget
costo máximo estimado COP
costo máximo estimado USD
evidence hash / cache hit
```

Después guarda usage y costo real estimado. Target AI y JS AI usan cache por `evidence_hash`; si la misma evidencia/modelo ya fue analizada, se reutiliza y el costo de la nueva ejecución es COP $0.

La salida Target AI está obligada a explicar en español:

- qué evidencia sostiene el lead;
- por qué importa;
- una prueba manual de bajo impacto;
- qué resultado lo confirma;
- qué resultado lo descarta;
- qué señales son ruido o bajo valor.

### Seguridad operativa

Negro v0.9 **no** hace por defecto:

- credential brute force;
- wordlists masivas DNS/VHost en bounty;
- port sweep;
- Nikto/full vulnerability scanning;
- submit automático de forms;
- uso automático de tokens/keys;
- claim automático de recursos dangling;
- explotación destructiva.

El perfil `mercadolibre` impone límites bajos para evitar trasladar al bounty real la agresividad de un lab. Revisa siempre la policy vigente del programa.

### Comandos nuevos

```bash
negro TARGET -w WORKSPACE policy --profile conservative|mercadolibre|lab
negro TARGET -w WORKSPACE dns-recon
negro TARGET -w WORKSPACE axfr
negro TARGET -w WORKSPACE smart-candidates --limit 20
negro TARGET -w WORKSPACE active-dns
negro TARGET -w WORKSPACE vhost http://TARGET:PORT/
negro TARGET -w WORKSPACE web-recon HOST
negro TARGET -w WORKSPACE crawl HOST --max-urls 120 --max-depth 2
negro TARGET -w WORKSPACE cors-check HOST --url https://HOST/path
negro TARGET -w WORKSPACE historical
negro TARGET -w WORKSPACE search-intel
negro TARGET -w WORKSPACE generate-leads
negro TARGET -w WORKSPACE ai-target-estimate
negro TARGET -w WORKSPACE ai-target
```

### Smoke test offline

```bash
PYTHONPATH=. python tests/smoke_test.py
```

No toca Internet ni consume OpenAI.

---

## v0.8.1 — build completo y endurecido

Incluye todas las mejoras funcionales de v0.8.0 y corrige el launcher del `.venv`. El instalador valida estructura, dependencias, Python, templates Jinja y JavaScript antes de crear `/usr/local/bin/negro`.

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

## v0.14.3 — AI Cache Reliability Hotfix

`Give me ideas` ya no puede quedar atrapado reutilizando una respuesta malformada. Los resultados no estructurados se marcan como inválidos, no se cachean como `done`, y la UI permite reintentar. También se exige Structured Outputs real en vez de caer silenciosamente a texto libre. Consulta `CHANGELOG.md`.
