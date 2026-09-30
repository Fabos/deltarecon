# Negro Recon — Metodología v0.19.2

## Principio

```text
DISCOVER → ASSOCIATE → INSPECT → CORRELATE → LEAD → VALIDATE → FINDING / DISCARDED
```

Negro separa **evidencia**, **hipótesis** e **impacto demostrado**. Nunca convierte una key, un source map, un parámetro `redirect` o un CNAME externo en vulnerabilidad sólo por existir.


## Knowledge Base de detectores

Negro no trata sus detectores como una caja negra. Cada señal debe poder responder tres preguntas: **qué observó**, **qué regla coincidió** y **qué prueba manual falta para demostrar impacto**.

Las reglas se resuelven en tres capas:

```text
Negro built-in
      ↓
Biblioteca personal del investigador
      ↓
Excepciones y reglas del proyecto
```

La biblioteca personal conserva vocabulario aprendido entre proyectos (`memberId`, `beneficiaryId`, `accessLevel`, etc.). Un proyecto puede añadir términos propios o excluir uno ruidoso sin borrarlo de la biblioteca global. Las hipótesis persisten `rule_match` para que el investigador pueda volver a la regla exacta que originó la señal.

El resultado de una prueba **no modifica automáticamente la biblioteca**. Los falsos positivos y hallazgos sirven para decidir manualmente qué regla conservar, excluir o mover entre capas. Así Negro aprende contigo sin convertir heurísticas locales en conocimiento global sin revisión.


## Estado de investigación: Coverage vs Signal

Negro registra dos dimensiones independientes:

- **Coverage**: `untested → testing → tested` describe cuánto se ha revisado.
- **Signal**: `normal → interesting → finding` describe qué tan importante es lo observado.

Un endpoint puede ser `testing + interesting`, `tested + normal` o `tested + finding`. Un Finding es una entidad persistente relacionada con los assets y la evidencia; el Host/Resource no deja de ser un asset.

Retests posteriores se registran sobre el Finding y pueden enlazar el HTTP Exchange exacto usado como evidencia.

## 1. Policy antes de tráfico

Cada target tiene un perfil:

- `conservative`: bounty general, bajo volumen;
- `mercadolibre`: límites aún más estrictos para un programa que prohíbe scans automatizados masivos;
- `lab`: HTB/labs explícitamente autorizados para enumeración activa.

La policy limita Active DNS, VHost discovery y crawling. Los forms nunca se envían automáticamente.

## 2. Discovery / history

Pasivo primero:

- crt.sh / CT intelligence;
- Subfinder / Amass passive;
- GAU / Wayback / Common Crawl / OTX / URLScan;
- Wayback CDX directo;
- URLScan directo;
- SecurityTrails opcional;
- GitHub public code search opcional;
- Search Intelligence como query generator.

Dirigido después:

- DNS infrastructure;
- reverse PTR;
- TLS SAN pivot;
- AXFR por NS;
- Smart DNS candidates + wildcard detection;
- Smart VHost + random baseline.

## 3. Host → HTTP intelligence

Sobre un host seleccionado:

```text
Basic Inspect
  A / AAAA / CNAME
  TLS
  HTTP / HTTPS

Web Recon
  redirect chain
  fingerprints
  robots.txt
  selected .well-known
  forms/comments/meta
```

Fingerprinting conserva `technology + category + confidence + evidence`.

OIDC Discovery importa `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri` y hosts relacionados. `assetlinks.json` conserva relación con paquetes Android.

## 4. Crawling controlado

BFS, bounded y same-scope:

- max URLs/depth por policy;
- respeta `robots.txt` y `Crawl-delay`;
- lee sitemaps XML;
- no sigue externos;
- no envía forms;
- no usa POST/PUT/DELETE;
- dedup/canonicalización de URLs.

Extrae:

- pages/links;
- JS;
- documents/archives;
- forms + fields;
- HTML comments;
- emails;
- external relationships;
- nuevos hosts in-scope;
- directory listing.

## 5. JavaScript / Source Maps

Determinístico primero:

```text
JS → hash → URLs/routes/WebSockets → sourceMappingURL → secrets/config → code-flow contexts
```

Source Maps:

- prueba múltiples candidatos;
- tolera inline Base64 sin padding;
- separa application / node_modules / webpack runtime;
- analiza `sourcesContent` de aplicación;
- enmascara candidatos sensibles antes de IA.

## 6. Historical intelligence

Wayback no es sólo `urls.txt`:

- first/last capture;
- count/status/MIME;
- historical-only vs observado por otras fuentes;
- contexto para legacy APIs, endpoints eliminados y JS antiguo.

CT añade first/last certificate sighting, cert count, issuers y wildcard indicator.

## 7. Correlation Engine

El motor une múltiples fuentes antes de pedir atención humana.

Ejemplo:

```text
crawler: /login?next=
JS: location.search → location.assign()
Wayback: endpoint histórico
OIDC: auth surface
         ↓
Open Redirect lead
confidence HIGH / review_priority HIGH
```

Cada lead debe responder:

1. ¿Qué evidencia existe?
2. ¿Por qué puede importar?
3. ¿Qué única prueba manual de bajo impacto hago?
4. ¿Qué confirma la hipótesis?
5. ¿Qué la descarta?

## 8. Lead families

Primera generación:

- Open Redirect;
- Source Map exposure;
- Secrets / API keys / client config;
- OAuth/OIDC surface;
- CORS;
- directory listing;
- cloud storage;
- Subdomain Takeover candidate.

Heurísticas adicionales:

- DOM XSS source→sink;
- SSRF URL-fetch surface;
- IDOR/BOLA object surface.

Estas últimas son **superficies de revisión**, no explotación automática.

## 9. IA

La IA no reemplaza parsers/regex/DNS/HTTP. Entra cuando hay que comprender/correlacionar mucho contexto.

```text
local deterministic filter
        ↓
small evidence payload
        ↓
AI triage / deep analysis
```

Requisitos:

- salida en español;
- términos técnicos útiles en inglés;
- no inventar endpoint/impacto;
- costo estimado COP/USD antes;
- usage/costo real después;
- cache por evidence hash/model;
- `why / next_test / confirm_if / discard_if`.

## 10. Regla de oro

```text
DISCOVERY != CONFIRMATION
CONFIRMATION != VULNERABILITY
VULNERABILITY != IMPACT UNTIL DEMONSTRATED
```

## Recalcular no significa volver a escanear

Cuando cambian reglas o aparece nuevo conocimiento, `Recalcular inteligencia` vuelve a ejecutar los motores locales sobre la evidencia persistida. Una hipótesis tiene dos dimensiones distintas:

- **estado humano**: candidata, en prueba, interesante, negativa, confirmada, etc.;
- **vigencia de regla**: si la evidencia todavía coincide con la Knowledge Base actual.

Si deja de coincidir, Negro no borra notas ni decisiones humanas: la marca como histórica/no vigente y la retira del mapa/rutas activas. Si una regla futura vuelve a justificarla, se reactiva usando la misma hipótesis. La recalculación no hace requests al target ni llamadas a IA.
