# Negro — Metodología de triage manual

Cuando Negro descubre algo “raro”, no saltamos directamente a explotación.

La pregunta inicial es:

> **¿Qué es este activo, cómo está conectado y qué evidencia tengo de impacto?**

## Flujo

```text
DISCOVERY
   ↓
PROVENANCE
   ↓
DNS
   ↓
TLS
   ↓
HTTP
   ↓
TECH / PROVIDER
   ↓
KNOWN RESOURCES
   ↓
PUBLIC ARTIFACTS
   ↓
CLASSIFY
```

## 1. Provenance

Antes de tocar el host, registra de dónde salió:

```text
crt.sh
Subfinder
Amass
GAU/OTX
GAU/URLScan
Wayback
etc.
```

Un hostname histórico no tiene el mismo significado que uno observado hoy en DNS.

## 2. DNS

Pruebas pequeñas y dirigidas:

```bash
dig +short HOST A
dig +short HOST AAAA
dig +short HOST CNAME
```

Preguntas:

- ¿resuelve?
- ¿apunta a infraestructura propia o a SaaS?
- ¿el CNAME parece activo, legacy o potencialmente dangling?
- ¿cambian las IPs?

Un CNAME externo es un **lead**, no un takeover.

## 3. TLS

```bash
openssl s_client \
-connect HOST:443 \
-servername HOST </dev/null 2>/dev/null \
| openssl x509 -noout \
-subject -issuer -dates -ext subjectAltName
```

Revisar:

- Subject / SAN
- issuer
- expiración
- si el hostname está cubierto

`NET::ERR_CERT_COMMON_NAME_INVALID` significa que el certificado presentado no cubre el hostname solicitado.

Eso por sí solo suele ser una misconfiguración operativa, no una vulnerabilidad de seguridad demostrada.

## 4. HTTP y HTTPS

No necesitas pelear con el navegador si TLS está roto.

```bash
curl -v --max-time 15 http://HOST/
curl -vkI --max-time 15 https://HOST/
curl -skL --max-time 15 https://HOST/ | head -n 80
```

`-k` sólo le dice a curl que continúe aunque el certificado no valide. Sirve para inspección controlada del servicio.

Revisar:

- status code
- redirects
- `Server`
- `Location`
- cookies
- HSTS
- title/body/error del proveedor

Si Chrome no ofrece “continuar”, puede ser por HSTS u otra política de validación estricta. Para recon no hace falta saltársela en el navegador: usa curl/OpenSSL.

## 5. Tecnología / proveedor

Identifica qué hay detrás:

```text
CloudFront
Google
Qualtrics
Nexus
SendGrid
GitHub Pages
S3
etc.
```

Una página de error del proveedor puede ser más valiosa que una página bonita porque ayuda a distinguir:

```text
activo configurado
vs
binding roto
vs
servicio desaparecido
```

## 6. Recursos ya descubiertos

Si GAU/OTX encontró una ruta específica, prueba **esa ruta exacta** antes de pensar en fuzzing.

Ejemplo:

```bash
curl -vk --max-time 15 https://HOST/wf
curl -v  --max-time 15 http://HOST/wf
```

Esto mantiene el triage dirigido y evita convertir cada lead en un escaneo masivo.

## 7. Artefactos públicos de bajo impacto

Si la web carga normalmente, puedes revisar recursos publicados por la propia aplicación:

```text
robots.txt
sitemap.xml
JS referenciado por la página
source maps referenciados
configuración frontend pública
```

No asumas que `/config` o un source map es sensible; revisa el contenido y busca impacto real.

## 8. Auth / boundaries

Si aparece login/SSO:

- identifica el proveedor;
- observa el flujo;
- usa únicamente cuentas propias o test autorizadas;
- no hagas brute force;
- no pruebes usuarios ajenos.

## 9. Clasificación Negro

### discarded

Revisado y sin interés de seguridad.

### informational

Da contexto útil, nombres internos, arquitectura o comportamiento, pero no demuestra impacto.

### lead

Hay una hipótesis concreta que merece otra prueba dirigida.

### finding

Existe impacto de seguridad reproducible y demostrable dentro del scope.

## 10. Nota mínima recomendada

Cada asset revisado debería terminar con una nota de una o dos líneas:

```text
Qué vi:
Qué probé:
Qué concluyo:
Qué falta (si aplica):
```

Ejemplo:

```text
Qué vi: certificado no cubre url8202.mercadolibre.com.
Qué probé: DNS, TLS, HTTP/HTTPS y ruta histórica /wf.
Conclusión: pendiente; parece integración legacy.
Falta: identificar proveedor y comportamiento de /wf.
```


## Triage básico dirigido de un activo

Cuando un hostname pasa de inventario a activo interesante, no se empieza con fuzzing. Primero se recoge contexto mínimo y reproducible.

```text
PROVENANCE
   ↓
DNS
   ↓
TLS
   ↓
HTTP / HTTPS
   ↓
RECURSOS YA CONOCIDOS
   ↓
DECISIÓN MANUAL
```

### 1. Provenance

¿De dónde salió el host? `crt.sh`, Subfinder, Amass, OTX, URLScan, etc.

### 2. DNS

Revisar como mínimo:

```text
A
AAAA
CNAME
```

Objetivo: saber si existe, a dónde resuelve y si delega en un proveedor externo.

### 3. TLS

En `:443` observar:

```text
subject
issuer
notBefore / notAfter
SAN
errores de handshake
```

Un certificado inválido es una observación, no una vulnerabilidad por sí sola.

### 4. HTTP / HTTPS

Hacer una única petición a `/` por esquema y registrar:

```text
status
Server
Location
Content-Type
Via
X-Powered-By
```

No seguir redirecciones automáticamente: el destino puede salir del scope y además la redirección es evidencia útil.

### 5. Recursos conocidos

Si una fuente histórica ya descubrió `/wf`, `/oauth/`, `/config`, etc., revisar primero esas rutas conocidas antes de pensar en content discovery.

### 6. Decisión

La inspección técnica no equivale a revisión completa.

Estados de revisión:

```text
pending
reviewed
```

Clasificación:

```text
unknown
informational
lead
discarded
finding
```

Ejemplos:

```text
pending + lead       = interesante; falta análisis
reviewed + discarded = revisado y cerrado
reviewed + informational = aporta contexto, sin vulnerabilidad
reviewed + finding   = impacto demostrado
```

Negro conserva notas e historial para evitar investigar dos veces el mismo activo.
