# Negro Recon — Methodology v0.6

Negro separa **descubrimiento**, **observación** y **decisión humana**.

## Flujo

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

## 1. Discover

Fuentes pasivas/históricas descubren hosts y URLs. Cada resultado conserva su provenance.

## 2. Associate

Cada URL se vincula al hostname correspondiente:

```text
api.example.com
├── /oauth/
├── /tracks
└── /errorux/config
```

Una URL observada por varias fuentes sigue siendo un solo resource con múltiples sources.

## 3. Inspect

Sobre un **host seleccionado explícitamente**:

- DNS A/AAAA/CNAME;
- TLS :443 y SAN;
- HTTP `/`;
- HTTPS `/`.

La inspección no cambia automáticamente review/classification.

## 4. Analyze — checklist inicial

Cuando un activo nos parece sospechoso seguimos el mismo orden:

```text
1. Provenance
   ¿quién lo encontró y cuándo?

2. DNS
   A / AAAA / CNAME
   ¿propio, CDN, SaaS, legacy?

3. TLS
   ¿certificado válido para el hostname?
   ¿qué SANs revela?
   ¿qué issuer/provider aparece?

4. HTTP / HTTPS
   status
   Server
   Location
   Content-Type
   comportamiento HTTP vs HTTPS

5. Recursos conocidos
   ¿OTX/Wayback/URLScan ya conocen rutas concretas?

6. Tecnología / integración
   ¿qué aplicación/proveedor parece ser?

7. Hipótesis
   ¿qué señal concreta justifica profundizar?
```

No saltar a fuzzing masivo sólo porque un hostname sea raro. Primero usar la evidencia ya disponible.

## 5. Classify

### Review state

```text
pending
in_progress
reviewed
```

### Classification

```text
unknown
informational
lead
discarded
finding
```

### Priority

```text
none
low
medium
high
```

Prioridad organiza nuestro tiempo; no equivale a severidad.

## 6. Remember

Una nota útil responde:

- qué vimos;
- qué validamos;
- qué falta;
- por qué queda abierto/cerrado.

Ejemplo:

```text
Revisado DNS/CNAME/TLS/HTTP y ruta histórica /wf.
Certificado no corresponde al hostname, pero no se encontró control externo
ni impacto adicional. Cerrar como discarded.
```

## Multi-target

Cada programa vive aislado:

```text
Negro Web
├── mercadolibre.com
│   └── workspace + negro.db
├── target-b.com
│   └── workspace + negro.db
└── target-c.net
    └── workspace + negro.db
```

Cambiar target en la UI nunca mezcla inventarios.

## Separación de fases

```text
Passive discovery    automatización razonable según las reglas
Active inspection    host seleccionado explícitamente
Deep enumeration     decisión explícita del investigador
Exploitation         manual y dentro de scope/reglas
```

## Regla de evidencia

```text
ASSET ≠ LEAD ≠ FINDING
```

Un CNAME externo, una ruta `admin`, un certificado inválido o código fuente accesible son señales; no findings por sí mismos.
