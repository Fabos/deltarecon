# Negro Recon — Methodology v0.5

Negro separa **descubrimiento** de **decisión**. Una herramienta puede encontrar miles de nombres; la metodología busca saber qué ya se revisó, qué quedó abierto y por qué.

## Flujo principal

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

### 1. Discover

Fuentes pasivas/históricas encuentran hosts y URLs. Cada resultado conserva su provenance.

### 2. Associate

Las URLs se vinculan al host correspondiente:

```text
api.example.com
├── /oauth/
├── /tracks
└── /errorux/config
```

Si varias fuentes observan el mismo recurso, Negro mantiene un solo nodo con múltiples sources.

### 3. Inspect

Cuando un activo merece atención se ejecuta Basic Inspect, **dirigido a un host seleccionado**:

- `A`
- `AAAA`
- `CNAME`
- TLS/SAN
- HTTP `/`
- HTTPS `/`

La inspección no marca automáticamente el activo como revisado.

### 4. Analyze

Con la información básica preguntamos, en orden:

```text
¿Quién resuelve este hostname?
¿Hay proveedor externo / SaaS?
¿El TLS corresponde al hostname?
¿Qué responde HTTP y HTTPS?
¿Existe una redirección?
¿Qué tecnología o producto parece ser?
¿Qué resources ya conocemos por fuentes históricas?
¿Tenemos una hipótesis concreta que justifique profundizar?
```

Evitar saltar directamente a fuzzing o scanning masivo. Si OTX/Wayback ya entregaron una ruta concreta, validar primero esa evidencia.

### 5. Classify

**Review state** describe cuánto trabajo humano se ha hecho:

```text
pending
in_progress
reviewed
```

**Classification** describe la conclusión actual:

```text
unknown
informational
lead
discarded
finding
```

**Priority** sólo ordena nuestro trabajo:

```text
none
low
medium
high
```

Prioridad no significa severidad.

### 6. Remember

Agregar una nota cuando una decisión no sea obvia. Una buena nota responde:

- qué vimos;
- qué comprobamos;
- qué falta;
- por qué lo dejamos abierto o cerrado.

Ejemplo:

```text
Revisado DNS/CNAME/TLS/HTTP y ruta histórica /wf.
Certificado no corresponde al hostname, pero no se encontró control externo
ni impacto adicional. Cerrar como discarded.
```

## Árbol

El árbol no es una lista de findings. Es un mapa de superficie:

```text
target
└── host
    ├── resource
    │   └── sources
    ├── inspections
    ├── notes
    ├── state
    └── priority
```

## Separación de fases

```text
Passive discovery    automatización razonable según reglas del programa
Active inspection    sólo al seleccionar un host
Deep enumeration     decisión explícita del investigador
Exploitation         manual y sólo cuando scope/reglas lo permiten
```

## Regla de evidencia

```text
ASSET ≠ LEAD ≠ FINDING
```

- hostname interesante → asset;
- señal que justifica seguir → lead;
- impacto reproducible → finding.

Un CNAME externo, `admin` en una ruta, un certificado inválido o código fuente accesible no son findings por sí solos.
