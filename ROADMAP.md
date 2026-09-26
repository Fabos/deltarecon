# Negro Recon — Learning Roadmap

Regla del proyecto:

> **Aprender manualmente -> entender qué aporta -> automatizar.**

## Implementado

### 01. crt.sh
Estado: AUTOMATIZADO

Conceptos:
- Certificate Transparency
- SANs
- wildcard certificates
- normalización
- deduplicación

### 02. Subfinder
Estado: AUTOMATIZADO

Conceptos:
- passive sources
- multi-source aggregation
- delta frente a crt.sh
- cobertura vs señal

## Siguiente

### 03. Amass passive
Estado: APRENDER MANUALMENTE

Antes de automatizar debemos entender:
- qué fuentes consulta;
- qué diferencia aporta frente a Subfinder;
- qué significa `-passive`;
- cómo medir hosts realmente nuevos;
- cuánto ruido agrega.

Después se integra a Negro como fuente #3.

## Pendiente

04. GAU
05. Wayback / CDX
06. URLScan
07. Passive DNS
08. TLS SAN pivots
09. GitHub / public code search

Cada módulo debe demostrar que aporta información distinta antes de automatizarse.
