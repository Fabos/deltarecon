# Negro Recon — Roadmap

Regla:

> **Aprender manualmente -> entender -> automatizar.**

## v0.3 implementado

- crt.sh
- Subfinder
- Amass passive
- GAU por provider
- URLs -> host -> resource
- SQLite (`negro.db`)
- review state
- classification
- notes
- árbol de assets
- cola de pendientes
- leads/findings
- migración conservadora desde v0.2

## Próximo aprendizaje manual

- URLScan directo
- Passive DNS
- TLS SAN pivots
- GitHub/public code search

## Más adelante

Importadores dirigidos para resultados de:

- content discovery
- crawling
- JS endpoints

La herramienta no debe lanzar fuzzing masivo por defecto. Primero aprenderemos cada técnica y respetaremos las reglas específicas de cada programa.

## Implementado en v0.4

### Basic host triage

Estado: AUTOMATIZADO / DIRIGIDO

Un host a la vez:
- DNS A / AAAA / CNAME
- TLS certificate metadata
- HTTP / HTTPS status and selected headers
- snapshot JSON + SQLite history

No convierte automáticamente un activo en `reviewed`; la clasificación sigue siendo humana.
