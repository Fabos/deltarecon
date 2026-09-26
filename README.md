# bb-recon v0.1

Orquestador sencillo de enumeración pasiva para Bug Bounty.

Flujo:

RAW -> NORMALIZED -> DELTA -> INVENTORY

Implementado en v0.1:
- crt.sh
- Subfinder

No hace HTTP probing, port scanning, fuzzing ni explotación.

## Usar tu workspace actual

```bash
python3 bb-recon.py mercadolibre.com -w ~/Documents/recon/mercadolibre run --sources crtsh subfinder
```

Ver estado:

```bash
python3 bb-recon.py mercadolibre.com -w ~/Documents/recon/mercadolibre status
```

Ver sólo lo nuevo que aportó Subfinder:

```bash
python3 bb-recon.py mercadolibre.com -w ~/Documents/recon/mercadolibre new subfinder
```

## Workspace nuevo

```bash
python3 bb-recon.py example.com init
python3 bb-recon.py example.com run
```

Por defecto crea:

```text
~/recon/example.com/
├── raw/
├── normalized/
├── delta/
├── inventory/
└── notes/
```

Próximas fuentes previstas:
- Amass passive
- GAU / Wayback
- URLScan
- passive DNS
- TLS SANs
- GitHub/code search
