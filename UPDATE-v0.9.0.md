# Upgrade a Negro v0.9.0

La migración de SQLite es aditiva: conserva hosts/resources/notes/inspections de v0.8.x y crea `relationships`, `leads_v2` y `ai_tasks`.

## Recomendado

Haz copia del repo antes de sobrescribir código. Los workspaces (`~/recon/...`) y configuración (`~/.config/negro/`) viven fuera del repo y no deben borrarse.

```bash
cd ~/Documents/recon/tools
cp -a deltarecon deltarecon.backup-v081

# Extrae el ZIP en /tmp y copia su contenido sobre el checkout actual:
unzip ~/Downloads/negro-recon-v0.9.0-full.zip -d /tmp/negro-v090
cp -a /tmp/negro-v090/negro-recon-v0.9.0/. ~/Documents/recon/tools/deltarecon/

cd ~/Documents/recon/tools/deltarecon
chmod +x negro.py negro_hunter.py install-web.sh
./install-web.sh
PYTHONPATH=. python tests/smoke_test.py
negro web
```

No uses `rsync --delete` sobre tu checkout si quieres conservar `.git`.

## Primer perfil

Para HTB/lab:

```bash
negro target.htb -w ~/recon/target policy --profile lab
```

Para Mercado Libre:

```bash
negro mercadolibre.com -w ~/Documents/recon/mercadolibre policy --profile mercadolibre
```

La v0.9 no cambia automáticamente tu perfil existente a `lab`; el default es conservador.
