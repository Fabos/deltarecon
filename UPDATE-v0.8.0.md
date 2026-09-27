# Actualización a Negro v0.8.0

## Antes de reemplazar archivos

```bash
cd ~/Documents/recon/tools/deltarecon
git add .
git commit -m "Backup before Negro v0.8.0"
```

## Reemplazar archivos y reinstalar entorno/launcher

```bash
chmod +x negro.py install-web.sh
./install-web.sh
```

El instalador reutiliza `.venv`, verifica dependencias y reemplaza de forma segura cualquier launcher/symlink viejo de `/usr/local/bin/negro` por un wrapper que siempre usa:

```text
<repo>/.venv/bin/python <repo>/negro.py
```

## Verificación rápida

```bash
which negro
cat /usr/local/bin/negro
negro --help
```

Al ejecutar `negro web`, el proceso debe usar el Python de `.venv`.

## Workspaces existentes

La migración de SQLite es conservadora: añade campos de análisis de Source Map sin borrar hosts, resources, estados, notas ni análisis previos.

Un `.map` descargado por v0.7.x puede reutilizarse localmente al estimar/ejecutar IA. Para mostrar todas las métricas nuevas en la tarjeta Source Map, también puedes pulsar **Reprocesar Source Map**.
