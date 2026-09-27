# Negro Recon v0.8.1 — instalación limpia

Este paquete es **completo**. No depende de archivos de versiones anteriores.

## Instalación recomendada

```bash
cd ~/Documents/recon/tools
rm -rf deltarecon
git clone https://github.com/Fabos/deltarecon.git
cd deltarecon
```

Copia **todo el contenido** de este ZIP sobre el checkout, reemplazando archivos. Luego:

```bash
chmod +x install-web.sh
./install-web.sh
negro web
```

`install-web.sh` falla antes de modificar el launcher si falta cualquier archivo crítico de `web/`, compila los módulos Python y carga todos los templates Jinja. El launcher generado usa siempre el `.venv` de este checkout.
