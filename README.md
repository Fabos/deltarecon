# Negro Recon 🐕 — v0.22.0

Negro es una capa local de inteligencia, memoria y organización encima de Burp Suite. No pretende ser un vulnerability scanner ni hacer el hacking por el usuario.

## Modelo central

`Rule → Signal → Hipótesis IA → Investigación humana`

- **Rules**: conocimiento determinístico configurable.
- **Signals**: observaciones automáticas con procedencia exacta; no son vulnerabilidades.
- **Hipótesis IA**: aparecen únicamente cuando el usuario ejecuta IA; separan hechos, inferencia, incógnitas y próxima prueba.
- **Investigaciones**: las crea el usuario al promover una hipótesis que considera valiosa.
- **Estados humanos / Findings**: siguen bajo control del hacker.

## v0.22.0 — búsqueda parcial + Parameter Explorer

### Buscar

La búsqueda libre ahora es **parcial por defecto** para fragmentos de 3 o más caracteres. No necesitas conocer el valor completo:

```text
1223              # encuentra 3001112233
AIza              # encuentra una Google API key más larga
response:owner    # fragmento dentro de responses
param:tenant      # fragmento dentro de parámetros
```

Los filtros estructurados siguen disponibles: `host:`, `method:`, `status:`, `state:`, `signal:`, `param:`, `cookie:`, `header:`, `body:`, `request:`, `response:`, `path:`, `type:` y `contains:`. Se pueden combinar. La ayuda integrada en **Buscar** resume la sintaxis y ejemplos sin convertirla en una guía de hacking.

Al actualizar desde v0.21, pulsa una vez **Actualizar índice** para construir el índice de fragmentos sobre el historial ya guardado. El tráfico nuevo se indexa automáticamente.

### Parameter Explorer

La nueva pestaña **Parámetros** agrega cuatro herramientas determinísticas:

- **Parameter Explorer**: agrupa nombres observados en query, path, JSON/form de request y JSON de response.
- **Follow Value**: sigue el mismo valor exacto por hash entre exchanges, superficies, recursos y hosts. Los valores sensibles permanecen enmascarados.
- **Find Related**: propone exchanges cercanos por valores/nombres compartidos, mismo recurso o mismo host y explica cada relación. El score es cercanía, no severidad.
- **Smart Diff**: compara dos exchanges y prioriza diferencias de negocio como IDs, ownership, roles, estados, precios, cupones y tenant. Headers sensibles se muestran enmascarados.

Para workspaces viejos pulsa una vez **Parámetros → Analizar historial** para extraer parámetros también de capturas anteriores.

El mapa mantiene las correcciones de v0.21: inventario observable antes de IA y perspectiva Burp independiente de las hipótesis.

## Arranque

```bash
chmod +x negro.py install-web.sh burp-extension/build-extension.sh
./install-web.sh
negro web
```

## Extensión Burp

**No necesitas actualizar la extensión al pasar de Negro v0.20.3 a v0.22.0.** La aplicación v0.22.0 sigue siendo compatible con **Negro Burp Bridge v0.20.3**.

Si necesitas recompilarla:

```bash
cd burp-extension
./build-extension.sh
```

Carga `build/libs/negro-burp-bridge-0.20.3.jar` desde Burp → Extensions.

Consulta `METHODOLOGY.md` para el modelo mental, `ROADMAP.md` para las siguientes fases y `CHANGELOG.md` para el historial consolidado.
