# Negro Recon 🐕 — v0.23.0

Negro es una capa local de inteligencia, memoria y organización encima de Burp Suite. No pretende ser un vulnerability scanner ni hacer el hacking por el usuario.

## Modelo central

`Rule → Signal → Hipótesis IA → Investigación humana`

- **Rules**: conocimiento determinístico configurable.
- **Signals**: observaciones automáticas con procedencia exacta; no son vulnerabilidades.
- **Hipótesis IA**: aparecen únicamente cuando el usuario ejecuta IA; separan hechos, inferencia, incógnitas y próxima prueba.
- **Investigaciones**: las crea el usuario al promover una hipótesis que considera valiosa.
- **Estados humanos / Findings**: siguen bajo control del hacker.

## v0.23.0 — Search unificado + Identity Contexts

### Buscar es la entrada principal

Ya no necesitas decidir primero si algo es "búsqueda" o "parámetro". Escribe lo que recuerdas en **Buscar**:

```text
4101
ownerId
1223
AIza
host:api.example.com method:GET ownerId
```

El texto libre sigue siendo parcial con FTS5 trigram. Cuando la consulta también coincide con una observación estructurada, Search muestra una tarjeta **Valor/Parámetro** con acciones directas: `HTTP`, `Follow Value`, `Explorar parámetro`, `Find Related`, `Smart Diff` y `Usar para identidad`.

**Parameter Explorer** sigue existiendo, pero como drill-down técnico: sirve para estudiar un nombre de parámetro después de encontrarlo, no como un segundo buscador. También se corrigió el contador de `valores distintos` que en v0.22 podía renderizar el método interno de un `dict`.

### Identity Contexts

La nueva vista **Identidades** separa tres cosas:

- **Identity**: la cuenta/persona que tú conoces, por ejemplo `Buyer A`.
- **Context**: rol/tenant/contexto humano, por ejemplo `Buyer · Colombia`.
- **Auth Material**: cookie, Bearer o sesión concreta que puede rotar.

La asignación inicial siempre es humana. Desde un resultado HTTP puedes usar **Asignar identidad**. Negro aprende fingerprints de cookies/tokens sin mostrarlos completos. Si el Bearer es JWT, puede aprender claims estables como `sub`, `userId` o `accountId`. Cuando un token rota pero conserva ese claim estable, Negro puede resolver la nueva sesión hacia la misma identidad.

También puedes convertir una observación estable (por ejemplo `userId=101` en `/me`) en un **resolver de identidad** desde Search. Roles compartidos como `role=buyer` no deben usarse como identidad.

Para tráfico histórico usa **Identidades → Resolver historial** después de haber enseñado al menos una identidad/resolver.

### Authorization Matrix

**Identidades → Authorization Matrix** compara únicamente lo que Burp observó bajo cada identidad. Una celda muestra conteos/status reales; `— No observado` significa exactamente eso y nunca se interpreta como permitido o denegado. Las rutas con IDs se agrupan visualmente como `{id}` para facilitar la comparación, manteniendo ejemplos de exchanges concretos.

## Arranque

```bash
chmod +x negro.py install-web.sh burp-extension/build-extension.sh
./install-web.sh
negro web
```

## Extensión Burp

**No necesitas actualizar la extensión para v0.23.0.** La aplicación sigue siendo compatible con **Negro Burp Bridge v0.20.3**.

Si necesitas recompilarla:

```bash
cd burp-extension
./build-extension.sh
```

Carga `build/libs/negro-burp-bridge-0.20.3.jar` desde Burp → Extensions.

Consulta `METHODOLOGY.md` para el modelo mental, `ROADMAP.md` para las siguientes fases y `CHANGELOG.md` para el historial consolidado.
