# Negro Recon 🐕 — v0.23.1

Negro es una capa local de inteligencia, memoria y organización encima de Burp Suite. No pretende ser un vulnerability scanner ni hacer el hacking por el usuario.

## Modelo central

`Rule → Signal → Hipótesis IA → Investigación humana`

- **Rules**: conocimiento determinístico configurable.
- **Signals**: observaciones automáticas con procedencia exacta; no son vulnerabilidades.
- **Hipótesis IA**: aparecen únicamente cuando el usuario ejecuta IA; separan hechos, inferencia, incógnitas y próxima prueba.
- **Investigaciones**: las crea el usuario al promover una hipótesis que considera valiosa.
- **Estados humanos / Findings**: siguen bajo control del hacker.

## v0.23.1 — Identity UX + valores locales completos

### Buscar es la entrada principal

Ya no necesitas decidir primero si algo es "búsqueda" o "parámetro". Escribe lo que recuerdas en **Buscar**:

```text
4101
ownerId
1223
AIza
host:api.example.com method:GET ownerId
```

El texto libre sigue siendo parcial con FTS5 trigram. Cuando la consulta también coincide con una observación estructurada, Search muestra una tarjeta **Valor/Parámetro** con acciones directas: `HTTP`, `Follow Value`, `Explorar parámetro`, `Find Related`, `Smart Diff` y `Usar para identidad`. En workspaces viejos usa una vez **Buscar → Actualizar datos**; ahora ese botón reconstruye tanto búsqueda como parámetros/valores históricos.

**Parameter Explorer** sigue existiendo, pero como drill-down técnico: sirve para estudiar un nombre de parámetro después de encontrarlo, no como un segundo buscador. También se corrigió el contador de `valores distintos` que en v0.22 podía renderizar el método interno de un `dict`.

### Identity Contexts

La regla mental es simple:

- **Identity**: la cuenta estable que tú conoces (`Buyer A`, `Buyer B`, `Seller A`).
- **Context**: rol/tenant opcional de esa cuenta (`buyer`, `seller`, `store-123`).
- **Auth Material**: la cookie, Bearer o JWT exacto observado para esa cuenta.
- **Resolver**: un valor estable que ayuda a reconocerla después (`jwt:sub=101`, `userId=101`, `accountId=...`).

No se asigna una **ruta** a una identidad. Se asigna un **exchange concreto**: por ejemplo, el `GET /me` que viste con la sesión de Buyer A. Antes de asignarlo, Negro muestra el request/response exacto, parámetros observados y auth material. Después de guardar, la página de la identidad muestra el exchange exacto asociado y qué credenciales/resolvers aprendió.

Negro es local-first. Desde v0.23.1 conserva también los valores completos observados (`value_raw`, `raw_value`) para facilitar el bounty. Los hashes/fingerprints se mantienen para correlación eficiente. Algunos previews compactos pueden seguir enmascarados, pero el detalle conserva el valor exacto.

Si el Bearer es JWT, Negro puede aprender claims estables como `sub`, `userId` o `accountId`. Si el token rota pero conserva ese claim, una nueva sesión puede resolverse hacia la misma Identity y el nuevo token se aprende como Auth Material adicional.

Un resolver de parámetro se crea solo cuando tú sabes que el valor identifica realmente a esa cuenta. `role=buyer` no sirve; `userId=101` confirmado en `/me` sí puede servir.

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

**No necesitas actualizar la extensión para v0.23.1.** La aplicación sigue siendo compatible con **Negro Burp Bridge v0.20.3**.

Si necesitas recompilarla:

```bash
cd burp-extension
./build-extension.sh
```

Carga `build/libs/negro-burp-bridge-0.20.3.jar` desde Burp → Extensions.

Consulta `METHODOLOGY.md` para el modelo mental, `ROADMAP.md` para las siguientes fases y `CHANGELOG.md` para el historial consolidado.
