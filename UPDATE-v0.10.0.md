# Upgrade a Negro v0.10.0 — Burp Bridge + HTTP Operations

## Qué cambia

Negro v0.10 introduce un modelo HTTP orientado al trabajo real de bug bounty:

```text
Target
  └── Host
       └── Resource
            └── Operation (GET/POST/PUT/DELETE/...)
                 └── HTTP Exchange
```

El mismo recurso no se duplica por método. Cada método observado mantiene `seen_count`, status más reciente, si fue visto autenticado, Content-Type y procedencia (`burp_proxy`, `burp_repeater`, etc.). Requests/responses idénticos se deduplican sin perder first/last seen.

## Burp en tiempo real

Se incluye `burp-extension/` con **Negro Burp Bridge** basado en Montoya API 2026.7.

- Captura tráfico HTTP observado por Burp sin filtrar por tipo de asset.
- Negro auto-enruta cada host al target más específico ya creado.
- Conserva request/response completos en Base64 y headers.
- JS observados por Burp entran automáticamente al pipeline JavaScript de Negro.
- Desde un Resource de Negro se puede usar **Send to Repeater →**. Si existe una request real observada para ese método, se reutiliza; si no, Burp construye una request base desde la URL.

> Seguridad: esta versión conserva evidencia HTTP completa localmente, incluyendo cookies o Authorization si estaban presentes. Mantén Negro escuchando en localhost y protege el workspace.

## Notificaciones de jobs

Los jobs ahora guardan snapshot antes/después y la UI muestra un toast al finalizar, por ejemplo:

```text
Web recon terminado
+5 resources · +2 JS · +1 observaciones
```

Si no hubo cambios: `Sin elementos nuevos`.

## API local

```text
GET  /api/ingest/health
POST /api/ingest/http
GET  /api/bridge/repeater/next
POST /api/bridge/repeater/{target_key}/{queue_id}/ack
```

## Build de la extensión Burp

Requiere Java 21 y Gradle:

```bash
cd burp-extension
gradle jar
```

Carga `build/libs/negro-burp-bridge-0.10.0.jar` desde **Burp → Extensions → Installed → Add → Java**.

Por defecto conecta a `http://127.0.0.1:8765`. La pestaña **Negro** dentro de Burp permite cambiar la URL y ver contadores.

## Flujo de prueba recomendado

1. Instalación limpia de Negro v0.10.
2. Repetir NegroLab para validar regresión del flujo v0.9.
3. Crear el target del lab de PortSwigger CORS.
4. Cargar Negro Burp Bridge.
5. Navegar autenticado con el navegador de Burp.
6. Abrir `My account` y confirmar que `/accountDetails` aparece automáticamente en Negro como Resource.
7. Confirmar que GET aparece como Operation y que el exchange indica `auth`.
8. Desde Negro, enviar `/accountDetails` a Repeater.
9. Ejecutar/practicar el CORS check con el endpoint ya conocido.
