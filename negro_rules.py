#!/usr/bin/env python3
"""Editable, inherited detector knowledge base for Negro.

v0.19 replaces opaque sensitivity presets with explicit rules:
BUILT-IN -> PERSONAL LIBRARY -> PROJECT OVERRIDES.

A rule match is a review signal, never a vulnerability verdict.
"""
from __future__ import annotations

import copy
from typing import Any


def _terms(*values: str) -> list[str]:
    return list(dict.fromkeys(str(v).strip() for v in values if str(v).strip()))


CATALOG: dict[str, dict[str, Any]] = {
    "access_object_reference": {
        "label": "Referencia de objeto / posible IDOR",
        "family": "Access Control",
        "lesson": "IDOR / BOLA aparece cuando el cliente puede elegir qué objeto pedir y el backend confía en ese identificador sin comprobar ownership, tenant o permiso sobre ESE objeto.",
        "how_it_happens": "La aplicación necesita identificadores como orderId, userId o memberId para localizar registros. El problema no es que el ID sea visible: el problema es que el servidor use ese ID y olvide comprobar si la identidad actual puede acceder al registro resultante.",
        "example": "GET /api/members/profile?memberId=83921. Negro sólo ve una superficie interesante. La vulnerabilidad se confirma únicamente si una segunda cuenta puede usar el memberId de la primera y leer/modificar algo que no le pertenece.",
        "what_negro_sees": "Nombres de parámetros que parecen identificadores, sufijos como Id/_id, UUID/IDs numéricos en path y contexto de autenticación. Puedes enseñarle vocabulario propio del programa, por ejemplo memberId o beneficiaryId.",
        "false_positives": "requestId, correlationId, trackingId, IDs de datos públicos, IDs que siempre apuntan al propio usuario o endpoints donde el backend valida ownership correctamente.",
        "manual_validation": "Compara la misma operación entre dos cuentas tuyas autorizadas cambiando sólo identidad/objeto. No basta con obtener 200: compara qué objeto regresó y si realmente pertenece a otra identidad.",
    },
    "mass_assignment": {
        "label": "Campos privilegiados / Mass Assignment",
        "family": "Access Control",
        "lesson": "Mass Assignment ocurre cuando el backend enlaza automáticamente propiedades controladas por el cliente a un modelo y permite modificar campos que la UI nunca debía exponer.",
        "how_it_happens": "Un DTO/model acepta más campos de los que la interfaz envía. Si roleId, permissions, ownerId o status llegan al binder y no existe una allowlist/autorización por campo, el usuario puede intentar modificar estado privilegiado.",
        "example": "PATCH /profile normalmente envía {name}. La respuesta también contiene roleId. Negro te recuerda probar, sobre tu propia cuenta, si el backend acepta {name, roleId}. Que roleId exista en JSON NO demuestra la vuln.",
        "what_negro_sees": "Campos privilegiados observados en respuestas que no aparecieron en la solicitud de edición, métodos de escritura y sesión autenticada.",
        "false_positives": "Campos read-only, propiedades calculadas, campos ignorados por el binder, DTOs con allowlist o controles posteriores que impiden ganar capacidad.",
        "manual_validation": "Añade un solo campo observado a una request legítima de tu propio objeto, verifica estado server-side y luego comprueba si realmente apareció una capacidad adicional.",
    },
    "method_access_control": {
        "label": "Autorización por método HTTP",
        "family": "Access Control",
        "lesson": "El control de acceso puede estar aplicado a POST pero no a GET/PUT/PATCH equivalentes, o diferentes rutas de middleware pueden tratar distinto el mismo recurso.",
        "how_it_happens": "Routers, proxies o middleware aplican reglas por verbo. Dos handlers alcanzan la misma operación de negocio pero sólo uno ejecuta el guard correcto.",
        "example": "POST /catalog/sellers/feature con JSON puede estar bloqueado. Si GET ejecuta la misma acción, la prueba correcta debe preservar la semántica: mover sellerId y feature al query, no cambiar sólo el verbo.",
        "what_negro_sees": "El mismo recurso observado con varios métodos y cuáles de ellos suelen cambiar estado.",
        "false_positives": "GET y POST con semánticas completamente distintas, OPTIONS/HEAD, endpoints REST normales donde todos los verbos aplican la misma autorización.",
        "manual_validation": "Compara una misma intención de negocio preservando todos los parámetros. Un error por request incompleta es no concluyente, no un descarte.",
    },
    "redirect_body_access_control": {
        "label": "Redirect con body significativo",
        "family": "Access Control",
        "lesson": "Un redirect no desenvía datos. Si el servidor construye información sensible y después responde 302, el navegador puede redirigir al usuario pero el body ya viajó por la red.",
        "how_it_happens": "El controlador carga el objeto, serializa datos o renderiza una vista y sólo después decide redirigir por falta de autorización.",
        "example": "GET /account?id=otro devuelve 302 Location:/ pero el body contiene una integrationKey. Burp permite ver la respuesta 302 antes de seguir Location.",
        "what_negro_sees": "Status 3xx, tamaño del body y campos que parecen identidad, privilegios o secretos.",
        "false_positives": "HTML genérico de redirect, mensajes de estado sin datos del objeto o bodies idénticos para todos los usuarios.",
        "manual_validation": "Inspecciona el body crudo sin seguir redirect y compara con tu propia identidad/objeto.",
    },
    "proxy_path_access_control": {
        "label": "403 de capa frontal / routing",
        "family": "Access Control",
        "lesson": "A veces el proxy/WAF autoriza una URI mientras el backend termina procesando otra. Diferencias entre capas pueden crear bypass de rutas protegidas.",
        "how_it_happens": "Nginx/CDN/API Gateway bloquea /admin, pero un header de rewrite o normalización distinta hace que el backend vea /admin mientras la capa frontal evaluó una ruta permitida.",
        "example": "Un 403 HTML de nginx para /ops y un 404 JSON de la app para /random sugieren capas distintas. Eso sólo justifica investigar routing; no demuestra X-Original-URL vulnerable.",
        "what_negro_sees": "Fingerprints de 403 frente a respuestas del backend: Server, Content-Type y diferencias fuertes de tamaño.",
        "false_positives": "Páginas de error personalizadas, CDN que cambia formato por status o rutas realmente bloqueadas sin discrepancia de interpretación.",
        "manual_validation": "Primero identifica qué capa generó cada respuesta. Sólo después prueba mecanismos de routing conocidos y permitidos por el scope.",
    },
    "referer_access_control": {
        "label": "Referer en acción sensible",
        "family": "Access Control",
        "lesson": "Referer es un header controlable por el cliente y no debería ser la prueba de autorización de una acción privilegiada.",
        "how_it_happens": "El backend intenta garantizar que una acción venga 'desde la página admin' comprobando Referer en vez de validar rol/permisos de la sesión.",
        "example": "POST /admin/publish funciona para un usuario low-privilege sólo cuando envía Referer: /admin. Eso sería relevante; simplemente observar Referer es sólo un quick check.",
        "what_negro_sees": "Acciones state-changing, rutas con verbos/nombres sensibles y presencia de Referer.",
        "false_positives": "Referer usado sólo para CSRF, telemetría, analytics o navegación mientras la autorización real depende del rol server-side.",
        "manual_validation": "Con tu cuenta de prueba compara request original, sin Referer y con Referer controlado manteniendo todo lo demás igual.",
    },
    "cors": {
        "label": "CORS reflejado",
        "family": "Cross-origin",
        "lesson": "CORS controla si JavaScript de otro origin puede LEER una respuesta del navegador. Reflejar Origin no es automáticamente vulnerable.",
        "how_it_happens": "El servidor construye Access-Control-Allow-Origin usando el Origin recibido sin una allowlist segura. El impacto aparece cuando un origin no confiable puede leer datos sensibles, especialmente con credenciales.",
        "example": "app.target.com → api.target.com puede ser first-party esperado. evil.example → api.target.com reflejado con credentials y respuesta autenticada sí merece una prueba fuerte.",
        "what_negro_sees": "Origin enviado, ACAO devuelto, Access-Control-Allow-Credentials, autenticación observada y si ambos hosts pertenecen al mismo proyecto.",
        "false_positives": "Origins first-party, allowlists explícitas, respuestas públicas, ACAO sin capacidad de leer datos sensibles o endpoints sin credenciales.",
        "manual_validation": "Usa un HTTPS origin controlado por ti y comprueba desde navegador si puede leer una respuesta autenticada sensible. No basta con ver ACAO en Burp.",
    },
    "js_sensitive_route": {
        "label": "Ruta sensible descubierta en JavaScript",
        "family": "JavaScript",
        "lesson": "Los bundles pueden revelar rutas no enlazadas. Descubrir /admin o /approve amplía superficie, pero no demuestra que la ruta sea accesible sin autorización.",
        "how_it_happens": "Frontends SPA incluyen nombres de endpoints, feature flags y rutas de módulos que el usuario actual quizá nunca navega.",
        "example": "admin-tools.js contiene /ops/audit/export. Negro crea el Resource y te recuerda revisar método, contexto legítimo y control de acceso.",
        "what_negro_sees": "URLs/rutas extraídas del JS y palabras que tú consideras de interés como admin, internal, approve o export.",
        "false_positives": "Código muerto, rutas legacy, strings de tests, rutas públicas o endpoints correctamente autorizados.",
        "manual_validation": "Abre el recurso de forma dirigida, entiende su función y valida autorización sin fuzzing masivo.",
    },
    "open_redirect": {
        "label": "Parámetros de redirección",
        "family": "URL / Navigation",
        "lesson": "Open Redirect existe cuando un parámetro controlable decide un destino externo sin una allowlist efectiva.",
        "how_it_happens": "Login, OAuth, logout y flujos de retorno aceptan next/returnUrl/redirectUri y luego construyen Location o navegación directamente.",
        "example": "GET /login?next=https://example-attacker.test termina en Location al dominio controlado. Ver un parámetro next solamente es una superficie.",
        "what_negro_sees": "Nombres de parámetros de navegación, rutas login/OAuth/callback y Location observado.",
        "false_positives": "Valores restringidos a paths relativos, allowlists fuertes, destinos firmados o parámetros que no controlan navegación.",
        "manual_validation": "Cambia sólo el destino por una URL HTTPS tuya y sigue Location/navegación final.",
    },
    "ssrf_surface": {
        "label": "URL controlable / posible fetch server-side",
        "family": "SSRF / URL fetch",
        "lesson": "SSRF requiere que el SERVIDOR haga una solicitud hacia una URL controlada. Que el cliente envíe una URL no demuestra consumo server-side.",
        "how_it_happens": "Funciones de preview, webhook, import, proxy, image fetch o PDF reciben una URL y el backend la solicita sin restricciones suficientes.",
        "example": "POST /preview {url:'https://tu-endpoint.test/x'}. Sólo es SSRF si observas que el servidor realiza el request saliente.",
        "what_negro_sees": "Parámetros URL-like y rutas con verbos de fetch/import/proxy/webhook/preview.",
        "false_positives": "URLs usadas únicamente por el frontend, valores almacenados pero no solicitados o allowlists efectivas.",
        "manual_validation": "Si el scope lo permite, usa exclusivamente un endpoint tuyo como marcador benigno y demuestra tráfico server-side.",
    },
    "secret_candidate": {
        "label": "Secretos / configuración en HTTP",
        "family": "Secrets",
        "lesson": "Una cadena con forma de token/key es una candidata, no necesariamente un secreto explotable. Muchas claves de cliente son públicas por diseño.",
        "how_it_happens": "Credenciales reales, tokens de CI, private keys o configuraciones terminan en JS/HTTP por errores de build, logging o serialización.",
        "example": "Una Google API key en JS puede ser esperada si está bien restringida; una private key o token GitHub reutilizable normalmente merece mucha más atención.",
        "what_negro_sees": "Firmas conocidas de formatos de credenciales. Negro persiste fingerprint/valor enmascarado, nunca el secreto completo en la alerta.",
        "false_positives": "Fixtures, ejemplos de documentación, claves públicas client-side, valores expirados o correctamente restringidos.",
        "manual_validation": "Primero clasifica el tipo y restricciones. Valida de forma mínima y no destructiva dentro del scope.",
    },
    "sensitive_response": {
        "label": "Campos sensibles devueltos por API",
        "family": "Data exposure",
        "lesson": "Una API puede devolver propiedades que el cliente no necesita: tokens, passwords, secrets o sesiones. El nombre ayuda a priorizar, pero el valor y contexto determinan impacto.",
        "how_it_happens": "Serialización de modelos completos, DTOs demasiado amplios o joins internos terminan devolviendo campos sensibles.",
        "example": "GET /profile devuelve passwordHash o integrationKey. Negro destaca el campo; tú confirmas si realmente es sensible/reutilizable.",
        "what_negro_sees": "Claves JSON configurables como password, api_key, access_token, session_token y valores no vacíos.",
        "false_positives": "Nombres engañosos, valores enmascarados, IDs públicos, tokens one-time expirados o datos necesarios por diseño.",
        "manual_validation": "Determina quién recibe el valor, por qué lo necesita y si otorga capacidad adicional fuera del flujo esperado.",
    },
    "sensitive_url": {
        "label": "Secretos en query string",
        "family": "Data exposure",
        "lesson": "Los secretos en URL pueden propagarse a historial, logs, proxies, analytics y Referer.",
        "how_it_happens": "Aplicaciones transportan password/token/api_key en GET o URLs compartibles en lugar de headers/body protegidos.",
        "example": "GET /download?access_token=... puede dejar el token en múltiples capas aun cuando TLS proteja el tránsito.",
        "what_negro_sees": "Nombres de query configurables asociados a credenciales y valores no vacíos.",
        "false_positives": "Campos llamados token que son IDs públicos, tokens no sensibles o valores ficticios.",
        "manual_validation": "Confirma que sea un secreto real y dónde se replica; no reutilices credenciales ajenas.",
    },
    "source_map": {
        "label": "Source maps públicos",
        "family": "JavaScript",
        "lesson": "Un .map ayuda a reconstruir código fuente original. Su existencia sola rara vez es una vulnerabilidad; importa lo que revela.",
        "how_it_happens": "El pipeline de producción publica archivos source map o deja sourceMappingURL accesible.",
        "example": "app.js.map contiene sourcesContent con endpoints internos o secretos. El impacto proviene de esa información, no del sufijo .map por sí mismo.",
        "what_negro_sees": "Paths/sufijos de source map, HTTP exitoso y análisis posterior de sourcesContent.",
        "false_positives": "Mapas que sólo contienen código ya público/minificado y no agregan información sensible.",
        "manual_validation": "Analiza fuentes, rutas y configuración; evita reportar sólo 'source map público' sin impacto.",
    },
    "api_docs": {
        "label": "Documentación API expuesta",
        "family": "API",
        "lesson": "Swagger/OpenAPI público amplía superficie y facilita entender parámetros, pero puede ser completamente intencional.",
        "how_it_happens": "La documentación de desarrollo queda publicada en producción o es parte deliberada del producto.",
        "example": "/v3/api-docs responde 200 y revela endpoints administrativos. Eso es inteligencia; la vuln aparece si esos endpoints tienen un fallo adicional.",
        "what_negro_sees": "Rutas conocidas y términos configurables de Swagger/OpenAPI/api-docs.",
        "false_positives": "APIs públicas documentadas por diseño.",
        "manual_validation": "Úsala para mapear superficie; no asumas impacto por exposición aislada.",
    },
    "error_disclosure": {
        "label": "Errores / detalles internos",
        "family": "Information disclosure",
        "lesson": "Errores verbosos pueden revelar stack, SQL, paths internos, versiones y arquitectura útil para encadenar otros fallos.",
        "how_it_happens": "Debug/exception handlers envían al cliente detalles pensados para logs internos.",
        "example": "Una respuesta 500 incluye Traceback y /home/app/services/payments.py:184. La gravedad depende de qué información adicional expone.",
        "what_negro_sees": "Patrones configurables de stack traces, SQL errors y filesystem paths.",
        "false_positives": "Mensajes genéricos, texto de documentación o valores que coinciden dentro de contenido esperado.",
        "manual_validation": "Reproduce con el mínimo input, captura el detalle y evalúa qué conocimiento sensible aporta.",
    },
}


BUILTIN_RULES: dict[str, dict[str, Any]] = {
    "access_object_reference": {
        "enabled": True,
        "lists": {
            "identifier_keys": _terms("id","userId","user_id","accountId","account_id","orderId","order_id","documentId","document_id","invoiceId","invoice_id","ticketId","ticket_id","profileId","profile_id","sellerId","seller_id","customerId","customer_id","ownerId","owner_id","resourceId","resource_id"),
            "identifier_suffixes": _terms("id", "_id"),
            "path_business_nouns": _terms("order","orders","user","users","account","accounts","document","documents","invoice","invoices","customer","customers","profile","profiles","member","members","seller","sellers"),
            "ignore_keys": _terms("requestId","request_id","traceId","trace_id","correlationId","correlation_id","trackingId","tracking_id"),
            "locations": _terms("query","json","form","multipart"),
        },
        "conditions": {"require_authenticated": True, "detect_numeric_path": True, "detect_uuid_path": True},
    },
    "mass_assignment": {
        "enabled": True,
        "lists": {
            "privileged_keys": _terms("role","roleId","role_id","roles","permission","permissions","scope","scopes","isAdmin","is_admin","admin","privilege","privileges","ownerId","owner_id","status","state","approved","verified","featured","tier","level"),
            "ignore_keys": _terms("id","created_at","updated_at","createdAt","updatedAt"),
            "methods": _terms("POST","PUT","PATCH"),
        },
        "conditions": {"require_authenticated": True, "require_response_only": True},
    },
    "method_access_control": {
        "enabled": True,
        "lists": {"state_changing_methods": _terms("POST","PUT","PATCH","DELETE"), "ignore_methods": _terms("OPTIONS","HEAD")},
        "conditions": {"require_authenticated": False, "require_state_changing": True, "require_two_successful_methods": False},
    },
    "redirect_body_access_control": {
        "enabled": True,
        "lists": {"statuses": _terms("301","302","303","307","308"), "interesting_keys": _terms("user","username","email","account","userId","api_key","apikey","secret","token","access_token","refresh_token","session","role","roleId","permission","permissions")},
        "conditions": {"require_interesting_field": False, "minimum_body_chars": 120},
    },
    "proxy_path_access_control": {
        "enabled": True,
        "lists": {"blocked_statuses": _terms("403"), "comparison_statuses": _terms("404"), "fingerprints": _terms("server","content-type","content-length")},
        "conditions": {"require_strong_difference": False},
    },
    "referer_access_control": {
        "enabled": True,
        "lists": {"methods": _terms("POST","PUT","PATCH","DELETE"), "sensitive_path_tokens": _terms("admin","internal","manage","management","approve","approval","promote","role","permission","delete","remove","publish","feature","export","refund","confirm","complete","finalize","verify","moderate","suspend","ban")},
        "conditions": {"require_authenticated": False, "require_sensitive_path": True},
    },
    "cors": {
        "enabled": True,
        "lists": {"ignore_origins": [], "trusted_origin_suffixes": []},
        "conditions": {"require_external_origin": True, "require_exact_reflection": True, "require_credentials": False, "require_authenticated": False, "ignore_project_scopes": True},
    },
    "js_sensitive_route": {
        "enabled": True,
        "lists": {"path_tokens": _terms("admin","internal","manage","management","approve","approval","audit","export","delete","role","permission","privilege","debug","ops","feature","moderation","staff","backoffice"), "ignore_tokens": []},
        "conditions": {"only_new_routes": False},
    },
    "open_redirect": {
        "enabled": True,
        "lists": {"parameter_keys": _terms("redirect","redirect_url","redirect_uri","return","returnUrl","return_url","next","continue","callback","url","dest","destination","goto","target","returnTo","return_to","checkout_url","domain_name"), "strong_parameter_keys": _terms("redirect","redirect_url","redirect_uri","return","returnUrl","return_url","next","continue","goto","returnTo","return_to","checkout_url"), "navigation_path_tokens": _terms("login","signin","sign-in","logout","auth","oauth","sso","callback","redirect","continue","checkout"), "locations": _terms("query","json","form","multipart")},
        "conditions": {"require_external_location": False, "require_context_for_ambiguous_keys": True},
    },
    "ssrf_surface": {
        "enabled": True,
        "lists": {"parameter_keys": _terms("url","uri","target","destination","dest","endpoint","webhook","feed","proxy","fetch","import","image","file","src","source"), "server_fetch_path_tokens": _terms("fetch","proxy","import","webhook","preview","image","download","remote","callback"), "locations": _terms("query","json","form","multipart")},
        "conditions": {"require_absolute_url": True, "require_server_fetch_path_token": False},
    },
    "secret_candidate": {
        "enabled": True,
        "lists": {"secret_types": _terms(
            "google_api_key","google_oauth_client_id","stripe_publishable_key","mapbox_public_token","sentry_dsn",
            "aws_access_key","aws_access_key_id","aws_secret_access_key","github_token","gitlab_token","npm_token",
            "stripe_live_secret","stripe_secret_key","slack_token","slack_webhook","google_oauth_secret","oauth_client_secret",
            "sendgrid_key","sendgrid_api_key","twilio_api_key","mailgun_key","jwt","literal_bearer_token","database_url",
            "basic_auth_url","presigned_url","discord_webhook","private_key","s3_bucket_url","azure_blob_url","firebase_config"
        )},
        "conditions": {"inspect_request": True, "inspect_response": True},
    },
    "sensitive_response": {
        "enabled": True,
        "lists": {"sensitive_keys": _terms("password","passwd","pwd","pass","client_secret","private_key","api_key","apikey","api-key","secret","access_key","secret_key","refresh_token","access_token","auth_token","session_token","token","session","session_id","sessionid","authorization"), "identity_keys": _terms("user","username","email","login","account","userid","user_id")},
        "conditions": {"require_identity_context": False},
    },
    "sensitive_url": {
        "enabled": True,
        "lists": {"query_keys": _terms("password","passwd","pwd","token","access_token","refresh_token","api_key","apikey","secret")},
        "conditions": {"require_nonempty_value": True},
    },
    "source_map": {
        "enabled": True,
        "lists": {"path_suffixes": _terms(".map")},
        "conditions": {"require_success_status": True},
    },
    "api_docs": {
        "enabled": True,
        "lists": {"path_tokens": _terms("/swagger","/openapi","/v3/api-docs","/api-docs")},
        "conditions": {"require_success_status": True},
    },
    "error_disclosure": {
        "enabled": True,
        "lists": {
            "enabled_pattern_types": _terms("stack_trace","sql_error","internal_path"),
            "custom_regex": [],
        },
        "conditions": {},
    },
}


SCHEMAS: dict[str, dict[str, Any]] = {
    "access_object_reference": {
        "lists": {
            "identifier_keys": ("Nombres exactos que parecen IDs de objeto", "Añade vocabulario propio del target: memberId, beneficiaryId, walletId..."),
            "identifier_suffixes": ("Sufijos de identificador", "Permite reconocer nombres no conocidos todavía. 'Id' es útil pero puede generar ruido."),
            "path_business_nouns": ("Palabras de negocio para IDs en path", "Ayudan a interpretar /orders/123 como más interesante que /assets/123."),
            "ignore_keys": ("Nombres que NO deben disparar IDOR", "Útil para requestId, traceId, trackingId u otros IDs técnicos."),
            "locations": ("Ubicaciones inspeccionadas", "query, json, form y multipart corresponden a dónde viaja el parámetro."),
        },
        "conditions": {
            "require_authenticated": ("Exigir request autenticada", "IDOR suele tener más valor cuando existe una identidad/ownership que comparar."),
            "detect_numeric_path": ("Detectar IDs numéricos en path", "Ejemplo /orders/123."),
            "detect_uuid_path": ("Detectar UUIDs en path", "Ejemplo /orders/550e8400-e29b-41d4-a716-446655440000."),
        },
    },
    "mass_assignment": {
        "lists": {
            "privileged_keys": ("Campos potencialmente privilegiados", "Agrega nombres propios del negocio como accessLevel, accountType o sellerStatus."),
            "ignore_keys": ("Campos read-only/ruidosos a ignorar", "createdAt/id suelen aparecer en responses sin ser buenos candidatos."),
            "methods": ("Métodos de edición", "Sólo estos verbos participan en la hipótesis."),
        },
        "conditions": {
            "require_authenticated": ("Exigir sesión autenticada", "Reduce señales en endpoints públicos."),
            "require_response_only": ("Campo debe aparecer en response pero no request", "Es la señal central: propiedad visible que la UI no estaba enviando."),
        },
    },
    "method_access_control": {
        "lists": {
            "state_changing_methods": ("Métodos que consideras state-changing", "Normalmente POST/PUT/PATCH/DELETE."),
            "ignore_methods": ("Métodos que no deben contar", "OPTIONS/HEAD suelen añadir ruido."),
        },
        "conditions": {
            "require_authenticated": ("Exigir contexto autenticado", "Útil si sólo quieres inconsistencias de autorización y no diferencias públicas."),
            "require_state_changing": ("Exigir al menos un método state-changing", "Evita alertas por GET/HEAD/OPTIONS."),
            "require_two_successful_methods": ("Exigir dos métodos 2xx/3xx observados", "Baja ruido, pero puede ocultar un bypass que aún no probaste."),
        },
    },
    "redirect_body_access_control": {
        "lists": {"statuses": ("Status considerados redirect", "Normalmente 301/302/303/307/308."), "interesting_keys": ("Campos sensibles/identidad dentro del body", "Amplía con nombres propios del target.")},
        "conditions": {"require_interesting_field": ("Exigir un campo interesante", "Si está desactivado también usa tamaño del body como señal."), "minimum_body_chars": ("Tamaño mínimo del body", "Evita alertas por cuerpos mínimos de redirect.")},
    },
    "proxy_path_access_control": {
        "lists": {"blocked_statuses": ("Status de bloqueo", "403 es el caso típico."), "comparison_statuses": ("Status para baseline backend", "404 suele servir para comparar fingerprint."), "fingerprints": ("Rasgos que comparar", "server, content-type, content-length.")},
        "conditions": {"require_strong_difference": ("Exigir diferencia fuerte", "Si se activa, Negro pide Server o Content-Type diferente en lugar de sólo tamaño.")},
    },
    "referer_access_control": {
        "lists": {"methods": ("Métodos sensibles", "Verbos sobre los que tiene sentido revisar Referer."), "sensitive_path_tokens": ("Palabras de acción privilegiada", "Agrega términos propios como activateMerchant o payoutApprove.")},
        "conditions": {"require_authenticated": ("Exigir sesión autenticada", "Reduce señales públicas."), "require_sensitive_path": ("Exigir palabra sensible en la ruta", "Desactivarlo hace que cualquier state-changing con Referer sea candidato.")},
    },
    "cors": {
        "lists": {"ignore_origins": ("Origins exactos a ignorar", "Ejemplo https://docs.vendor.com si sabes que es legítimo."), "trusted_origin_suffixes": ("Sufijos de origins confiables", "Ejemplo .example.com. Los scopes del proyecto ya se ignoran por separado.")},
        "conditions": {"require_external_origin": ("Origin debe ser externo al proyecto", "Evita ruido app.target → api.target."), "require_exact_reflection": ("ACAO debe reflejar exactamente Origin", "La señal clásica de reflexión."), "require_credentials": ("Exigir Allow-Credentials:true", "Hace la señal más fuerte para sesiones cookie."), "require_authenticated": ("Exigir request autenticada observada", "Reduce endpoints públicos."), "ignore_project_scopes": ("Ignorar origins dentro de scopes del proyecto", "Recomendado para proyectos multi-host.")},
    },
    "js_sensitive_route": {
        "lists": {"path_tokens": ("Palabras que vuelven una ruta interesante", "Tu vocabulario ofensivo acumulado."), "ignore_tokens": ("Palabras que quieres ignorar", "Útil para nombres comunes que generan ruido en un proyecto.")},
        "conditions": {"only_new_routes": ("Alertar sólo rutas nuevas", "Si está activo, una ruta ya conocida no vuelve a elevarse por JS.")},
    },
    "open_redirect": {
        "lists": {"parameter_keys": ("Parámetros que podrían controlar navegación", "next, returnUrl, redirectUri..."), "strong_parameter_keys": ("Nombres de alta señal", "Estos no necesitan tanto contexto adicional."), "navigation_path_tokens": ("Rutas donde redirects son comunes", "login, oauth, callback..."), "locations": ("Ubicaciones inspeccionadas", "query/json/form/multipart.")},
        "conditions": {"require_external_location": ("Exigir Location externo ya observado", "Muy preciso, pero sólo detecta después de ver la redirección."), "require_context_for_ambiguous_keys": ("Exigir contexto para url/target/destination", "Evita confundir URL-fetch con redirect.")},
    },
    "ssrf_surface": {
        "lists": {"parameter_keys": ("Parámetros URL-like", "url, webhook, endpoint, image, source..."), "server_fetch_path_tokens": ("Acciones que sugieren fetch server-side", "fetch, proxy, import, preview..."), "locations": ("Ubicaciones inspeccionadas", "query/json/form/multipart.")},
        "conditions": {"require_absolute_url": ("Exigir http(s)://", "Reduce ruido de paths relativos."), "require_server_fetch_path_token": ("Exigir palabra de fetch en la ruta", "Más preciso, pero puede perder SSRF en endpoints con nombres opacos.")},
    },
    "secret_candidate": {
        "lists": {"secret_types": ("Familias de firmas activas", "Puedes quitar familias que en un programa sean puro ruido.")},
        "conditions": {"inspect_request": ("Inspeccionar requests", "Busca credenciales también en datos enviados."), "inspect_response": ("Inspeccionar responses", "Busca secretos/config devueltos por servidor.")},
    },
    "sensitive_response": {
        "lists": {"sensitive_keys": ("Nombres de campos sensibles", "Añade vocabulario como integrationKey o recoverySecret."), "identity_keys": ("Campos que dan contexto de identidad", "Ayudan a entender respuestas de perfil/cuenta.")},
        "conditions": {"require_identity_context": ("Exigir identidad en el mismo JSON", "Reduce ruido, pero puede ocultar secretos en respuestas separadas.")},
    },
    "sensitive_url": {
        "lists": {"query_keys": ("Nombres sensibles en query", "password, token, api_key...")},
        "conditions": {"require_nonempty_value": ("Exigir valor no vacío", "Normalmente debe permanecer activo.")},
    },
    "source_map": {
        "lists": {"path_suffixes": ("Sufijos de source map", "Normalmente .map.")},
        "conditions": {"require_success_status": ("Exigir respuesta <400", "Evita elevar candidatos inexistentes observados como 404.")},
    },
    "api_docs": {
        "lists": {"path_tokens": ("Rutas de documentación API", "Swagger/OpenAPI y convenciones propias del framework.")},
        "conditions": {"require_success_status": ("Exigir respuesta <400", "Reduce candidatos no accesibles.")},
    },
    "error_disclosure": {
        "lists": {"enabled_pattern_types": ("Familias built-in activas", "stack_trace, sql_error, internal_path."), "custom_regex": ("Regex adicionales (avanzado)", "Una expresión por línea. Regex inválidos se ignoran y se muestran como advertencia.")},
        "conditions": {},
    },
}


# v0.38 — Negro ships with one integrated example only. The previous engines are
# kept internally for backwards-compatible workspaces/migrations, but they are
# retired from automatic evaluation unless they are reintroduced deliberately in
# a future module. This keeps day-to-day Signals quiet and teaches the Rule →
# Signal model with one high-signal, explainable example.
ACTIVE_BUILTIN_RULE_IDS = {"error_disclosure"}
RETIRED_BUILTIN_RULE_IDS = set(BUILTIN_RULES) - ACTIVE_BUILTIN_RULE_IDS
for _rule_id, _rule_cfg in BUILTIN_RULES.items():
    if _rule_id not in ACTIVE_BUILTIN_RULE_IDS:
        _rule_cfg["enabled"] = False

CATALOG = {
    key: value for key, value in CATALOG.items()
    if key in ACTIVE_BUILTIN_RULE_IDS
}
if "error_disclosure" in CATALOG:
    CATALOG["error_disclosure"]["label"] = "Errores con detalles internos"
    CATALOG["error_disclosure"]["family"] = "Divulgación de información"


def _clean_list(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        s = str(value or "").strip()
        if not s:
            continue
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def normalize_layer(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    if "enabled" in raw and raw.get("enabled") is not None:
        out["enabled"] = bool(raw.get("enabled"))
    for bucket in ("add", "exclude"):
        data = raw.get(bucket)
        if isinstance(data, dict):
            out[bucket] = {str(k): _clean_list(v) for k, v in data.items() if _clean_list(v)}
    cond = raw.get("conditions")
    if isinstance(cond, dict):
        clean_cond: dict[str, Any] = {}
        for k, v in cond.items():
            if isinstance(v, bool) or isinstance(v, int) or isinstance(v, float) or isinstance(v, str):
                clean_cond[str(k)] = v
        if clean_cond:
            out["conditions"] = clean_cond
    return out


def merge_detector_rules(detector_id: str, global_layer: Any = None, project_layer: Any = None) -> dict[str, Any]:
    base = copy.deepcopy(BUILTIN_RULES.get(detector_id) or {"enabled": True, "lists": {}, "conditions": {}})
    global_layer = normalize_layer(global_layer)
    project_layer = normalize_layer(project_layer)
    provenance: dict[str, dict[str, list[str]]] = {}

    for name, values in list((base.get("lists") or {}).items()):
        values = _clean_list(values)
        base["lists"][name] = values
        provenance[name] = {"builtin": list(values), "personal": [], "project": [], "excluded_personal": [], "excluded_project": []}

    for label, layer in (("personal", global_layer), ("project", project_layer)):
        if "enabled" in layer:
            base["enabled"] = bool(layer["enabled"])
        for name, additions in (layer.get("add") or {}).items():
            base.setdefault("lists", {}).setdefault(name, [])
            provenance.setdefault(name, {"builtin": [], "personal": [], "project": [], "excluded_personal": [], "excluded_project": []})
            existing_lower = {x.lower() for x in base["lists"][name]}
            for item in _clean_list(additions):
                if item.lower() not in existing_lower:
                    base["lists"][name].append(item)
                    existing_lower.add(item.lower())
                provenance[name][label].append(item)
        for name, excluded in (layer.get("exclude") or {}).items():
            provenance.setdefault(name, {"builtin": [], "personal": [], "project": [], "excluded_personal": [], "excluded_project": []})
            ex = {x.lower() for x in _clean_list(excluded)}
            base.setdefault("lists", {}).setdefault(name, [])
            base["lists"][name] = [x for x in base["lists"][name] if x.lower() not in ex]
            provenance[name]["excluded_" + label].extend(_clean_list(excluded))
        for name, value in (layer.get("conditions") or {}).items():
            base.setdefault("conditions", {})[name] = value

    base["provenance"] = provenance
    base["global_layer"] = global_layer
    base["project_layer"] = project_layer
    return base


def rule_list(effective: dict[str, Any], name: str) -> list[str]:
    return _clean_list((effective.get("lists") or {}).get(name) or [])


def rule_bool(effective: dict[str, Any], name: str, default: bool = False) -> bool:
    value = (effective.get("conditions") or {}).get(name, default)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "si", "sí"}
    return bool(value)


def rule_int(effective: dict[str, Any], name: str, default: int = 0) -> int:
    try:
        return int((effective.get("conditions") or {}).get(name, default))
    except Exception:
        return int(default)
