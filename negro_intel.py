#!/usr/bin/env python3
"""Passive intelligence, JavaScript analysis and optional AI helpers for Negro Recon.

All network actions here are explicit, low-volume and target-scoped. Nothing marks a
resource as a vulnerability automatically.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable

CONFIG_DIR = Path.home() / ".config" / "negro"
SECRETS_PATH = CONFIG_DIR / "secrets.env"
SETTINGS_PATH = CONFIG_DIR / "settings.json"

DEFAULT_SETTINGS = {
    "ai_model": "gpt-6-luna",
    "ai_output_tokens": 3000,
    "usd_cop_rate": 3344.62,
    "usd_cop_rate_date": "2026-09-26",
    "js_max_download_mb": 8,
    "js_ai_max_chars": 650000,
    "job_max_workers": 3,
    "urlscan_detail_limit": 8,
    "wayback_limit": 5000,
}

OPENAI_PRICING = {
    # Standard processing prices per 1M text tokens, snapshot 2026-09-26.
    "gpt-6-luna": {"input": 0.10, "output": 0.50, "long_input": 0.20, "long_output": 0.75},
    "gpt-6-sol": {"input": 2.00, "output": 10.00, "long_input": 4.00, "long_output": 15.00},
}
LONG_CONTEXT_THRESHOLD = 272_000

SIGNAL_KEYWORDS = [
    "authorization", "bearer", "access_token", "refresh_token", "apikey", "api_key",
    "graphql", "websocket", "wss://", "admin", "internal", "debug", "swagger",
    "openapi", "upload", "download", "export", "import", "role", "permission",
    "featureflag", "feature_flag", "localstorage", "sessionstorage", "oauth", "sso",
    "password", "secret", "privatekey", "client_secret", "bucket", "s3", "firebase",
]

ABS_URL_RE = re.compile(r"(?P<url>(?:https?|wss?)://[^\s\"'<>\\]+)", re.I)
REL_PATH_RE = re.compile(
    r"[\"'](?P<path>/(?:api|v\d+|graphql|admin|internal|auth|oauth|account|user|users|order|orders|payment|payments|seller|checkout|upload|download|export|import|debug|swagger|openapi|config|feature)[^\"'\\\s]{0,240})[\"']",
    re.I,
)
SOURCEMAP_RE = re.compile(r"(?:sourceMappingURL=)([^\s*]+)")


DETECTION_RULES = [
    {"id":"google_api_key","label":"Google API key","category":"public_client_config","confidence":"high","pattern":r"\bAIza[0-9A-Za-z_-]{35}\b"},
    {"id":"google_oauth_client_id","label":"Google OAuth Client ID","category":"public_client_config","confidence":"high","pattern":r"\b[0-9]{6,}-[0-9A-Za-z_-]{20,}\.apps\.googleusercontent\.com\b"},
    {"id":"stripe_publishable_key","label":"Stripe publishable key","category":"public_client_config","confidence":"high","pattern":r"\bpk_(?:live|test)_[0-9A-Za-z]{16,}\b"},
    {"id":"mapbox_public_token","label":"Mapbox public token","category":"public_client_config","confidence":"medium","pattern":r"\bpk\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"},
    {"id":"sentry_dsn","label":"Sentry DSN","category":"public_client_config","confidence":"high","pattern":r"https://[0-9A-Za-z]+@[0-9A-Za-z.-]+(?:\:\d+)?/\d+"},
    {"id":"aws_access_key_id","label":"AWS Access Key ID","category":"potential_secret","confidence":"high","pattern":r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"},
    {"id":"aws_secret_access_key","label":"AWS Secret Access Key","category":"potential_secret","confidence":"high","pattern":r"(?i)(?:aws_secret_access_key|secretAccessKey)\s*[:=]\s*[\"']([A-Za-z0-9/+=]{40})[\"']"},
    {"id":"github_token","label":"GitHub token","category":"potential_secret","confidence":"high","pattern":r"\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|gh[ousr]_[A-Za-z0-9]{30,})\b"},
    {"id":"gitlab_token","label":"GitLab token","category":"potential_secret","confidence":"high","pattern":r"\bglpat-[A-Za-z0-9_-]{20,}\b"},
    {"id":"npm_token","label":"npm token","category":"potential_secret","confidence":"high","pattern":r"\bnpm_[A-Za-z0-9]{30,}\b"},
    {"id":"sendgrid_api_key","label":"SendGrid API key","category":"potential_secret","confidence":"high","pattern":r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{32,}\b"},
    {"id":"slack_webhook","label":"Slack webhook","category":"potential_secret","confidence":"high","pattern":r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}"},
    {"id":"stripe_secret_key","label":"Stripe secret key","category":"potential_secret","confidence":"high","pattern":r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"},
    {"id":"jwt","label":"JWT token","category":"potential_secret","confidence":"medium","pattern":r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"},
    {"id":"private_key","label":"Private key","category":"potential_secret","confidence":"high","pattern":r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"},
    {"id":"oauth_client_secret","label":"OAuth client_secret","category":"potential_secret","confidence":"high","pattern":r"(?i)(?:client_secret|clientSecret)\s*[:=]\s*[\"']([A-Za-z0-9._~+\-/=]{12,})[\"']"},
    {"id":"literal_bearer_token","label":"Bearer token literal","category":"potential_secret","confidence":"medium","pattern":r"(?i)Bearer\s+([A-Za-z0-9._~+\-/=]{20,})"},
    {"id":"database_url","label":"Database connection URL","category":"potential_secret","confidence":"high","pattern":r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s\"'<>]{8,}"},
    {"id":"basic_auth_url","label":"URL con Basic Auth embebido","category":"potential_secret","confidence":"high","pattern":r"https?://[^\s:/@]+:[^\s/@]+@[^\s\"'<>]+"},
    {"id":"presigned_url","label":"Signed / presigned URL","category":"potential_secret","confidence":"high","pattern":r"https?://[^\s\"'<>]+(?:X-Amz-Signature|X-Goog-Signature|[?&]sig=)[^\s\"'<>]+"},
    {"id":"discord_webhook","label":"Discord webhook","category":"potential_secret","confidence":"high","pattern":r"https://(?:discord(?:app)?\.com)/api/webhooks/\d+/[A-Za-z0-9._-]{20,}"},
    {"id":"s3_bucket_url","label":"S3 bucket / endpoint","category":"surface_config","confidence":"medium","pattern":r"https?://[A-Za-z0-9._-]+\.s3(?:[.-][A-Za-z0-9-]+)?\.amazonaws\.com(?:/[^\s\"'<>]*)?"},
    {"id":"azure_blob_url","label":"Azure Blob endpoint","category":"surface_config","confidence":"medium","pattern":r"https?://[A-Za-z0-9-]+\.blob\.core\.windows\.net(?:/[^\s\"'<>]*)?"},
]

DETECTION_CATEGORY_LABELS = {
    "potential_secret": "Potential secret",
    "public_client_config": "Public client config",
    "surface_config": "Surface / infrastructure config",
}

DETECTION_VALIDATION_HINTS = {
    "google_api_key": "Revisar a qué API se usa y si tiene restricciones de HTTP referrer, IP o API. Que sea visible en frontend no implica exposición.",
    "google_oauth_client_id": "Un OAuth Client ID suele ser público. Revisar redirect URIs y configuración del flujo, no tratarlo como secreto.",
    "stripe_publishable_key": "La publishable key está diseñada para cliente. Revisar sólo el contexto y endpoints asociados; no confundirla con una secret key.",
    "mapbox_public_token": "Los public tokens de Mapbox pueden ser client-side. Revisar scopes/restricciones y uso previsto.",
    "sentry_dsn": "Un Sentry DSN suele ser visible. Revisar si expone metadata útil o configuración inesperada, sin asumir que es credencial privada.",
    "firebase_config": "Firebase client config suele ser pública. Revisar reglas de acceso/servicios asociados con cuentas y acciones autorizadas.",
    "aws_access_key_id": "Un Access Key ID por sí solo no autentica. Buscar contexto/pareja Secret Access Key; no usar credenciales automáticamente.",
    "aws_secret_access_key": "Candidato de alta señal. Confirmar contexto y scope antes de cualquier validación; Negro no lo usa automáticamente.",
    "github_token": "Candidato de alta señal. Verificar origen/contexto y scope del programa antes de cualquier uso.",
    "gitlab_token": "Candidato de alta señal. Verificar origen/contexto y scope del programa antes de cualquier uso.",
    "npm_token": "Candidato de alta señal. Verificar si es real/activo sólo mediante una validación permitida por el programa.",
    "sendgrid_api_key": "Candidato de alta señal. No enviar correo ni consumir servicios automáticamente; validar sólo de forma permitida.",
    "slack_webhook": "Un webhook puede permitir acciones. No enviar mensajes automáticamente; validar contexto y ownership primero.",
    "discord_webhook": "Un webhook puede permitir acciones. No enviar mensajes automáticamente; validar contexto y ownership primero.",
    "stripe_secret_key": "Candidato a secret key. No realizar cobros/acciones; validar alcance y exposición de forma segura.",
    "jwt": "Un JWT embebido puede estar expirado, ser de prueba o público. Revisar claims/contexto sin asumir validez actual.",
    "private_key": "Material criptográfico privado es alta señal. Confirmar que no sea fixture/test antes de escalar la revisión.",
    "oauth_client_secret": "Un client_secret en frontend es inusual. Confirmar que sea un valor real y no placeholder antes de considerarlo finding.",
    "literal_bearer_token": "Revisar si es token real, fixture o ejemplo. No reutilizarlo automáticamente.",
    "database_url": "Revisar si incluye credenciales reales y si corresponde a producción; no conectar automáticamente.",
    "basic_auth_url": "Revisar si usuario/password son reales o de ejemplo; no autenticar automáticamente.",
    "presigned_url": "Las signed URLs pueden ser temporales. Revisar expiración, recurso y sensibilidad sin ampliar el acceso fuera de scope.",
    "s3_bucket_url": "Útil para surface mapping. La URL del bucket no implica bucket público ni misconfiguration.",
    "azure_blob_url": "Útil para surface mapping. Validar políticas de acceso sólo con requests de bajo impacto permitidas por scope.",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_settings() -> dict[str, Any]:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    data = dict(DEFAULT_SETTINGS)
    if SETTINGS_PATH.exists():
        try:
            raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                data.update(raw)
        except Exception:
            pass
    return data


def save_settings(values: dict[str, Any]) -> dict[str, Any]:
    current = load_settings()
    current.update(values)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return current


def load_secrets() -> dict[str, str]:
    """Environment wins; secrets.env is a local fallback and is never returned to UI."""
    values: dict[str, str] = {}
    if SECRETS_PATH.exists():
        try:
            for raw in SECRETS_PATH.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key:
                    values[key] = value
        except Exception:
            pass
    for key in ("OPENAI_API_KEY", "URLSCAN_API_KEY", "SECURITYTRAILS_API_KEY", "GITHUB_TOKEN"):
        if os.environ.get(key):
            values[key] = os.environ[key]
    return values


def secret_status() -> dict[str, bool]:
    secrets = load_secrets()
    return {k: bool(secrets.get(k)) for k in ("OPENAI_API_KEY", "URLSCAN_API_KEY", "SECURITYTRAILS_API_KEY", "GITHUB_TOKEN")}


def runtime_dependency_status() -> dict[str, bool]:
    """Report optional local analysis/AI dependencies without exposing secrets."""
    import importlib.util
    return {
        "openai": importlib.util.find_spec("openai") is not None,
        "tiktoken": importlib.util.find_spec("tiktoken") is not None,
        "jsbeautifier": importlib.util.find_spec("jsbeautifier") is not None,
    }


def http_json(url: str, *, headers: dict[str, str] | None = None, timeout: int = 30, max_bytes: int = 25_000_000) -> Any:
    req_headers = {"User-Agent": "Negro-Recon/0.8.1", "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise RuntimeError(f"Respuesta demasiado grande (> {max_bytes} bytes)")
    return json.loads(raw.decode("utf-8", errors="replace"))


def _decode_data_url(url: str, *, max_bytes: int) -> tuple[bytes, str, str]:
    """Decode RFC2397 data URLs, tolerating omitted Base64 padding.

    Some JS bundlers emit inline source maps without the trailing '=' padding.
    urllib's data: handler is stricter and raises binascii.Error: Incorrect padding.
    """
    if not url.lower().startswith("data:") or "," not in url:
        raise RuntimeError("data URL inválida")
    header, payload = url.split(",", 1)
    meta = header[5:]
    parts = meta.split(";") if meta else []
    content_type = parts[0] if parts and "/" in parts[0] else "text/plain"
    is_b64 = any(part.lower() == "base64" for part in parts[1:] if part)
    try:
        if is_b64:
            encoded = urllib.parse.unquote_to_bytes(payload)
            encoded = b"".join(encoded.split())
            encoded += b"=" * ((-len(encoded)) % 4)
            raw = base64.b64decode(encoded, validate=False)
        else:
            raw = urllib.parse.unquote_to_bytes(payload)
    except Exception as exc:
        raise RuntimeError(f"No pude decodificar source map inline: {exc}") from exc
    if len(raw) > max_bytes:
        raise RuntimeError(f"Recurso demasiado grande (> {max_bytes} bytes)")
    return raw, content_type, "data:inline-source-map"


def http_bytes(url: str, *, timeout: int = 25, max_bytes: int = 8_000_000, insecure: bool = True) -> tuple[bytes, str, str]:
    if url.lower().startswith("data:"):
        return _decode_data_url(url, max_bytes=max_bytes)
    req = urllib.request.Request(url, headers={"User-Agent": "Negro-Recon/0.8.1", "Accept": "*/*"})
    context = ssl._create_unverified_context() if insecure and url.lower().startswith("https://") else None
    with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
        raw = response.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise RuntimeError(f"Recurso demasiado grande (> {max_bytes} bytes)")
        content_type = response.headers.get("Content-Type", "")
        final_url = response.geturl()
    return raw, content_type, final_url


def wayback_cdx(domain: str, *, limit: int = 5000, timeout: int = 45) -> dict[str, Any]:
    query = urllib.parse.urlencode({
        "url": f"{domain}/",
        "matchType": "domain",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype,digest,length",
        "filter": "statuscode:200",
        "collapse": "urlkey",
        "limit": str(max(1, min(limit, 20000))),
    })
    url = f"https://web.archive.org/cdx/search/cdx?{query}"
    data = http_json(url, timeout=timeout, max_bytes=40_000_000)
    captures: list[dict[str, str]] = []
    if isinstance(data, list) and data:
        header = data[0] if isinstance(data[0], list) else []
        for row in data[1:]:
            if not isinstance(row, list):
                continue
            item = {str(header[i]): str(row[i]) for i in range(min(len(header), len(row)))}
            captures.append(item)
    return {"source_url": url, "captures": captures, "count": len(captures)}


def urlscan_direct(domain: str, *, detail_limit: int = 8, timeout: int = 35) -> dict[str, Any]:
    secrets = load_secrets()
    headers: dict[str, str] = {}
    if secrets.get("URLSCAN_API_KEY"):
        headers["api-key"] = secrets["URLSCAN_API_KEY"]
    query = urllib.parse.urlencode({"q": f"page.domain:{domain} OR domain:{domain}", "size": "100"})
    search_url = f"https://urlscan.io/api/v1/search/?{query}"
    search = http_json(search_url, headers=headers, timeout=timeout, max_bytes=15_000_000)
    results = search.get("results", []) if isinstance(search, dict) else []
    scans: list[dict[str, Any]] = []
    request_urls: list[str] = []
    for result in results[: max(0, min(detail_limit, 20))]:
        if not isinstance(result, dict):
            continue
        scan_id = result.get("_id") or result.get("task", {}).get("uuid")
        page = result.get("page") if isinstance(result.get("page"), dict) else {}
        task = result.get("task") if isinstance(result.get("task"), dict) else {}
        item: dict[str, Any] = {
            "id": scan_id,
            "date": task.get("time") or result.get("date"),
            "page_url": page.get("url"),
            "task_url": task.get("url"),
            "domain": page.get("domain"),
            "ip": page.get("ip"),
        }
        for candidate in (item.get("page_url"), item.get("task_url")):
            if isinstance(candidate, str):
                request_urls.append(candidate)
        if scan_id:
            try:
                detail_url = f"https://urlscan.io/api/v1/result/{scan_id}/"
                detail = http_json(detail_url, headers=headers, timeout=timeout, max_bytes=30_000_000)
                reqs = detail.get("data", {}).get("requests", []) if isinstance(detail, dict) else []
                local_urls: list[str] = []
                for entry in reqs:
                    if not isinstance(entry, dict):
                        continue
                    req = entry.get("request") if isinstance(entry.get("request"), dict) else {}
                    inner = req.get("request") if isinstance(req.get("request"), dict) else req
                    u = inner.get("url") if isinstance(inner, dict) else None
                    if isinstance(u, str):
                        local_urls.append(u)
                        request_urls.append(u)
                item["request_count"] = len(local_urls)
                item["requests"] = local_urls[:5000]
            except Exception as exc:
                item["detail_error"] = str(exc)[:300]
        scans.append(item)
    return {
        "search_url": search_url,
        "total": search.get("total") if isinstance(search, dict) else None,
        "scans": scans,
        "urls": sorted(set(request_urls)),
        "authenticated": bool(headers.get("api-key")),
    }


def securitytrails_subdomains(domain: str, *, timeout: int = 30) -> dict[str, Any]:
    key = load_secrets().get("SECURITYTRAILS_API_KEY")
    if not key:
        raise RuntimeError(f"Falta SECURITYTRAILS_API_KEY en {SECRETS_PATH}")
    url = f"https://api.securitytrails.com/v1/domain/{urllib.parse.quote(domain)}/subdomains"
    data = http_json(url, headers={"APIKEY": key}, timeout=timeout, max_bytes=10_000_000)
    subs = data.get("subdomains", []) if isinstance(data, dict) else []
    hosts = []
    for sub in subs:
        if isinstance(sub, str) and sub.strip():
            hosts.append(f"{sub.strip().lower().rstrip('.')}.{domain}")
    return {"url": url, "hosts": sorted(set(hosts)), "count": len(set(hosts))}


def securitytrails_dns_history(hostname: str, *, timeout: int = 30) -> dict[str, Any]:
    key = load_secrets().get("SECURITYTRAILS_API_KEY")
    if not key:
        raise RuntimeError(f"Falta SECURITYTRAILS_API_KEY en {SECRETS_PATH}")
    output: dict[str, Any] = {"hostname": hostname, "records": {}}
    for record_type in ("a", "aaaa"):
        url = f"https://api.securitytrails.com/v1/history/{urllib.parse.quote(hostname)}/dns/{record_type}"
        try:
            data = http_json(url, headers={"APIKEY": key}, timeout=timeout, max_bytes=10_000_000)
            output["records"][record_type] = data
        except urllib.error.HTTPError as exc:
            output["records"][record_type] = {"error": f"HTTP {exc.code}"}
        except Exception as exc:
            output["records"][record_type] = {"error": str(exc)[:300]}
    return output


def github_code_search(domain: str, *, timeout: int = 35, max_results: int = 100) -> dict[str, Any]:
    token = load_secrets().get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError(f"Falta GITHUB_TOKEN en {SECRETS_PATH}")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.text-match+json",
        "X-GitHub-Api-Version": "2026-03-10",
    }
    query = urllib.parse.urlencode({"q": f'"{domain}"', "per_page": str(max(1, min(max_results, 100)))})
    url = f"https://api.github.com/search/code?{query}"
    data = http_json(url, headers=headers, timeout=timeout, max_bytes=20_000_000)
    items_out: list[dict[str, Any]] = []
    fragments: list[str] = []
    if isinstance(data, dict):
        for item in data.get("items", [])[:max_results]:
            if not isinstance(item, dict):
                continue
            matches = []
            for match in item.get("text_matches", []) or []:
                if not isinstance(match, dict):
                    continue
                fragment = str(match.get("fragment", ""))[:6000]
                if fragment:
                    fragments.append(fragment)
                matches.append({"fragment": fragment, "matches": match.get("matches", [])})
            repo = item.get("repository") if isinstance(item.get("repository"), dict) else {}
            items_out.append({
                "repo": repo.get("full_name"),
                "path": item.get("path"),
                "html_url": item.get("html_url"),
                "text_matches": matches,
            })
    return {
        "search_url": url,
        "total_count": data.get("total_count") if isinstance(data, dict) else None,
        "items": items_out,
        "fragments": fragments,
    }


class _ScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        values = dict(attrs)
        src = values.get("src")
        if src:
            self.scripts.append(src)


def discover_js(hostname: str, domain: str, *, timeout: int = 25) -> dict[str, Any]:
    errors: list[str] = []
    for scheme in ("https", "http"):
        base = f"{scheme}://{hostname}/"
        try:
            raw, ctype, final_url = http_bytes(base, timeout=timeout, max_bytes=3_000_000, insecure=True)
            text = raw.decode("utf-8", errors="replace")
            parser = _ScriptParser()
            parser.feed(text)
            urls = sorted(set(urllib.parse.urljoin(final_url, src) for src in parser.scripts))
            in_scope: list[str] = []
            external: list[str] = []
            for url in urls:
                host = urllib.parse.urlsplit(url).hostname or ""
                if host == domain or host.endswith("." + domain):
                    in_scope.append(url)
                else:
                    external.append(url)
            return {"page_url": final_url, "content_type": ctype, "in_scope": in_scope, "external": external, "errors": errors}
        except Exception as exc:
            errors.append(f"{scheme}: {str(exc)[:300]}")
    return {"page_url": None, "in_scope": [], "external": [], "errors": errors}


def beautify_js(text: str) -> str:
    try:
        import jsbeautifier  # type: ignore
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        opts.preserve_newlines = True
        return jsbeautifier.beautify(text, opts)
    except Exception:
        return text


def _mask_value(value: str) -> str:
    value = value or ""
    if len(value) <= 8:
        return "•" * max(4, len(value))
    if value.startswith("-----BEGIN"):
        return value.splitlines()[0] + " …"
    keep = 4 if len(value) < 32 else 6
    return f"{value[:keep]}…{value[-keep:]}"


def detect_credentials_and_config(text: str, *, max_unique_per_rule: int = 8, context_radius: int = 220) -> list[dict[str, Any]]:
    """Detecta credenciales/config cliente con valores enmascarados.

    La detección es una pista, no una vulnerabilidad. Nunca devuelve el valor completo
    del candidato; conserva un hash corto para deduplicación y contexto enmascarado.
    """
    findings: list[dict[str, Any]] = []
    raw_masks: dict[str, str] = {}
    pending: list[tuple[dict[str, Any], int, int]] = []
    for rule in DETECTION_RULES:
        regex = re.compile(rule["pattern"])
        seen: dict[str, dict[str, Any]] = {}
        for match in regex.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            if not value:
                continue
            digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]
            item = seen.get(digest)
            if item is None:
                if len(seen) >= max_unique_per_rule:
                    continue
                masked = _mask_value(value)
                raw_masks[value] = masked
                item = {
                    "type": rule["id"],
                    "label": rule["label"],
                    "category": rule["category"],
                    "category_label": DETECTION_CATEGORY_LABELS.get(rule["category"], rule["category"]),
                    "confidence": rule["confidence"],
                    "masked_value": masked,
                    "fingerprint": digest,
                    "occurrences": 0,
                    "context": "",
                    "validation_hint": DETECTION_VALIDATION_HINTS.get(rule["id"], "Revisar el contexto y validar manualmente sin asumir impacto."),
                }
                seen[digest] = item
                pending.append((item, match.start(), match.end()))
            item["occurrences"] += 1
        findings.extend(seen.values())

    # Build contexts only after all candidates are known so a nearby second secret
    # cannot leak unmasked inside another finding's context.
    for item, start_pos, end_pos in pending:
        a = max(0, start_pos - context_radius)
        b = min(len(text), end_pos + context_radius)
        context = text[a:b]
        for raw_value, masked in sorted(raw_masks.items(), key=lambda kv: len(kv[0]), reverse=True):
            context = context.replace(raw_value, masked)
        item["context"] = context

    lower = text.lower()
    firebase_terms = sum(1 for term in ("firebaseconfig", "authdomain", "projectid", "storagebucket", "messagingsenderid") if term in lower)
    if firebase_terms >= 2:
        findings.append({
            "type":"firebase_config", "label":"Firebase client configuration",
            "category":"public_client_config", "category_label":DETECTION_CATEGORY_LABELS["public_client_config"],
            "confidence":"medium", "masked_value":"config object", "fingerprint":"firebase-config",
            "occurrences":firebase_terms, "context":"Se detectaron múltiples campos típicos de Firebase client configuration.",
            "validation_hint": DETECTION_VALIDATION_HINTS["firebase_config"]
        })
    return findings

def redact_sensitive_literals(text: str) -> str:
    """Enmascara candidatos antes de enviar contextos a servicios externos."""
    out = text
    for rule in DETECTION_RULES:
        regex = re.compile(rule["pattern"])
        def repl(match):
            value = match.group(1) if match.lastindex else match.group(0)
            if not value:
                return match.group(0)
            return match.group(0).replace(value, _mask_value(value))
        out = regex.sub(repl, out)
    return out


def analyze_js_text(text: str, base_url: str, domain: str, *, max_contexts: int = 120) -> dict[str, Any]:
    absolute = sorted(set(m.group("url").rstrip(",);]") for m in ABS_URL_RE.finditer(text)))
    relative = sorted(set(m.group("path") for m in REL_PATH_RE.finditer(text)))
    source_maps = list(dict.fromkeys(m.group(1).strip().strip('"\'') for m in SOURCEMAP_RE.finditer(text)))

    keywords: dict[str, int] = {}
    lower = text.lower()
    contexts: list[dict[str, str]] = []
    ranges: list[tuple[int, int]] = []
    for keyword in SIGNAL_KEYWORDS:
        count = lower.count(keyword)
        if count:
            keywords[keyword] = count
            pos = 0
            for _ in range(min(count, 5)):
                idx = lower.find(keyword, pos)
                if idx < 0:
                    break
                start = max(0, idx - 650)
                end = min(len(text), idx + len(keyword) + 900)
                if not any(start < b and end > a for a, b in ranges):
                    ranges.append((start, end))
                    contexts.append({"signal": keyword, "context": text[start:end]})
                    if len(contexts) >= max_contexts:
                        break
                pos = idx + len(keyword)
        if len(contexts) >= max_contexts:
            break

    resolved_paths = []
    for path in relative:
        try:
            resolved_paths.append(urllib.parse.urljoin(base_url, path))
        except Exception:
            pass

    in_scope_urls: list[str] = []
    external_urls: list[str] = []
    websocket_urls: list[str] = []
    for url in sorted(set(absolute + resolved_paths)):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme in ("ws", "wss"):
            websocket_urls.append(url)
            continue
        host = parsed.hostname or ""
        if host == domain or host.endswith("." + domain):
            in_scope_urls.append(url)
        else:
            external_urls.append(url)

    detections = detect_credentials_and_config(text)
    detection_counts: dict[str, int] = {}
    for item in detections:
        detection_counts[item["category"]] = detection_counts.get(item["category"], 0) + 1

    return {
        "absolute_urls": absolute,
        "relative_paths": relative,
        "in_scope_urls": sorted(set(in_scope_urls)),
        "external_urls": sorted(set(external_urls)),
        "websockets": sorted(set(websocket_urls)),
        "source_maps": source_maps,
        "keywords": keywords,
        "contexts": contexts,
        "detections": detections,
        "detection_counts": detection_counts,
    }


def classify_sourcemap_source(path: str) -> str:
    low = (path or "").lower()
    if "/node_modules/" in low or low.startswith("webpack://node_modules/"):
        return "dependency"
    if "webpack/runtime/" in low or low.endswith("webpack/bootstrap") or "/webpack/bootstrap" in low:
        return "runtime"
    return "application"


def analyze_sourcemap_data(data: dict[str, Any], base_url: str, domain: str, *, max_source_chars: int = 4_000_000) -> dict[str, Any]:
    sources = data.get("sources", []) if isinstance(data.get("sources"), list) else []
    contents = data.get("sourcesContent", []) if isinstance(data.get("sourcesContent"), list) else []
    counts = {"application":0, "dependency":0, "runtime":0}
    app_sources: list[str] = []
    app_parts: list[str] = []
    content_count = 0
    app_content_count = 0
    total_chars = 0
    for idx, source in enumerate(sources):
        source_name = source if isinstance(source, str) else f"source-{idx}"
        kind = classify_sourcemap_source(source_name)
        counts[kind] = counts.get(kind, 0) + 1
        if kind == "application":
            app_sources.append(source_name)
        content = contents[idx] if idx < len(contents) else None
        if isinstance(content, str) and content.strip():
            content_count += 1
            if kind == "application" and total_chars < max_source_chars:
                remaining = max_source_chars - total_chars
                piece = f"\n/* NEGRO_SOURCE: {source_name} */\n{content[:remaining]}\n"
                app_parts.append(piece)
                total_chars += len(piece)
                app_content_count += 1

    app_text = "".join(app_parts)
    analysis = analyze_js_text(app_text, base_url, domain, max_contexts=160) if app_text else {
        "in_scope_urls": [], "external_urls": [], "websockets": [], "relative_paths": [],
        "keywords": {}, "contexts": [], "source_maps": [], "detections": [], "detection_counts": {}
    }
    return {
        "sources_count": len(sources),
        "sources_content_count": content_count,
        "application_sources_count": counts.get("application",0),
        "dependency_sources_count": counts.get("dependency",0),
        "runtime_sources_count": counts.get("runtime",0),
        "application_sources_with_content": app_content_count,
        "application_sources_sample": app_sources[:120],
        "analysis": analysis,
        "application_text_chars_analyzed": len(app_text),
    }

def estimate_tokens(text: str) -> tuple[int, str]:
    try:
        import tiktoken  # type: ignore
        enc = tiktoken.get_encoding("o200k_base")
        return len(enc.encode(text)), "o200k_base"
    except Exception:
        # Conservative code heuristic; minified JS tends to tokenize densely.
        return max(1, int(len(text.encode("utf-8")) / 3.2)), "heuristic_bytes/3.2"


def ai_payload(local_analysis: dict[str, Any], sourcemap_analysis: dict[str, Any] | None = None, *, max_chars: int = 650000) -> str:
    compact = {
        "urls_in_scope": local_analysis.get("in_scope_urls", [])[:1000],
        "external_urls": local_analysis.get("external_urls", [])[:300],
        "websockets": local_analysis.get("websockets", [])[:200],
        "relative_paths": local_analysis.get("relative_paths", [])[:1500],
        "source_maps_candidates": local_analysis.get("source_maps", [])[:100],
        "keyword_counts": local_analysis.get("keywords", {}),
        "credentials_and_config": local_analysis.get("detections", [])[:80],
    }
    envelope: dict[str, Any] = {"bundle_local_analysis": compact, "source_map_confirmed": bool(sourcemap_analysis)}
    sm_local: dict[str, Any] = {}
    if sourcemap_analysis:
        sm_local = sourcemap_analysis.get("analysis", {}) if isinstance(sourcemap_analysis.get("analysis"), dict) else {}
        envelope["source_map"] = {
            "selected_url": sourcemap_analysis.get("url"),
            "sources_count": sourcemap_analysis.get("sources_count", 0),
            "sources_content_count": sourcemap_analysis.get("sources_content_count", 0),
            "application_sources_count": sourcemap_analysis.get("application_sources_count", 0),
            "dependency_sources_count": sourcemap_analysis.get("dependency_sources_count", 0),
            "runtime_sources_count": sourcemap_analysis.get("runtime_sources_count", 0),
            "application_sources_with_content": sourcemap_analysis.get("application_sources_with_content", 0),
            "application_sources_sample": sourcemap_analysis.get("application_sources_sample", [])[:120],
            "urls_in_scope": sm_local.get("in_scope_urls", [])[:500],
            "relative_paths": sm_local.get("relative_paths", [])[:1000],
            "websockets": sm_local.get("websockets", [])[:100],
            "credentials_and_config": sm_local.get("detections", [])[:100],
            "keyword_counts": sm_local.get("keywords", {}),
        }
    parts = ["NEGRO_EVIDENCE\n" + json.dumps(envelope, ensure_ascii=False, indent=2), "\nCODE_CONTEXTS\n"]
    remaining = max_chars - sum(len(x) for x in parts)
    for origin, analysis in (("bundle", local_analysis), ("source_map_application_code", sm_local)):
        for item in analysis.get("contexts", []) if isinstance(analysis, dict) else []:
            safe_context = redact_sensitive_literals(str(item.get('context','')))
            block = f"\n--- origin={origin} signal={item.get('signal','')} ---\n{safe_context}\n"
            if len(block) > remaining:
                return "".join(parts)
            parts.append(block)
            remaining -= len(block)
    return "".join(parts)

def estimate_ai_cost(payload: str, model: str, output_tokens: int, usd_cop_rate: float) -> dict[str, Any]:
    if model not in OPENAI_PRICING:
        raise ValueError(f"Modelo sin tabla de precio local: {model}")
    input_tokens, method = estimate_tokens(payload)
    prices = OPENAI_PRICING[model]
    long_context = input_tokens > LONG_CONTEXT_THRESHOLD
    in_rate = prices["long_input"] if long_context else prices["input"]
    out_rate = prices["long_output"] if long_context else prices["output"]
    input_usd = (input_tokens / 1_000_000) * in_rate
    output_usd_max = (output_tokens / 1_000_000) * out_rate
    total_usd_max = input_usd + output_usd_max
    return {
        "model": model,
        "input_tokens_est": input_tokens,
        "token_method": method,
        "output_tokens_budget": output_tokens,
        "long_context": long_context,
        "input_rate_per_m": in_rate,
        "output_rate_per_m": out_rate,
        "input_cost_usd_est": input_usd,
        "max_total_usd_est": total_usd_max,
        "usd_cop_rate": usd_cop_rate,
        "max_total_cop_est": total_usd_max * usd_cop_rate,
        "pricing_snapshot": "2026-09-26",
    }


def run_openai_js_analysis(payload: str, *, model: str, output_tokens: int) -> tuple[dict[str, Any], dict[str, Any]]:
    key = load_secrets().get("OPENAI_API_KEY")
    if not key:
        raise RuntimeError(f"Falta OPENAI_API_KEY en {SECRETS_PATH}")
    try:
        from openai import OpenAI  # type: ignore
    except ModuleNotFoundError as exc:
        import sys
        raise RuntimeError(
            "El SDK de OpenAI no está instalado en el Python que ejecuta Negro. "
            f"Python actual: {sys.executable}. Ejecuta ./install-web.sh y verifica que aparezca '✓ openai'."
        ) from exc
    except ImportError as exc:
        import sys
        raise RuntimeError(
            "El paquete openai existe pero falló al importarse. "
            f"Python actual: {sys.executable}. Detalle: {exc}. "
            "Ejecuta ./install-web.sh para reparar/actualizar las dependencias."
        ) from exc

    system = """Analizas evidencia JavaScript de un target de Bug Bounty explícitamente autorizado.
Responde SIEMPRE en español. Mantén en inglés únicamente términos técnicos útiles para pentesting y código, por ejemplo: API key, endpoint, source map, localStorage, WebSocket, Authorization, Bearer token, OAuth, SSO, JWT, role, payload y nombres exactos observados en código.

No declares una vulnerabilidad sólo por aparecer algo en el cliente. Reconstruye comportamiento y señala pistas para validación manual. Usa únicamente la evidencia suministrada; si falta evidencia, dilo. Nunca inventes endpoints, métodos, roles, secretos, impacto ni findings.

Distingue especialmente:
- potential_secret: candidato que podría ser credencial/secreto y requiere validación;
- public_client_config: configuración que normalmente puede ser visible en frontend (por ejemplo Google API key, Firebase config, OAuth Client ID, Sentry DSN, Stripe publishable key); visible NO implica vulnerable;
- surface_config: configuración útil para reconstruir superficie/infraestructura.

Si la evidencia indica source_map_confirmed=true, trátalo como confirmado y usa sus métricas/archivos; no digas que su disponibilidad está sin confirmar. Prioriza código de aplicación y evita convertir node_modules/librerías conocidas en hallazgos.

Return ONLY valid JSON con este schema exacto (los valores textuales deben estar en español):
{
  "summary": "...",
  "architecture": {"api_bases": [], "websockets": [], "graphql": [], "roles": [], "feature_flags": [], "storage_keys": []},
  "observations": [
    {"signal":"high|medium|low", "title":"...", "evidence":"...", "why_interesting":"...", "manual_validation":"..."}
  ],
  "resources": [
    {"url_or_path":"...", "method":"unknown|GET|POST|PUT|PATCH|DELETE", "auth_context":"...", "evidence":"..."}
  ]
}
Mantén los excerpts de evidencia cortos y trazables al contexto suministrado."""
    client = OpenAI(api_key=key)
    response = client.responses.create(
        model=model,
        reasoning={"effort": "low"},
        max_output_tokens=output_tokens,
        instructions=system,
        input=payload,
    )
    text = response.output_text or ""
    parsed: dict[str, Any]
    try:
        parsed = json.loads(text)
    except Exception:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            parsed = json.loads(text[start:end + 1])
        else:
            parsed = {"summary": "No se pudo parsear JSON", "raw": text[:12000], "observations": [], "resources": []}

    usage = getattr(response, "usage", None)
    usage_out = {
        "input_tokens": getattr(usage, "input_tokens", None),
        "output_tokens": getattr(usage, "output_tokens", None),
        "total_tokens": getattr(usage, "total_tokens", None),
    }
    return parsed, usage_out
