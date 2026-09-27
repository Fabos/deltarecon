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
    req_headers = {"User-Agent": "Negro-Recon/0.7.2", "Accept": "application/json"}
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
    req = urllib.request.Request(url, headers={"User-Agent": "Negro-Recon/0.7.2", "Accept": "*/*"})
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

    return {
        "absolute_urls": absolute,
        "relative_paths": relative,
        "in_scope_urls": sorted(set(in_scope_urls)),
        "external_urls": sorted(set(external_urls)),
        "websockets": sorted(set(websocket_urls)),
        "source_maps": source_maps,
        "keywords": keywords,
        "contexts": contexts,
    }


def estimate_tokens(text: str) -> tuple[int, str]:
    try:
        import tiktoken  # type: ignore
        enc = tiktoken.get_encoding("o200k_base")
        return len(enc.encode(text)), "o200k_base"
    except Exception:
        # Conservative code heuristic; minified JS tends to tokenize densely.
        return max(1, int(len(text.encode("utf-8")) / 3.2)), "heuristic_bytes/3.2"


def ai_payload(local_analysis: dict[str, Any], *, max_chars: int = 650000) -> str:
    compact = {
        "urls_in_scope": local_analysis.get("in_scope_urls", [])[:1000],
        "external_urls": local_analysis.get("external_urls", [])[:300],
        "websockets": local_analysis.get("websockets", [])[:200],
        "relative_paths": local_analysis.get("relative_paths", [])[:1500],
        "source_maps": local_analysis.get("source_maps", [])[:100],
        "keyword_counts": local_analysis.get("keywords", {}),
    }
    parts = ["LOCAL_EXTRACTION\n" + json.dumps(compact, ensure_ascii=False, indent=2), "\nCODE_CONTEXTS\n"]
    remaining = max_chars - sum(len(x) for x in parts)
    for item in local_analysis.get("contexts", []):
        block = f"\n--- signal={item.get('signal','')} ---\n{item.get('context','')}\n"
        if len(block) > remaining:
            break
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

    system = """You analyze JavaScript evidence from an explicitly authorized bug-bounty target.
Do not claim a vulnerability from client-side code alone. Reconstruct application behavior and identify high-signal items for manual validation. Use only the supplied evidence; if evidence is insufficient, say so. Never invent endpoints, methods, roles, secrets, impact, or findings.
Return ONLY valid JSON with this schema:
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
Keep evidence excerpts short and traceable to the supplied contexts."""
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
