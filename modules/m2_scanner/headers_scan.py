"""
Scanner de cabeçalhos HTTP.

Responsável por:
- Resolver o IP do domínio
- Capturar os headers HTTP brutos (formato exibido na seção "Integridade" da Ficha)
- Detectar CDN/WAF pela presença de headers característicos
- Registrar a cadeia de redirecionamentos

Saída usada pelo M4 para preencher o bloco "INTEGRIDADE (PRESENÇA DE FIREWALL, WAF...)"
exatamente como aparece nas fichas geradas manualmente.
"""

from __future__ import annotations

import socket
import http.client
from urllib.parse import urlparse
from typing import Any

import requests

_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) "
    "Gecko/20100101 Firefox/124.0"
)
_TIMEOUT = 15

# CDNs e WAFs identificáveis por headers característicos
_CDN_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare":  ["cf-ray", "cf-cache-status", "cf-request-id"],
    "Akamai":      ["x-akamai-request-id", "x-check-cacheable"],
    "Fastly":      ["x-served-by", "x-cache-hits", "fastly-restarts"],
    "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop"],
    "Azure CDN":   ["x-msedge-ref"],
    "Sucuri WAF":  ["x-sucuri-id", "x-sucuri-cache"],
    "Imperva":     ["x-iinfo", "x-cdn"],
}


def scan_headers(url: str) -> dict[str, Any]:
    """
    Retorna:
    {
        "ip": str | None,
        "cdn_waf": str | None,       # ex: "Cloudflare"
        "server": str | None,
        "headers": dict[str, str],   # Todos os headers da resposta final
        "redirect_chain": list[str], # ex: ["HTTP→HTTPS", "www→apex"]
        "raw_block": str,            # Bloco formatado para a seção Integridade da Ficha
        "http_version": str,         # "HTTP/1.1" | "HTTP/2" | "HTTP/3"
        "status_code": int | None,
        "error": str | None,
    }
    """
    domain = _extract_domain(url)
    ip = _resolve_ip(domain)

    try:
        session = requests.Session()
        session.max_redirects = 10
        resp = session.get(
            _ensure_https(url),
            headers={"User-Agent": _USER_AGENT},
            timeout=_TIMEOUT,
            allow_redirects=True,
            verify=True,
        )
    except requests.exceptions.SSLError:
        # Tenta HTTP puro se HTTPS falhar (site muito degradado)
        try:
            resp = requests.get(
                _ensure_http(url),
                headers={"User-Agent": _USER_AGENT},
                timeout=_TIMEOUT,
                allow_redirects=True,
                verify=False,
            )
        except Exception as e:
            return _error_result(ip, str(e))
    except Exception as e:
        return _error_result(ip, str(e))

    headers_dict = dict(resp.headers)
    cdn_waf = _detect_cdn(headers_dict)
    redirect_chain = _build_redirect_chain(resp)
    raw_block = _build_raw_block(ip, cdn_waf, resp)

    return {
        "ip": ip,
        "cdn_waf": cdn_waf,
        "server": headers_dict.get("Server") or headers_dict.get("server"),
        "headers": headers_dict,
        "redirect_chain": redirect_chain,
        "raw_block": raw_block,
        "http_version": _detect_http_version(headers_dict),
        "status_code": resp.status_code,
        "error": None,
    }


# ── Helpers ──────────────────────────────────────────────────────────────────

def _extract_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.netloc or parsed.path


def _resolve_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def _ensure_https(url: str) -> str:
    if url.startswith("http://"):
        return url.replace("http://", "https://", 1)
    if not url.startswith("https://"):
        return f"https://{url}"
    return url


def _ensure_http(url: str) -> str:
    if url.startswith("https://"):
        return url.replace("https://", "http://", 1)
    if not url.startswith("http://"):
        return f"http://{url}"
    return url


def _detect_cdn(headers: dict[str, str]) -> str | None:
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for cdn, signatures in _CDN_SIGNATURES.items():
        if any(sig in headers_lower for sig in signatures):
            return cdn
    # Fallback: campo Server
    server = headers_lower.get("server", "")
    for cdn in _CDN_SIGNATURES:
        if cdn.lower() in server.lower():
            return cdn
    return None


def _build_redirect_chain(resp: requests.Response) -> list[str]:
    chain = []
    for r in resp.history:
        chain.append(f"{r.url}  →  (HTTP {r.status_code})")
    return chain


def _detect_http_version(headers: dict[str, str]) -> str:
    headers_lower = {k.lower(): v for k, v in headers.items()}
    alt_svc = headers_lower.get("alt-svc", "")
    if "h3" in alt_svc:
        return "HTTP/3 (suportado via alt-svc)"
    if "h2" in alt_svc:
        return "HTTP/2"
    return "HTTP/1.1"


def _build_raw_block(ip: str | None, cdn: str | None, resp: requests.Response) -> str:
    """
    Formata o bloco de texto exibido na seção "Integridade" da Ficha,
    replicando exatamente o formato produzido manualmente:

        104.21.10.178
        Cloudflare
        HTTP/1.1 301 Moved Permanently
        Date: ...
        Server: cloudflare
        CF-RAY: ...
    """
    lines: list[str] = []
    if ip:
        lines.append(ip)
    if cdn:
        lines.append(cdn)

    # Primeira resposta da cadeia (antes do redirect final) é mais informativa
    source_resp = resp.history[0] if resp.history else resp
    proto = "HTTP/1.1"
    status_line = f"{proto} {source_resp.status_code} {source_resp.reason or ''}"
    lines.append(status_line)

    for k, v in source_resp.headers.items():
        lines.append(f"{k}: {v}")

    return "\n".join(lines)


def _error_result(ip: str | None, error: str) -> dict[str, Any]:
    return {
        "ip": ip,
        "cdn_waf": None,
        "server": None,
        "headers": {},
        "redirect_chain": [],
        "raw_block": ip or "",
        "http_version": "HTTP/1.1",
        "status_code": None,
        "error": error,
    }
