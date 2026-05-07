"""
Scanner Qualys SSL Labs — API v3.

Não requer chave de API. Rate limit: ~25 análises novas por dia por IP.
Tempo de análise: 60 a 180 segundos. Um loop de polling é obrigatório.

Referência oficial: https://api.ssllabs.com/api/v3/
"""

from __future__ import annotations

import time
from typing import Any

import requests
from colorama import Fore, Style

from config import SSL_LABS_API_BASE, SSL_LABS_POLL_INTERVAL_SEC, SSL_LABS_MAX_WAIT_SEC

_BASE = SSL_LABS_API_BASE
_TIMEOUT = 20          # Timeout por requisição HTTP individual
_POLL_INTERVAL = SSL_LABS_POLL_INTERVAL_SEC
_MAX_WAIT = SSL_LABS_MAX_WAIT_SEC

# IDs de protocolo conforme especificação SSL Labs
_PROTOCOL_NAMES: dict[int, str] = {
    512: "SSL 2.0",
    768: "SSL 3.0",
    769: "TLS 1.0",
    770: "TLS 1.1",
    771: "TLS 1.2",
    772: "TLS 1.3",
}


def scan_ssl_labs(domain: str) -> dict[str, Any]:
    """
    Inicia e aguarda a análise do SSL Labs para o domínio.

    Retorna:
    {
        "grade":   str | None,         # ex: "A", "A+", "B", "F"
        "scores":  dict[str, int],     # Protocol, Key, Cipher
        "hsts": {
            "present": bool,
            "max_age": int | None,
            "include_subdomains": bool,
            "preload": bool,
        },
        "tls": dict[str, bool],        # {"TLS 1.3": True, "TLS 1.2": True, ...}
        "cert_valid": bool | None,
        "sni_required": bool | None,
        "ip": str | None,
        "error": str | None,
    }
    """
    print(f"{Fore.CYAN}[SSL Labs] Iniciando análise de {domain}...{Style.RESET_ALL}")

    try:
        raw = _fetch_analysis(domain)
    except Exception as e:
        return _error_result(str(e))

    if raw.get("status") == "ERROR":
        msg = raw.get("statusMessage", "Erro desconhecido do SSL Labs")
        return _error_result(msg)

    endpoints = raw.get("endpoints", [])
    if not endpoints:
        return _error_result("Nenhum endpoint retornado pelo SSL Labs")

    # Usa o endpoint com melhor nota
    endpoint = _best_endpoint(endpoints)
    details = endpoint.get("details") or {}

    return {
        "grade":      endpoint.get("grade"),
        "scores":     _extract_scores(endpoint),
        "hsts":       _extract_hsts(details),
        "tls":        _extract_tls(details),
        "cert_valid": _extract_cert_validity(details),
        "sni_required": details.get("sniRequired"),
        "ip":         endpoint.get("ipAddress"),
        "error":      None,
    }


# ── Polling loop ─────────────────────────────────────────────────────────────

def _fetch_analysis(domain: str) -> dict:
    """Tenta usar cache recente; se indisponível, inicia análise nova e faz polling."""
    # Tenta cache primeiro (economiza quota diária de 25 análises/IP)
    params_cache = {
        "host":       domain,
        "publish":    "off",
        "fromCache":  "on",
        "maxAge":     24,        # aceita cache de até 24h
        "all":        "done",
    }
    try:
        resp = requests.get(f"{_BASE}/analyze", params=params_cache, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "READY":
            print(f"  {Fore.GREEN}[SSL Labs] Usando resultado em cache.{Style.RESET_ALL}")
            return data
    except Exception:
        pass

    # Cache indisponível — inicia nova análise
    params_start = {
        "host":      domain,
        "publish":   "off",
        "startNew":  "on",
        "all":       "done",
    }

    resp = requests.get(f"{_BASE}/analyze", params=params_start, timeout=_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()

    elapsed = 0
    while data.get("status") not in ("READY", "ERROR"):
        status = data.get("status", "?")
        pct = _progress_pct(data)
        print(
            f"  {Fore.YELLOW}[SSL Labs] {status} {pct}  "
            f"({elapsed}s decorridos){Style.RESET_ALL}",
            end="\r",
        )

        time.sleep(_POLL_INTERVAL)
        elapsed += _POLL_INTERVAL

        if elapsed >= _MAX_WAIT:
            raise TimeoutError(
                f"SSL Labs não concluiu em {_MAX_WAIT}s. "
                "Tente novamente em alguns minutos."
            )

        resp = requests.get(
            f"{_BASE}/analyze",
            params={"host": domain, "all": "done"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

    if data.get("status") == "READY":
        print(
            f"  {Fore.GREEN}[SSL Labs] Análise concluída ({elapsed}s).          {Style.RESET_ALL}"
        )
    else:
        print(
            f"  {Fore.RED}[SSL Labs] Finalizado com erro ({elapsed}s).          {Style.RESET_ALL}"
        )
    return data


def _progress_pct(data: dict) -> str:
    endpoints = data.get("endpoints", [])
    if not endpoints:
        return ""
    pcts = [e.get("progress", 0) or 0 for e in endpoints]
    avg = sum(pcts) // len(pcts) if pcts else 0
    return f"[{avg}%]"


# ── Extratores de campos ──────────────────────────────────────────────────────

def _best_endpoint(endpoints: list[dict]) -> dict:
    """Retorna o endpoint com melhor grade (A+ > A > B > ... > F)."""
    grade_order = ["A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M"]

    def _rank(ep: dict) -> int:
        g = ep.get("grade", "Z")
        try:
            return grade_order.index(g)
        except ValueError:
            return 99

    return min(endpoints, key=_rank)


def _extract_scores(endpoint: dict) -> dict[str, int | None]:
    details = endpoint.get("details") or {}
    return {
        "suporte_protocolo": details.get("protScore"),
        "chaves":            details.get("keyScore"),
        "forca_cifra":       details.get("cipherScore"),
    }


def _extract_hsts(details: dict) -> dict[str, Any]:
    policy = details.get("hstsPolicy") or {}
    status = policy.get("status", "absent")
    present = status == "present"
    return {
        "present":           present,
        "max_age":           policy.get("maxAge") if present else None,
        "include_subdomains": bool(policy.get("includeSubDomains")) if present else False,
        "preload":           bool(policy.get("preload")) if present else False,
    }


def _extract_tls(details: dict) -> dict[str, bool]:
    supported_ids: set[int] = set()
    for proto in details.get("protocols", []):
        pid = proto.get("id")
        if pid is not None:
            supported_ids.add(int(pid))

    return {
        name: (pid in supported_ids)
        for pid, name in _PROTOCOL_NAMES.items()
    }


def _extract_cert_validity(details: dict) -> bool | None:
    cert_chains = details.get("certChains") or []
    if not cert_chains:
        return None
    # Se todas as chains tiverem issues, o certificado é inválido
    issues = [c.get("issues", 0) for c in cert_chains]
    return all(i == 0 for i in issues)


def _error_result(error: str) -> dict[str, Any]:
    return {
        "grade":      None,
        "scores":     {"suporte_protocolo": None, "chaves": None, "forca_cifra": None},
        "hsts":       {"present": False, "max_age": None, "include_subdomains": False, "preload": False},
        "tls":        {name: False for name in _PROTOCOL_NAMES.values()},
        "cert_valid": None,
        "sni_required": None,
        "ip":         None,
        "error":      error,
    }
