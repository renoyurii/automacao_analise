"""
Módulo 2 — Varredura Ativa.

Interface pública: use apenas scan_all() para consumir este módulo.

Todos os scanners executam em paralelo via ThreadPoolExecutor.
O SSL Labs é o mais lento (60–180s); os demais concluem em < 10s.
Tempo total ≈ tempo do SSL Labs.

Se um scanner falhar, os outros continuam — a chave "error" no resultado
indica o que não funcionou, sem interromper o fluxo.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from typing import Any

from colorama import Fore, Style

from .headers_scan import scan_headers
from .ssl_labs import scan_ssl_labs
from .wappalyzer_scan import scan_wappalyzer
from .shodan_scan import scan_ports
from .whois_lookup import scan_whois


def scan_all(url: str) -> dict[str, Any]:
    """
    Executa todos os scanners em paralelo e retorna scan_data.

    Retorna:
    {
        "headers":    {...},   # IP, CDN, raw block para Integridade
        "ssl_labs":   {...},   # Grade, HSTS, TLS versions
        "wappalyzer": {...},   # Stack tecnológica
        "ports":      {...},   # Portas abertas
        "whois":      {...},   # Registro de domínio
    }
    """
    domain = _extract_domain(url)
    print(f"\n{Fore.CYAN}[M2] Iniciando varredura de {domain}{Style.RESET_ALL}")
    print(f"     5 scanners em paralelo — aguarde SSL Labs (~60–180s)\n")

    tasks = {
        "headers":    lambda: scan_headers(url),
        "ssl_labs":   lambda: scan_ssl_labs(domain),
        "wappalyzer": lambda: scan_wappalyzer(url),
        "ports":      lambda: scan_ports(domain),
        "whois":      lambda: scan_whois(domain),
    }

    results: dict[str, Any] = {}

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_key = {executor.submit(fn): key for key, fn in tasks.items()}

        for future in as_completed(future_to_key):
            key = future_to_key[future]
            try:
                results[key] = future.result(timeout=310)
                _print_done(key, results[key])
            except Exception as e:
                results[key] = {"error": str(e)}
                print(f"  {Fore.RED}[{key}] FALHOU: {e}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}[M2] Varredura concluída.{Style.RESET_ALL}")
    return results


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    domain = parsed.netloc or parsed.path
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _print_done(key: str, result: dict) -> None:
    error = result.get("error")
    if error:
        print(f"  {Fore.YELLOW}[{key:<12}] ⚠  {error[:80]}{Style.RESET_ALL}")
    else:
        summary = _summarize(key, result)
        print(f"  {Fore.GREEN}[{key:<12}] ✓  {summary}{Style.RESET_ALL}")


def _summarize(key: str, result: dict) -> str:
    if key == "ssl_labs":
        grade = result.get("grade", "?")
        hsts = "HSTS ✓" if result.get("hsts", {}).get("present") else "HSTS ✗"
        return f"Grade {grade} | {hsts}"
    if key == "headers":
        cdn = result.get("cdn_waf") or "CDN não detectado"
        ip = result.get("ip") or "IP ?"
        return f"{ip} | {cdn}"
    if key == "wappalyzer":
        n = len(result.get("technologies", []))
        return f"{n} tecnologias detectadas"
    if key == "ports":
        ports = result.get("open_ports", [])
        non_std = result.get("non_standard_ports", [])
        src = result.get("source", "")
        alert = f" ⚠ não-padrão: {non_std}" if non_std else ""
        return f"{len(ports)} porta(s) abertas [{src}]{alert}"
    if key == "whois":
        owner = result.get("owner") or "proprietário ?"
        expires = result.get("expires") or "?"
        return f"{owner} | expira {expires}"
    return "OK"
