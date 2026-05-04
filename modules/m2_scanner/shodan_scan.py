"""
Scanner de portas abertas.

Estratégia dupla:
  1. Shodan API (se SHODAN_API_KEY configurada no .env) — dados ricos, porém
     podem estar desatualizados (cache de dias a semanas).
  2. Scan TCP direto via socket (fallback sempre ativo) — tempo real, gratuito,
     sem chave. Cobre as portas não-padrão mais relevantes para segurança web.

Nota sobre Cloudflare: sites protegidos por Cloudflare expõem apenas as portas
do proxy CDN (80/443). Isso é o comportamento esperado e correto — o servidor
de origem não deve ser atingível diretamente.
"""

from __future__ import annotations

import concurrent.futures
import socket
from typing import Any

import requests

from config import SHODAN_API_KEY, EXPECTED_PORTS, BANNER_REQUIRED_PORTS

# Portas não-padrão com alto risco de exposição acidental
_PORTS_TO_PROBE = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    110,   # POP3
    143,   # IMAP
    445,   # SMB
    1433,  # MSSQL
    3306,  # MySQL
    3389,  # RDP — crítico: Windows Remote Desktop
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8080,  # HTTP alternativo
    8443,  # HTTPS alternativo
    8888,  # Jupyter / painel admin
    27017, # MongoDB
]

_TCP_TIMEOUT = 2     # Segundos por tentativa de conexão
_MAX_WORKERS = 20    # Threads paralelas para o scan TCP


def scan_ports(domain: str, ip: str | None = None) -> dict[str, Any]:
    """
    Verifica portas abertas no host.

    Retorna:
    {
        "ip":                 str | None,
        "open_ports":         list[int],
        "non_standard_ports": list[int],   # Portas fora do padrão {80, 443}
        "source":             "shodan" | "tcp_scan",
        "error":              str | None,
    }
    """
    target_ip = ip or _resolve(domain)

    if SHODAN_API_KEY:
        result = _scan_shodan(target_ip)
        if result["error"] is None:
            return result
        # Shodan falhou — cai no TCP scan sem interromper o fluxo
        print(f"  [Portas] Shodan indisponível ({result['error']}). Usando TCP scan.")

    return _scan_tcp(target_ip, domain)


# ── Shodan ────────────────────────────────────────────────────────────────────

def _scan_shodan(ip: str | None) -> dict[str, Any]:
    if not ip:
        return _error_result(None, "IP não resolvido para consulta Shodan")
    try:
        import shodan
    except ImportError:
        return _error_result(ip, "No module named 'shodan'")
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)
        open_ports = sorted(set(host.get("ports", [])))
        return _build_result(ip, open_ports, "shodan")
    except Exception as e:
        return _error_result(ip, str(e))


# ── TCP scan direto ───────────────────────────────────────────────────────────

def _scan_tcp(ip: str | None, domain: str) -> dict[str, Any]:
    """
    Tenta conexão TCP nas portas de _PORTS_TO_PROBE + 80 + 443.
    Usa ThreadPoolExecutor para paralelizar as tentativas.
    """
    if not ip:
        return _error_result(None, f"Não foi possível resolver {domain}")

    all_ports = sorted(set(_PORTS_TO_PROBE + [80, 443]))
    open_ports: list[int] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
        futures = {ex.submit(_probe_port, ip, p): p for p in all_ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass

    return _build_result(ip, sorted(open_ports), "tcp_scan")


def _probe_port(ip: str, port: int) -> bool:
    """
    Verifica se a porta está realmente em serviço.
    Portas de serviço (FTP, SSH, RDP...) exigem banner para evitar
    falsos positivos causados por CDNs que absorvem conexões TCP.
    """
    try:
        with socket.create_connection((ip, port), timeout=_TCP_TIMEOUT) as s:
            if port not in BANNER_REQUIRED_PORTS:
                return True
            # Porta de serviço: aguarda banner (ex: "220 FTP ready")
            s.settimeout(_TCP_TIMEOUT)
            try:
                banner = s.recv(256)
                return len(banner) > 0
            except (socket.timeout, OSError):
                return False
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def _build_result(ip: str | None, open_ports: list[int], source: str) -> dict[str, Any]:
    non_standard = [p for p in open_ports if p not in EXPECTED_PORTS]
    return {
        "ip":                 ip,
        "open_ports":         open_ports,
        "non_standard_ports": non_standard,
        "source":             source,
        "error":              None,
    }


def _error_result(ip: str | None, error: str) -> dict[str, Any]:
    return {
        "ip":                 ip,
        "open_ports":         [],
        "non_standard_ports": [],
        "source":             "tcp_scan",
        "error":              error,
    }
