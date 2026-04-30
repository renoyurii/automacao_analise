"""
Testes do Módulo 3 — Motor de Decisão.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from modules.m3_engine import evaluate


def _scan_data() -> dict:
    return {
        "headers": {
            "status_code": 200,
            "cdn_waf": "Cloudflare",
            "raw_block": "Server: cloudflare",
        },
        "ssl_labs": {
            "grade": "A",
            "scores": {"suporte_protocolo": 100, "chaves": 100, "forca_cifra": 100},
            "hsts": {"present": True, "max_age": 31_536_000},
            "tls": {
                "TLS 1.3": True,
                "TLS 1.2": True,
                "TLS 1.1": False,
                "TLS 1.0": False,
                "SSL 3.0": False,
                "SSL 2.0": False,
            },
            "cert_valid": True,
        },
        "wappalyzer": {"technologies": []},
        "ports": {"open_ports": [80, 443], "non_standard_ports": [], "source": "test"},
        "whois": {"owner": "Leiloeiro Teste", "expires": "20990101", "raw": "domain: exemplo.com.br"},
    }


def test_disponibilidade_declarada_fica_conforme():
    claimed = {
        "redundancy_claimed": True,
        "backup_claimed": True,
        "energy_redundancy": True,
        "firewall_waf": ["Cloudflare"],
        "os_versions": [],
        "raw_sections": {
            "redundancia": "Redundância declarada.",
            "backup": "Backup declarado.",
            "energia": "Energia declarada.",
        },
    }

    result = evaluate(claimed, _scan_data(), "https://exemplo.com.br", "exemplo.com.br")

    disponibilidade = result["checks"]["disponibilidade"]
    assert disponibilidade["redundancia"]["status"] == "CONFORME"
    assert disponibilidade["backup"]["status"] == "CONFORME"
    assert disponibilidade["energia"]["status"] == "CONFORME"


def test_disponibilidade_nao_declarada_continua_nao_conforme():
    claimed = {
        "redundancy_claimed": True,
        "backup_claimed": False,
        "energy_redundancy": True,
        "firewall_waf": ["Cloudflare"],
        "os_versions": [],
        "raw_sections": {
            "redundancia": "Redundância declarada.",
            "energia": "Energia declarada.",
        },
    }

    result = evaluate(claimed, _scan_data(), "https://exemplo.com.br", "exemplo.com.br")

    assert result["checks"]["disponibilidade"]["backup"]["status"] == "NÃO CONFORME"
