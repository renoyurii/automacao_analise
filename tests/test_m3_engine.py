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
        "whois": {"owner": "Declarante Teste", "expires": "20990101", "raw": "domain: exemplo.com.br"},
    }


def _ev(quote: str, source: str = "leiloeiro.pdf", page: int | None = 1) -> dict:
    return {"quote": quote, "source": source, "page": page}


def test_disponibilidade_declarada_fica_conforme():
    claimed = {
        "redundancy_claimed": True,
        "backup_claimed": True,
        "energy_redundancy": True,
        "firewall_waf": ["Cloudflare"],
        "os_versions": [],
        "evidence": {
            "hsts": [], "ssl_cert": [],
            "redundancy": [_ev("Servidores em alta disponibilidade com balanceador de carga.")],
            "backup":     [_ev("Backups diários automatizados, retenção 30 dias.")],
            "energy":     [_ev("Datacenter com nobreak e gerador de emergência.")],
        },
        "raw_sections": {},
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
        "evidence": {
            "hsts": [], "ssl_cert": [],
            "redundancy": [_ev("Servidores em alta disponibilidade.")],
            "backup":     [],
            "energy":     [_ev("Datacenter com nobreak.")],
        },
        "raw_sections": {},
    }

    result = evaluate(claimed, _scan_data(), "https://exemplo.com.br", "exemplo.com.br")

    assert result["checks"]["disponibilidade"]["backup"]["status"] == "NÃO CONFORME"


def test_disponibilidade_sem_evidencia_alguma_eh_nao_conforme():
    """Boolean True isolado (sem evidência textual) NÃO é suficiente."""
    claimed = {
        "redundancy_claimed": True,
        "backup_claimed": True,
        "energy_redundancy": True,
        "firewall_waf": ["Cloudflare"],
        "os_versions": [],
        "evidence": {"hsts": [], "ssl_cert": [], "redundancy": [], "backup": [], "energy": []},
        "raw_sections": {},
    }

    result = evaluate(claimed, _scan_data(), "https://exemplo.com.br", "exemplo.com.br")

    disp = result["checks"]["disponibilidade"]
    assert disp["redundancia"]["status"] == "NÃO CONFORME"
    assert disp["backup"]["status"] == "NÃO CONFORME"
    assert disp["energia"]["status"] == "NÃO CONFORME"
    assert result["overall_status"] == "NÃO CONFORME"


def test_disponibilidade_inferida_eh_atencao():
    """Evidência apenas inferida ([INFERIDO]) ⇒ ATENÇÃO, não CONFORME."""
    claimed = {
        "redundancy_claimed": True,
        "backup_claimed": True,
        "energy_redundancy": True,
        "firewall_waf": ["Cloudflare"],
        "os_versions": [],
        "evidence": {
            "hsts": [], "ssl_cert": [],
            "redundancy": [_ev('[INFERIDO] AWS — alta disponibilidade nativa. Trecho do documento: "hospedado na AWS"')],
            "backup":     [_ev("Backups diários.")],
            "energy":     [_ev('[INFERIDO] AWS — energia redundante por SLA. Trecho do documento: "AWS"')],
        },
        "raw_sections": {},
    }

    result = evaluate(claimed, _scan_data(), "https://exemplo.com.br", "exemplo.com.br")
    disp = result["checks"]["disponibilidade"]
    assert disp["redundancia"]["status"] == "ATENÇÃO"
    assert disp["backup"]["status"] == "CONFORME"
    assert disp["energia"]["status"] == "ATENÇÃO"


def test_portas_anomalas_nao_derrubam_overall():
    """Portas viram ATENÇÃO; overall continua CONFORME."""
    scan = _scan_data()
    scan["ports"] = {
        "open_ports": [80, 443, 22, 3306],
        "non_standard_ports": [22, 3306],
        "source": "tcp_scan",
    }
    claimed = {
        "redundancy_claimed": True,
        "backup_claimed": True,
        "energy_redundancy": True,
        "firewall_waf": ["Cloudflare"],
        "os_versions": [],
        "evidence": {
            "hsts": [], "ssl_cert": [],
            "redundancy": [_ev("HA com balanceador.")],
            "backup":     [_ev("Backups diários.")],
            "energy":     [_ev("UPS e gerador.")],
        },
        "raw_sections": {},
    }
    result = evaluate(claimed, scan, "https://exemplo.com.br", "exemplo.com.br")
    assert result["checks"]["portas"]["status"] == "ATENÇÃO"
    assert result["overall_status"] == "CONFORME"
    assert "portas" not in result["conclusao"].lower()
