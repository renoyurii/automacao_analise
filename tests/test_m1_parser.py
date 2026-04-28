"""
Testes do Módulo 1 — Parser de Documentos.

Usa os documentos reais do processo como fixtures, sem mocks:
  - Declaração Erika Maciel (PDF) → SEI 2022-06125971
  - Relatório técnico Frederico Leilões (PDF) → SEI 2021-06115087

Execute com:
    python -m pytest tests/test_m1_parser.py -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from modules.m1_parser import parse_document
from modules.m1_parser.pdf_reader import read_pdf
from modules.m1_parser.docx_reader import read_docx

# ── Caminhos dos documentos reais ────────────────────────────────────────────

SEI_ROOT = "/Users/renoyuri/Documents/Estágio/SEI /Leiloeiro"

PDF_ERIKA = f"{SEI_ROOT}/2022-06125971 - Erika Maciel Ramos/SEI - 2022-06125971.pdf"
PDF_FREDERICO = f"{SEI_ROOT}/2021-06115087/SEI - 2021-06115087.pdf"


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def claims_erika():
    return parse_document(PDF_ERIKA)


@pytest.fixture(scope="module")
def claims_frederico():
    return parse_document(PDF_FREDERICO)


# ── Testes: estrutura do retorno ─────────────────────────────────────────────

class TestReturnStructure:
    REQUIRED_KEYS = [
        "hsts_claimed", "tls_versions_claimed", "ssl_cert_claimed",
        "os_versions", "virtualization", "firewall_waf", "backup_claimed",
        "redundancy_claimed", "energy_redundancy", "monitoring_url",
        "open_ports_declared", "update_routine", "datacenter", "raw_sections",
    ]

    def test_erika_has_all_keys(self, claims_erika):
        for key in self.REQUIRED_KEYS:
            assert key in claims_erika, f"Chave ausente: {key}"

    def test_frederico_has_all_keys(self, claims_frederico):
        for key in self.REQUIRED_KEYS:
            assert key in claims_frederico, f"Chave ausente: {key}"

    def test_tls_versions_is_list(self, claims_erika):
        assert isinstance(claims_erika["tls_versions_claimed"], list)

    def test_ports_is_list_of_ints(self, claims_frederico):
        ports = claims_frederico["open_ports_declared"]
        assert isinstance(ports, list)
        assert all(isinstance(p, int) for p in ports)


# ── Testes: Erika Maciel (declaração em bullet points) ──────────────────────

class TestErikaMaciel:
    def test_hsts_not_claimed(self, claims_erika):
        # Declaração diz "Recomenda-se a implementação do HSTS" = NÃO implementado
        assert claims_erika["hsts_claimed"] is False, (
            f"HSTS deveria ser False (não implementado). "
            f"Obtido: {claims_erika['hsts_claimed']}"
        )

    def test_ssl_cert_claimed(self, claims_erika):
        assert claims_erika["ssl_cert_claimed"] is True, (
            "SSL declarado como 'Sim' na declaração da Erika Maciel"
        )

    def test_windows_server_detected(self, claims_erika):
        os_list = [v.lower() for v in claims_erika["os_versions"]]
        assert any("windows" in v for v in os_list), (
            f"Windows Server não detectado. OS encontrados: {claims_erika['os_versions']}"
        )

    def test_hyperv_detected(self, claims_erika):
        assert "Hyper-V" in claims_erika["virtualization"], (
            f"Hyper-V não detectado. Virtualização encontrada: {claims_erika['virtualization']}"
        )

    def test_cloudflare_detected(self, claims_erika):
        fw = [f.lower() for f in claims_erika["firewall_waf"]]
        assert any("cloudflare" in f for f in fw), (
            f"Cloudflare não detectado nos firewalls: {claims_erika['firewall_waf']}"
        )

    def test_backup_claimed(self, claims_erika):
        assert claims_erika["backup_claimed"] is True, (
            "Declaração menciona 'backups externos na MSP Backups'"
        )

    def test_redundancy_claimed(self, claims_erika):
        assert claims_erika["redundancy_claimed"] is True, (
            "Declaração menciona 'replicação de dados entre servidores'"
        )

    def test_raw_sections_not_empty(self, claims_erika):
        assert len(claims_erika["raw_sections"]) > 0


# ── Testes: Frederico Leilões (relatório técnico estruturado) ────────────────

class TestFredericoLeiloes:
    def test_ports_detected(self, claims_frederico):
        ports = claims_frederico["open_ports_declared"]
        assert 80 in ports, f"Porta 80 não detectada. Portas encontradas: {ports}"
        assert 443 in ports, f"Porta 443 não detectada. Portas encontradas: {ports}"

    def test_monitoring_url_detected(self, claims_frederico):
        url = claims_frederico["monitoring_url"]
        assert url is not None, "URL de monitoramento não detectada"
        assert "visar" in url.lower() or "monit" in url.lower(), (
            f"URL de monitoramento inesperada: {url}"
        )

    def test_backup_claimed(self, claims_frederico):
        assert claims_frederico["backup_claimed"] is True

    def test_redundancy_claimed(self, claims_frederico):
        assert claims_frederico["redundancy_claimed"] is True

    def test_windows_server_detected(self, claims_frederico):
        os_list = [v.lower() for v in claims_frederico["os_versions"]]
        assert any("windows" in v for v in os_list), (
            f"Windows Server não detectado: {claims_frederico['os_versions']}"
        )

    def test_firewall_detected(self, claims_frederico):
        assert len(claims_frederico["firewall_waf"]) > 0, (
            "Nenhum firewall/WAF detectado no relatório do Frederico"
        )


# ── Testes: readers individuais ───────────────────────────────────────────────

class TestPdfReader:
    def test_returns_text(self):
        result = read_pdf(PDF_ERIKA)
        assert len(result["text"]) > 100
        assert result["source_format"] == "pdf"
        assert result["page_count"] > 0

    def test_frederico_has_sections(self):
        result = read_pdf(PDF_FREDERICO)
        text_lower = result["text"].lower()
        assert "disponibilidade" in text_lower
        assert "firewall" in text_lower

    def test_invalid_path_raises(self):
        with pytest.raises(FileNotFoundError):
            read_pdf("/caminho/que/nao/existe.pdf")


class TestDocxReader:
    def test_invalid_path_raises(self):
        with pytest.raises(FileNotFoundError):
            read_docx("/caminho/que/nao/existe.docx")


# ── Testes: parse_document (interface pública) ───────────────────────────────

class TestParseDocument:
    def test_unsupported_format_raises(self, tmp_path):
        dummy = tmp_path / "arquivo.txt"
        dummy.write_text("conteúdo")
        with pytest.raises(ValueError, match="Formato não suportado"):
            parse_document(str(dummy))

    def test_pdf_erika_returns_dict(self):
        result = parse_document(PDF_ERIKA)
        assert isinstance(result, dict)

    def test_pdf_frederico_returns_dict(self):
        result = parse_document(PDF_FREDERICO)
        assert isinstance(result, dict)
