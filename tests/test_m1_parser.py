"""
Testes do Módulo 1 — Parser de Documentos.

Os testes portáveis usam os documentos de referência versionados no projeto.
Os testes com documentos reais do SEI continuam disponíveis como integração,
mas são ignorados quando esses PDFs não existem ou não podem ser lidos pelo
ambiente atual.

Execute com:
    python -m pytest tests/test_m1_parser.py -v
"""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from modules.m1_parser import parse_document
from modules.m1_parser.claim_extractor import extract_claims
from modules.m1_parser.pdf_reader import read_pdf
from modules.m1_parser.docx_reader import read_docx

# ── Caminhos dos documentos ──────────────────────────────────────────────────

LOCAL_PDF = PROJECT_ROOT / "docs/referencia/arquivos_base/leiloeiro.pdf"
LOCAL_DOCX = PROJECT_ROOT / "docs/referencia/arquivos_base/leiloeiro.docx"

SEI_ROOT = Path(os.getenv("SEI_ROOT", ""))

PDF_SAMPLE_A = SEI_ROOT / os.getenv("PDF_SAMPLE_A", "sample_a.pdf") if SEI_ROOT.name else Path("sample_a.pdf")
PDF_SAMPLE_B = SEI_ROOT / os.getenv("PDF_SAMPLE_B", "sample_b.pdf") if SEI_ROOT.name else Path("sample_b.pdf")


def _require_readable(path: Path, label: str) -> Path:
    try:
        with path.open("rb") as fh:
            fh.read(1)
    except OSError as exc:
        pytest.skip(f"{label} indisponível para teste de integração: {path} ({exc})")
    return path


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def claims_local_pdf():
    return parse_document(LOCAL_PDF)


@pytest.fixture(scope="module")
def claims_local_docx():
    return parse_document(LOCAL_DOCX)


@pytest.fixture(scope="module")
def claims_sample_a():
    return parse_document(_require_readable(PDF_SAMPLE_A, "PDF_SAMPLE_A"))


@pytest.fixture(scope="module")
def claims_sample_b():
    return parse_document(_require_readable(PDF_SAMPLE_B, "PDF_SAMPLE_B"))


# ── Testes: estrutura do retorno ─────────────────────────────────────────────

class TestReturnStructure:
    REQUIRED_KEYS = [
        "hsts_claimed", "tls_versions_claimed", "ssl_cert_claimed",
        "os_versions", "virtualization", "firewall_waf", "backup_claimed",
        "redundancy_claimed", "energy_redundancy", "monitoring_url",
        "open_ports_declared", "update_routine", "datacenter",
        "evidence", "raw_sections",
    ]

    def test_sample_a_has_all_keys(self, claims_sample_a):
        for key in self.REQUIRED_KEYS:
            assert key in claims_sample_a, f"Chave ausente: {key}"

    def test_sample_b_has_all_keys(self, claims_sample_b):
        for key in self.REQUIRED_KEYS:
            assert key in claims_sample_b, f"Chave ausente: {key}"

    def test_tls_versions_is_list(self, claims_sample_a):
        assert isinstance(claims_sample_a["tls_versions_claimed"], list)

    def test_ports_is_list_of_ints(self, claims_sample_b):
        ports = claims_sample_b["open_ports_declared"]
        assert isinstance(ports, list)
        assert all(isinstance(p, int) for p in ports)


# ── Testes portáveis: fixtures versionadas no projeto ────────────────────────

class TestPortableFixtures:
    def test_local_pdf_has_all_keys(self, claims_local_pdf):
        for key in TestReturnStructure.REQUIRED_KEYS:
            assert key in claims_local_pdf, f"Chave ausente: {key}"

    def test_local_docx_has_all_keys(self, claims_local_docx):
        for key in TestReturnStructure.REQUIRED_KEYS:
            assert key in claims_local_docx, f"Chave ausente: {key}"

    def test_local_pdf_reader_returns_text(self):
        result = read_pdf(LOCAL_PDF)
        assert len(result["text"]) > 100
        assert result["source_format"] == "pdf"
        assert result["total_page_count"] > 0

    def test_local_docx_reader_returns_text(self):
        result = read_docx(LOCAL_DOCX)
        assert len(result["text"]) > 100
        assert result["source_format"] == "docx"

    def test_evidence_entries_have_source_and_page_shape(self, claims_local_pdf):
        ev = claims_local_pdf.get("evidence", {})
        for key in ("redundancy", "backup", "energy", "hsts", "ssl_cert"):
            for entry in ev.get(key, []):
                assert isinstance(entry, dict)
                assert "quote" in entry
                assert "source" in entry
                assert "page" in entry
                assert entry["source"] == LOCAL_PDF.name
                assert entry["page"] is None or isinstance(entry["page"], int)

    def test_parse_document_accepts_custom_source_name(self):
        result = parse_document(str(LOCAL_PDF), source_name="custom_name.pdf")
        ev = result.get("evidence", {})
        for key in ("redundancy", "backup", "energy"):
            for entry in ev.get(key, []):
                assert entry["source"] == "custom_name.pdf"


# ── Testes: evidências específicas de disponibilidade ────────────────────────

class TestAvailabilityEvidence:
    def test_extracts_specific_labeled_availability_evidence(self):
        text = """
        Relatório técnico do ambiente web
        1. Disponibilidade
        Redundância de serviço => A aplicação está hospedada em ambiente com
        balanceador de carga e servidores redundantes, garantindo alta disponibilidade
        em caso de falha.
        Backup e recuperação => São realizados backups diários com retenção de
        30 dias e testes periódicos de restauração.
        Recurso contínuo de energia => O datacenter possui nobreaks e gerador
        para alimentação ininterrupta dos servidores.
        2. Integridade
        Firewall Cloudflare.
        """

        result = extract_claims({"text": text, "image_page_count": 0})

        assert result["redundancy_claimed"] is True
        assert result["backup_claimed"] is True
        assert result["energy_redundancy"] is True
        # extract_claims devolve list[str]. parse_document é que enriquece
        # para list[dict{quote, source, page}]; aqui chamamos direto, então
        # ainda esperamos strings.
        ev = result["evidence"]
        assert any("balanceador de carga" in q.lower() for q in ev["redundancy"])
        assert any("backups diários" in q.lower() for q in ev["backup"])
        assert any("nobreaks" in q.lower() for q in ev["energy"])

    def test_ignores_methodology_as_availability_evidence(self):
        text = """
        2.2. VERIFICAÇÃO DE DISPONIBILIDADE
        Esta etapa compreende a avaliação dos seguintes aspectos relacionados à
        disponibilidade e resiliência da infraestrutura:
        • Redundância de serviço: verificação da existência de mecanismos que
        garantam a continuidade operacional em caso de falhas;
        • Rotina de backup e recuperação: análise dos procedimentos adotados para
        cópia de segurança e restauração de dados;
        • Redundância de energia elétrica: avaliação da existência de sistemas de
        alimentação ininterrupta (nobreak/gerador) para garantir a operação contínua.
        """

        result = extract_claims({"text": text, "image_page_count": 0})

        # Cada bullet menciona o termo, mas sempre dentro do template (3+
        # itens na mesma janela). O regex deve descartar todas as sentenças
        # como template e portanto não promover os booleanos para True.
        ev = result["evidence"]
        assert ev["redundancy"] == []
        assert ev["backup"] == []
        assert ev["energy"] == []
        assert result["redundancy_claimed"] is None
        assert result["backup_claimed"] is None
        assert result["energy_redundancy"] is None


# ── Testes: Sample A (declaração em bullet points) ──────────────────────────

class TestSampleA:
    def test_hsts_not_claimed(self, claims_sample_a):
        assert claims_sample_a["hsts_claimed"] is False, (
            f"HSTS deveria ser False (não implementado). "
            f"Obtido: {claims_sample_a['hsts_claimed']}"
        )

    def test_ssl_cert_claimed(self, claims_sample_a):
        assert claims_sample_a["ssl_cert_claimed"] is True

    def test_windows_server_detected(self, claims_sample_a):
        os_list = [v.lower() for v in claims_sample_a["os_versions"]]
        assert any("windows" in v for v in os_list), (
            f"Windows Server não detectado. OS encontrados: {claims_sample_a['os_versions']}"
        )

    def test_hyperv_detected(self, claims_sample_a):
        assert "Hyper-V" in claims_sample_a["virtualization"], (
            f"Hyper-V não detectado. Virtualização encontrada: {claims_sample_a['virtualization']}"
        )

    def test_cloudflare_detected(self, claims_sample_a):
        fw = [f.lower() for f in claims_sample_a["firewall_waf"]]
        assert any("cloudflare" in f for f in fw), (
            f"Cloudflare não detectado nos firewalls: {claims_sample_a['firewall_waf']}"
        )

    def test_backup_claimed(self, claims_sample_a):
        assert claims_sample_a["backup_claimed"] is True

    def test_redundancy_claimed(self, claims_sample_a):
        assert claims_sample_a["redundancy_claimed"] is True

    def test_raw_sections_not_empty(self, claims_sample_a):
        assert len(claims_sample_a["raw_sections"]) > 0


# ── Testes: Sample B (relatório técnico estruturado) ─────────────────────────

class TestSampleB:
    def test_ports_detected(self, claims_sample_b):
        ports = claims_sample_b["open_ports_declared"]
        assert 80 in ports, f"Porta 80 não detectada. Portas encontradas: {ports}"
        assert 443 in ports, f"Porta 443 não detectada. Portas encontradas: {ports}"

    def test_monitoring_url_detected(self, claims_sample_b):
        url = claims_sample_b["monitoring_url"]
        assert url is not None, "URL de monitoramento não detectada"

    def test_backup_claimed(self, claims_sample_b):
        assert claims_sample_b["backup_claimed"] is True

    def test_redundancy_claimed(self, claims_sample_b):
        assert claims_sample_b["redundancy_claimed"] is True

    def test_windows_server_detected(self, claims_sample_b):
        os_list = [v.lower() for v in claims_sample_b["os_versions"]]
        assert any("windows" in v for v in os_list), (
            f"Windows Server não detectado: {claims_sample_b['os_versions']}"
        )

    def test_firewall_detected(self, claims_sample_b):
        assert len(claims_sample_b["firewall_waf"]) > 0, (
            "Nenhum firewall/WAF detectado"
        )


# ── Testes: readers individuais ───────────────────────────────────────────────

class TestPdfReader:
    def test_returns_text(self):
        result = read_pdf(_require_readable(PDF_SAMPLE_A, "PDF_SAMPLE_A"))
        assert len(result["text"]) > 100
        assert result["source_format"] == "pdf"
        assert result["page_count"] > 0

    def test_sample_b_has_sections(self):
        result = read_pdf(_require_readable(PDF_SAMPLE_B, "PDF_SAMPLE_B"))
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

    def test_pdf_sample_a_returns_dict(self):
        result = parse_document(_require_readable(PDF_SAMPLE_A, "PDF_SAMPLE_A"))
        assert isinstance(result, dict)

    def test_pdf_sample_b_returns_dict(self):
        result = parse_document(_require_readable(PDF_SAMPLE_B, "PDF_SAMPLE_B"))
        assert isinstance(result, dict)
