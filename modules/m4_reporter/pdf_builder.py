"""
Geração da Ficha de Verificação em PDF.

O PDF segue a estrutura da ficha institucional: cabeçalho, introdução,
gráfico/pontuação SSL Labs, seções numeradas, recomendações e conclusão final.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from typing import Any, Iterable

from fpdf import FPDF, FontFace, XPos, YPos
from fpdf.enums import TableBordersLayout, TableCellFillMode

from config import REPORT_FOOTER, REPORT_HEADER_LINE1, REPORT_HEADER_LINE2

# ── Sanitização de texto para Latin-1 ────────────────────────────────────────

_UNICODE_MAP = str.maketrans({
    "—": "-",
    "–": "-",
    "−": "-",
    "‘": "'",
    "’": "'",
    "“": '"',
    "”": '"',
    "…": "...",
    "•": "*",
    "·": ".",
    "→": "->",
    "⇒": "=>",
    "⚠": "!",
    "✅": "OK",
    "❌": "X",
    "🔵": "*",
    " ": " ",
})

# ── Paleta inspirada na ficha/manual ─────────────────────────────────────────

_BLUE       = (0, 42, 125)
_BLUE_MID   = (82, 105, 132)
_BLUE_LIGHT = (219, 228, 241)
_GREEN      = (104, 173, 67)
_GREEN_DARK = (73, 145, 45)
_GREEN_BG   = (123, 185, 88)
_RED        = (198, 40, 40)
_AMBER      = (230, 81, 0)
_GRAY       = (135, 135, 135)
_LIGHT_GRAY = (242, 242, 242)
_TEXT       = (20, 20, 20)
_WHITE      = (255, 255, 255)
_BLACK      = (0, 0, 0)

_STATUS_FG = {
    "CONFORME": _GREEN_DARK,
    "NÃO CONFORME": _RED,
    "ATENÇÃO": _AMBER,
    "NÃO VERIFICÁVEL": (84, 110, 122),
}

_TABLE_HDR = FontFace(emphasis="BOLD", color=_WHITE, fill_color=_BLUE_MID)
_TABLE_BODY_FILL = (255, 255, 255)
_TABLE_ALT_FILL = (240, 243, 247)

_TLS_ROWS = [
    ("TLS 1.3", "TLS 1.3"),
    ("TLS 1.2", "TLS 1.2"),
    ("TLS 1.1", "TLS 1.1"),
    ("TLS 1.0", "TLS 1.0"),
    ("SSL 3.0", "SSL3 - SEGURANÇA"),
    ("SSL 2.0", "SSL2 - SEGURANÇA"),
]


class _FichaPDF(FPDF):
    def __init__(self, domain: str, anal_date: str) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self._domain = domain
        self._anal_date = anal_date
        self.set_margins(left=18, top=28, right=18)
        self.set_auto_page_break(auto=True, margin=22)

    def normalize_text(self, txt: str) -> str:
        txt = str(txt).translate(_UNICODE_MAP)
        return txt.encode("latin-1", errors="replace").decode("latin-1")

    def header(self) -> None:
        self.set_y(9)
        self.set_draw_color(*_BLUE)
        self.set_line_width(0.35)
        self.rect(18, 8, 10, 10)
        self.set_xy(18, 10)
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*_BLUE)
        self.cell(10, 4, "SI", align="C")

        self.set_xy(31, 8.5)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(100, 100, 100)
        self.cell(90, 4, "Análise de Segurança da Informação", new_y=YPos.NEXT)
        self.set_x(31)
        self.cell(90, 4, "Homologação — Ficha de Verificação", new_y=YPos.NEXT)
        self.set_x(31)
        self.cell(90, 4, "Departamento de Segurança da Informação")

        self.set_xy(158, 9)
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(195, 195, 195)
        self.cell(34, 8, "SI", align="R")
        self.set_text_color(*_TEXT)
        self.set_y(28)

    def footer(self) -> None:
        self.set_y(-18)
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*_BLACK)
        self.multi_cell(0, 3.6, REPORT_FOOTER, align="C")
        self.set_y(-14)
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(255, 0, 0)
        self.cell(42, 4, "Documento Restrito", align="L")
        self.set_text_color(120, 120, 120)
        self.cell(0, 4, f"Página {self.page_no()}", align="R")
        self.set_text_color(*_TEXT)


# ── Interface pública ─────────────────────────────────────────────────────────

def generate_pdf_report(rd: dict[str, Any], out_path: str | Path) -> str:
    domain = rd.get("domain", "")
    anal_date = rd.get("analysis_date", date.today().isoformat())

    pdf = _FichaPDF(domain=domain, anal_date=anal_date)
    pdf.add_page()

    _add_intro(pdf, rd)
    _add_ssl_labs_card(pdf, rd)
    _add_disponibilidade(pdf, rd)
    _add_integridade(pdf, rd)
    _add_aplicacoes(pdf, rd)
    _add_hsts(pdf, rd)
    _add_criptografia(pdf, rd)
    _add_seguranca_rede(pdf, rd)
    _add_recomendacoes(pdf)
    _add_conclusao(pdf, rd)

    path = str(out_path)
    pdf.output(path)
    return path


# ── Seções principais ────────────────────────────────────────────────────────

def _add_intro(pdf: _FichaPDF, rd: dict[str, Any]) -> None:
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*_TEXT)
    pdf.cell(0, 8, "Homologação de Leiloeiros e Corretores de Imóveis",
             align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(8)
    _blank_box(pdf)
    pdf.ln(8)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Lista de Verificação de Segurança da Informação",
             align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)

    for text in (REPORT_HEADER_LINE1, REPORT_HEADER_LINE2):
        _paragraph(pdf, text, align="J")

    pdf.ln(4)
    _paragraph(
        pdf,
        "Para análise assertiva do ambiente disponibilizado publicamente na rede mundial "
        "internet, solicita-se as versões dos respectivos serviços da sustentação do website, "
        "tais como servidor web e linguagem de programação de back-end (ex.: Apache, IIS e PHP, ASP.NET).",
        align="J",
    )
    _paragraph(
        pdf,
        "Observa-se que muitos dos incidentes cibernéticos podem ser ocasionados através dos "
        "serviços que proveem a aplicação web caso estejam em versões desatualizadas ou descontinuadas.",
        align="J",
    )

    pdf.ln(2)
    _blank_box(pdf)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 5, rd.get("url", rd.get("domain", "")),
             align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _add_ssl_labs_card(pdf: _FichaPDF, rd: dict[str, Any]) -> None:
    ssl = rd.get("raw", {}).get("ssl_labs") or {}
    grade = ssl.get("grade") or "N/A"
    scores = ssl.get("scores") or {}
    cert_score = _cert_score(ssl.get("cert_valid"))
    score_rows = [
        ("CERTIFICADO", cert_score),
        ("SUPORTE DE PROTOCOLO", scores.get("suporte_protocolo")),
        ("CHAVES", scores.get("chaves")),
        ("FORÇA DE CIFRA", scores.get("forca_cifra")),
    ]

    if pdf.will_page_break(88):
        pdf.add_page()

    x = 18
    y = pdf.get_y() + 1
    w = 174
    h = 94
    panel = _grade_color(grade)

    pdf.set_fill_color(*panel)
    pdf.rect(x, y, w, h, style="F")
    pdf.set_draw_color(80, 130, 55)
    pdf.rect(x, y, w, h)

    # Título e grade
    _raised_box(pdf, x + 12, y + 6, 56, 9, "CLASSIFICAÇÃO GERAL", font_size=8.5)
    pdf.set_fill_color(98, 168, 58)
    pdf.rect(x + 26, y + 24, 36, 32, style="F")
    pdf.set_draw_color(65, 125, 45)
    pdf.rect(x + 26, y + 24, 36, 32)
    pdf.set_xy(x + 26, y + 31)
    pdf.set_font("Helvetica", "", 36)
    pdf.set_text_color(*_WHITE)
    pdf.cell(36, 17, str(grade), align="C")

    # Pontuação / primeiro gráfico
    row_x = x + 78
    row_y = y + 25
    for i, (label, score) in enumerate(score_rows):
        yy = row_y + i * 10
        _score_bar(pdf, row_x, yy, 86, label, score)

    messages = _ssl_messages(ssl)
    msg_y = y + 67
    for i, (message, color) in enumerate(messages[:3]):
        yy = msg_y + i * 8
        fill = (77, 154, 218) if color == "blue" else _GREEN_DARK if color == "green" else _RED
        pdf.set_fill_color(*fill)
        pdf.rect(x + 2, yy, w - 4, 6.5, style="F")
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(*_WHITE)
        pdf.set_xy(x + 4, yy + 1.1)
        pdf.cell(w - 8, 3.5, message, align="C")

    pdf.set_text_color(*_TEXT)
    pdf.set_y(y + h + 9)


def _add_disponibilidade(pdf: _FichaPDF, rd: dict[str, Any]) -> None:
    if pdf.get_y() > 205:
        pdf.add_page()
    _numbered_heading(pdf, "1. Disponibilidade")
    evidence = rd.get("raw", {}).get("evidence", {}) or {}
    checks = rd.get("checks", {}).get("disponibilidade", {}) or {}

    _ev_map = {"redundancia": "redundancy", "backup": "backup", "energia": "energy"}

    items = [
        ("Redundância de serviço", "redundancia"),
        ("Backup e recuperação", "backup"),
        ("Recurso contínuo de energia", "energia"),
    ]

    for label, key in items:
        ev_key = _ev_map.get(key, key)
        evidences = list(evidence.get(ev_key, []) or [])
        status = (checks.get(key) or {}).get("status", "")

        # Reserva espaço estimado para o item inteiro (citação + linha de fonte)
        block_chars = sum(len(_evidence_text(_quote(e))) for e in evidences) or 30
        estimated_h = 13 + max(1, block_chars // 105 + 1) * 4.8 + 4 * len(evidences)
        if pdf.will_page_break(estimated_h):
            pdf.add_page()

        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*_TEXT)
        pdf.cell(0, 6, f"{label} =>", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        if not evidences:
            color = _STATUS_FG.get(status, _RED)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*color)
            pdf.cell(0, 5, "Não informado", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(*_TEXT)
            pdf.ln(2)
            continue

        for ev in evidences:
            quote = _evidence_text(_quote(ev))
            if not quote:
                continue
            bullet = "• " if len(evidences) > 1 else ""
            _paragraph(pdf, f"{bullet}“{quote}”", size=8.2, left=7)

            source = _source(ev)
            page = _page(ev)
            if source:
                page_part = f" · página {page}" if isinstance(page, int) and page > 0 else ""
                _paragraph(
                    pdf, f"Fonte: {source}{page_part}",
                    size=7.5, left=10, color=_GRAY,
                )
        pdf.ln(2)


def _quote(ev) -> str:
    if isinstance(ev, dict):
        return str(ev.get("quote", ""))
    return str(ev or "")


def _source(ev) -> str:
    if isinstance(ev, dict):
        return str(ev.get("source", ""))
    return ""


def _page(ev):
    if isinstance(ev, dict):
        return ev.get("page")
    return None


def _add_integridade(pdf: _FichaPDF, rd: dict[str, Any]) -> None:
    _numbered_heading(
        pdf,
        "2. Integridade (Presença de firewall e/ou detecção de intrusão; Firewall, WAF, IPS/IDS) =>",
    )
    raw_block = rd.get("raw", {}).get("headers_raw_block", "")
    lines = [ln for ln in raw_block.splitlines() if ln.strip()][:28]
    if not lines:
        detail = rd.get("checks", {}).get("integridade", {}).get("detail", "Não disponível.")
        lines = [detail]
    _raw_box(pdf, "INTEGRIDADE (PRESENÇA DE FIREWALL, WAF, BALANCEADOR, IPS/IDS)", lines)


def _add_aplicacoes(pdf: _FichaPDF, rd: dict[str, Any]) -> None:
    _numbered_heading(pdf, "3. Aplicações Atualizadas =>")
    techs = rd.get("raw", {}).get("technologies", []) or []
    rows: list[list[str]] = []
    for tech in sorted(techs, key=lambda x: (x.get("category", ""), x.get("name", ""))):
        rows.append([
            tech.get("category", ""),
            tech.get("name", ""),
            tech.get("version") or "—",
            _eol_label(tech),
        ])
    if not rows:
        rows = [["—", "Nenhuma tecnologia detectada", "—", "—"]]
    _table(pdf, "APLICAÇÕES", ["Categoria", "Tecnologia", "Versão", "EOL"], rows, (38, 64, 28, 28))


def _add_hsts(pdf: _FichaPDF, rd: dict[str, Any]) -> None:
    _numbered_heading(pdf, "4. HSTS =>")
    check = rd.get("checks", {}).get("hsts", {}) or {}
    status = check.get("status", "NÃO VERIFICÁVEL")
    found = check.get("found")
    value = status if found is None else ("SIM" if found else "NÃO")
    _table(
        pdf,
        "HSTS",
        ["HSTS", "Status"],
        [["Segurança Estrita de Transporte (HSTS)", value]],
        (110, 48),
    )
    detail = check.get("detail", "")
    if detail and status in ("ATENÇÃO", "NÃO CONFORME"):
        _paragraph(pdf, detail, size=8.2, left=3)


def _add_criptografia(pdf: _FichaPDF, rd: dict[str, Any]) -> None:
    _numbered_heading(pdf, "5. Criptografia - SSL - TLS 1.2|1.3")
    cripto = rd.get("checks", {}).get("criptografia", {}) or {}
    rows = []
    for key, display_name in _TLS_ROWS:
        check = cripto.get(key, {}) or {}
        found = check.get("found")
        status = check.get("status", "NÃO VERIFICÁVEL")
        if found is None:
            value = "NÃO VERIFICÁVEL"
        else:
            value = "SIM" if found else "NÃO"
        rows.append([display_name, value])
    _table(pdf, "CRIPTOGRAFIA - SSL - TLS 1.2|1.3", ["Protocolos", "Possui?"], rows, (82, 76))


def _add_seguranca_rede(pdf: _FichaPDF, rd: dict[str, Any]) -> None:
    _numbered_heading(pdf, "6. Segurança de Rede =>")
    whois_raw = rd.get("raw", {}).get("whois_raw", "")
    lines = [
        ln for ln in whois_raw.splitlines()
        if ln.strip() and not ln.strip().startswith(("%", "#"))
    ][:34]
    if not lines:
        detail = rd.get("checks", {}).get("seguranca_rede", {}).get("detail", "Não disponível.")
        lines = [detail]
    _raw_box(pdf, "INFORMAÇÕES DE REDE", lines)

    portas = rd.get("checks", {}).get("portas", {})
    if portas:
        _paragraph(pdf, f"Portas: {portas.get('detail', '')}", size=8.2, left=3)


def _add_recomendacoes(pdf: _FichaPDF) -> None:
    _center_heading(pdf, "Recomendações")
    recs = [
        (
            "",
            "Manter um site com um design limpo e minimalista, utilizando apenas um alerta de evento "
            "para informar os clientes, é uma abordagem correta e eficaz, especialmente quando o objetivo "
            "é evitar poluição visual e garantir uma experiência de usuário clara e direta.",
        ),
        (
            "Disponibilidade do Site:",
            "A disponibilidade contínua do site é imprescindível para sua homologação. Qualquer interrupção "
            "no acesso, como manutenções programadas ou não programadas, deve ser devidamente comunicada aos "
            "usuários com antecedência, sempre que possível, por meio de alertas claros e visíveis no site "
            "ou por outros canais de comunicação.",
        ),
        (
            "Restrições de Conteúdo:",
            "É expressamente proibido o uso de links ou a divulgação de qualquer conteúdo relacionado a sites "
            "de pornografia, conforme as políticas de uso e boas práticas estabelecidas.",
        ),
        (
            "Política de Privacidade e Proteção de Dados:",
            "O presente site deve disponibilizar, de forma clara e acessível, sua Política de Privacidade e "
            "Proteção de Dados. Esse documento deve informar aos usuários como seus dados pessoais são "
            "coletados, armazenados, utilizados e protegidos, em conformidade com as leis e regulamentações "
            "vigentes, como a Lei Geral de Proteção de Dados (LGPD) no Brasil.",
        ),
    ]
    for title, body in recs:
        if title:
            pdf.set_font("Helvetica", "B", 8.5)
            pdf.cell(0, 5, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        _paragraph(pdf, body, size=8.5, align="J")
        pdf.ln(1)


def _add_conclusao(pdf: _FichaPDF, rd: dict[str, Any]) -> None:
    _center_heading(pdf, "Conclusão")
    _paragraph(pdf, rd.get("conclusao", "-"), size=9.2, align="J")
    pdf.ln(2)
    overall = rd.get("overall_status", "NÃO VERIFICÁVEL")
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*_TEXT)
    pdf.cell(24, 5, "Status Final: ")
    pdf.set_text_color(*_STATUS_FG.get(overall, _TEXT))
    pdf.cell(0, 5, overall, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(*_TEXT)
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(0, 5, f"Data da análise: {rd.get('analysis_date', date.today().isoformat())}",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)


# ── Elementos visuais ────────────────────────────────────────────────────────

def _blank_box(pdf: _FichaPDF) -> None:
    pdf.set_draw_color(*_BLACK)
    pdf.rect(42, pdf.get_y(), 126, 10)
    pdf.ln(12)


def _raised_box(pdf: _FichaPDF, x: float, y: float, w: float, h: float, text: str, font_size: float = 8) -> None:
    pdf.set_fill_color(*_GREEN_DARK)
    pdf.rect(x + 0.8, y + 0.8, w, h, style="F")
    pdf.set_fill_color(91, 164, 54)
    pdf.rect(x, y, w, h, style="F")
    pdf.set_xy(x, y + 2.2)
    pdf.set_font("Helvetica", "B", font_size)
    pdf.set_text_color(*_WHITE)
    pdf.cell(w, 3.5, text, align="C")


def _score_bar(pdf: _FichaPDF, x: float, y: float, w: float, label: str, score: Any) -> None:
    value = _format_score(score)
    value_w = 13
    try:
        pct = max(0, min(100, int(score)))
    except Exception:
        pct = 100

    pdf.set_fill_color(84, 150, 48)
    pdf.rect(x, y, w, 7, style="F")
    pdf.set_fill_color(113, 180, 72)
    pdf.rect(x, y, max(0, (w - value_w) * pct / 100), 7, style="F")
    pdf.set_fill_color(175, 175, 175)
    pdf.rect(x + w - value_w, y, value_w, 7, style="F")
    pdf.set_draw_color(65, 125, 45)
    pdf.rect(x, y, w, 7)

    pdf.set_font("Helvetica", "B", 7.8)
    pdf.set_text_color(*_WHITE)
    pdf.set_xy(x + 2, y + 1.5)
    pdf.cell(w - value_w - 4, 3.5, label, align="R")
    pdf.set_xy(x + w - value_w, y + 1.5)
    pdf.cell(value_w, 3.5, value, align="C")


def _numbered_heading(pdf: _FichaPDF, title: str) -> None:
    if pdf.will_page_break(22):
        pdf.add_page()
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*_TEXT)
    pdf.cell(0, 6, title, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)


def _center_heading(pdf: _FichaPDF, title: str) -> None:
    if pdf.will_page_break(28):
        pdf.add_page()
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(*_TEXT)
    pdf.cell(0, 9, title, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)


def _table(
    pdf: _FichaPDF,
    title: str,
    headers: list[str],
    rows: Iterable[list[str]],
    col_widths: tuple[int | float, ...],
) -> None:
    if pdf.will_page_break(22):
        pdf.add_page()
    pdf.set_draw_color(*_BLACK)
    pdf.set_font("Helvetica", "", 8)
    with pdf.table(
        col_widths=col_widths,
        line_height=6,
        headings_style=_TABLE_HDR,
        borders_layout=TableBordersLayout.ALL,
        first_row_as_headings=True,
        cell_fill_mode=TableCellFillMode.ROWS,
        cell_fill_color=_TABLE_BODY_FILL,
        text_align="LEFT",
        padding=2,
    ) as table:
        title_row = table.row()
        title_row.cell(title, colspan=len(headers), style=_TABLE_HDR, align="CENTER")
        hdr = table.row()
        for h in headers:
            hdr.cell(h, style=_TABLE_HDR, align="CENTER")
        for i, row in enumerate(rows):
            tr = table.row()
            fill = _TABLE_ALT_FILL if i % 2 else _TABLE_BODY_FILL
            for cell in row:
                tr.cell(str(cell), style=FontFace(fill_color=fill))
    pdf.ln(4)


def _raw_box(pdf: _FichaPDF, title: str, lines: list[str]) -> None:
    if pdf.will_page_break(28):
        pdf.add_page()
    pdf.set_draw_color(*_BLACK)
    pdf.set_font("Courier", "", 8)
    with pdf.table(
        col_widths=(174,),
        line_height=5.2,
        headings_style=_TABLE_HDR,
        borders_layout=TableBordersLayout.ALL,
        first_row_as_headings=True,
        cell_fill_mode=TableCellFillMode.ROWS,
        cell_fill_color=_TABLE_BODY_FILL,
        text_align="LEFT",
        padding=2,
    ) as table:
        title_row = table.row()
        title_row.cell(title, style=_TABLE_HDR, align="CENTER")
        for i, line in enumerate(lines):
            fill = _TABLE_ALT_FILL if i % 2 else _TABLE_BODY_FILL
            table.row().cell(_trim_line(line, 130), style=FontFace(fill_color=fill))
    pdf.ln(4)


# ── Texto e dados ────────────────────────────────────────────────────────────

def _paragraph(
    pdf: _FichaPDF,
    text: str,
    *,
    size: float = 9,
    left: float = 0,
    align: str = "L",
    color: tuple[int, int, int] | None = None,
) -> None:
    pdf.set_font("Helvetica", "", size)
    pdf.set_text_color(*(color or _TEXT))
    x = pdf.l_margin + left
    pdf.set_x(x)
    pdf.multi_cell(174 - left, 4.8, _space(text), align=align,
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(*_TEXT)


def _cert_score(cert_valid: Any) -> int | None:
    if cert_valid is True:
        return 100
    if cert_valid is False:
        return 0
    return None


def _format_score(score: Any) -> str:
    if score is None:
        return "N/A"
    try:
        return str(int(score))
    except Exception:
        return str(score)


def _grade_color(grade: str) -> tuple[int, int, int]:
    if grade in ("A+", "A", "A-"):
        return _GREEN_BG
    if grade in ("B", "C"):
        return (221, 158, 58)
    if grade == "N/A":
        return (150, 160, 165)
    return (195, 75, 65)


def _ssl_messages(ssl: dict[str, Any]) -> list[tuple[str, str]]:
    messages: list[tuple[str, str]] = []
    if ssl.get("sni_required") is True:
        messages.append(("Este site funciona apenas em navegadores com suporte a SNI.", "blue"))

    tls = ssl.get("tls") or {}
    if tls.get("TLS 1.3"):
        messages.append(("Este servidor suporta TLS 1.3.", "green"))
    elif tls.get("TLS 1.2"):
        messages.append(("Este servidor suporta TLS 1.2.", "green"))
    else:
        messages.append(("TLS 1.2 ou superior não foi confirmado neste servidor.", "red"))

    hsts = ssl.get("hsts") or {}
    if hsts.get("present"):
        max_age = hsts.get("max_age") or 0
        if max_age >= 31_536_000:
            msg = "Segurança de Transporte Estrita HTTP (HSTS) com longa duração implementada neste servidor."
        else:
            msg = "Segurança de Transporte Estrita HTTP (HSTS) implementada neste servidor."
        messages.append((msg, "green"))
    else:
        messages.append(("HSTS não implementado neste servidor.", "red"))
    return messages


def _eol_label(tech: dict[str, Any]) -> str:
    if tech.get("eol") is True:
        return "EOL"
    if tech.get("eol") is False:
        return "OK"
    return "—"


def _evidence_text(raw_text: str) -> str:
    raw_text = (raw_text or "").strip()
    if not raw_text:
        return ""
    if raw_text.startswith("[INFERIDO] "):
        raw_text = "Inferido - " + raw_text[len("[INFERIDO] "):]
    raw_text = raw_text.replace("Trecho do documento: ", "")
    raw_text = raw_text.replace('"', "")
    return _clean_evidence_text(raw_text)


def _clean_evidence_text(text: str) -> str:
    patterns = [
        r"Evidências?\s+(?:Brame\s+)?Leilões",
        r"Demandas?\s*",
        r"Despacho\s*[-–]\s*TJ/[\w/]+",
        r"Source:\s*\w+\s*\d*",
        r"Informar\s+a\s+exist[êe]ncia\s+de:?\s*●?\s*",
        r"●\s*redund[âa]ncia\s+de\s+servi[çc]os;?\s*",
        r"●\s*rotina\s+de\s+backup\s+e\s+recupera[çc][ãa]o;?\s*",
        r"●\s*recurso\s+cont[íi]nuo\s+de\s+energia;?\s*",
        r"CÓDIGO\s+N\.\d+\s+NORMA\s+VERSÃO\s+V\.\d+[^\n]*",
        r"PUBLICADO\s+EM:\s+\d{2}/\d{2}/\d{4}[^\n]*",
        r"VÁLIDO\s+ATÉ:\s+\d{2}/\d{2}/\d{4}[^\n]*",
    ]
    cleaned = text
    for pattern in patterns:
        cleaned = re.sub(pattern, " ", cleaned, flags=re.IGNORECASE)
    return _space(cleaned).strip(" ;:.,●")


def _space(text: str) -> str:
    return re.sub(r"\s+", " ", str(text)).strip()


def _trim_line(text: str, max_len: int) -> str:
    text = _space(text)
    return text if len(text) <= max_len else text[: max_len - 1] + "…"
