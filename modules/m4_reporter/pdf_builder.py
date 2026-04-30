"""
Geração de Ficha de Verificação em PDF.
Usa fpdf2 (pure Python, sem dependências externas além do pip).
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

from fpdf import FPDF, FontFace, XPos, YPos
from fpdf.enums import TableBordersLayout, TableCellFillMode

# ── Sanitização de texto para Latin-1 ────────────────────────────────────────
# Sobrescrever normalize_text garante que qualquer texto vindo do scanner
# (em-dash, aspas tipográficas, etc.) seja limpo antes de chegar ao encoder.

_UNICODE_MAP = str.maketrans({
    "—": "-",   # em dash —
    "–": "-",   # en dash –
    "‘": "'",   # aspas esquerda '
    "’": "'",   # aspas direita '
    "“": '"',   # aspas dupla esquerda "
    "”": '"',   # aspas dupla direita "
    "…": "...", # reticências …
    "•": "*",   # bullet •
    "·": ".",   # ponto mediano ·
    "→": "->",  # seta direita →
    " ": " ",   # espaço não-separável
})

# ── Paleta TJRJ ───────────────────────────────────────────────────────────────
_C_PRIMARY    = (0,   61, 165)
_C_DARK       = (0,   26, 110)
_C_WHITE      = (255, 255, 255)
_C_BG_ROW_A   = (248, 251, 255)
_C_BG_LIGHT   = (232, 240, 254)
_C_GREEN      = (46,  125,  50)
_C_GREEN_BG   = (232, 245, 233)
_C_RED        = (198,  40,  40)
_C_RED_BG     = (255, 235, 238)
_C_AMBER      = (230,  81,   0)
_C_AMBER_BG   = (255, 243, 224)
_C_NEUTRAL    = (84,  110, 122)
_C_TEXT       = (55,   65,  75)
_C_SUBTEXT    = (110, 120, 130)

_STATUS_FG = {
    "CONFORME":        _C_GREEN,
    "NÃO CONFORME":    _C_RED,
    "ATENÇÃO":         _C_AMBER,
    "NÃO VERIFICÁVEL": _C_NEUTRAL,
}
_C_NEUTRAL_BG = (236, 239, 241)

_STATUS_BG = {
    "CONFORME":        _C_GREEN_BG,
    "NÃO CONFORME":    _C_RED_BG,
    "ATENÇÃO":         _C_AMBER_BG,
    "NÃO VERIFICÁVEL": _C_NEUTRAL_BG,
}

_HDR_STYLE = FontFace(
    emphasis="BOLD",
    color=_C_WHITE,
    fill_color=_C_DARK,
)


# ── Classe principal ──────────────────────────────────────────────────────────

class _FichaPDF(FPDF):
    def __init__(self, domain: str, anal_date: str) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self._domain    = domain
        self._anal_date = anal_date
        self.set_margins(left=15, top=28, right=15)
        self.set_auto_page_break(auto=True, margin=20)

    def normalize_text(self, txt: str) -> str:
        """Substitui chars fora do Latin-1 antes de passar ao encoder da fonte."""
        txt = txt.translate(_UNICODE_MAP)
        return txt.encode("latin-1", errors="replace").decode("latin-1")

    def header(self) -> None:
        self.set_fill_color(*_C_DARK)
        self.rect(0, 0, 210, 22, style="F")
        self.set_xy(15, 5)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*_C_WHITE)
        self.cell(130, 7, "Ficha de Verificacao de Seguranca - Leiloeiro Judicial", border=0)
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(190, 210, 245)
        self.set_xy(145, 5)
        self.cell(50, 4, self._domain, border=0, align="R",
                  new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_xy(145, 10)
        self.cell(50, 4, self._anal_date, border=0, align="R",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_y(28)
        self.set_text_color(0, 0, 0)

    def footer(self) -> None:
        self.set_y(-13)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*_C_NEUTRAL)
        self.cell(0, 5, "SEAUD . DESEG . GABPRES . TJRJ", border=0, align="L",
                  new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(0, 5, f"Pagina {self.page_no()}", border=0, align="R")


# ── Helpers de layout ─────────────────────────────────────────────────────────

def _section_title(pdf: FPDF, title: str) -> None:
    if pdf.will_page_break(12):
        pdf.add_page()
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(*_C_BG_LIGHT)
    pdf.set_text_color(*_C_PRIMARY)
    pdf.cell(0, 7, f"  {title.upper()}", border=0, fill=True,
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(*_C_PRIMARY)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(3)
    pdf.set_text_color(0, 0, 0)


def _status_card(pdf: FPDF, overall: str, conclusao: str) -> None:
    is_ok  = (overall == "CONFORME")
    fg_col = _C_GREEN if is_ok else _C_RED
    bg_col = _C_GREEN_BG if is_ok else _C_RED_BG

    # Mede altura real do bloco de conclusão antes de desenhar o fundo
    # Usa local_context para renderizar em modo "fantasma" e obter a altura
    conclusao_lines = max(1, len(conclusao) // 95 + 1)
    card_h = 8 + 8 + (conclusao_lines * 5) + 4  # status + padding + conclusao + base

    y0 = pdf.get_y()

    # Fundo
    pdf.set_fill_color(*bg_col)
    pdf.rect(15, y0, 180, card_h, style="F")
    # Barra lateral
    pdf.set_fill_color(*fg_col)
    pdf.rect(15, y0, 2.5, card_h, style="F")

    # Status
    pdf.set_xy(20, y0 + 3)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*fg_col)
    pdf.cell(0, 8, overall, border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Conclusão
    pdf.set_xy(20, pdf.get_y() + 1)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*_C_NEUTRAL)
    pdf.multi_cell(173, 5, conclusao, border=0)

    pdf.set_y(y0 + card_h + 5)
    pdf.set_text_color(0, 0, 0)


# ── Dados ─────────────────────────────────────────────────────────────────────

def _flatten_checks(checks: dict, prefix: str = "") -> list[dict]:
    rows: list[dict] = []
    for key, val in checks.items():
        label = f"{prefix} / {key}" if prefix else key
        if isinstance(val, dict) and "status" in val:
            rows.append({
                "label":  label.replace("_", " ").title(),
                "status": val.get("status", "?"),
                "sev":    val.get("severity") or "",
                "detail": val.get("detail", ""),
            })
        elif isinstance(val, dict):
            rows.extend(_flatten_checks(val, prefix=label))
    return rows


def _eol_label(t: dict) -> str:
    if t.get("eol") is True:
        d = t.get("eol_date", "")
        return f"EOL {d}" if d else "EOL"
    if t.get("eol") is False:
        return "Suportado"
    return "-"


# ── Tabelas ───────────────────────────────────────────────────────────────────

def _checks_table(pdf: FPDF, checks: dict) -> None:
    rows = _flatten_checks(checks)
    if not rows:
        return

    _section_title(pdf, "Verificações")
    pdf.set_font("Helvetica", "", 7.5)

    with pdf.table(
        col_widths=(55, 40, 16, 69),
        line_height=6,
        headings_style=_HDR_STYLE,
        borders_layout=TableBordersLayout.HORIZONTAL_LINES,
        first_row_as_headings=True,
        cell_fill_mode=TableCellFillMode.ROWS,
        cell_fill_color=_C_BG_ROW_A,
        text_align="LEFT",
        padding=2,
    ) as table:
        hdr = table.row()
        for h in ("Seção", "Status", "Sev.", "Detalhe"):
            hdr.cell(h)

        for row in rows:
            status = row["status"]
            fg     = _STATUS_FG.get(status, _C_NEUTRAL)
            tr = table.row()
            tr.cell(row["label"])
            tr.cell(status,       style=FontFace(emphasis="BOLD", color=fg))
            tr.cell(row["sev"],   style=FontFace(color=_C_SUBTEXT))
            tr.cell(row["detail"])

    pdf.ln(4)


def _techs_table(pdf: FPDF, techs: list[dict]) -> None:
    if not techs:
        return

    _section_title(pdf, "Tecnologias detectadas")
    pdf.set_font("Helvetica", "", 7.5)

    sorted_techs = sorted(techs, key=lambda x: (x.get("category", ""), x.get("name", "")))

    with pdf.table(
        col_widths=(42, 55, 28, 55),
        line_height=6,
        headings_style=_HDR_STYLE,
        borders_layout=TableBordersLayout.HORIZONTAL_LINES,
        first_row_as_headings=True,
        cell_fill_mode=TableCellFillMode.ROWS,
        cell_fill_color=_C_BG_ROW_A,
        text_align="LEFT",
        padding=2,
    ) as table:
        hdr = table.row()
        for h in ("Categoria", "Tecnologia", "Versão", "EOL"):
            hdr.cell(h)

        for t in sorted_techs:
            eol     = t.get("eol")
            eol_txt = _eol_label(t)
            eol_fg  = _C_RED if eol is True else _C_GREEN if eol is False else _C_NEUTRAL

            tr = table.row()
            tr.cell(t.get("category", ""))
            tr.cell(t.get("name", ""))
            tr.cell(t.get("version") or "-", style=FontFace(color=_C_SUBTEXT))
            tr.cell(eol_txt, style=FontFace(emphasis="BOLD", color=eol_fg))

    pdf.ln(3)


# ── Interface pública ─────────────────────────────────────────────────────────

def generate_pdf_report(rd: dict[str, Any], out_path: str | Path) -> str:
    """
    Gera a ficha de verificação em PDF a partir dos dados de resultado do M3.
    Retorna o caminho absoluto do arquivo gerado.
    """
    domain    = rd.get("domain", "")
    anal_date = rd.get("analysis_date", date.today().isoformat())
    overall   = rd.get("overall_status", "?")
    conclusao = rd.get("conclusao", "")
    checks    = rd.get("checks", {})
    techs     = rd.get("raw", {}).get("technologies", [])

    pdf = _FichaPDF(domain=domain, anal_date=anal_date)
    pdf.add_page()

    _status_card(pdf, overall, conclusao)
    _checks_table(pdf, checks)
    _techs_table(pdf, techs)

    path = str(out_path)
    pdf.output(path)
    return path
