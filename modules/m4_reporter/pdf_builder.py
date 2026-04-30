"""
Geração de Ficha de Verificação em PDF.
Usa fpdf2 (pure Python, sem dependências externas além do pip).
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

from fpdf import FPDF, XPos, YPos

# ── Sanitização de texto para Latin-1 ────────────────────────────────────────
# fpdf2 com fontes internas usa Latin-1. Dados do scanner podem conter
# caracteres Unicode (em-dash, aspas tipográficas, etc.) que causam erro.
# Sobrescrever normalize_text garante que QUALQUER texto passado ao PDF
# seja limpo automaticamente, sem precisar tratar em cada chamada.

_UNICODE_MAP = str.maketrans({
    "—": "-",    # em dash
    "–": "-",    # en dash
    "‘": "'",    # aspas tipográficas simples esquerdas
    "’": "'",    # aspas tipográficas simples direitas
    "“": '"',    # aspas tipográficas duplas esquerdas
    "”": '"',    # aspas tipográficas duplas direitas
    "…": "...",  # reticências
    "•": "*",    # bullet
    "·": ".",    # ponto mediano
    "→": "->",   # seta direita
    " ": " ",    # espaço não-separável
})


# ── Paleta TJRJ ───────────────────────────────────────────────────────────────
_C_PRIMARY   = (0,   61, 165)
_C_DARK      = (0,   26, 110)
_C_WHITE     = (255, 255, 255)
_C_BG_ROW_A  = (248, 251, 255)
_C_BG_ROW_B  = (255, 255, 255)
_C_BG_LIGHT  = (232, 240, 254)
_C_GREEN     = (46,  125,  50)
_C_GREEN_BG  = (232, 245, 233)
_C_RED       = (198,  40,  40)
_C_RED_BG    = (255, 235, 238)
_C_AMBER     = (230,  81,   0)
_C_AMBER_BG  = (255, 243, 224)
_C_NEUTRAL   = (84,  110, 122)
_C_NEUTRAL_BG = (236, 239, 241)
_C_SEPARATOR = (220, 228, 238)

_STATUS_FG = {
    "CONFORME":        _C_GREEN,
    "NÃO CONFORME":    _C_RED,
    "ATENÇÃO":         _C_AMBER,
    "NÃO VERIFICÁVEL": _C_NEUTRAL,
}
_STATUS_BG = {
    "CONFORME":        _C_GREEN_BG,
    "NÃO CONFORME":    _C_RED_BG,
    "ATENÇÃO":         _C_AMBER_BG,
    "NÃO VERIFICÁVEL": _C_NEUTRAL_BG,
}


# ── Classe principal ──────────────────────────────────────────────────────────

class _FichaPDF(FPDF):
    def __init__(self, domain: str, anal_date: str) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self._domain    = domain
        self._anal_date = anal_date
        self.set_margins(left=15, top=25, right=15)
        self.set_auto_page_break(auto=True, margin=18)

    def normalize_text(self, txt: str) -> str:
        """Substitui chars fora do Latin-1 antes de passar ao encoder da fonte."""
        txt = txt.translate(_UNICODE_MAP)
        return txt.encode("latin-1", errors="replace").decode("latin-1")

    def header(self) -> None:
        # Barra azul
        self.set_fill_color(*_C_DARK)
        self.rect(0, 0, 210, 20, style="F")
        # Título
        self.set_xy(15, 4)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*_C_WHITE)
        self.cell(130, 7, "Ficha de Verificação de Segurança — Leiloeiro Judicial", border=0)
        # Domínio + data à direita
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(190, 210, 245)
        self.set_xy(145, 4)
        self.cell(50, 4, self._domain, border=0, align="R",
                  new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_xy(145, 9)
        self.cell(50, 4, self._anal_date, border=0, align="R",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        # Volta à margem
        self.set_y(25)
        self.set_text_color(0, 0, 0)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*_C_NEUTRAL)
        self.cell(0, 5, "SEAUD · DESEG · GABPRES · TJRJ", border=0, align="L",
                  new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(0, 5, f"Página {self.page_no()}", border=0, align="R")


# ── Helpers de layout ─────────────────────────────────────────────────────────

def _section_title(pdf: FPDF, title: str) -> None:
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(*_C_BG_LIGHT)
    pdf.set_text_color(*_C_PRIMARY)
    pdf.cell(0, 6, f"  {title.upper()}", border=0, fill=True,
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(*_C_PRIMARY)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(2)
    pdf.set_text_color(0, 0, 0)


def _status_card(pdf: FPDF, overall: str, conclusao: str) -> None:
    is_ok  = (overall == "CONFORME")
    fg_col = _C_GREEN if is_ok else _C_RED
    bg_col = _C_GREEN_BG if is_ok else _C_RED_BG
    x0, y0 = pdf.get_x(), pdf.get_y()

    # Fundo do card
    pdf.set_fill_color(*bg_col)
    pdf.rect(15, y0, 180, 22, style="F")

    # Barra lateral colorida
    pdf.set_fill_color(*fg_col)
    pdf.rect(15, y0, 2, 22, style="F")

    # Texto status
    pdf.set_xy(20, y0 + 3)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*fg_col)
    pdf.cell(80, 8, overall, border=0)

    # Texto conclusão
    pdf.set_xy(20, y0 + 12)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*_C_NEUTRAL)
    pdf.multi_cell(173, 4.5, conclusao, border=0)

    pdf.set_y(y0 + 25)
    pdf.set_text_color(0, 0, 0)


# ── Tabelas ───────────────────────────────────────────────────────────────────

def _flatten_checks(checks: dict, prefix: str = "") -> list[dict]:
    rows: list[dict] = []
    for key, val in checks.items():
        label = f"{prefix} / {key}" if prefix else key
        if isinstance(val, dict) and "status" in val:
            rows.append({
                "label":  label.replace("_", " "),
                "status": val.get("status", "?"),
                "sev":    val.get("severity") or "",
                "detail": val.get("detail", ""),
            })
        elif isinstance(val, dict):
            rows.extend(_flatten_checks(val, prefix=label))
    return rows


def _checks_table(pdf: FPDF, checks: dict) -> None:
    _section_title(pdf, "Verificações")

    rows   = _flatten_checks(checks)
    col_w  = [55, 38, 16, 71]
    hdrs   = ["Seção", "Status", "Sev.", "Detalhe"]

    # Cabeçalho
    pdf.set_font("Helvetica", "B", 7.5)
    pdf.set_fill_color(*_C_PRIMARY)
    pdf.set_text_color(*_C_WHITE)
    for h, w in zip(hdrs, col_w):
        pdf.cell(w, 6, f"  {h}", border=0, fill=True,
                 new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.ln(6)

    for idx, row in enumerate(rows):
        status = row["status"]
        status_fg = _STATUS_FG.get(status, _C_NEUTRAL)
        row_bg = _C_BG_ROW_A if idx % 2 == 0 else _C_BG_ROW_B

        # Estima altura da linha pelo campo detalhe (pode quebrar)
        detail_text = (row["detail"] or "")[:160]
        # fpdf2: medir altura de multi_cell sem desenhar
        n_lines = max(1, len(detail_text) // 68 + 1)
        row_h = 5 * n_lines + 2

        if pdf.get_y() + row_h > 272:
            pdf.add_page()

        y = pdf.get_y()

        # Fundo da linha
        pdf.set_fill_color(*row_bg)
        pdf.rect(15, y, 180, row_h, style="F")

        # Separador de linha
        pdf.set_draw_color(*_C_SEPARATOR)
        pdf.line(15, y + row_h, 195, y + row_h)

        cell_h = row_h

        # Coluna: Seção
        pdf.set_xy(15, y)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(55, 65, 75)
        label = row["label"].title()
        pdf.multi_cell(col_w[0], 5, f"  {label}", border=0, fill=False)

        # Coluna: Status
        pdf.set_xy(15 + col_w[0], y)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*status_fg)
        pdf.cell(col_w[1], cell_h, f"  {status}", border=0, fill=False,
                 new_x=XPos.RIGHT, new_y=YPos.TOP)

        # Coluna: Severidade
        pdf.set_font("Helvetica", "", 6.5)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(col_w[2], cell_h, f"  {row['sev']}", border=0, fill=False,
                 new_x=XPos.RIGHT, new_y=YPos.TOP)

        # Coluna: Detalhe
        pdf.set_xy(15 + col_w[0] + col_w[1] + col_w[2], y)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(55, 65, 75)
        pdf.multi_cell(col_w[3], 5, f"  {detail_text}", border=0, fill=False)

        pdf.set_y(y + row_h)

    pdf.ln(4)
    pdf.set_text_color(0, 0, 0)


def _eol_label(t: dict) -> str:
    if t.get("eol") is True:
        d = t.get("eol_date", "")
        return f"EOL {d}" if d else "EOL"
    if t.get("eol") is False:
        return "Suportado"
    return "-"


def _techs_table(pdf: FPDF, techs: list[dict]) -> None:
    if not techs:
        return

    _section_title(pdf, "Tecnologias detectadas")

    col_w = [45, 55, 25, 55]
    hdrs  = ["Categoria", "Tecnologia", "Versão", "EOL"]

    pdf.set_font("Helvetica", "B", 7.5)
    pdf.set_fill_color(*_C_PRIMARY)
    pdf.set_text_color(*_C_WHITE)
    for h, w in zip(hdrs, col_w):
        pdf.cell(w, 6, f"  {h}", border=0, fill=True,
                 new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.ln(6)

    sorted_techs = sorted(techs, key=lambda x: (x.get("category", ""), x.get("name", "")))

    for idx, t in enumerate(sorted_techs):
        if pdf.get_y() > 272:
            pdf.add_page()

        row_bg = _C_BG_ROW_A if idx % 2 == 0 else _C_BG_ROW_B
        y = pdf.get_y()

        pdf.set_fill_color(*row_bg)
        pdf.rect(15, y, 180, 5.5, style="F")
        pdf.set_draw_color(*_C_SEPARATOR)
        pdf.line(15, y + 5.5, 195, y + 5.5)

        pdf.set_font("Helvetica", "", 7)

        # Categoria
        pdf.set_xy(15, y)
        pdf.set_text_color(55, 65, 75)
        pdf.cell(col_w[0], 5.5, f"  {t.get('category', '')}", border=0,
                 new_x=XPos.RIGHT, new_y=YPos.TOP)

        # Tecnologia
        pdf.cell(col_w[1], 5.5, f"  {t.get('name', '')}", border=0,
                 new_x=XPos.RIGHT, new_y=YPos.TOP)

        # Versão
        pdf.set_text_color(*_C_NEUTRAL)
        pdf.cell(col_w[2], 5.5, f"  {t.get('version') or '-'}", border=0,
                 new_x=XPos.RIGHT, new_y=YPos.TOP)

        # EOL
        eol = t.get("eol")
        eol_text = _eol_label(t)
        if eol is True:
            pdf.set_text_color(*_C_RED)
        elif eol is False:
            pdf.set_text_color(*_C_GREEN)
        else:
            pdf.set_text_color(*_C_NEUTRAL)
        pdf.cell(col_w[3], 5.5, f"  {eol_text}", border=0,
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_text_color(0, 0, 0)
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
    pdf.ln(2)
    _checks_table(pdf, checks)
    _techs_table(pdf, techs)

    path = str(out_path)
    pdf.output(path)
    return path
