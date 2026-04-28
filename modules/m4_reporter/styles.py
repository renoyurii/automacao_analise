"""
Constantes de estilo e helpers de XML para python-docx.

Centraliza cores, fontes e manipulação de XML para que o ficha_builder
permaneça legível e focado na estrutura do documento.
"""

from __future__ import annotations

from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor

# ── Paleta de cores ───────────────────────────────────────────────────────────

GREEN   = RGBColor(0x2E, 0x7D, 0x32)   # Conforme
RED     = RGBColor(0xC6, 0x28, 0x28)   # Não Conforme
ORANGE  = RGBColor(0xBF, 0x36, 0x0C)   # Atenção
GRAY    = RGBColor(0x54, 0x6E, 0x7A)   # Não Verificável
DARK    = RGBColor(0x1A, 0x1A, 0x2E)   # Texto principal
BLUE_HD = RGBColor(0x0D, 0x47, 0xA1)   # Cabeçalho de tabela
WHITE   = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT   = RGBColor(0xF5, 0xF5, 0xF5)   # Fundo alternado de linha
MID     = RGBColor(0xE3, 0xF2, 0xFD)   # Azul claro para cabeçalho de tabela

STATUS_COLOR: dict[str, RGBColor] = {
    "CONFORME":        GREEN,
    "NÃO CONFORME":    RED,
    "ATENÇÃO":         ORANGE,
    "NÃO VERIFICÁVEL": GRAY,
}

SIM_NÃO_COLOR: dict[bool, RGBColor] = {
    True:  GREEN,
    False: RED,
}

# ── Tamanhos de fonte ─────────────────────────────────────────────────────────

FONT_TITLE    = Pt(13)
FONT_SECTION  = Pt(11)
FONT_BODY     = Pt(10)
FONT_SMALL    = Pt(9)
FONT_MONO     = Pt(8.5)
FONT_GRADE    = Pt(28)

FONT_NAME         = "Calibri"
FONT_NAME_MONO    = "Courier New"


# ── Helpers de XML ────────────────────────────────────────────────────────────

def set_cell_bg(cell, hex_color: str) -> None:
    """Define cor de fundo de uma célula de tabela."""
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color.lstrip("#"))
    tcPr.append(shd)


def set_table_borders(table, color: str = "BDBDBD", size: str = "4") -> None:
    """Adiciona bordas finas a toda a tabela."""
    tbl = table._tbl
    tblPr = tbl.tblPr
    if tblPr is None:
        tblPr = OxmlElement("w:tblPr")
        tbl.insert(0, tblPr)
    tblBorders = OxmlElement("w:tblBorders")
    for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), size)
        el.set(qn("w:space"), "0")
        el.set(qn("w:color"), color.lstrip("#"))
        tblBorders.append(el)
    tblPr.append(tblBorders)


def set_cell_vertical_align(cell, align: str = "center") -> None:
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    vAlign = OxmlElement("w:vAlign")
    vAlign.set(qn("w:val"), align)
    tcPr.append(vAlign)


def set_paragraph_spacing(para, before: int = 0, after: int = 4) -> None:
    fmt = para.paragraph_format
    fmt.space_before = Pt(before)
    fmt.space_after = Pt(after)


def remove_paragraph_spacing(para) -> None:
    set_paragraph_spacing(para, 0, 0)


def set_col_width(table, col_idx: int, width_cm: float) -> None:
    from docx.shared import Cm
    for row in table.rows:
        row.cells[col_idx].width = Cm(width_cm)
