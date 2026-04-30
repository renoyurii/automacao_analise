"""
Módulo 4 — Gerador de Relatório.

Interface pública: generate_ficha() → .docx | generate_pdf() → .pdf
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .ficha_builder import build_ficha
from .pdf_builder import generate_pdf_report


def generate_ficha(result_data: dict[str, Any], output_path: str | Path) -> str:
    """Gera a Ficha de Verificação em .docx. Retorna o caminho gerado."""
    return build_ficha(result_data, output_path)


def generate_pdf(result_data: dict[str, Any], output_path: str | Path) -> str:
    """Gera a Ficha de Verificação em .pdf. Retorna o caminho gerado."""
    return generate_pdf_report(result_data, output_path)
