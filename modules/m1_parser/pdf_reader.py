"""
Extrator de texto e tabelas de arquivos PDF.

Usa pdfplumber como engine principal (melhor fidelidade de layout e tabelas).
Usa pypdf como fallback para metadados e em caso de falha do pdfplumber.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pdfplumber
from pypdf import PdfReader as _PyPdfReader


def read_pdf(path: str | Path) -> dict[str, Any]:
    """
    Lê um PDF e retorna estrutura normalizada com texto, tabelas e metadados.

    Retorna:
        {
            "text": str,              # Texto completo de todas as páginas
            "tables": list[list],     # Tabelas extraídas [[linha, ...], ...]
            "metadata": dict,         # Título, autor, criador
            "page_count": int,
            "source_path": str,
            "source_format": "pdf",
        }
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"PDF não encontrado: {path}")

    text_parts: list[str] = []
    tables: list[list[list[str | None]]] = []
    image_page_indices: list[int] = []

    total_pages = 0
    with pdfplumber.open(path) as pdf:
        total_pages = len(pdf.pages)
        for i, page in enumerate(pdf.pages):
            page_text = page.extract_text()
            if page_text and page_text.strip():
                text_parts.append(page_text)
            else:
                image_page_indices.append(i)

            for table in page.extract_tables():
                if _table_has_content(table):
                    tables.append(_normalize_table(table))

    metadata = _extract_metadata(path)
    text_pages = len(text_parts)

    return {
        "text": "\n".join(text_parts),
        "tables": tables,
        "metadata": metadata,
        "page_count": text_pages,
        "total_page_count": total_pages,
        "image_page_count": total_pages - text_pages,
        "image_page_indices": image_page_indices,
        "source_path": str(path),
        "source_format": "pdf",
    }


def _extract_metadata(path: Path) -> dict[str, str]:
    try:
        reader = _PyPdfReader(str(path))
        meta = reader.metadata or {}
        return {
            "title": meta.get("/Title", "") or "",
            "author": meta.get("/Author", "") or "",
            "creator": meta.get("/Creator", "") or "",
        }
    except Exception:
        return {"title": "", "author": "", "creator": ""}


def _table_has_content(table: list[list] | None) -> bool:
    if not table:
        return False
    return any(
        cell is not None and str(cell).strip()
        for row in table
        for cell in row
    )


def _normalize_table(table: list[list]) -> list[list[str]]:
    return [
        [str(cell).strip() if cell is not None else "" for cell in row]
        for row in table
    ]
