"""
Extrator de texto e tabelas de arquivos .docx.

Usa python-docx para percorrer parágrafos e tabelas em ordem de documento,
preservando o contexto entre seções.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from docx import Document
from docx.oxml.ns import qn


def read_docx(path: str | Path) -> dict[str, Any]:
    """
    Lê um .docx e retorna estrutura normalizada com texto, tabelas e metadados.

    Retorna a mesma estrutura de read_pdf para que o claim_extractor
    possa processar ambos sem distinção.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"DOCX não encontrado: {path}")

    doc = Document(str(path))

    # Percorre o corpo do documento em ordem (parágrafos intercalados com tabelas)
    # preservando a sequência real do documento — critical para contexto correto.
    text_parts: list[str] = []
    tables: list[list[list[str]]] = []

    for block in _iter_blocks(doc):
        if block["type"] == "paragraph":
            if block["text"].strip():
                text_parts.append(block["text"])
        elif block["type"] == "table":
            if _table_has_content(block["data"]):
                tables.append(block["data"])
                # Também injeta o texto da tabela no fluxo principal
                # para que o claim_extractor encontre keywords dentro de tabelas.
                for row in block["data"]:
                    line = " | ".join(cell for cell in row if cell)
                    if line.strip():
                        text_parts.append(line)

    metadata = _extract_metadata(doc)

    return {
        "text": "\n".join(text_parts),
        "tables": tables,
        "metadata": metadata,
        "page_count": None,  # DOCX não expõe número de páginas diretamente
        "total_page_count": None,
        "image_page_count": 0,
        "source_path": str(path),
        "source_format": "docx",
    }


def _iter_blocks(doc: Document):
    """
    Itera sobre o corpo do documento respeitando a ordem real dos elementos
    (parágrafos e tabelas intercalados), conforme o XML do arquivo.
    """
    body = doc.element.body
    for child in body:
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag

        if tag == "p":
            # Parágrafo
            text = "".join(
                node.text or ""
                for node in child.iter()
                if node.tag.endswith("}t")
            )
            yield {"type": "paragraph", "text": text}

        elif tag == "tbl":
            # Tabela
            rows: list[list[str]] = []
            for tr in child.findall(f".//{{{_W}}}tr"):
                row: list[str] = []
                for tc in tr.findall(f".//{{{_W}}}tc"):
                    cell_text = "".join(
                        node.text or ""
                        for node in tc.iter()
                        if node.tag.endswith("}t")
                    )
                    row.append(cell_text.strip())
                if row:
                    rows.append(row)
            yield {"type": "table", "data": rows}


_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def _extract_metadata(doc: Document) -> dict[str, str]:
    try:
        props = doc.core_properties
        return {
            "title": props.title or "",
            "author": props.author or "",
            "creator": props.last_modified_by or "",
        }
    except Exception:
        return {"title": "", "author": "", "creator": ""}


def _table_has_content(table: list[list[str]]) -> bool:
    return any(cell.strip() for row in table for cell in row)
