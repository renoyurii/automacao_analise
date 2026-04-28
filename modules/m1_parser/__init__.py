"""
Módulo 1 — Parsing de Documentos.

Interface pública: use apenas parse_document() para consumir este módulo.
Os readers internos não devem ser chamados diretamente pelo main.py.
"""

from __future__ import annotations

import os
from typing import Any

from .claim_extractor import extract_claims
from .docx_reader import read_docx
from .pdf_reader import read_pdf

_SUPPORTED = {".pdf", ".docx"}


def parse_document(path: str) -> dict[str, Any]:
    """
    Ponto de entrada único do M1.

    Detecta o formato pelo sufixo, delega ao reader correto e
    passa o resultado pelo claim_extractor.

    Retorna: claimed_data (dict com todas as alegações estruturadas).
    """
    ext = os.path.splitext(path)[1].lower()

    if ext not in _SUPPORTED:
        raise ValueError(
            f"Formato não suportado: '{ext}'. "
            f"Formatos aceitos: {', '.join(_SUPPORTED)}"
        )

    raw = read_pdf(path) if ext == ".pdf" else read_docx(path)
    return extract_claims(raw)
