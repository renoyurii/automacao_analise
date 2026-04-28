"""
Módulo 4 — Gerador de Relatório.

Interface pública: use apenas generate_ficha() para consumir este módulo.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .ficha_builder import build_ficha


def generate_ficha(result_data: dict[str, Any], output_path: str | Path) -> str:
    """
    Gera a Ficha de Verificação de Segurança da Informação em .docx.

    Parâmetros:
        result_data — saída de modules.m3_engine.evaluate()
        output_path — caminho de saída para o arquivo .docx

    Retorna: caminho absoluto do arquivo gerado.
    """
    return build_ficha(result_data, output_path)
