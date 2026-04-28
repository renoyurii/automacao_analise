"""
Módulo 3 — Motor de Decisão.

Interface pública: use apenas evaluate() para consumir este módulo.
"""

from __future__ import annotations

from typing import Any

from .comparator import compare


def evaluate(
    claimed_data: dict[str, Any],
    scan_data: dict[str, Any],
    url: str,
    domain: str,
) -> dict[str, Any]:
    """
    Cruza claimed_data (M1) com scan_data (M2) e retorna result_data para o M4.

    Parâmetros:
        claimed_data — saída de modules.m1_parser.parse_document()
        scan_data    — saída de modules.m2_scanner.scan_all()
        url          — URL original do leiloeiro
        domain       — domínio limpo (sem www, sem protocolo)

    Retorna: result_data com checks, status geral e conclusão.
    """
    return compare(claimed_data, scan_data, url, domain)
