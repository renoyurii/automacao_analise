"""
Verificador de evidências extraídas pelo LLM.

Dado um conjunto de citações (llm_evidence) e o texto-fonte por página,
verifica se cada citação realmente existe no documento original e identifica
em qual página ela se encontra.

Usa difflib.SequenceMatcher (stdlib) — sem dependências externas.
Performance: < 100ms para 5 citações × 40 páginas típicas de leiloeiro.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any


@dataclass
class EvidenceResult:
    """Resultado da verificação de uma citação."""
    quote: str                  # Texto original fornecido pelo LLM
    verified: bool              # True se a citação foi localizada no documento
    confidence: float           # Similaridade (0.0 a 1.0)
    page_number: int | None     # Página onde foi encontrada (1-based) ou None
    matched_text: str           # Trecho real do documento que corresponde


_THRESHOLD = 0.70  # Mínimo de similaridade para considerar verificado


def verify_evidence(
    llm_evidence: dict[str, str],
    pages_text: list[str],
    full_text: str,
    threshold: float = _THRESHOLD,
) -> dict[str, EvidenceResult]:
    """
    Verifica cada citação do LLM contra o texto-fonte do documento.

    Args:
        llm_evidence: dict com chaves (hsts, ssl_cert, backup, redundancy, energy)
                      e valores sendo a citação textual extraída pelo LLM.
        pages_text:   lista de strings, index = página 0-based.
        full_text:    texto completo concatenado (fallback para DOCX ou cross-page).
        threshold:    similaridade mínima para marcar como verificado.

    Returns:
        dict com as mesmas chaves, valores são EvidenceResult.
    """
    results: dict[str, EvidenceResult] = {}

    for key, quote in llm_evidence.items():
        if not quote or not quote.strip():
            results[key] = EvidenceResult(
                quote="", verified=False, confidence=0.0,
                page_number=None, matched_text="",
            )
            continue

        quote_norm = _normalize(quote)

        # Fase 1: busca por página (rápido — verifica substring primeiro)
        best_match = _find_best_match_in_pages(quote_norm, pages_text, threshold)

        # Fase 2: fallback para texto completo (cross-page ou DOCX)
        if best_match is None and full_text:
            match_text, confidence = _fuzzy_find(quote_norm, _normalize(full_text))
            if confidence >= threshold:
                best_match = (None, confidence, match_text)

        if best_match is not None:
            page_idx, confidence, matched_text = best_match
            results[key] = EvidenceResult(
                quote=quote.strip(),
                verified=True,
                confidence=confidence,
                page_number=(page_idx + 1) if page_idx is not None else None,
                matched_text=matched_text.strip(),
            )
        else:
            results[key] = EvidenceResult(
                quote=quote.strip(),
                verified=False,
                confidence=0.0,
                page_number=None,
                matched_text="",
            )

    return results


def _find_best_match_in_pages(
    quote_norm: str,
    pages_text: list[str],
    threshold: float,
) -> tuple[int, float, str] | None:
    """
    Busca a melhor correspondência da citação em cada página.
    Retorna (page_index, confidence, matched_text) ou None.
    """
    best: tuple[int, float, str] | None = None
    best_confidence = 0.0

    for page_idx, page_text in enumerate(pages_text):
        if not page_text:
            continue

        page_norm = _normalize(page_text)

        # Fast check: se um fragmento significativo da citação existe na página
        fragment = quote_norm[:40]
        if fragment not in page_norm:
            # Tenta com fragmento menor
            fragment = quote_norm[:20]
            if fragment not in page_norm:
                continue

        # Busca detalhada na página
        matched_text, confidence = _fuzzy_find(quote_norm, page_norm)

        if confidence > best_confidence:
            best_confidence = confidence
            best = (page_idx, confidence, matched_text)

    if best is not None and best[1] >= threshold:
        return best
    return None


def _fuzzy_find(needle: str, haystack: str) -> tuple[str, float]:
    """
    Encontra o trecho do haystack mais similar ao needle.
    Usa sliding window com tamanho adaptativo.

    Retorna (matched_text, confidence).
    """
    if not needle or not haystack:
        return "", 0.0

    # Caso ideal: substring exata
    if needle in haystack:
        return needle, 1.0

    # Sliding window: tamanho da janela = len(needle) ± 30%
    needle_len = len(needle)
    min_window = max(10, int(needle_len * 0.7))
    max_window = int(needle_len * 1.4)

    best_ratio = 0.0
    best_text = ""

    # Step adaptativo baseado no tamanho do haystack
    step = max(1, needle_len // 8)

    for window_size in range(min_window, min(max_window + 1, len(haystack) + 1), max(1, (max_window - min_window) // 4)):
        for start in range(0, len(haystack) - window_size + 1, step):
            candidate = haystack[start:start + window_size]
            ratio = SequenceMatcher(None, needle, candidate, autojunk=False).ratio()

            if ratio > best_ratio:
                best_ratio = ratio
                best_text = candidate

                # Early exit para match quase perfeito
                if ratio >= 0.95:
                    return best_text, best_ratio

    return best_text, best_ratio


def _normalize(text: str) -> str:
    """Normaliza whitespace para comparação mais tolerante."""
    return re.sub(r"\s+", " ", text.strip().lower())
