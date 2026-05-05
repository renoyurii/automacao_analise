"""
Localizador de evidências no documento original.

Dada uma citação textual e o texto-fonte por página, devolve o número da
página onde a citação aparece (1-based) usando substring exata + fuzzy
match com difflib.SequenceMatcher.

Usa apenas stdlib. Performance: < 50 ms por citação em PDFs típicos.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher

_THRESHOLD = 0.70  # similaridade mínima para considerar localizado


def locate_page(
    quote: str,
    pages_text: list[str],
    full_text: str = "",
    threshold: float = _THRESHOLD,
) -> int | None:
    """
    Devolve o número da página (1-based) onde a citação aparece, ou None.

    Args:
        quote:       trecho a localizar.
        pages_text:  lista de strings, index = página 0-based.
        full_text:   texto completo (fallback se a citação cruza páginas).
        threshold:   similaridade mínima para considerar localizado.
    """
    if not quote or not quote.strip():
        return None

    needle = _normalize(quote)
    if not needle:
        return None

    page_idx = _best_page(needle, pages_text, threshold)
    if page_idx is not None:
        return page_idx + 1

    # Fallback: confirma que a citação ao menos existe no texto inteiro.
    # Sem `pages_text` (ex.: DOCX) devolve None — a UI mostra apenas o nome
    # do arquivo.
    if full_text and _fuzzy_find(needle, _normalize(full_text))[1] >= threshold:
        return None
    return None


# ── Helpers ──────────────────────────────────────────────────────────────────

def _best_page(needle: str, pages_text: list[str], threshold: float) -> int | None:
    best_idx: int | None = None
    best_ratio = 0.0

    for idx, page in enumerate(pages_text):
        if not page:
            continue
        haystack = _normalize(page)
        if not haystack:
            continue

        # Substring exata é o caminho rápido (a maioria dos casos cai aqui).
        if needle in haystack:
            return idx

        # Fragmento curto na página → confirma que vale tentar fuzzy.
        fragment = needle[:40] if len(needle) > 40 else needle[:20]
        if fragment not in haystack:
            continue

        _, ratio = _fuzzy_find(needle, haystack)
        if ratio > best_ratio:
            best_ratio = ratio
            best_idx = idx

    if best_idx is not None and best_ratio >= threshold:
        return best_idx
    return None


def _fuzzy_find(needle: str, haystack: str) -> tuple[str, float]:
    if not needle or not haystack:
        return "", 0.0
    if needle in haystack:
        return needle, 1.0

    needle_len = len(needle)
    min_window = max(10, int(needle_len * 0.7))
    max_window = int(needle_len * 1.4)
    step = max(1, needle_len // 8)

    best_ratio = 0.0
    best_text = ""

    window_step = max(1, (max_window - min_window) // 4)
    for window_size in range(min_window, min(max_window + 1, len(haystack) + 1), window_step):
        for start in range(0, len(haystack) - window_size + 1, step):
            candidate = haystack[start:start + window_size]
            ratio = SequenceMatcher(None, needle, candidate, autojunk=False).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_text = candidate
                if ratio >= 0.95:
                    return best_text, best_ratio
    return best_text, best_ratio


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())
