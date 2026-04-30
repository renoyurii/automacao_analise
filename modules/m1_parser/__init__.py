"""
Módulo 1 — Parsing de Documentos.

Pipeline:
    1. read_pdf / read_docx           — extrai texto bruto + metadata
    2. vision_extractor (se aplicável) — descreve páginas-imagem em texto
    3. extract_claims (regex)          — baseline + raw_sections (sempre roda)
    4. extract_claims_with_llm (LLM)   — fonte primária quando API key disponível
    5. _merge_claims                   — LLM autoritativo para booleanos/strings,
                                          união para listas, regex preserva
                                          raw_sections para evidências

Interface pública: parse_document(). Os submódulos não devem ser chamados
diretamente pelo main.py.
"""

from __future__ import annotations

import os
from typing import Any

from .claim_extractor import extract_claims
from .docx_reader import read_docx
from .llm_extractor import extract_claims_with_llm, is_available as llm_available
from .pdf_reader import read_pdf

_SUPPORTED = {".pdf", ".docx"}

# Campos que o merge precisa conhecer
_BOOL_FIELDS = (
    "hsts_claimed", "ssl_cert_claimed",
    "backup_claimed", "redundancy_claimed", "energy_redundancy",
)
_LIST_FIELDS = (
    "tls_versions_claimed", "os_versions", "virtualization",
    "firewall_waf", "open_ports_declared", "datacenter",
)
_STR_FIELDS = ("monitoring_url", "update_routine")


def parse_document(path: str) -> dict[str, Any]:
    """
    Ponto de entrada único do M1.

    Detecta o formato pelo sufixo, delega ao reader correto, enriquece com
    Vision AI quando há páginas-imagem, e roda extração regex + LLM em
    paralelo conceitual (regex sempre, LLM quando disponível).

    Retorna: claimed_data — alegações estruturadas com raw_sections para
    evidência e (quando o LLM rodou) campo llm_evidence com citações por item.
    """
    ext = os.path.splitext(path)[1].lower()

    if ext not in _SUPPORTED:
        raise ValueError(
            f"Formato não suportado: '{ext}'. "
            f"Formatos aceitos: {', '.join(_SUPPORTED)}"
        )

    raw = read_pdf(path) if ext == ".pdf" else read_docx(path)

    # Vision AI: descreve páginas-imagem em texto antes da extração
    if ext == ".pdf" and raw.get("image_page_count", 0) > 0:
        indices = raw.get("image_page_indices", [])
        if indices and os.environ.get("ANTHROPIC_API_KEY", "").strip():
            from .vision_extractor import extract_text_from_image_pages
            vision_text = extract_text_from_image_pages(path, indices)
            if vision_text:
                raw["text"] = raw["text"] + "\n\n" + vision_text

    # Regex: sempre roda (baseline + raw_sections para o M4)
    regex_claims = extract_claims(raw)

    # LLM: roda quando API key disponível e não desativado
    if llm_available():
        llm_claims = extract_claims_with_llm(raw["text"])
        if llm_claims is not None:
            return _merge_claims(regex_claims, llm_claims)

    return regex_claims


# ── Merge regex × LLM ────────────────────────────────────────────────────────

def _merge_claims(regex: dict[str, Any], llm: dict[str, Any]) -> dict[str, Any]:
    """
    Combina os resultados das duas extrações.

    Política:
        - Booleans:  LLM autoritativo quando não-None. Regex preserva quando LLM=None.
        - Listas:    união (preserva descobertas únicas de ambas as fontes).
        - Strings:   LLM ganha quando preenchido. Regex preserva quando LLM vazio.
        - raw_sections: vem do regex (LLM não produz texto contextual de seção).
        - llm_evidence: vem do LLM, exposto para auditoria no M4.
    """
    merged: dict[str, Any] = dict(regex)

    for f in _BOOL_FIELDS:
        if llm.get(f) is not None:
            merged[f] = llm[f]

    for f in _LIST_FIELDS:
        seen = list(regex.get(f, []) or [])
        for item in (llm.get(f, []) or []):
            if item not in seen:
                seen.append(item)
        merged[f] = seen

    for f in _STR_FIELDS:
        if llm.get(f):
            merged[f] = llm[f]

    if llm.get("llm_evidence"):
        merged["llm_evidence"] = llm["llm_evidence"]

    return merged
