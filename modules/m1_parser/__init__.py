"""
Módulo 1 — Parsing de Documentos.

Pipeline:
    1. read_pdf / read_docx           — extrai texto bruto + pages_text
    2. vision_extractor (se aplicável) — descreve páginas-imagem em texto
    3. extract_claims (regex)          — baseline + listas de citações
    4. extract_claims_with_llm (LLM)   — fonte primária quando API key disponível
    5. _merge_claims                   — LLM autoritativo para booleanos/strings,
                                          união para listas, evidências unidas
                                          (LLM ∪ regex) por item.
    6. _attribute_sources              — para cada citação, anexa source
                                          (nome do arquivo) e page (1-based).

Interface pública: parse_document(). Os submódulos não devem ser chamados
diretamente pelo main.py.

Estrutura final de cada evidência:
    {"quote": str, "source": str, "page": int | None}
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from .claim_extractor import extract_claims
from .docx_reader import read_docx
from .evidence_locator import locate_page
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
_EVIDENCE_KEYS = ("hsts", "ssl_cert", "backup", "redundancy", "energy")
_INFERIDO_PREFIX = "[INFERIDO] "


def parse_document(path: str, source_name: str | None = None) -> dict[str, Any]:
    """
    Ponto de entrada único do M1.

    Args:
        path:        caminho local do arquivo a parsear (.pdf ou .docx).
        source_name: nome amigável do arquivo a registrar nas evidências
                     (default: basename de `path`). Útil quando o arquivo
                     vem de um upload temporário e o nome real está noutra
                     variável.

    Retorna: claimed_data — alegações estruturadas com listas de citações
    verbatim por item em `evidence`. Cada citação é um dict
    `{"quote", "source", "page"}`.
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

    regex_claims = extract_claims(raw)

    if llm_available():
        llm_claims = extract_claims_with_llm(raw["text"])
        if llm_claims is not None:
            merged = _merge_claims(regex_claims, llm_claims)
        else:
            merged = regex_claims
    else:
        merged = regex_claims

    # Atribuição de fonte + página acontece DEPOIS do merge, com base no
    # texto-fonte original (pages_text disponível só para PDF).
    display_name = source_name or Path(path).name
    pages_text = raw.get("pages_text") or []
    full_text = raw.get("text", "")
    merged["evidence"] = _attribute_sources(
        merged.get("evidence", {}) or {},
        display_name=display_name,
        pages_text=pages_text,
        full_text=full_text,
    )
    return merged


# ── Merge regex × LLM ────────────────────────────────────────────────────────

def _merge_claims(regex: dict[str, Any], llm: dict[str, Any]) -> dict[str, Any]:
    """
    Combina os resultados das duas extrações.

    Política:
        - Booleans:   LLM autoritativo quando não-None. Regex preserva quando LLM=None.
        - Listas:     união (preserva descobertas únicas de ambas as fontes).
        - Strings:    LLM ganha quando preenchido. Regex preserva quando LLM vazio.
        - Evidence:   união LLM ∪ regex por item, deduplicada por similaridade.
        - raw_sections: vem do regex (LLM não produz texto contextual de seção).
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

    merged_evidence: dict[str, list[str]] = {}
    regex_ev = regex.get("evidence", {}) or {}
    llm_ev   = llm.get("evidence", {})   or {}

    for key in _EVIDENCE_KEYS:
        # LLM tem prioridade no formato (citação verbatim), mas o regex pode
        # encontrar trechos que o LLM perdeu — então a ordem é LLM primeiro,
        # regex em seguida, com deduplicação fuzzy.
        candidates = list(llm_ev.get(key, []) or []) + list(regex_ev.get(key, []) or [])
        merged_evidence[key] = _dedupe_evidence(candidates)

    merged["evidence"] = merged_evidence

    # Recoerência booleana ←→ evidência: se houver evidência mas o boolean
    # ficou None (ex.: regex disse None e LLM não respondeu), promovemos
    # para True. Se o LLM disse False explicitamente, respeitamos.
    _bool_for_key = {
        "backup":     "backup_claimed",
        "redundancy": "redundancy_claimed",
        "energy":     "energy_redundancy",
        "hsts":       "hsts_claimed",
        "ssl_cert":   "ssl_cert_claimed",
    }
    for ev_key, bool_field in _bool_for_key.items():
        if merged.get(bool_field) is None and merged_evidence.get(ev_key):
            merged[bool_field] = True

    return merged


def _dedupe_evidence(quotes: list[str]) -> list[str]:
    """
    Remove citações redundantes preservando ordem (LLM primeiro).

    Critério: duas citações são equivalentes se a normalização (whitespace
    + lowercase) de uma contém a outra OU se compartilham > 85% dos tokens
    da menor. Inferências ([INFERIDO]) só sobrevivem se NÃO houver nenhuma
    citação direta — evitamos misturar inferência com evidência real.
    """
    direct = [q for q in quotes if not q.startswith(_INFERIDO_PREFIX)]
    inferred = [q for q in quotes if q.startswith(_INFERIDO_PREFIX)]

    pool = direct if direct else inferred
    out: list[str] = []
    norms: list[str] = []
    for raw in pool:
        q = (raw or "").strip()
        if not q:
            continue
        norm = re.sub(r"\s+", " ", q.lower()).strip()
        if not norm:
            continue
        if any(_is_redundant(norm, prev) for prev in norms):
            continue
        out.append(q)
        norms.append(norm)

    return out[:8]


def _is_redundant(a: str, b: str) -> bool:
    if a == b:
        return True
    if a in b or b in a:
        return True
    tokens_a = set(re.findall(r"\w+", a))
    tokens_b = set(re.findall(r"\w+", b))
    if not tokens_a or not tokens_b:
        return False
    smaller = tokens_a if len(tokens_a) <= len(tokens_b) else tokens_b
    overlap = len(tokens_a & tokens_b) / max(1, len(smaller))
    return overlap >= 0.85


# ── Atribuição de fonte por evidência ────────────────────────────────────────

def _attribute_sources(
    evidence: dict[str, list[str]],
    display_name: str,
    pages_text: list[str],
    full_text: str,
) -> dict[str, list[dict]]:
    """
    Converte cada citação str → {"quote", "source", "page"} localizando
    a página de origem no texto extraído.

    Para inferências ([INFERIDO]), busca a página do snippet entre aspas
    no corpo da inferência; se não localizar, devolve page=None.
    """
    out: dict[str, list[dict]] = {}
    for key, quotes in evidence.items():
        attributed: list[dict] = []
        for q in quotes:
            search_target = _quote_for_locate(q)
            page = locate_page(search_target, pages_text, full_text)
            attributed.append({
                "quote":  q,
                "source": display_name,
                "page":   page,
            })
        out[key] = attributed
    return out


def _quote_for_locate(quote: str) -> str:
    """
    Para inferências, o que rastreamos no documento é o snippet entre aspas
    dentro da string [INFERIDO] ... Trecho do documento: "<snippet>".
    """
    if quote.startswith(_INFERIDO_PREFIX):
        m = re.search(r'Trecho do documento:\s*"([^"]+)"', quote)
        if m:
            return m.group(1)
    return quote
