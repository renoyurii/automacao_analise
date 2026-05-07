"""
Interface web — SecAnalysis — Analise Automatizada de Seguranca.
"""

from __future__ import annotations

import base64
import os
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent))
load_dotenv(Path(__file__).parent / ".env", override=True)


# -- Page config (must be first Streamlit call) --------------------------------

st.set_page_config(
    page_title="SecAnalysis - Analise de Seguranca",
    page_icon="\U0001f6e1️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# -- Design tokens -------------------------------------------------------------

_STATUS_BG = {
    "CONFORME":        "rgba(16,185,129,.10)",
    "NAO CONFORME":    "rgba(239,68,68,.10)",
    "ATENCAO":         "rgba(245,158,11,.10)",
    "NAO VERIFICAVEL": "rgba(100,116,139,.08)",
}
_STATUS_FG = {
    "CONFORME":        "#10B981",
    "NAO CONFORME":    "#EF4444",
    "ATENCAO":         "#F59E0B",
    "NAO VERIFICAVEL": "#64748B",
}
_STATUS_ICON = {
    "CONFORME":        "✅",
    "NAO CONFORME":    "❌",
    "ATENCAO":         "⚠️",
    "NAO VERIFICAVEL": "\U0001f535",
}


# -- CSS -----------------------------------------------------------------------

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

/* -- Reset & Base -- */
*, *::before, *::after { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important; }
code, pre, .stCode, [data-testid="stCode"] * { font-family: 'JetBrains Mono', monospace !important; }

/* -- Dark background -- */
[data-testid="stAppViewContainer"] > .main {
    background: #0B0F1A;
}
.block-container {
    padding: 1.5rem 2.2rem 3rem;
    max-width: 1120px;
}
[data-testid="stAppViewContainer"] h1,
[data-testid="stAppViewContainer"] h2,
[data-testid="stAppViewContainer"] h3,
[data-testid="stAppViewContainer"] p,
[data-testid="stAppViewContainer"] span,
[data-testid="stAppViewContainer"] div,
[data-testid="stAppViewContainer"] label {
    color: #E2E8F0 !important;
}
[data-testid="stAppViewContainer"] small {
    color: #64748B !important;
}

/* -- Sidebar -- */
[data-testid="stSidebar"] {
    background: linear-gradient(185deg, #0F1629 0%, #111827 50%, #0B0F1A 100%);
    border-right: 1px solid rgba(99,102,241,.08);
}
[data-testid="stSidebar"] p,
[data-testid="stSidebar"] span,
[data-testid="stSidebar"] small,
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] div { color: rgba(203,213,225,.85) !important; }
[data-testid="stSidebar"] strong { color: #E2E8F0 !important; }
[data-testid="stSidebar"] hr { border-color: rgba(99,102,241,.10) !important; }

/* -- Header -- */
.app-header {
    background: linear-gradient(135deg, #0F1629 0%, #1E1B4B 40%, #312E81 100%);
    color: #E2E8F0;
    padding: 2.2rem 2.8rem 2rem;
    border-radius: 14px;
    margin-bottom: 2rem;
    box-shadow: 0 4px 32px rgba(99,102,241,.12), 0 0 0 1px rgba(99,102,241,.08);
    border: 1px solid rgba(99,102,241,.12);
    position: relative;
    overflow: hidden;
}
.app-header::before {
    content: '';
    position: absolute;
    top: -50%;
    right: -20%;
    width: 300px;
    height: 300px;
    background: radial-gradient(circle, rgba(99,102,241,.08) 0%, transparent 70%);
    pointer-events: none;
}
.app-header h1 {
    font-size: 1.4rem;
    font-weight: 700;
    margin: 0 0 .35rem;
    letter-spacing: -.3px;
    color: #E2E8F0 !important;
}
.app-header p {
    font-size: .8rem;
    margin: 0;
    color: rgba(148,163,184,.7) !important;
    letter-spacing: .3px;
    font-weight: 400;
}

/* -- Cards -- */
.card {
    background: rgba(15,22,41,.65);
    border-radius: 12px;
    box-shadow: 0 2px 16px rgba(0,0,0,.2);
    padding: 1.5rem 1.8rem;
    margin-bottom: 1.1rem;
    border: 1px solid rgba(99,102,241,.08);
    backdrop-filter: blur(8px);
}
.card-conforme { border-left: 4px solid #10B981; }
.card-nao-conforme { border-left: 4px solid #EF4444; }

/* -- Result -- */
.result-status {
    font-size: 1.5rem;
    font-weight: 700;
    letter-spacing: -.4px;
}
.result-meta { font-size: .76rem; color: #64748B !important; margin-bottom: .6rem; }
.result-conclusao { font-size: .88rem; color: #94A3B8 !important; margin-top: .5rem; line-height: 1.55; }
.conforme-text { color: #10B981 !important; }
.nao-conforme-text { color: #EF4444 !important; }

/* -- Sidebar logo area -- */
.sb-logo { padding: 1.6rem 0 1.2rem; text-align: center; }
.sb-logo-icon { font-size: 2.4rem; }
.sb-logo-name {
    font-size: 1rem;
    font-weight: 700;
    color: #E2E8F0 !important;
    letter-spacing: .3px;
    margin-top: .4rem;
    background: linear-gradient(135deg, #6366F1, #818CF8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.sb-logo-sub {
    font-size: .62rem;
    color: rgba(148,163,184,.5) !important;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-top: .15rem;
    font-weight: 500;
}

/* -- Sidebar section -- */
.sb-section { margin-bottom: .2rem; }
.sb-item { font-size: .8rem; padding: .2rem 0; color: rgba(203,213,225,.7) !important; }
.sb-label {
    font-size: .6rem;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: rgba(99,102,241,.6) !important;
    margin-bottom: .5rem;
    display: block;
    font-weight: 600;
}

/* -- SSL cache badge -- */
.ssl-cache-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(16,185,129,.08);
    border: 1px solid rgba(16,185,129,.2);
    border-radius: 6px;
    padding: 4px 10px;
    font-size: .72rem;
    color: #10B981 !important;
    margin-top: .3rem;
}

/* -- Inputs -- */
[data-testid="stTextInput"] input {
    border-radius: 8px;
    border-color: rgba(99,102,241,.15);
    background: rgba(15,22,41,.6);
    color: #E2E8F0;
}
[data-testid="stTextInput"] input:focus {
    border-color: #6366F1;
    box-shadow: 0 0 0 2px rgba(99,102,241,.15);
}

/* -- Buttons -- */
[data-testid="stDownloadButton"] button,
.stButton button {
    border-radius: 8px;
    font-weight: 500;
    letter-spacing: .2px;
}

/* -- Expander -- */
[data-testid="stExpander"] {
    border-radius: 10px !important;
    border-color: rgba(99,102,241,.1) !important;
    background: rgba(15,22,41,.4) !important;
}

/* -- Tabs -- */
[data-testid="stTabs"] [data-baseweb="tab"] {
    font-size: .85rem;
    color: #64748B !important;
}
[data-testid="stTabs"] [data-baseweb="tab"][aria-selected="true"] {
    color: #6366F1 !important;
}

/* -- Evidence cards -- */
.ev-card {
    background: rgba(15,22,41,.5);
    border: 1px solid rgba(99,102,241,.08);
    border-radius: 10px;
    padding: 1rem 1.2rem;
    margin-bottom: .7rem;
}
.ev-quote {
    font-size: .82rem;
    color: #CBD5E1 !important;
    background: rgba(99,102,241,.04);
    padding: .5rem .7rem;
    border-radius: 6px;
    font-style: italic;
    margin-top: .4rem;
    border-left: 2px solid rgba(99,102,241,.2);
}

/* -- Status bar -- */
[data-testid="stStatusWidget"] {
    background: rgba(15,22,41,.8) !important;
    border-color: rgba(99,102,241,.1) !important;
}

/* -- Scrollbar -- */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #0B0F1A; }
::-webkit-scrollbar-thumb { background: rgba(99,102,241,.2); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(99,102,241,.35); }
</style>
""", unsafe_allow_html=True)


# -- SSL Cache -----------------------------------------------------------------

def _get_ssl_cache(domain: str) -> dict | None:
    """Retorna dados SSL em cache para o dominio, ou None."""
    cache = st.session_state.get("_ssl_cache", {})
    entry = cache.get(domain)
    if entry is None:
        return None
    return entry.get("data")


def _set_ssl_cache(domain: str, data: dict) -> None:
    """Armazena resultado SSL Labs em cache (session_state)."""
    if "_ssl_cache" not in st.session_state:
        st.session_state["_ssl_cache"] = {}
    st.session_state["_ssl_cache"][domain] = {
        "data": data,
        "ts": time.time(),
    }


def _scan_all_with_cache(url: str, domain: str) -> dict:
    """Executa scan completo, reutilizando SSL Labs do cache quando disponivel."""
    from modules.m2_scanner import scan_all

    cached_ssl = _get_ssl_cache(domain)
    if cached_ssl is not None:
        # Roda headers, wappalyzer, ports, whois em paralelo -- pula SSL Labs
        from modules.m2_scanner.headers_scan import scan_headers
        from modules.m2_scanner.wappalyzer_scan import scan_wappalyzer
        from modules.m2_scanner.shodan_scan import scan_ports
        from modules.m2_scanner.whois_lookup import scan_whois

        tasks = {
            "headers":    lambda: scan_headers(url),
            "wappalyzer": lambda: scan_wappalyzer(url),
            "ports":      lambda: scan_ports(domain),
            "whois":      lambda: scan_whois(domain),
        }
        results: dict = {"ssl_labs": cached_ssl}
        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {ex.submit(fn): key for key, fn in tasks.items()}
            for future in as_completed(futures):
                key = futures[future]
                try:
                    results[key] = future.result(timeout=60)
                except Exception as e:
                    results[key] = {"error": str(e)}
        return results

    # Sem cache -- executa tudo incluindo SSL Labs
    result = scan_all(url)
    if "ssl_labs" in result and not result["ssl_labs"].get("error"):
        _set_ssl_cache(domain, result["ssl_labs"])
    return result


# -- Helpers -------------------------------------------------------------------

def _domain_from_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return (parsed.netloc or parsed.path).lstrip("www.").split(":")[0]


def _flatten_checks(checks: dict, prefix: str = "") -> list[dict]:
    rows: list[dict] = []
    for key, val in checks.items():
        label = f"{prefix}/{key}" if prefix else key
        if isinstance(val, dict) and "status" in val:
            rows.append({
                "label":    label,
                "status":   val.get("status", "?"),
                "severity": val.get("severity"),
                "detail":   val.get("detail", ""),
            })
        elif isinstance(val, dict):
            rows.extend(_flatten_checks(val, prefix=label))
    return rows


def _eol_label(tech: dict) -> str:
    if tech.get("eol") is True:
        d = tech.get("eol_date")
        return "❌ EOL" + (f" ({d})" if d else "")
    if tech.get("eol") is False:
        return "✅ Suportado"
    if tech.get("version") and tech.get("checked"):
        return "⚠️ Nao encontrado"
    return "—"


def _color_status_row(row: pd.Series) -> list[str]:
    raw = row.get("Status", "")
    key = raw.split(" ", 1)[-1] if " " in raw else raw
    bg  = _STATUS_BG.get(key, "")
    fg  = _STATUS_FG.get(key, "")
    return [
        f"background-color:{bg};color:{fg}" if col == "Status" else ""
        for col in row.index
    ]


def _color_eol_row(row: pd.Series) -> list[str]:
    eol = row.get("EOL", "")
    if "❌" in eol:
        return ["", "", "", "background-color:rgba(239,68,68,.1);color:#EF4444"]
    if "✅" in eol:
        return ["", "", "", "background-color:rgba(16,185,129,.1);color:#10B981"]
    return ["", "", "", ""]


def _show_pdf_embed(pdf_bytes: bytes) -> None:
    """Embed PDF viewer using base64 object/embed (bypasses Chrome CSP)."""
    mb = len(pdf_bytes) / (1024 * 1024)

    if mb > 6:
        st.info(
            f"\U0001f4c4 PDF com {mb:.1f} MB — pre-visualizacao indisponivel para "
            f"arquivos acima de 6 MB. Use o botao de download."
        )
        return

    b64 = base64.b64encode(pdf_bytes).decode()
    data_uri = f"data:application/pdf;base64,{b64}#toolbar=0&navpanes=0"
    st.markdown(f"""
    <div style="border:1px solid rgba(99,102,241,.12);border-radius:10px;overflow:hidden;">
        <object data="{data_uri}" type="application/pdf"
                width="100%" height="700px" style="border:none;display:block;">
            <embed src="{data_uri}" type="application/pdf"
                   width="100%" height="700px" style="border:none;display:block;">
                <p style="text-align:center;padding:2rem;color:#64748B;">
                    Pre-visualizacao indisponivel neste navegador.
                    Use o botao de download.
                </p>
            </embed>
        </object>
    </div>
    """, unsafe_allow_html=True)


def _render_quote(ev) -> str:
    """
    Sanitiza HTML basico e converte [INFERIDO] em prefixo legivel.
    Aceita dict {quote, source, page} ou str (legado).
    """
    import html
    if isinstance(ev, dict):
        raw = ev.get("quote", "")
        source = ev.get("source", "")
        page = ev.get("page")
    else:
        raw = ev
        source = ""
        page = None

    text = (raw or "").strip()
    if text.startswith("[INFERIDO] "):
        body = text[len("[INFERIDO] "):]
        body_html = (
            f"<strong style='color:#F59E0B'>Inferido — </strong>"
            f"{html.escape(body)}"
        )
    else:
        body_html = f"&ldquo;{html.escape(text)}&rdquo;"

    footer = ""
    if source:
        page_part = f" · pagina {page}" if isinstance(page, int) and page > 0 else ""
        footer = (
            f"<div style='font-size:.7rem;color:#64748B;margin-top:.3rem;"
            f"font-style:normal;'>Fonte: {html.escape(source)}{page_part}</div>"
        )
    return body_html + footer


def _merge_claimed(claims: list[dict]) -> dict:
    """
    Une as extracoes de N documentos.

    Regras:
      - Booleanos: True ganha de False ganha de None.
      - Listas (tecnologias etc.): uniao preservando ordem.
      - Strings: primeiro valor nao-vazio.
      - Evidencias: concatena listas de TODOS os documentos. Mantem o
        atributo `source` por citacao (origem visivel). Dedup so remove
        a mesma citacao vinda do mesmo arquivo.
    """
    if len(claims) == 1:
        return claims[0]

    bool_fields = [
        "hsts_claimed", "ssl_cert_claimed",
        "backup_claimed", "redundancy_claimed", "energy_redundancy",
    ]
    list_fields = [
        "tls_versions_claimed", "os_versions", "virtualization",
        "firewall_waf", "open_ports_declared", "datacenter",
    ]
    str_fields = ["monitoring_url", "update_routine"]
    evidence_keys = ("hsts", "ssl_cert", "backup", "redundancy", "energy")

    merged: dict = {}
    for field in bool_fields:
        vals = [c.get(field) for c in claims]
        merged[field] = (
            True  if any(v is True  for v in vals) else
            False if any(v is False for v in vals) else None
        )
    for field in list_fields:
        seen: list = []
        for c in claims:
            for item in (c.get(field) or []):
                if item not in seen:
                    seen.append(item)
        merged[field] = seen
    for field in str_fields:
        merged[field] = next((c.get(field) for c in claims if c.get(field)), None)

    # Evidencia: une preservando atribuicao (source/page por citacao).
    import re
    def _norm(t: str) -> str:
        return re.sub(r"\s+", " ", (t or "").lower()).strip()

    merged_evidence: dict[str, list[dict]] = {k: [] for k in evidence_keys}
    for c in claims:
        ev = c.get("evidence", {}) or {}
        for k in evidence_keys:
            for entry in (ev.get(k) or []):
                if isinstance(entry, str):
                    entry = {"quote": entry, "source": "", "page": None}
                key = (_norm(entry.get("quote", "")), entry.get("source", ""))
                if not key[0]:
                    continue
                seen_keys = {(_norm(e.get("quote", "")), e.get("source", ""))
                             for e in merged_evidence[k]}
                if key in seen_keys:
                    continue
                merged_evidence[k].append(entry)
    merged["evidence"] = merged_evidence

    # raw_sections -- concatenacao simples.
    all_keys: set[str] = set()
    for c in claims:
        all_keys.update((c.get("raw_sections") or {}).keys())
    raw_sections: dict = {}
    for key in all_keys:
        parts = [
            (c.get("raw_sections") or {}).get(key, "").strip()
            for c in claims
            if (c.get("raw_sections") or {}).get(key, "").strip()
        ]
        raw_sections[key] = " [...] ".join(parts)
    merged["raw_sections"] = raw_sections
    merged["image_page_count"] = sum(c.get("image_page_count", 0) or 0 for c in claims)
    return merged


def _parse_all_documents(paths_with_names: list[tuple[str, str]]) -> dict:
    from modules.m1_parser import parse_document
    return _merge_claimed([
        parse_document(path, source_name=name)
        for path, name in paths_with_names
    ])


# -- Sidebar -------------------------------------------------------------------

with st.sidebar:
    st.markdown("""
    <div class="sb-logo">
        <div class="sb-logo-icon">\U0001f6e1️</div>
        <div class="sb-logo-name">SecAnalysis</div>
        <div class="sb-logo-sub">automated security</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    vision_active = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    llm_extract_active = vision_active and os.environ.get("M1_LLM_DISABLE", "") != "1"

    st.markdown('<span class="sb-label">Componentes</span>', unsafe_allow_html=True)
    st.markdown(f"""
    <div class="sb-section">
        <div class="sb-item">{"\U0001f7e2" if llm_extract_active else "⚪"} Extracao via Claude {"ativa" if llm_extract_active else "inativa"}</div>
        <div class="sb-item">{"\U0001f7e2" if vision_active else "⚪"} Vision AI {"ativa" if vision_active else "inativa"}</div>
        <div class="sb-item">\U0001f7e2 SSL Labs (Qualys)</div>
        <div class="sb-item">\U0001f7e2 endoflife.date</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    st.markdown('<span class="sb-label">Pipeline</span>', unsafe_allow_html=True)
    st.markdown("""
    <div class="sb-section">
        <div class="sb-item">M1 · Parsing de documentos</div>
        <div class="sb-item">M2 · Varredura do site</div>
        <div class="sb-item">M3 · Analise de conformidade</div>
        <div class="sb-item">M4 · Geracao de relatorio</div>
    </div>
    """, unsafe_allow_html=True)

    # SSL Cache status
    ssl_cache = st.session_state.get("_ssl_cache", {})
    if ssl_cache:
        st.markdown("---")
        st.markdown('<span class="sb-label">SSL Cache</span>', unsafe_allow_html=True)
        for cached_domain, cached_entry in ssl_cache.items():
            grade = cached_entry.get("data", {}).get("grade", "?")
            st.markdown(
                f'<div class="ssl-cache-badge">'
                f'\U0001f512 {cached_domain} · Grade {grade}'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.markdown("---")
    st.markdown(
        '<div style="font-size:.68rem;color:rgba(148,163,184,.3);text-align:center;padding-top:.4rem;">'
        "SecAnalysis<br>v2.0 · 2026"
        "</div>",
        unsafe_allow_html=True,
    )


# -- Header --------------------------------------------------------------------

st.markdown("""
<div class="app-header">
    <h1>\U0001f6e1️ SecAnalysis — Analise de Seguranca</h1>
    <p>Analise automatizada de conformidade de seguranca da informacao</p>
</div>
""", unsafe_allow_html=True)


# -- Form ----------------------------------------------------------------------

col_url, col_file = st.columns([5, 4])

with col_url:
    url_input = st.text_input(
        "URL do site do leiloeiro",
        placeholder="https://www.exemplo.com.br",
    )

with col_file:
    uploaded = st.file_uploader(
        "Declaracoes do leiloeiro (PDF / DOCX)",
        type=["pdf", "docx"],
        accept_multiple_files=True,
        help="Um ou mais arquivos enviados pelo leiloeiro via SEI",
    )


# -- Document preview ----------------------------------------------------------

if uploaded:
    pdf_files = [f for f in uploaded if f.name.lower().endswith(".pdf")]

    if pdf_files:
        label = (
            f"Pre-visualizar — {pdf_files[0].name}"
            if len(pdf_files) == 1
            else f"Pre-visualizar documentos ({len(pdf_files)} PDFs)"
        )
        with st.expander(f"\U0001f4c4 {label}", expanded=False):
            if len(pdf_files) == 1:
                sel = pdf_files[0]
            else:
                sel = st.selectbox(
                    "Selecionar documento",
                    options=pdf_files,
                    format_func=lambda f: f.name,
                )

            sel.seek(0)
            _show_pdf_embed(sel.read())
            sel.seek(0)


# -- Trigger -------------------------------------------------------------------

ready = bool(url_input.strip() and uploaded)
col_btn, col_hint = st.columns([1, 5])

domain_preview = _domain_from_url(url_input) if url_input.strip() else ""
has_ssl_cache = domain_preview and _get_ssl_cache(domain_preview) is not None

with col_btn:
    run = st.button("Analisar", type="primary", disabled=not ready, use_container_width=True)

with col_hint:
    if not ready:
        st.caption("Preencha a URL e carregue a declaracao para habilitar a analise.")
    elif has_ssl_cache:
        st.caption("\U0001f512 SSL Labs em cache — analise mais rapida.")
    else:
        st.caption("A analise leva aprox. **3 minutos** — SSL Labs pode ser o gargalo.")


# -- Pipeline completo (M1 + M2 -> M3 -> M4) -----------------------------------

if run and ready:
    for k in ("result", "ficha_path", "pdf_path", "url_used", "domain_used"):
        st.session_state.pop(k, None)

    tmp_paths_with_names: list[tuple[str, str]] = []
    for uf in uploaded:
        uf.seek(0)
        data = uf.read()
        suffix = Path(uf.name).suffix.lower()
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(data)
            tmp_paths_with_names.append((tmp.name, uf.name))
        uf.seek(0)

    tmp_paths = [p for p, _ in tmp_paths_with_names]

    try:
        with st.status("Executando analise completa...", expanded=True) as status_box:
            from modules.m1_parser import parse_document
            from modules.m2_scanner import scan_all
            from modules.m3_engine import evaluate
            from modules.m4_reporter import generate_ficha, generate_pdf

            domain = _domain_from_url(url_input)
            n = len(tmp_paths_with_names)
            ai_note = " + Vision AI" if vision_active else ""
            st.write(f"M1 · Parsing de {n} documento(s){ai_note} e M2 · Varredura web — em paralelo...")
            for _, original_name in tmp_paths_with_names:
                st.write(f"  · {original_name}")

            if has_ssl_cache:
                st.write("\U0001f512 SSL Labs em cache — pulando analise SSL.")
            else:
                st.write("Aguardando SSL Labs (Qualys) — pode levar ate 3 minutos...")

            with ThreadPoolExecutor(max_workers=2) as ex:
                fut_m1 = ex.submit(_parse_all_documents, tmp_paths_with_names)
                fut_m2 = ex.submit(_scan_all_with_cache, url_input, domain)
                claimed = fut_m1.result()
                scan    = fut_m2.result()

            st.write(f"✓ M1 concluido ({n} documento(s))")
            st.write("✓ M2 concluido")

            st.write("M3 · Cruzando dados e aplicando regras de conformidade...")
            result = evaluate(claimed, scan, url_input, domain)
            st.write("✓ M3 concluido")

            st.write("M4 · Gerando ficha de verificacao...")
            out_dir = Path(__file__).parent / "output"
            out_dir.mkdir(exist_ok=True)
            safe_domain = domain.replace(".", "_")
            out_path = out_dir / f"ficha_verificacao_{safe_domain}_{date.today().isoformat()}.docx"
            ficha_path = str(generate_ficha(result, out_path))
            st.write("✓ Ficha .docx gerada")

            pdf_out = out_dir / f"ficha_verificacao_{safe_domain}_{date.today().isoformat()}.pdf"
            pdf_path = generate_pdf(result, pdf_out)
            st.write("✓ PDF gerado")

            status_box.update(label="Relatorio gerado com sucesso", state="complete", expanded=False)

        st.session_state["result"]      = result
        st.session_state["ficha_path"]  = ficha_path
        st.session_state["pdf_path"]    = pdf_path
        st.session_state["url_used"]    = url_input
        st.session_state["domain_used"] = domain

    except Exception as exc:
        st.error(f"Erro durante a analise: {exc}")
        st.exception(exc)
    finally:
        for p in tmp_paths:
            try:
                os.unlink(p)
            except OSError:
                pass


# -- Results -------------------------------------------------------------------

if "result" in st.session_state:
    rd         = st.session_state["result"]
    ficha_path = st.session_state["ficha_path"]
    pdf_path   = st.session_state.get("pdf_path")

    overall   = rd.get("overall_status", "?")
    domain    = rd.get("domain", "")
    anal_date = rd.get("analysis_date", date.today().isoformat())
    conclusao = rd.get("conclusao", "")
    checks    = rd.get("checks", {})
    techs     = rd.get("raw", {}).get("technologies", [])

    is_ok     = (overall == "CONFORME")
    card_cls  = "card-conforme" if is_ok else "card-nao-conforme"
    txt_cls   = "conforme-text" if is_ok else "nao-conforme-text"
    icon      = "✅" if is_ok else "❌"

    st.markdown("---")

    # -- Result card + download panel ------------------------------------------

    col_card, col_dl = st.columns([3, 2])

    with col_card:
        st.markdown(f"""
        <div class="card {card_cls}">
            <div class="result-meta">\U0001f310 {domain} &nbsp;·&nbsp; {anal_date}</div>
            <div class="result-status {txt_cls}">{icon} {overall}</div>
            <div class="result-conclusao">{conclusao}</div>
        </div>
        """, unsafe_allow_html=True)

    with col_dl:
        st.markdown("<div style='height:.6rem'></div>", unsafe_allow_html=True)
        st.markdown("**Baixar ficha**")

        with open(ficha_path, "rb") as fh:
            st.download_button(
                label="⬇  Download .docx",
                data=fh.read(),
                file_name=Path(ficha_path).name,
                mime=(
                    "application/vnd.openxmlformats-officedocument"
                    ".wordprocessingml.document"
                ),
                use_container_width=True,
            )

        if pdf_path and Path(pdf_path).exists():
            with open(pdf_path, "rb") as fh:
                st.download_button(
                    label="⬇  Download .pdf",
                    data=fh.read(),
                    file_name=Path(pdf_path).name,
                    mime="application/pdf",
                    use_container_width=True,
                )
        else:
            st.caption("PDF nao disponivel para esta analise.")

    # -- Ficha preview (if PDF was generated) ----------------------------------

    if pdf_path and Path(pdf_path).exists():
        with st.expander("\U0001f4c4 Pre-visualizar ficha gerada", expanded=False):
            with open(pdf_path, "rb") as fh:
                _show_pdf_embed(fh.read())

    st.markdown("<div style='height:.8rem'></div>", unsafe_allow_html=True)

    # -- Tabs ------------------------------------------------------------------

    tab_ev, tab_chk, tab_tec, tab_raw = st.tabs([
        "\U0001f4cb Extracao M1", "Verificacoes", "Tecnologias detectadas", "Dados brutos",
    ])

    with tab_ev:
        evidence = rd.get("raw", {}).get("evidence", {}) or {}

        _ev_labels = [
            ("redundancy", "Redundancia de Servico"),
            ("backup",     "Backup e Recuperacao"),
            ("energy",     "Recurso Continuo de Energia"),
            ("hsts",       "HSTS"),
            ("ssl_cert",   "Certificado SSL/TLS"),
        ]

        any_evidence = any(evidence.get(k) for k, _ in _ev_labels)
        if not any_evidence:
            st.warning(
                "Nenhuma evidencia textual extraida do documento. "
                "Verifique se o relatorio do leiloeiro esta completo."
            )
        else:
            st.markdown(
                "<p style='font-size:.83rem;color:#94A3B8;margin-bottom:1rem;'>"
                "Citacoes verbatim extraidas do documento — todas as mencoes relevantes "
                "que sustentam cada item da Ficha de Verificacao.</p>",
                unsafe_allow_html=True,
            )

        for key, label in _ev_labels:
            quotes = list(evidence.get(key, []) or [])
            if not quotes:
                continue

            def _qtext(e):
                return e.get("quote", "") if isinstance(e, dict) else str(e or "")
            inferred = all(_qtext(q).startswith("[INFERIDO] ") for q in quotes)
            badge_color = "#F59E0B" if inferred else "#10B981"
            badge_icon = "⚠️" if inferred else "✅"
            badge_text = "Inferido" if inferred else f"{len(quotes)} citacao(oes)"

            quotes_html = "".join(
                f"<div class='ev-quote'>{_render_quote(q)}</div>"
                for q in quotes
            )

            st.markdown(
                f"<div class='ev-card' style='border-left:3px solid {badge_color};'>"
                f"<div style='display:flex;justify-content:space-between;align-items:center;'>"
                f"<strong style='font-size:.9rem;color:#E2E8F0;'>{label}</strong>"
                f"<span style='font-size:.72rem;color:{badge_color};'>{badge_icon} {badge_text}</span>"
                f"</div>"
                f"{quotes_html}"
                f"</div>",
                unsafe_allow_html=True,
            )

    with tab_chk:
        rows = _flatten_checks(checks)
        if rows:
            df_chk = pd.DataFrame([
                {
                    "Secao":      r["label"],
                    "Status":     f"{_STATUS_ICON.get(r['status'], '?')} {r['status']}",
                    "Severidade": r["severity"] or "—",
                    "Detalhe":    r["detail"],
                }
                for r in rows
            ])
            st.dataframe(
                df_chk.style.apply(_color_status_row, axis=1),
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Secao":      st.column_config.TextColumn(width="medium"),
                    "Status":     st.column_config.TextColumn(width="medium"),
                    "Severidade": st.column_config.TextColumn(width="small"),
                    "Detalhe":    st.column_config.TextColumn(width="large"),
                },
            )
        else:
            st.info("Nenhuma verificacao disponivel.")

    with tab_tec:
        if techs:
            df_tec = pd.DataFrame([
                {
                    "Categoria":  t.get("category", ""),
                    "Tecnologia": t.get("name", ""),
                    "Versao":     t.get("version") or "—",
                    "EOL":        _eol_label(t),
                }
                for t in sorted(techs, key=lambda x: (x.get("category", ""), x.get("name", "")))
            ])
            st.dataframe(
                df_tec.style.apply(_color_eol_row, axis=1),
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Categoria":  st.column_config.TextColumn(width="medium"),
                    "Tecnologia": st.column_config.TextColumn(width="medium"),
                    "Versao":     st.column_config.TextColumn(width="small"),
                    "EOL":        st.column_config.TextColumn(width="small"),
                },
            )
        else:
            st.info("Nenhuma tecnologia detectada.")

    with tab_raw:
        raw = rd.get("raw", {})
        t_whois, t_hdrs, t_ssl = st.tabs(["WHOIS", "Cabecalhos HTTP", "SSL Labs"])
        with t_whois:
            st.code(raw.get("whois_raw", "Nao disponivel"), language=None)
        with t_hdrs:
            st.code(raw.get("headers_raw_block", "Nao disponivel"), language=None)
        with t_ssl:
            ssl = raw.get("ssl_labs", {})
            st.json({k: v for k, v in ssl.items() if k != "raw_endpoints"})
