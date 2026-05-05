"""
Interface web — Sistema de Análise Automatizada de Segurança.
DESEG / SEAUD / GABPRES — TJRJ
"""

from __future__ import annotations

import base64
import os
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent))
load_dotenv(Path(__file__).parent / ".env", override=True)


# ── Page config (must be first Streamlit call) ─────────────────────────────────

st.set_page_config(
    page_title="DESEG — Homologação de Leiloeiros",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ── Design tokens ──────────────────────────────────────────────────────────────

_STATUS_BG = {
    "CONFORME":        "#E8F5E9",
    "NÃO CONFORME":    "#FFEBEE",
    "ATENÇÃO":         "#FFF3E0",
    "NÃO VERIFICÁVEL": "#ECEFF1",
}
_STATUS_FG = {
    "CONFORME":        "#2E7D32",
    "NÃO CONFORME":    "#C62828",
    "ATENÇÃO":         "#E65100",
    "NÃO VERIFICÁVEL": "#546E7A",
}
_STATUS_ICON = {
    "CONFORME":        "✅",
    "NÃO CONFORME":    "❌",
    "ATENÇÃO":         "⚠️",
    "NÃO VERIFICÁVEL": "🔵",
}


# ── CSS ────────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
/* ─ Background ─ */
[data-testid="stAppViewContainer"] > .main {
    background-color: #EEF2F8;
}
.block-container {
    padding: 1.8rem 2.2rem 3rem;
    max-width: 1080px;
}

/* ─ Sidebar ─ */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #001A6E 0%, #0039C2 100%);
    border-right: none;
}
[data-testid="stSidebar"] p,
[data-testid="stSidebar"] span,
[data-testid="stSidebar"] small,
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] div { color: rgba(225,235,255,.9) !important; }
[data-testid="stSidebar"] strong { color: #FFFFFF !important; }
[data-testid="stSidebar"] hr    { border-color: rgba(255,255,255,.12) !important; }

/* ─ Header ─ */
.tjrj-header {
    background: linear-gradient(130deg, #001257 0%, #003DA5 55%, #1565C0 100%);
    color: white;
    padding: 2rem 2.5rem 1.8rem;
    border-radius: 12px;
    margin-bottom: 2rem;
    box-shadow: 0 6px 24px rgba(0,29,110,.18);
}
.tjrj-header h1 {
    font-size: 1.5rem;
    font-weight: 700;
    margin: 0 0 .3rem;
    letter-spacing: -.4px;
    color: white;
}
.tjrj-header p {
    font-size: .82rem;
    margin: 0;
    color: rgba(255,255,255,.72);
    letter-spacing: .2px;
}

/* ─ Cards ─ */
.card {
    background: white;
    border-radius: 10px;
    box-shadow: 0 1px 4px rgba(0,0,0,.07), 0 2px 12px rgba(0,0,0,.04);
    padding: 1.4rem 1.8rem;
    margin-bottom: 1.1rem;
}
.card-conforme     { border-left: 5px solid #2E7D32; }
.card-nao-conforme { border-left: 5px solid #C62828; }

/* ─ Result ─ */
.result-status {
    font-size: 1.5rem;
    font-weight: 700;
    letter-spacing: -.4px;
}
.result-meta     { font-size: .78rem; color: #90A4AE; margin-bottom: .6rem; }
.result-conclusao { font-size: .9rem; color: #455A64; margin-top: .5rem; line-height: 1.5; }
.conforme-text    { color: #2E7D32; }
.nao-conforme-text{ color: #C62828; }

/* ─ Sidebar logo area ─ */
.sb-logo { padding: 1.6rem 0 1.2rem; text-align: center; }
.sb-logo-icon { font-size: 2.6rem; }
.sb-logo-name { font-size: 1.05rem; font-weight: 700; color: white !important; letter-spacing: .5px; margin-top: .4rem; }
.sb-logo-sub  { font-size: .68rem; color: rgba(255,255,255,.55) !important; letter-spacing: 1.2px; text-transform: uppercase; margin-top: .15rem; }

/* ─ Sidebar section ─ */
.sb-section { margin-bottom: .2rem; }
.sb-item    { font-size: .82rem; padding: .18rem 0; }
.sb-label   { font-size: .65rem; letter-spacing: 1px; text-transform: uppercase; color: rgba(255,255,255,.45) !important; margin-bottom: .4rem; display: block; }

/* ─ Inputs ─ */
[data-testid="stTextInput"] input {
    border-radius: 7px;
    border-color: #CBD5E1;
}

/* ─ Buttons ─ */
[data-testid="stDownloadButton"] button {
    border-radius: 7px;
    font-weight: 500;
}

/* ─ Expander ─ */
[data-testid="stExpander"] {
    border-radius: 8px !important;
    border-color: #DDE5EF !important;
}

/* ─ Tabs ─ */
[data-testid="stTabs"] [data-baseweb="tab"] {
    font-size: .88rem;
}
</style>
""", unsafe_allow_html=True)


# ── Helpers ────────────────────────────────────────────────────────────────────

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
        return "⚠️ Não encontrado"
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
        return ["", "", "", "background-color:#FFEBEE;color:#C62828"]
    if "✅" in eol:
        return ["", "", "", "background-color:#E8F5E9;color:#2E7D32"]
    return ["", "", "", ""]


def _show_pdf_embed(pdf_bytes: bytes) -> None:
    """Embed PDF viewer using base64 iframe."""
    mb = len(pdf_bytes) / (1024 * 1024)
    if mb > 30:
        st.warning(f"Arquivo grande ({mb:.0f} MB) — pré-visualização pode ser lenta.")

    b64 = base64.b64encode(pdf_bytes).decode()
    st.markdown(
        f"""
        <div style="border:1px solid #DDE5EF;border-radius:8px;overflow:hidden;">
            <iframe
                src="data:application/pdf;base64,{b64}#toolbar=0&navpanes=0"
                width="100%"
                height="700px"
                style="border:none;display:block;"
            ></iframe>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _merge_claimed(claims: list[dict]) -> dict:
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


def _parse_all_documents(paths: list[str]) -> dict:
    from modules.m1_parser import parse_document
    return _merge_claimed([parse_document(p) for p in paths])


# ── Sidebar ────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div class="sb-logo">
        <div class="sb-logo-icon">⚖️</div>
        <div class="sb-logo-name">DESEG</div>
        <div class="sb-logo-sub">TJRJ · GABPRES</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    vision_active = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())

    # LLM Extractor compartilha a mesma key, mas pode ser desativado via M1_LLM_DISABLE
    llm_extract_active = vision_active and os.environ.get("M1_LLM_DISABLE", "") != "1"

    st.markdown('<span class="sb-label">Componentes</span>', unsafe_allow_html=True)
    st.markdown(f"""
    <div class="sb-section">
        <div class="sb-item">{"🟢" if llm_extract_active else "⚪"} Extração via Claude {"ativa" if llm_extract_active else "inativa"}</div>
        <div class="sb-item">{"🟢" if vision_active else "⚪"} Vision AI {"ativa" if vision_active else "inativa"}</div>
        <div class="sb-item">🟢 SSL Labs (Qualys)</div>
        <div class="sb-item">🟢 endoflife.date</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    st.markdown('<span class="sb-label">Pipeline</span>', unsafe_allow_html=True)
    st.markdown("""
    <div class="sb-section">
        <div class="sb-item">M1 · Parsing de documentos</div>
        <div class="sb-item">M2 · Varredura do site</div>
        <div class="sb-item">M3 · Análise de conformidade</div>
        <div class="sb-item">M4 · Geração de relatório</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown(
        '<div style="font-size:.72rem;color:rgba(255,255,255,.4);text-align:center;padding-top:.4rem;">'
        "SEAUD · GABPRES · TJRJ<br>v2.0 · 2026"
        "</div>",
        unsafe_allow_html=True,
    )


# ── Header ─────────────────────────────────────────────────────────────────────

st.markdown("""
<div class="tjrj-header">
    <h1>Homologação de Leiloeiros Judiciais</h1>
    <p>Análise automatizada de conformidade de segurança · Departamento de Segurança da Informação</p>
</div>
""", unsafe_allow_html=True)


# ── Form ───────────────────────────────────────────────────────────────────────

col_url, col_file = st.columns([5, 4])

with col_url:
    url_input = st.text_input(
        "URL do site do leiloeiro",
        placeholder="https://www.exemplo.com.br",
    )

with col_file:
    uploaded = st.file_uploader(
        "Declarações do leiloeiro (PDF / DOCX)",
        type=["pdf", "docx"],
        accept_multiple_files=True,
        help="Um ou mais arquivos enviados pelo leiloeiro via SEI",
    )


# ── Document preview ───────────────────────────────────────────────────────────

if uploaded:
    pdf_files = [f for f in uploaded if f.name.lower().endswith(".pdf")]

    if pdf_files:
        label = (
            f"Pré-visualizar — {pdf_files[0].name}"
            if len(pdf_files) == 1
            else f"Pré-visualizar documentos ({len(pdf_files)} PDFs)"
        )
        with st.expander(f"📄 {label}", expanded=False):
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


# ── Trigger ────────────────────────────────────────────────────────────────────

ready = bool(url_input.strip() and uploaded)
col_btn, col_hint = st.columns([1, 5])

with col_btn:
    run = st.button("Analisar", type="primary", disabled=not ready, use_container_width=True)

with col_hint:
    if not ready:
        st.caption("Preencha a URL e carregue a declaração para habilitar a análise.")
    else:
        st.caption("A análise leva aprox. **3 minutos** — SSL Labs pode ser o gargalo.")


# ── Analysis ───────────────────────────────────────────────────────────────────

if run and ready:
    tmp_paths: list[str] = []
    for uf in uploaded:
        uf.seek(0)
        data = uf.read()
        suffix = Path(uf.name).suffix.lower()
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(data)
            tmp_paths.append(tmp.name)
        uf.seek(0)

    try:
        with st.status("Executando análise...", expanded=True) as status_box:
            from modules.m1_parser import parse_document
            from modules.m2_scanner import scan_all
            from modules.m3_engine import evaluate
            from modules.m4_reporter import generate_ficha, generate_pdf

            n = len(tmp_paths)
            ai_note = " + Vision AI" if vision_active else ""
            st.write(f"M1 · Parsing de {n} documento(s){ai_note} e M2 · Varredura web — em paralelo...")
            st.write("Aguardando SSL Labs (Qualys) — pode levar até 3 minutos...")

            with ThreadPoolExecutor(max_workers=2) as ex:
                fut_m1 = ex.submit(_parse_all_documents, tmp_paths)
                fut_m2 = ex.submit(scan_all, url_input)
                claimed = fut_m1.result()
                scan    = fut_m2.result()

            st.write(f"✓ M1 concluído ({n} documento(s))")
            st.write("✓ M2 concluído")
            st.write("M3 · Cruzando dados e aplicando regras de conformidade...")

            domain = _domain_from_url(url_input)
            result = evaluate(claimed, scan, url_input, domain)
            st.write("✓ M3 concluído")

            st.write("M4 · Gerando ficha de verificação (.docx)...")
            out_dir = Path(__file__).parent / "output"
            out_dir.mkdir(exist_ok=True)
            safe_domain = domain.replace(".", "_")
            out_path = out_dir / f"ficha_verificacao_{safe_domain}_{date.today().isoformat()}.docx"
            ficha_path = str(generate_ficha(result, out_path))
            st.write("✓ M4 concluído (.docx)")

            pdf_out = out_dir / f"ficha_verificacao_{safe_domain}_{date.today().isoformat()}.pdf"
            st.write("Gerando PDF...")
            pdf_path = generate_pdf(result, pdf_out)
            st.write("✓ PDF gerado")

            status_box.update(label="Análise concluída", state="complete", expanded=False)

        st.session_state["result"]     = result
        st.session_state["ficha_path"] = ficha_path
        st.session_state["pdf_path"]   = pdf_path

    except Exception as exc:
        st.error(f"Erro durante a análise: {exc}")
        st.exception(exc)
    finally:
        for p in tmp_paths:
            try:
                os.unlink(p)
            except OSError:
                pass


# ── Results ────────────────────────────────────────────────────────────────────

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

    # ── Result card + download panel ──────────────────────────────────────────

    col_card, col_dl = st.columns([3, 2])

    with col_card:
        st.markdown(f"""
        <div class="card {card_cls}">
            <div class="result-meta">🌐 {domain} &nbsp;·&nbsp; {anal_date}</div>
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
            st.caption("PDF não disponível para esta análise.")

    # ── Ficha preview (if PDF was generated) ─────────────────────────────────

    if pdf_path and Path(pdf_path).exists():
        with st.expander("📄 Pré-visualizar ficha gerada", expanded=False):
            with open(pdf_path, "rb") as fh:
                _show_pdf_embed(fh.read())

    st.markdown("<div style='height:.8rem'></div>", unsafe_allow_html=True)

    # ── Tabs ─────────────────────────────────────────────────────────────────

    tab_ev, tab_chk, tab_tec, tab_raw = st.tabs([
        "📋 Extração M1", "Verificações", "Tecnologias detectadas", "Dados brutos",
    ])

    with tab_ev:
        ev_verification = rd.get("raw", {}).get("evidence_verification", {})
        llm_ev = rd.get("raw", {}).get("llm_evidence", {})

        if ev_verification:
            st.markdown(
                "<p style='font-size:.85rem;color:#546E7A;margin-bottom:1rem;'>"
                "Evidências extraídas do documento pelo LLM, verificadas contra o texto-fonte original. "
                "Cada citação foi localizada no PDF com a página de origem.</p>",
                unsafe_allow_html=True,
            )

            _ev_labels = {
                "hsts": ("HSTS", "hsts_claimed"),
                "ssl_cert": ("Certificado SSL/TLS", "ssl_cert_claimed"),
                "backup": ("Backup e Recuperação", "backup_claimed"),
                "redundancy": ("Redundância de Serviço", "redundancy_claimed"),
                "energy": ("Recurso Contínuo de Energia", "energy_redundancy"),
            }

            for key, (label, bool_field) in _ev_labels.items():
                ev = ev_verification.get(key, {})
                quote = ev.get("quote", "")
                if not quote:
                    continue

                verified = ev.get("verified", False)
                confidence = ev.get("confidence", 0)
                page_num = ev.get("page_number")

                # Header com badge de verificação
                badge_color = "#2E7D32" if verified else "#E65100"
                badge_icon = "✅" if verified else "⚠️"
                page_badge = f"&nbsp;·&nbsp;📄 Página {page_num}" if page_num else ""
                conf_pct = f"{confidence * 100:.0f}%"

                st.markdown(
                    f"<div style='background:white;border:1px solid #DDE5EF;border-radius:8px;"
                    f"padding:1rem 1.2rem;margin-bottom:.7rem;border-left:4px solid {badge_color};'>"
                    f"<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem;'>"
                    f"<strong style='font-size:.92rem;'>{label}</strong>"
                    f"<span style='font-size:.75rem;color:{badge_color};'>"
                    f"{badge_icon} Verificada ({conf_pct}){page_badge}</span>"
                    f"</div>"
                    f"<div style='font-size:.84rem;color:#37474F;background:#F8FAFB;"
                    f"padding:.6rem .8rem;border-radius:5px;font-style:italic;'>"
                    f"\"{quote}\"</div>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

            # Resumo
            total = sum(1 for v in ev_verification.values() if v.get("quote"))
            verified_count = sum(1 for v in ev_verification.values() if v.get("verified"))
            st.markdown(
                f"<p style='font-size:.8rem;color:#78909C;margin-top:.8rem;text-align:right;'>"
                f"Verificadas: {verified_count}/{total} · "
                f"Fonte: Claude LLM (Tool Use) + verificação por difflib</p>",
                unsafe_allow_html=True,
            )
        elif llm_ev:
            st.info("Evidências extraídas pelo LLM (sem verificação de página disponível).")
            for key, quote in llm_ev.items():
                if quote:
                    st.text(f"{key}: {quote}")
        else:
            st.warning(
                "Extração via LLM não ativa — usando fallback regex. "
                "Configure ANTHROPIC_API_KEY no .env para extração com citação textual verificável."
            )

    with tab_chk:
        rows = _flatten_checks(checks)
        if rows:
            df_chk = pd.DataFrame([
                {
                    "Seção":      r["label"],
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
                    "Seção":      st.column_config.TextColumn(width="medium"),
                    "Status":     st.column_config.TextColumn(width="medium"),
                    "Severidade": st.column_config.TextColumn(width="small"),
                    "Detalhe":    st.column_config.TextColumn(width="large"),
                },
            )
        else:
            st.info("Nenhuma verificação disponível.")

    with tab_tec:
        if techs:
            df_tec = pd.DataFrame([
                {
                    "Categoria":  t.get("category", ""),
                    "Tecnologia": t.get("name", ""),
                    "Versão":     t.get("version") or "—",
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
                    "Versão":     st.column_config.TextColumn(width="small"),
                    "EOL":        st.column_config.TextColumn(width="small"),
                },
            )
        else:
            st.info("Nenhuma tecnologia detectada.")

    with tab_raw:
        raw = rd.get("raw", {})
        t_whois, t_hdrs, t_ssl = st.tabs(["WHOIS", "Cabeçalhos HTTP", "SSL Labs"])
        with t_whois:
            st.code(raw.get("whois_raw", "Não disponível"), language=None)
        with t_hdrs:
            st.code(raw.get("headers_raw_block", "Não disponível"), language=None)
        with t_ssl:
            ssl = raw.get("ssl_labs", {})
            st.json({k: v for k, v in ssl.items() if k != "raw_endpoints"})
