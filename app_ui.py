"""
Interface web — Sistema de Análise Automatizada de Segurança.
DESEG / SEAUD / GABPRES — TJRJ

Uso:
    streamlit run app_ui.py
"""

from __future__ import annotations

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

# Garante que os imports do projeto funcionam de qualquer diretório
sys.path.insert(0, str(Path(__file__).parent))

# Carrega variáveis do .env (inclui ANTHROPIC_API_KEY para Vision AI)
load_dotenv(Path(__file__).parent / ".env")


# ── Helpers de exibição (definidos antes do uso) ──────────────────────────────

_STATUS_EMOJI = {
    "CONFORME":        "✅",
    "NÃO CONFORME":    "❌",
    "ATENÇÃO":         "⚠️",
    "NÃO VERIFICÁVEL": "🔵",
}
_STATUS_BG = {
    "CONFORME":        "#e8f5e9",
    "NÃO CONFORME":    "#ffebee",
    "ATENÇÃO":         "#fff3e0",
    "NÃO VERIFICÁVEL": "#eceff1",
}
_STATUS_FG = {
    "CONFORME":        "#2E7D32",
    "NÃO CONFORME":    "#C62828",
    "ATENÇÃO":         "#E65100",
    "NÃO VERIFICÁVEL": "#546E7A",
}


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
        eol_date = tech.get("eol_date")
        return "❌ EOL" + (f" ({eol_date})" if eol_date else "")
    if tech.get("eol") is False:
        return "✅ Suportado"
    if tech.get("version") and tech.get("checked"):
        return "⚠️ Não encontrado"
    return "—"


def _color_status_row(row: pd.Series) -> list[str]:
    raw_status = row.get("Status", "")
    # Remove emoji prefix para recuperar a chave
    status_key = raw_status.split(" ", 1)[-1] if " " in raw_status else raw_status
    bg = _STATUS_BG.get(status_key, "")
    fg = _STATUS_FG.get(status_key, "")
    return [
        f"background-color:{bg};color:{fg}" if col == "Status" else ""
        for col in row.index
    ]


def _color_eol_row(row: pd.Series) -> list[str]:
    eol = row.get("EOL", "")
    if "EOL" in eol and "❌" in eol:
        return ["", "", "", "background-color:#ffebee;color:#C62828"]
    if "✅" in eol:
        return ["", "", "", "background-color:#e8f5e9;color:#2E7D32"]
    return ["", "", "", ""]


def _domain_from_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return (parsed.netloc or parsed.path).lstrip("www.").split(":")[0]


def _merge_claimed(claims: list[dict]) -> dict:
    """Mescla claimed_data de múltiplos documentos num único dict."""
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
        if any(v is True for v in vals):
            merged[field] = True
        elif any(v is False for v in vals):
            merged[field] = False
        else:
            merged[field] = None

    for field in list_fields:
        seen: list = []
        for c in claims:
            for item in (c.get(field) or []):
                if item not in seen:
                    seen.append(item)
        merged[field] = seen

    for field in str_fields:
        merged[field] = next((c.get(field) for c in claims if c.get(field)), None)

    # Mescla seções brutas: concatena fragmentos de documentos diferentes
    all_sec_keys: set[str] = set()
    for c in claims:
        all_sec_keys.update((c.get("raw_sections") or {}).keys())
    raw_sections: dict[str, str] = {}
    for key in all_sec_keys:
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
    """Faz o parsing de todos os documentos e mescla os resultados."""
    from modules.m1_parser import parse_document
    claims = [parse_document(p) for p in paths]
    return _merge_claimed(claims)


def _display_results(rd: dict, ficha_path: str) -> None:
    overall   = rd.get("overall_status", "?")
    domain    = rd.get("domain", "")
    anal_date = rd.get("analysis_date", date.today().isoformat())
    conclusao = rd.get("conclusao", "")
    checks    = rd.get("checks", {})
    techs     = rd.get("raw", {}).get("technologies", [])

    is_ok      = (overall == "CONFORME")
    card_class = "overall-conforme" if is_ok else "overall-nao-conforme"
    text_class = "text-conforme"    if is_ok else "text-nao-conforme"
    icon       = "✅" if is_ok else "❌"

    # ── Card de resultado ─────────────────────────────────────────────────────
    col_info, col_dl = st.columns([3, 1])

    with col_info:
        st.markdown(f"""
        <div class="card {card_class}">
          <div style="font-size:.8rem;color:#546E7A;">🌐 {domain} &nbsp;·&nbsp; {anal_date}</div>
          <div class="overall-text {text_class}">{icon} {overall}</div>
          <div style="margin-top:.4rem;font-size:.9rem;">{conclusao}</div>
        </div>
        """, unsafe_allow_html=True)

    with col_dl:
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        with open(ficha_path, "rb") as f:
            st.download_button(
                label="⬇️  Baixar Ficha (.docx)",
                data=f.read(),
                file_name=Path(ficha_path).name,
                mime=(
                    "application/vnd.openxmlformats-officedocument"
                    ".wordprocessingml.document"
                ),
                use_container_width=True,
            )
        st.caption(f"`{Path(ficha_path).name}`")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Tabela de verificações ────────────────────────────────────────────────
    st.subheader("Verificações")
    rows = _flatten_checks(checks)
    df_checks = pd.DataFrame([
        {
            "Seção":      r["label"],
            "Status":     f"{_STATUS_EMOJI.get(r['status'], '?')} {r['status']}",
            "Severidade": r["severity"] or "—",
            "Detalhe":    r["detail"],
        }
        for r in rows
    ])
    st.dataframe(
        df_checks.style.apply(_color_status_row, axis=1),
        use_container_width=True,
        hide_index=True,
        column_config={
            "Seção":      st.column_config.TextColumn(width="medium"),
            "Status":     st.column_config.TextColumn(width="medium"),
            "Severidade": st.column_config.TextColumn(width="small"),
            "Detalhe":    st.column_config.TextColumn(width="large"),
        },
    )

    # ── Tecnologias detectadas ────────────────────────────────────────────────
    if techs:
        st.subheader("Tecnologias detectadas")
        df_techs = pd.DataFrame([
            {
                "Categoria":  t.get("category", ""),
                "Tecnologia": t.get("name", ""),
                "Versão":     t.get("version") or "—",
                "EOL":        _eol_label(t),
            }
            for t in sorted(techs, key=lambda x: (x.get("category", ""), x.get("name", "")))
        ])
        st.dataframe(
            df_techs.style.apply(_color_eol_row, axis=1),
            use_container_width=True,
            hide_index=True,
            column_config={
                "Categoria":  st.column_config.TextColumn(width="medium"),
                "Tecnologia": st.column_config.TextColumn(width="medium"),
                "Versão":     st.column_config.TextColumn(width="small"),
                "EOL":        st.column_config.TextColumn(width="small"),
            },
        )

    # ── Dados brutos ──────────────────────────────────────────────────────────
    with st.expander("🔎 Dados brutos (WHOIS · Cabeçalhos HTTP · SSL Labs)"):
        raw = rd.get("raw", {})
        tab_whois, tab_hdrs, tab_ssl = st.tabs(["WHOIS", "Cabeçalhos HTTP", "SSL Labs"])

        with tab_whois:
            st.code(raw.get("whois_raw", "Não disponível"), language=None)
        with tab_hdrs:
            st.code(raw.get("headers_raw_block", "Não disponível"), language=None)
        with tab_ssl:
            ssl = raw.get("ssl_labs", {})
            st.json({k: v for k, v in ssl.items() if k != "raw_endpoints"})


# ── Configuração da página ────────────────────────────────────────────────────

st.set_page_config(
    page_title="DESEG — Homologação de Leiloeiros",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown("""
<style>
    .block-container  { padding-top: 1.5rem; max-width: 980px; }
    .deseg-header     { border-bottom: 2px solid #0D47A1; padding-bottom: .6rem; margin-bottom: 1.2rem; }
    .deseg-header h1  { font-size: 1.45rem; margin: 0; color: #0D47A1; }
    .deseg-header p   { margin: 0; color: #546E7A; font-size: .85rem; }
    .card             { border: 1px solid #e0e0e0; border-radius: 8px; padding: 1rem 1.2rem; }
    .overall-conforme     { background: #e8f5e9; border-left: 5px solid #2E7D32; }
    .overall-nao-conforme { background: #ffebee; border-left: 5px solid #C62828; }
    .overall-text     { font-size: 1.35rem; font-weight: 700; }
    .text-conforme    { color: #2E7D32; }
    .text-nao-conforme{ color: #C62828; }
</style>
""", unsafe_allow_html=True)

# ── Cabeçalho ─────────────────────────────────────────────────────────────────

st.markdown("""
<div class="deseg-header">
  <h1>⚖️ Homologação de Leiloeiros Judiciais</h1>
  <p>Departamento de Segurança da Informação (DESEG) · SEAUD · GABPRES · TJRJ</p>
</div>
""", unsafe_allow_html=True)

# ── Formulário ────────────────────────────────────────────────────────────────

col_url, col_file = st.columns([3, 2])

with col_url:
    url_input = st.text_input(
        "🌐 URL do site do leiloeiro",
        placeholder="https://www.exemplo.com.br",
    )

with col_file:
    uploaded = st.file_uploader(
        "📄 Declaração(ões) do leiloeiro",
        type=["pdf", "docx"],
        accept_multiple_files=True,
        help="Um ou mais arquivos PDF/DOCX enviados pelo leiloeiro via SEI",
    )

ready = bool(url_input.strip() and uploaded)
col_btn, col_hint = st.columns([1, 5])

with col_btn:
    run = st.button("▶  Analisar", type="primary", disabled=not ready, use_container_width=True)

with col_hint:
    if not ready:
        st.caption("Preencha a URL e faça upload da declaração para habilitar a análise.")
    else:
        st.caption("⏳ A análise leva **aprox. 3 minutos** (varredura SSL Labs + bundles JS).")

st.divider()

# ── Análise ───────────────────────────────────────────────────────────────────

if run and ready:
    # Salva todos os arquivos carregados em arquivos temporários
    tmp_paths: list[str] = []
    for uf in uploaded:
        suffix = Path(uf.name).suffix.lower()
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(uf.read())
            tmp_paths.append(tmp.name)

    try:
        with st.status("🔍 Executando análise completa...", expanded=True) as status_widget:
            from modules.m1_parser import parse_document
            from modules.m2_scanner import scan_all
            from modules.m3_engine import evaluate
            from modules.m4_reporter import generate_ficha

            n_docs = len(tmp_paths)
            vision_active = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
            vision_note = " · Vision AI ativa 🔬" if vision_active else " · Vision AI inativa (sem ANTHROPIC_API_KEY)"
            st.write(
                f"🔄 M1 (parsing de {n_docs} documento(s){vision_note}) e M2 (varredura web) em paralelo..."
            )
            st.write("⏳ Aguardando SSL Labs — pode levar até 3 minutos, por favor aguarde...")

            with ThreadPoolExecutor(max_workers=2) as ex:
                fut_m1 = ex.submit(_parse_all_documents, tmp_paths)
                fut_m2 = ex.submit(scan_all, url_input)
                claimed = fut_m1.result()
                scan    = fut_m2.result()

            st.write(f"✅ M1 — Parsing de {n_docs} documento(s) concluído.")
            st.write("✅ M2 — Varredura concluída.")
            st.write("🔄 M3 — Cruzando dados e aplicando regras de conformidade...")

            domain = _domain_from_url(url_input)
            result = evaluate(claimed, scan, url_input, domain)

            st.write("✅ M3 — Análise concluída.")
            st.write("🔄 M4 — Gerando Ficha de Verificação (.docx)...")

            out_dir = Path(__file__).parent / "output"
            out_dir.mkdir(exist_ok=True)
            safe_domain = domain.replace(".", "_")
            out_path = (
                out_dir / f"ficha_verificacao_{safe_domain}_{date.today().isoformat()}.docx"
            )
            ficha_path = generate_ficha(result, out_path)

            st.write("✅ M4 — Ficha gerada.")
            status_widget.update(label="✅ Análise concluída!", state="complete", expanded=False)

        st.session_state["result"]     = result
        st.session_state["ficha_path"] = ficha_path

    except Exception as exc:
        st.error(f"Erro durante a análise: {exc}")
        st.exception(exc)
    finally:
        for p in tmp_paths:
            os.unlink(p)

# ── Resultado ─────────────────────────────────────────────────────────────────

if "result" in st.session_state:
    _display_results(
        st.session_state["result"],
        st.session_state["ficha_path"],
    )
