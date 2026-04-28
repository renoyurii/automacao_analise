"""
Detecção de stack tecnológica — substituto funcional do Wappalyzer.

python-Wappalyzer está quebrado no Python 3.14 (depende de pkg_resources removido).
Esta implementação usa:
  1. builtwith — detecção por base de dados de assinaturas
  2. Headers HTTP — Server, X-Powered-By, Via, X-Generator, alt-svc
  3. HTML fonte — scripts carregados, meta tags, atributos de bibliotecas JS

Categorias replicam as usadas na Ficha de Verificação do DESEG-TJRJ.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import builtwith
import requests
from bs4 import BeautifulSoup

_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) "
    "Gecko/20100101 Firefox/124.0"
)
_TIMEOUT = 20


# ── Assinaturas de detecção por HTML/Headers ──────────────────────────────────
# Formato: (regex_pattern, categoria_pt, nome, grupo_para_versão | None)

_SCRIPT_SIGNATURES: list[tuple[str, str, str, str | None]] = [
    # jQuery
    (r"jquery[.\-](\d+\.\d+(?:\.\d+)?)", "Biblioteca JavaScript", "jQuery", r"\1"),
    # jQuery UI
    (r"jquery[\.\-]ui[\.\-](\d+\.\d+(?:\.\d+)?)", "Biblioteca JavaScript", "jQuery UI", r"\1"),
    # Vue.js — CDN com versão (ex: vue@2.7.14/dist/vue.min.js)
    (r"vue@(\d+\.\d+(?:\.\d+)?)[/\"]", "Framework JavaScript", "Vue.js", r"\1"),
    # Vue.js — arquivo local versionado (ex: vue.2.7.14.min.js)
    (r"vue[.\-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", "Framework JavaScript", "Vue.js", r"\1"),
    # Vue.js — comentário de versão em bundle (ex: /*! Vue v2.7.14 */)
    (r"Vue\s+v(\d+\.\d+(?:\.\d+)?)", "Framework JavaScript", "Vue.js", r"\1"),
    # Vue.js — sem versão (arquivo genérico ou detectado por atributos data-v-)
    (r"(?<!\w)vue(?:\.min|\.runtime(?:\.min)?)?\.js(?!\d)", "Framework JavaScript", "Vue.js", None),
    # Bootstrap
    (r"bootstrap(?:\.min)?\.js", "UI Frameworks", "Bootstrap", None),
    (r"bootstrap(?:\.min)?\.css", "UI Frameworks", "Bootstrap", None),
    # Moment.js
    (r"moment(?:\.min)?\.js(?:\?v=(\d[\d.]+))?", "Biblioteca JavaScript", "Moment.js", r"\1"),
    # FancyBox
    (r"fancybox(?:[.\-](\d+\.\d+(?:\.\d+)?))?", "Biblioteca JavaScript", "FancyBox", r"\1"),
    # core-js (polyfill moderno) — CDN ou path versionado
    (r"core-js(?:@|[/\-])(\d+\.\d+(?:\.\d+)?)", "Biblioteca JavaScript", "core-js", r"\1"),
    (r"core-js(?:\.min)?\.js", "Biblioteca JavaScript", "core-js", None),
    # Font Awesome — kit CDN (kit.fontawesome.com/<hash>.js) ou arquivo local
    (r"kit\.fontawesome\.com", "Script de Fonte", "Font Awesome", None),
    (r"cdnjs\.cloudflare\.com/ajax/libs/font-awesome/(\d+[\d.]+)/", "Script de Fonte", "Font Awesome", r"\1"),
    (r"font-awesome(?:\.min)?\.(?:css|js)", "Script de Fonte", "Font Awesome", None),
    (r"fontawesome(?:\.min)?\.(?:css|js)", "Script de Fonte", "Font Awesome", None),
    # Slick carousel
    (r"slick(?:\.min)?\.js", "Biblioteca JavaScript", "Slick", None),
    # Select2
    (r"select2(?:\.min)?\.js", "Biblioteca JavaScript", "Select2", None),
    # Webpack (detectado via artefatos no bundle inline)
    (r"__webpack_require__|__webpack_chunk_load__|webpackJsonp", "Diversos", "Webpack", None),
    # Google Tag Manager
    (r"googletagmanager\.com/gtm\.js", "Gestor de Tags", "Google Tag Manager", None),
    # Google Analytics GA4
    (r"googletagmanager\.com/gtag/js\?id=G-", "Ferramenta Estatística", "Google Analytics (GA4)", "GA4"),
    (r"google-analytics\.com/analytics\.js", "Ferramenta Estatística", "Google Analytics", None),
    # Google Fonts
    (r"fonts\.googleapis\.com", "Script de Fonte", "Google Font API", None),
    # Google Sign-in
    (r"apis\.google\.com/js/platform\.js", "Autenticação", "Google Sign-in", None),
    # Cloudflare Insights
    (r"cloudflareinsights\.com", "Ferramenta Estatística", "Cloudflare Browser Insights", None),
    # WhatsApp Business Chat
    (r"wa\.me|api\.whatsapp\.com|wa-widget", "Chat Direto", "WhatsApp Business Chat", None),
    # JivoChat
    (r"jivosite\.com|jivo\.chat", "Chat Direto", "JivoChat", None),
    # reCAPTCHA
    (r"google\.com/recaptcha", "Segurança", "reCAPTCHA", None),
    # PWA
    (r"manifest\.json|serviceWorker\.register", "Diversos", "PWA", None),
]

_META_SIGNATURES: list[tuple[str, str, str, str | None]] = [
    # OpenGraph
    (r'property=["\']og:', "Diversos", "Open Graph", None),
    # Generator
    (r'name=["\']generator["\'].*content=["\']([^"\']+)', "CMS", None, r"\1"),
]

_HEADER_SIGNATURES: dict[str, tuple[str, str]] = {
    "strict-transport-security": ("Segurança", "HSTS"),
    "content-security-policy":   ("Segurança", "Script de Fonte"),
    "x-powered-by":              ("Servidor Web", None),   # Valor vira o nome
    "server":                    ("Servidor Web", None),
    "x-aspnet-version":          ("Framework Web", "Microsoft ASP.NET"),
    "x-aspnetmvc-version":       ("Framework Web", "Microsoft ASP.NET MVC"),
    "x-generator":               ("CMS", None),
    "x-drupal-cache":            ("CMS", "Drupal"),
    "x-wp-total":                ("CMS", "WordPress"),
}

_ALT_SVC_HTTP3 = re.compile(r'\bh3\b', re.IGNORECASE)


# ── Interface pública ─────────────────────────────────────────────────────────

def scan_wappalyzer(url: str) -> dict[str, Any]:
    """
    Retorna:
    {
        "technologies": [
            {"category": str, "name": str, "version": str | None},
            ...
        ],
        "error": str | None,
    }
    """
    try:
        html, headers, final_url = _fetch_page(url)
    except Exception as e:
        return {"technologies": [], "error": str(e)}

    techs: list[dict] = []
    seen: set[tuple[str, str]] = set()      # dedup por (category, name)
    seen_names: dict[str, int] = {}         # name_lower → índice em techs

    def _add(category: str, name: str, version: str | None = None) -> None:
        key = (category, name)
        name_lower = name.lower()
        if key not in seen:
            seen.add(key)
            # Se já existe uma entrada com o mesmo nome mas categoria diferente,
            # atualiza a versão existente (sem version) em vez de duplicar.
            if name_lower in seen_names:
                existing = techs[seen_names[name_lower]]
                if existing["version"] is None and version is not None:
                    existing["version"] = version
            else:
                seen_names[name_lower] = len(techs)
                techs.append({"category": category, "name": name, "version": version})
        elif version is not None:
            # Mesma (category, name) já existe — atualiza versão se estava vazia.
            idx = seen_names.get(name_lower)
            if idx is not None and techs[idx]["version"] is None:
                techs[idx]["version"] = version

    # 1. builtwith
    try:
        bw = builtwith.builtwith(final_url)
        for category, names in bw.items():
            cat_pt = _translate_category(category)
            for name in names:
                _add(cat_pt, name)
    except Exception:
        pass

    # 2. Detecção via headers HTTP
    headers_lower = {k.lower(): v for k, v in headers.items()}
    _detect_from_headers(headers_lower, _add)

    # 3. Detecção via HTML
    if html:
        src_texts = _detect_from_html(html, _add)
        # 4. Busca de versões em bundles JS locais (Vue, React, etc. empacotados)
        _detect_from_bundles(src_texts, final_url, _add)

    # Ordena por categoria para saída consistente
    techs.sort(key=lambda t: (t["category"], t["name"]))

    return {"technologies": techs, "error": None}


# ── Detecção por fonte ────────────────────────────────────────────────────────

def _fetch_page(url: str) -> tuple[str | None, dict, str]:
    """Retorna (html, headers, final_url)."""
    target = url if url.startswith("http") else f"https://{url}"
    resp = requests.get(
        target,
        headers={"User-Agent": _UA},
        timeout=_TIMEOUT,
        allow_redirects=True,
        verify=True,
    )
    ct = resp.headers.get("Content-Type", "")
    html = resp.text if "html" in ct else None
    return html, dict(resp.headers), str(resp.url)


def _detect_from_headers(
    headers: dict[str, str],
    add: Any,
) -> None:
    for header_key, (category, fixed_name) in _HEADER_SIGNATURES.items():
        value = headers.get(header_key)
        if value is None:
            continue
        name = fixed_name if fixed_name else value.split("/")[0].strip()
        version = None
        if fixed_name is None and "/" in value:
            version = value.split("/", 1)[1].strip()
        add(category, name, version)

    # HTTP/3 via alt-svc
    alt_svc = headers.get("alt-svc", "")
    if _ALT_SVC_HTTP3.search(alt_svc):
        add("Diversos", "HTTP/3")


def _detect_from_html(html: str, add: Any) -> list[str]:
    """Detecta tecnologias no HTML. Retorna lista de src de scripts para análise de bundles."""
    soup = BeautifulSoup(html, "html.parser")

    # Todos os atributos src de <script> e href de <link>
    src_texts: list[str] = []
    for tag in soup.find_all("script", src=True):
        src_texts.append(tag["src"])
    for tag in soup.find_all("link", href=True):
        src_texts.append(tag["href"])

    # Scripts inline + src
    all_html = html

    for pattern, category, fixed_name, version_group in _SCRIPT_SIGNATURES:
        m = re.search(pattern, all_html, re.IGNORECASE)
        if m:
            name = fixed_name
            version = None
            if version_group and version_group != r"\1":
                version = version_group  # valor fixo (ex: "GA4")
            elif version_group == r"\1":
                try:
                    version = m.group(1) or None
                except IndexError:
                    version = None
            if name:
                add(category, name, version)
            else:
                # Caso generator — extrai valor do match
                val = m.group(1) if version_group == r"\1" else None
                if val:
                    add(category, val)

    # Vue.js — atributos de estilo com escopo (data-v-XXXXXXXX) indicam Vue 2/3
    if re.search(r'\bdata-v-[a-f0-9]{6,8}\b', html):
        add("Framework JavaScript", "Vue.js")

    # Meta OpenGraph
    og_tags = soup.find_all("meta", property=re.compile(r"^og:", re.I))
    if og_tags:
        add("Diversos", "Open Graph")

    # Meta generator
    gen = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
    if gen and gen.get("content"):
        add("CMS", gen["content"])

    return src_texts


# ── Detecção em bundles JS locais ─────────────────────────────────────────────

_BUNDLE_CDN_EXCLUDE = re.compile(
    r"googleapis|jquery\.com|cloudflareinsights|fontawesome|maxcdn|gstatic|ga\.js",
    re.IGNORECASE,
)

_BUNDLE_SIGNATURES: list[tuple[str, str, str]] = [
    (r"Vue\.js\s+v(\d+\.\d+\.\d+)",              "Framework JavaScript", "Vue.js"),
    (r'"vue":\s*"(\d+\.\d+\.\d+)"',              "Framework JavaScript", "Vue.js"),
    (r"React\s+v(\d+\.\d+\.\d+)",                "Framework JavaScript", "React"),
    (r"core-js[/ ](?:v|version[:\s]+)?(\d+\.\d+(?:\.\d+)?)", "Biblioteca JavaScript", "core-js"),
    (r"angular[/ ]v?(\d+\.\d+\.\d+)",            "Framework JavaScript", "Angular"),
]

_BUNDLE_MARKERS: list[tuple[str, str, str]] = [
    (r"window\.webpackJsonp|__webpack_require__", "Diversos", "Webpack"),
]

_BUNDLE_MAX_BYTES = 600_000   # 600 KB por bundle
_BUNDLE_MAX_FETCH = 4         # máximo de bundles a buscar


def _detect_from_bundles(src_texts: list[str], base_url: str, add: Any) -> None:
    """Busca versões de frameworks e marcadores em bundles JS locais."""
    from urllib.parse import urljoin

    local_js = [
        s for s in src_texts
        if s.endswith(".js")
        and not _BUNDLE_CDN_EXCLUDE.search(s)
        and (s.startswith("/") or not s.startswith("http"))
    ][:_BUNDLE_MAX_FETCH]

    for src in local_js:
        url = urljoin(base_url, src)
        try:
            resp = requests.get(url, headers={"User-Agent": _UA}, timeout=8, stream=True)
            if not resp.ok:
                continue
            raw = b""
            for chunk in resp.iter_content(8192):
                raw += chunk
                if len(raw) >= _BUNDLE_MAX_BYTES:
                    break
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            continue

        for pattern, category, name in _BUNDLE_SIGNATURES:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                add(category, name, m.group(1))

        for pattern, category, name in _BUNDLE_MARKERS:
            if re.search(pattern, text, re.IGNORECASE):
                add(category, name)


# ── Utilitários ───────────────────────────────────────────────────────────────

_CAT_MAP: dict[str, str] = {
    "cdn":               "CDN",
    "javascript-frameworks": "Framework Web",
    "javascript-graphics":   "Biblioteca JavaScript",
    "programming-languages": "Linguagem de Programação",
    "web-servers":           "Servidor Web",
    "cms":               "CMS",
    "analytics":         "Ferramenta Estatística",
    "ecommerce":         "E-commerce",
    "security":          "Segurança",
    "widgets":           "Widgets",
}


def _translate_category(cat: str) -> str:
    return _CAT_MAP.get(cat.lower(), cat.replace("-", " ").title())
