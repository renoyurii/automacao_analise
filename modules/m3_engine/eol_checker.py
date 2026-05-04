"""
Verificação de End-of-Life de tecnologias via endoflife.date API.

Consulta https://endoflife.date/api/{product}/{cycle}.json
Gratuita, sem chave, atualizada pela comunidade.

Referência no PAT: Tarefa #6 — "Verifica se os aplicativos informados estão
sob o suporte de segurança do fornecedor do software. Utilizar: End Of Life."
"""

from __future__ import annotations

import re
import time
from datetime import date
from typing import Any

import requests

_BASE = "https://endoflife.date/api"
_TIMEOUT = 10

# Cache em memória — evita requisições repetidas na mesma sessão Streamlit.
# TTL de 1h é suficiente: dados de EOL mudam no máximo semanalmente.
_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 3600  # 1 hora


# ── Extratores de versão (definidos antes do mapa que os referencia) ──────────

def _major(version: str | None) -> str | None:
    if not version:
        return None
    m = re.search(r"(\d+)", version)
    return m.group(1) if m else None


def _major_minor(version: str | None) -> str | None:
    if not version:
        return None
    m = re.search(r"(\d+\.\d+)", version)
    return m.group(1) if m else _major(version)


# Mapeamento de nomes detectados (Wappalyzer/M1) → produto no endoflife.date
# Formato: nome_lower → (eol_product, fn_extrai_cycle(version) | None)
_PRODUCT_MAP: dict[str, tuple[str, Any]] = {
    "jquery":             ("jquery",         _major),         # EOL usa ciclos major: 3, 2, 1
    "jquery ui":          ("jquery",         _major),         # sem produto separado
    "bootstrap":          ("bootstrap",      _major),
    "moment.js":          ("momentjs",       _major_minor),
    "fancybox":           ("jquery",         None),           # sem produto no eol.date
    "php":                ("php",            _major_minor),
    "microsoft asp.net":  ("asp.net-core",   _major_minor),
    "asp.net":            ("asp.net-core",   _major_minor),
    "windows server 2016":("windows-server", lambda v: "2016"),
    "windows server 2019":("windows-server", lambda v: "2019"),
    "windows server 2022":("windows-server", lambda v: "2022"),
    "windows server 2025":("windows-server", lambda v: "2025"),
    "mysql":              ("mysql",          _major_minor),
    "postgresql":         ("postgresql",     _major),
    "nodejs":             ("nodejs",         _major),
    "node.js":            ("nodejs",         _major),
    "nginx":              ("nginx",          _major_minor),
    "apache":             ("apache",         _major_minor),
    "drupal":             ("drupal",         _major),
    "wordpress":          ("wordpress",      _major),
    "laravel":            ("laravel",        _major),
    "django":             ("django",         _major_minor),
    "react":              ("react",          _major),
    "angular":            ("angular",        _major),
    "angularjs":          ("angularjs",      _major),
    "vue.js":             ("vuejs",          _major_minor),
    "vue":                ("vuejs",          _major_minor),
    "next.js":            ("nextjs",         _major),
    "nuxt.js":            ("nuxt",           _major),
    "joomla":             ("joomla",         _major),
    "magento":            ("magento",        _major),
    "shopify":            ("shopify",        _major),
}


# ── Interface pública ─────────────────────────────────────────────────────────

def check_eol(technologies: list[dict], os_versions: list[str]) -> list[dict]:
    """
    Recebe a lista de tecnologias do M2 e os OS declarados do M1.
    Retorna a lista enriquecida com status EOL.

    Cada item retornado:
    {
        "category": str,
        "name":     str,
        "version":  str | None,
        "eol":      bool | None,     # True = EOL, False = suportado, None = não verificado
        "eol_date": str | None,      # Data de fim de suporte (se disponível)
        "checked":  bool,            # Se a consulta ao endoflife.date foi feita
    }
    """
    results: list[dict] = []

    # Tecnologias do Wappalyzer
    for tech in technologies:
        entry = dict(tech)
        entry["eol"] = None
        entry["eol_date"] = None
        entry["checked"] = False

        name = tech.get("name", "")
        version = tech.get("version")

        eol_result = _lookup(name, version)
        entry.update(eol_result)
        results.append(entry)

    # OS declarados no M1 (não detectados pelo Wappalyzer)
    for os_str in os_versions:
        entry = {
            "category": "Sistema Operacional",
            "name": os_str,
            "version": None,
            "eol": None,
            "eol_date": None,
            "checked": False,
        }
        eol_result = _lookup(os_str.lower(), None)
        entry.update(eol_result)
        results.append(entry)

    return results


# ── Consulta à API ────────────────────────────────────────────────────────────

def _lookup(name: str, version: str | None) -> dict:
    """Mapeia nome → produto endoflife.date e consulta a API."""
    name_lower = name.lower().strip()

    # Tenta match direto no mapa
    mapping = _PRODUCT_MAP.get(name_lower)

    # Tenta match parcial (ex: "jQuery 1.11.3" → "jquery")
    if mapping is None:
        for key, val in _PRODUCT_MAP.items():
            if key in name_lower:
                mapping = val
                break

    if mapping is None:
        return {"eol": None, "eol_date": None, "checked": False}

    product, cycle_fn = mapping
    cycle = cycle_fn(version) if (cycle_fn and version) else None

    if cycle is None:
        # Sem versão → só confirma que o produto existe, não verifica EOL
        return {"eol": None, "eol_date": None, "checked": False}

    return _query_api(product, cycle)


def _query_api(product: str, cycle: str) -> dict:
    cache_key = f"{product}/{cycle}"

    # Verifica cache em memória
    if cache_key in _CACHE:
        ts, cached_result = _CACHE[cache_key]
        if time.time() - ts < _CACHE_TTL:
            return cached_result

    url = f"{_BASE}/{product}/{cycle}.json"
    try:
        resp = requests.get(url, timeout=_TIMEOUT)
        if resp.status_code == 404:
            result = {"eol": None, "eol_date": None, "checked": True}
            _CACHE[cache_key] = (time.time(), result)
            return result
        resp.raise_for_status()
        data = resp.json()

        eol_raw = data.get("eol")
        if eol_raw is False:
            result = {"eol": False, "eol_date": None, "checked": True}
        elif isinstance(eol_raw, str):
            result = {"eol": _date_passed(eol_raw), "eol_date": eol_raw, "checked": True}
        else:
            result = {"eol": None, "eol_date": None, "checked": True}

        _CACHE[cache_key] = (time.time(), result)
        return result

    except Exception:
        return {"eol": None, "eol_date": None, "checked": False}


def _date_passed(date_str: str) -> bool:
    try:
        return date.fromisoformat(date_str) < date.today()
    except ValueError:
        return False
