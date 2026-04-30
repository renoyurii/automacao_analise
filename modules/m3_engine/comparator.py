"""
Motor de Decisão — cruza claimed_data (M1) com scan_data (M2).

Regra de Ouro: varredura ativa tem PRIORIDADE ABSOLUTA quando ela
consegue verificar um item. Quando não consegue (ex: backup físico),
o status é NÃO VERIFICÁVEL — nunca NÃO CONFORME por falta de evidência.

Status possíveis:
  CONFORME        — verificado e dentro do esperado
  NÃO CONFORME    — verificado e fora do esperado (com severidade)
  NÃO VERIFICÁVEL — não é possível confirmar via scan externo
  ATENÇÃO         — tecnicamente conforme mas com ressalva de boas práticas

Severidade (só para NÃO CONFORME):
  CRITICO — compromete operação ou segurança imediata
  ALTO    — risco relevante, exige correção antes da homologação
  MEDIO   — risco moderado, exige plano de correção
  BAIXO   — desvio de boas práticas sem risco imediato
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from config import CLOUDFLARE_PROXY_PORTS, EXPECTED_PORTS
from .eol_checker import check_eol

# Limiar HSTS mínimo recomendado (OWASP): 1 ano em segundos
_HSTS_MIN_MAX_AGE = 31_536_000

# Portas de alto risco se expostas diretamente (fora de proxy CDN)
_CRITICAL_PORTS = {22, 3389, 5900, 1433, 3306, 5432, 6379, 27017}


# ── Interface pública ─────────────────────────────────────────────────────────

def compare(
    claimed_data: dict[str, Any],
    scan_data: dict[str, Any],
    url: str,
    domain: str,
) -> dict[str, Any]:
    """
    Retorna result_data completo para consumo pelo M4.

    result_data = {
        "domain":         str,
        "url":            str,
        "analysis_date":  str,
        "overall_status": str,
        "checks":         dict,
        "raw":            dict,
        "conclusao":      str,
    }
    """
    ssl   = scan_data.get("ssl_labs") or {}
    hdrs  = scan_data.get("headers") or {}
    tech  = scan_data.get("wappalyzer") or {}
    ports = scan_data.get("ports") or {}
    whois = scan_data.get("whois") or {}

    cdn = hdrs.get("cdn_waf")

    technologies_with_eol = check_eol(
        tech.get("technologies", []),
        claimed_data.get("os_versions", []),
    )

    checks = {
        "url_acesso":    _check_url(hdrs),
        "disponibilidade": _check_disponibilidade(claimed_data),
        "integridade":   _check_integridade(hdrs, claimed_data),
        "hsts":          _check_hsts(ssl, claimed_data),
        "criptografia":  _check_criptografia(ssl),
        "aplicacoes":    _check_aplicacoes(technologies_with_eol),
        "portas":        _check_portas(ports, cdn),
        "seguranca_rede": _check_whois(whois),
    }

    overall = _overall_status(checks)
    conclusao = _build_conclusao(checks, domain)

    return {
        "domain":        domain,
        "url":           url,
        "analysis_date": date.today().isoformat(),
        "overall_status": overall,
        "checks":        checks,
        "raw": {
            "headers_raw_block":    hdrs.get("raw_block", ""),
            "whois_raw":            whois.get("raw", ""),
            "technologies":         technologies_with_eol,
            "ssl_labs":             ssl,
            "ports":                ports,
            "claimed_raw_sections": claimed_data.get("raw_sections", {}),
            "image_page_count":     claimed_data.get("image_page_count", 0),
        },
        "conclusao": conclusao,
    }


# ── Verificações individuais ──────────────────────────────────────────────────

def _check_url(hdrs: dict) -> dict:
    code = hdrs.get("status_code")
    error = hdrs.get("error")
    if error and not code:
        return _result("NÃO CONFORME", None, error,
                       "Site inacessível durante a análise.", "CRITICO")
    if code and code < 500:
        return _result("CONFORME", None, code, f"Site acessível (HTTP {code}).")
    return _result("NÃO CONFORME", None, code,
                   f"Site retornou erro HTTP {code}.", "ALTO")


def _check_disponibilidade(claimed: dict) -> dict:
    """
    Disponibilidade (redundância, backup, energia) é avaliada pela declaração.
    Se o item foi declarado no documento, atende ao requisito da ficha.
    """
    image_pages = claimed.get("image_page_count", 0) or 0
    raw_secs    = claimed.get("raw_sections", {}) or {}

    def _nv(key: str, label: str, sec_key: str) -> dict:
        val = claimed.get(key)
        sec_text = (raw_secs.get(sec_key, "") or "").lstrip()
        is_inferred = sec_text.startswith("[INFERIDO]")

        if val is True and is_inferred:
            return _result(
                "CONFORME", val, True,
                f"{label}: Inferido a partir do contexto. "
                "Há evidência documental suficiente para registrar o item como declarado."
            )
        if val is True:
            return _result(
                "CONFORME", val, True,
                f"{label}: Declarado no documento."
            )
        return _result(
            "NÃO CONFORME", val, None,
            f"{label}: não declarado no documento.",
            "MEDIO",
        )

    return {
        "redundancia": _nv("redundancy_claimed", "Redundância de serviço",      "redundancia"),
        "backup":      _nv("backup_claimed",     "Backup e recuperação",        "backup"),
        "energia":     _nv("energy_redundancy",  "Recurso contínuo de energia", "energia"),
    }


def _check_integridade(hdrs: dict, claimed: dict) -> dict:
    cdn = hdrs.get("cdn_waf")
    claimed_fw = claimed.get("firewall_waf") or []

    if cdn:
        detail = (
            f"CDN/WAF detectado: {cdn}. "
            f"Cabeçalhos HTTP confirmam proteção de borda."
        )
        if claimed_fw:
            detail += f" Leiloeiro declarou: {', '.join(claimed_fw[:3])}."
        return _result("CONFORME", claimed_fw or None, cdn, detail)

    if claimed_fw:
        return _result(
            "NÃO VERIFICÁVEL", claimed_fw, None,
            "Leiloeiro declarou firewall/WAF mas nenhum CDN foi detectado "
            "nos cabeçalhos HTTP. Proteção interna não é verificável externamente."
        )
    return _result(
        "NÃO CONFORME", None, None,
        "Nenhum CDN/WAF detectado nos cabeçalhos. "
        "Leiloeiro não declarou mecanismos de proteção.", "MEDIO"
    )


def _check_hsts(ssl: dict, claimed: dict) -> dict:
    if ssl.get("error"):
        return _result("NÃO VERIFICÁVEL", claimed.get("hsts_claimed"), None,
                       f"SSL Labs indisponível: {ssl['error']}")

    hsts = ssl.get("hsts") or {}
    present = hsts.get("present", False)
    max_age = hsts.get("max_age")
    claimed_val = claimed.get("hsts_claimed")

    if not present:
        return _result(
            "NÃO CONFORME", claimed_val, False,
            "HSTS não está ativo. O Strict-Transport-Security header "
            "está ausente na resposta do servidor.", "ALTO"
        )

    # HSTS presente — verifica max-age
    if max_age is not None and max_age < _HSTS_MIN_MAX_AGE:
        return _result(
            "ATENÇÃO", claimed_val, True,
            f"HSTS ativo mas max-age={max_age}s ({max_age//86400} dias) "
            f"está abaixo do mínimo recomendado de {_HSTS_MIN_MAX_AGE//86400} dias (OWASP)."
        )

    detail = f"HSTS ativo (max-age={max_age}s"
    if hsts.get("include_subdomains"):
        detail += ", includeSubDomains"
    if hsts.get("preload"):
        detail += ", preload"
    detail += ")."
    return _result("CONFORME", claimed_val, True, detail)


def _check_criptografia(ssl: dict) -> dict:
    if ssl.get("error"):
        nv = _result("NÃO VERIFICÁVEL", None, None, f"SSL Labs: {ssl['error']}")
        return {k: nv for k in ["grade", "TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "SSL 2.0"]}

    tls = ssl.get("tls") or {}
    grade = ssl.get("grade")
    scores = ssl.get("scores") or {}

    results: dict[str, dict] = {}

    # Grade geral
    if grade in ("A+", "A"):
        results["grade"] = _result("CONFORME", None, grade, f"Classificação SSL Labs: {grade}.")
    elif grade == "B":
        results["grade"] = _result("ATENÇÃO", None, grade,
                                   "Classificação B indica configuração subótima "
                                   "(cifras fracas ou protocolo legado ativo).")
    elif grade:
        results["grade"] = _result("NÃO CONFORME", None, grade,
                                   f"Classificação {grade} indica problemas sérios de configuração TLS.",
                                   "ALTO")
    else:
        results["grade"] = _result("NÃO VERIFICÁVEL", None, None, "Grade não disponível.")

    # Protocolos esperados como SUPORTADOS
    for proto in ("TLS 1.2", "TLS 1.3"):
        supported = tls.get(proto, False)
        if supported:
            results[proto] = _result("CONFORME", None, True, f"{proto} suportado.")
        else:
            sev = "CRITICO" if proto == "TLS 1.2" else "MEDIO"
            results[proto] = _result("NÃO CONFORME", None, False,
                                     f"{proto} não suportado. "
                                     f"{'TLS 1.2 é requisito mínimo (PAT tarefa #3).' if proto == 'TLS 1.2' else 'TLS 1.3 é recomendado pelo OWASP.'}",
                                     sev)

    # Protocolos esperados como DESABILITADOS
    for proto in ("TLS 1.1", "TLS 1.0", "SSL 3.0", "SSL 2.0"):
        supported = tls.get(proto, False)
        if not supported:
            results[proto] = _result("CONFORME", None, False, f"{proto} desabilitado.")
        else:
            results[proto] = _result("NÃO CONFORME", None, True,
                                     f"{proto} ainda suportado. Protocolo legado e inseguro deve ser desabilitado.",
                                     "ALTO")

    return results


def _check_aplicacoes(technologies_with_eol: list[dict]) -> dict:
    eol_items    = [t for t in technologies_with_eol if t.get("eol") is True]
    unknown_items = [t for t in technologies_with_eol if t.get("eol") is None and t.get("version")]

    if eol_items:
        names  = ", ".join(
            f"{t['name']} {t['version'] or ''} (EOL: {t.get('eol_date', '?')})"
            for t in eol_items
        )
        detail = f"{len(eol_items)} tecnologia(s) com versões sem suporte ativo: {names}."
        status = "ATENÇÃO"
    elif unknown_items:
        detail = (
            f"{len(unknown_items)} tecnologia(s) com versão detectada mas "
            "ciclo de vida não consultado. Verificação manual recomendada."
        )
        status = "ATENÇÃO"
    else:
        detail = "Todas as tecnologias verificadas estão sob suporte ativo."
        status = "CONFORME"

    return {
        "status":       status,
        "severity":     None,
        "eol_items":    eol_items,
        "technologies": technologies_with_eol,
        "detail":       detail,
    }


def _check_portas(ports: dict, cdn: str | None) -> dict:
    if ports.get("error") and not ports.get("open_ports"):
        return _result("NÃO VERIFICÁVEL", None, None,
                       f"Scan de portas não concluído: {ports.get('error')}")

    open_ports = ports.get("open_ports", [])
    non_std = ports.get("non_standard_ports", [])
    source = ports.get("source", "tcp_scan")

    is_cloudflare = cdn == "Cloudflare"

    # Filtra portas Cloudflare do total de não-padrão
    cf_ports = [p for p in non_std if p in CLOUDFLARE_PROXY_PORTS]
    truly_non_std = [p for p in non_std if p not in CLOUDFLARE_PROXY_PORTS]
    critical_exposed = [p for p in truly_non_std if p in _CRITICAL_PORTS]

    if critical_exposed:
        return _result(
            "NÃO CONFORME", None, open_ports,
            f"Portas críticas expostas publicamente: {critical_exposed}. "
            "Serviços de administração remota acessíveis pela internet.",
            "CRITICO"
        )

    if truly_non_std:
        return _result(
            "NÃO CONFORME", None, open_ports,
            f"Portas não-padrão expostas: {truly_non_std}. "
            "Verificar se são serviços necessários e se estão protegidos.",
            "MEDIO"
        )

    if cf_ports and is_cloudflare:
        return _result(
            "ATENÇÃO", None, open_ports,
            f"Portas {cf_ports} abertas são portas de proxy do Cloudflare "
            "(comportamento esperado e documentado pelo CDN). "
            f"Fonte do scan: {source}."
        )

    if set(open_ports) <= EXPECTED_PORTS:
        return _result("CONFORME", None, open_ports,
                       f"Apenas portas padrão abertas: {open_ports}. Fonte: {source}.")

    return _result("CONFORME", None, open_ports,
                   f"Portas abertas: {open_ports}. Fonte: {source}.")


def _check_whois(whois: dict) -> dict:
    if whois.get("error"):
        return _result("NÃO VERIFICÁVEL", None, None,
                       f"WHOIS indisponível: {whois['error']}")

    owner = whois.get("owner", "Não informado")
    expires_str = whois.get("expires")
    expiring_soon = False

    if expires_str:
        try:
            exp_date = datetime.strptime(expires_str[:8], "%Y%m%d").date()
            days_left = (exp_date - date.today()).days
            expiring_soon = days_left < 30
            expires_fmt = exp_date.strftime("%d/%m/%Y")
        except Exception:
            expires_fmt = expires_str
            days_left = None
    else:
        expires_fmt = "Não informado"
        days_left = None

    if expiring_soon:
        return _result(
            "NÃO CONFORME", None, expires_str,
            f"Domínio expira em {days_left} dias ({expires_fmt}). "
            "Renovação urgente necessária para continuidade da homologação.",
            "ALTO"
        )

    return _result(
        "CONFORME", None, expires_str,
        f"Proprietário: {owner}. Expiração: {expires_fmt}."
    )


# ── Status global e conclusão ─────────────────────────────────────────────────

def _overall_status(checks: dict) -> str:
    """CONFORME somente se nenhum item crítico/alto estiver NÃO CONFORME."""
    for check in _flatten_checks(checks):
        if check.get("status") == "NÃO CONFORME":
            sev = check.get("severity", "")
            if sev in ("CRITICO", "ALTO", "MEDIO"):
                return "NÃO CONFORME"
    return "CONFORME"


def _build_conclusao(checks: dict, domain: str) -> str:
    """Gera o texto de conclusão dinamicamente baseado nos achados."""
    non_conformidades: list[str] = []

    disp = checks.get("disponibilidade", {})
    _disp_labels = {
        "redundancia": "redundância de serviço",
        "backup":      "backup e recuperação",
        "energia":     "recurso contínuo de energia",
    }
    for key, label in _disp_labels.items():
        if disp.get(key, {}).get("status") == "NÃO CONFORME":
            non_conformidades.append(f"não declarou {label}")

    hsts = checks.get("hsts", {})
    if hsts.get("status") == "NÃO CONFORME":
        non_conformidades.append("não habilitou o HSTS")

    cripto = checks.get("criptografia", {})
    for proto in ("TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0"):
        if cripto.get(proto, {}).get("status") == "NÃO CONFORME":
            non_conformidades.append(f"mantém o {proto} ativo (protocolo inseguro)")
    for proto in ("TLS 1.2", "TLS 1.3"):
        if cripto.get(proto, {}).get("status") == "NÃO CONFORME":
            non_conformidades.append(f"não suporta {proto}")

    portas = checks.get("portas", {})
    if portas.get("status") == "NÃO CONFORME":
        non_conformidades.append("expõe portas de rede fora do padrão")

    whois = checks.get("seguranca_rede", {})
    if whois.get("status") == "NÃO CONFORME":
        non_conformidades.append("possui domínio com expiração iminente")

    if not non_conformidades:
        return "O leiloeiro atendeu as solicitações."

    items = "; ".join(non_conformidades)
    return f"O leiloeiro apresenta não conformidades: {items}."


# ── Utilitários ───────────────────────────────────────────────────────────────

def _result(
    status: str,
    claimed: Any,
    found: Any,
    detail: str,
    severity: str | None = None,
) -> dict:
    return {
        "status":   status,
        "claimed":  claimed,
        "found":    found,
        "detail":   detail,
        "severity": severity,
    }


def _flatten_checks(checks: dict) -> list[dict]:
    """Itera recursivamente sobre todos os checks para verificar status."""
    flat: list[dict] = []
    for v in checks.values():
        if isinstance(v, dict):
            if "status" in v:
                flat.append(v)
            else:
                flat.extend(_flatten_checks(v))
    return flat
