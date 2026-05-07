"""
Extrator de alegações estruturadas a partir do texto bruto do documento.

Estratégia conservadora: identifica seções por palavras-chave e extrai o
contexto textual relevante, sem tentar parsear valores exatos de texto livre.
O M3 (motor de decisão) é quem decide "conforme/não conforme" — o M1 apenas
mapeia o que foi declarado e onde.

Estrutura de saída (claimed_data):
    {
        "hsts_claimed":           bool | None,
        "tls_versions_claimed":   list[str],          # e.g. ["TLS 1.2", "TLS 1.3"]
        "ssl_cert_claimed":       bool | None,
        "os_versions":            list[str],
        "virtualization":         list[str],
        "firewall_waf":           list[str],
        "backup_claimed":         bool | None,
        "redundancy_claimed":     bool | None,
        "energy_redundancy":      bool | None,
        "monitoring_url":         str | None,
        "open_ports_declared":    list[int],
        "update_routine":         str | None,         # "manual" | "automatico" | None
        "datacenter":             list[str],
        "evidence":               dict[str, list[str]],
            #   chaves: hsts, ssl_cert, backup, redundancy, energy
            #   valores: lista de citações verbatim do documento
        "raw_sections":           dict[str, str],     # snippets para HSTS/TLS/etc
    }
"""

from __future__ import annotations

import re
from typing import Any


# ── Padrões e palavras-chave ────────────────────────────────────────────────

_RE_URL = re.compile(r"https?://[^\s,;\"'<>\)\]]+", re.IGNORECASE)
_RE_PORT_LABEL = re.compile(r"\bporta[s]?\s*[:=]?\s*(\d+)", re.IGNORECASE)
_RE_PORT_TCP = re.compile(r"\b(\d{2,5})/tcp\b", re.IGNORECASE)
_RE_TLS = re.compile(r"\btls\s*(\d+\.\d+)\b", re.IGNORECASE)
_RE_OS_WINDOWS = re.compile(
    r"windows\s+(?:server\s+)?(\d{4}(?:\s+r2)?)", re.IGNORECASE
)
_RE_OS_LINUX = re.compile(
    r"(ubuntu|debian|centos|red\s*hat|rhel|rocky|alma)\s+[\d.]+", re.IGNORECASE
)

# Mapeamento: seção → palavras-chave que delimitam início da seção no texto
# Usado APENAS para campos não-disponibilidade (HSTS, TLS, etc.).
_SECTION_KEYWORDS: dict[str, list[str]] = {
    "hsts":          ["hsts", "http strict transport security"],
    "tls":           ["tls", "protocolo", "criptografia", "ssl"],
    "ssl_cert":      ["certificado ssl", "certificado de segurança", "ssl emitido",
                      "autoridade certificadora", "certificado digital"],
    "os":            ["sistema operacional", "windows server", "ubuntu", "centos",
                      "versão do so", "versões do sistema"],
    "virtualizacao": ["virtualização", "virtualizado", "hyper-v", "vmware",
                      "virtualbox", "kvm", "proxmox"],
    "firewall":      ["firewall", "waf", "ips", "ids", "detecção de intrusão",
                      "cloudflare", "fortigate", "fortinet"],
    "monitoramento": ["monitoramento", "uptime", "uptime kuma", "zabbix", "nagios",
                      "grafana", "painel de monitoramento"],
    "portas":        ["porta", "port", "nmap", "80/tcp", "443/tcp"],
    "atualizacao":   ["atualização", "atualizações", "patches", "updates",
                      "atualizado", "manutenção de segurança"],
    "datacenter":    ["datacenter", "data center", "ascenty", "equinix", "locaweb",
                      "aws", "azure", "google cloud", "hospedagem", "servidor"],
}

# Indicadores booleanos positivos
_POSITIVE = [
    r"\bsim\b", r"\byes\b", r"está ativ", r"implementad", r"habilitad",
    r"configurad", r"possu", r"contamos com", r"trabalhamos com",
    r"utilizamos", r"adotamos", r"conta com", r"está em uso",
    r"com redundância",
]

_NEGATIVE = [
    r"\bnão\b", r"\bnao\b", r"\bnot\b", r"não habilit", r"não implement",
    r"não possu", r"recomenda-se a implementação", r"recomendamos a implementação",
]

_VIRT_MAP: dict[str, list[str]] = {
    "Hyper-V":  ["hyper-v", "hyperv"],
    "VMware":   ["vmware", "vsphere", "esxi"],
    "KVM":      ["kvm"],
    "Proxmox":  ["proxmox"],
    "Docker":   ["docker", "container", "kubernetes"],
}

_FIREWALL_TERMS = [
    "cloudflare", "fortigate", "fortinet", "pfsense", "sophos", "barracuda",
    "checkpoint", "f5", "imperva", "aws shield", "azure firewall",
    "firewall", "waf", "ips", "ids",
]

_FIREWALL_DISPLAY: dict[str, str] = {
    "waf": "WAF", "ips": "IPS", "ids": "IDS",
    "f5": "F5", "pfsense": "pfSense",
    "checkpoint": "Check Point", "aws shield": "AWS Shield",
}

_DATACENTER_TERMS = [
    "ascenty", "equinix", "locaweb", "digitalocean",
    "aws", "amazon web services", "azure", "google cloud", "gcp",
    "oracle cloud", "linode", "vultr", "hetzner",
]

# ── Disponibilidade — vocabulário e templates ─────────────────────────────────

_AVAILABILITY_KEYS = ("redundancy", "backup", "energy")

# Padrões fortes (presença obriga capturar trecho como evidência)
_AVAILABILITY_TERMS: dict[str, list[str]] = {
    "redundancy": [
        r"redund[âa]ncia\s+de\s+servi[çc]os?",
        r"alta\s+disponibilidade", r"high\s+availability\b",
        r"\bha\b", r"failover", r"toler[âa]ncia\s+a\s+falhas?",
        r"balanceador(?:es)?\s+de\s+carga", r"balanceamento\s+de\s+carga",
        r"load\s+balanc(?:er|ing)",
        r"replica[çc][ãa]o(?:\s+de\s+servidores)?", r"replica[çc][ãa]o\s+geogr[áa]fica",
        r"servidores?\s+redundantes?", r"sem\s+pontos?\s+[úu]nicos?\s+de\s+falha",
        r"multi[-\s]?az\b", r"multi[-\s]?regi[ãa]o", r"multi[-\s]?zonas?",
        r"cluster\b", r"kubernetes", r"\bk8s\b", r"\beks\b", r"\bgks\b", r"\bgke\b",
        r"\becs\b", r"docker\s+swarm",
        r"tier\s*(?:iii|iv|3|4)\b",
    ],
    "backup": [
        r"\bbackups?\b", r"c[óo]pias?\s+de\s+seguran[çc]a",
        r"snapshots?", r"replica[çc][ãa]o\s+de\s+dados",
        r"reten[çc][ãa]o\s+de\s+(?:dados|backups?)",
        r"testes?\s+de\s+restaura[çc][ãa]o", r"restaura[çc][ãa]o\s+de\s+dados",
        r"recupera[çc][ãa]o\s+de\s+dados",
        r"plano\s+de\s+recupera[çc][ãa]o", r"disaster\s+recovery", r"\bdr\b",
        r"rotina\s+de\s+backup", r"agendamento\s+(?:di[áa]ri[ao]|de\s+backup)",
        r"\braid\b\s*(?:1|5|6|10)?",
        r"amazon\s+rds\s+automated\s+backups", r"azure\s+backup",
    ],
    "energy": [
        r"\bups\b", r"no[\s-]?break", r"nobreak",
        r"gerador(?:es)?(?:\s+de\s+emerg[êe]ncia)?",
        r"motogerador", r"fonte\s+redundante", r"dupla\s+fonte",
        r"\bats\b", r"transfer[êe]ncia\s+autom[áa]tica\s+de\s+energia",
        r"energia\s+ininterrupta", r"alimenta[çc][ãa]o\s+ininterrupta",
        r"interrup[çc][õo]es\s+de\s+energia",
        r"plano\s+de\s+conting[êe]ncia\s+para\s+(?:interrup[çc][õo]es\s+de\s+)?energia",
        r"recurso\s+cont[íi]nuo\s+de\s+energia",
        r"datacenter\s+tier\s*(?:ii|iii|iv|2|3|4)\b",
        r"sistemas?\s+redundantes?\s+de\s+energia",
    ],
}

# Sinônimos para inferência indireta (provedor cloud → energia/redundância)
_AVAILABILITY_INFERENCE: dict[str, list[tuple[re.Pattern[str], str]]] = {
    "energy": [
        (re.compile(r"amazon\s+web\s+services|\baws\b", re.IGNORECASE),
         "AWS — energia redundante por SLA"),
        (re.compile(r"microsoft\s+azure|\bazure\b", re.IGNORECASE),
         "Microsoft Azure — energia redundante por SLA"),
        (re.compile(r"google\s+cloud|\bgcp\b", re.IGNORECASE),
         "Google Cloud — energia redundante por SLA"),
        (re.compile(r"oracle\s+cloud", re.IGNORECASE),
         "Oracle Cloud — energia redundante por SLA"),
        (re.compile(r"\bibm\s+cloud\b", re.IGNORECASE),
         "IBM Cloud — energia redundante por SLA"),
        (re.compile(r"digitalocean", re.IGNORECASE),
         "DigitalOcean — energia redundante por SLA"),
        (re.compile(r"\blinode\b", re.IGNORECASE),
         "Linode — energia redundante por SLA"),
        (re.compile(r"\bvultr\b", re.IGNORECASE),
         "Vultr — energia redundante por SLA"),
        (re.compile(r"\bequinix\b", re.IGNORECASE),
         "Datacenter Equinix Tier III/IV — energia redundante"),
        (re.compile(r"\bascenty\b", re.IGNORECASE),
         "Datacenter Ascenty Tier III — energia redundante"),
    ],
    "redundancy": [
        (re.compile(r"amazon\s+web\s+services|\baws\b", re.IGNORECASE),
         "AWS — alta disponibilidade nativa (multi-AZ)"),
        (re.compile(r"microsoft\s+azure|\bazure\b", re.IGNORECASE),
         "Azure — alta disponibilidade nativa"),
        (re.compile(r"google\s+cloud|\bgcp\b", re.IGNORECASE),
         "GCP — alta disponibilidade nativa"),
    ],
    # Backup NÃO admite inferência: requer declaração explícita.
    "backup": [],
}

# Cabeçalhos de seção que ajudam a delimitar a janela do leiloeiro
_SECTION_HEADER_PATTERNS = [
    r"redund[âa]ncia\s+de\s+servi[çc]os?",
    r"backup\s+e\s+recupera[çc][ãa]o",
    r"recurso\s+cont[íi]nuo\s+de\s+energia",
    r"recupera[çc][ãa]o\s+e\s+continuidade\s+operacional",
    r"pol[íi]tica\s+de\s+backup",
    r"caracter[íi]sticas\s+para\s+manuten[çc][ãa]o",
    r"infraestrutura\s+e\s+ambiente",
]

# Templates do TJ / texto metodológico — quando uma sentença é claramente
# do enunciado da demanda (perguntas, lista de itens a investigar, descrição
# da metodologia), ela NÃO conta como evidência da resposta do leiloeiro.
_TEMPLATE_FRAGMENTS = [
    "informar a existência",
    "informar a existencia",
    "rotina de backup e recuperação",
    "rotina de backup e recuperacao",
    "recurso contínuo de energia",
    "recurso continuo de energia",
]

# Marcadores de texto metodológico/introdutório (RAD/PAT/escopo de auditoria)
# que invalidam o trecho como declaração do leiloeiro, mesmo que o termo
# específico apareça na sentença.
_METHODOLOGY_MARKERS = [
    "verificação da existência", "verificacao da existencia",
    "avaliação da existência", "avaliacao da existencia",
    "análise dos procedimentos", "analise dos procedimentos",
    "deve apresentar", "deverá apresentar", "devera apresentar",
    "metodologia e etapas", "critérios adotados", "criterios adotados",
    "esta etapa compreende", "compreende a avaliação",
    "compreende a avaliacao", "solicita-se", "solicitamos",
    "garantam a continuidade", "para garantir a operação",
    "para garantir a operacao",
]

# Trechos de cabeçalho/rodapé/sumário que nunca entram em evidência
_NOISE_PATTERNS = [
    re.compile(r"\.{5,}"),                                       # sumário
    re.compile(r"CÓDIGO\s+N\.\d+\s+NORMA\s+VERSÃO", re.IGNORECASE),
    re.compile(r"^\s*p[áa]gina\s+\d+\s*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"DOC\.\d+-\d+", re.IGNORECASE),
    re.compile(r"documento\s+restrito", re.IGNORECASE),
    re.compile(r"endere[çc]o:\s+(?:tribunal|poder\s+judici[áa]rio)", re.IGNORECASE),
]

_INFERIDO_PREFIX = "[INFERIDO] "


# ── Interface pública ────────────────────────────────────────────────────────

def extract_claims(document_data: dict[str, Any]) -> dict[str, Any]:
    """
    Recebe o dict de read_pdf() ou read_docx() e retorna claimed_data.
    """
    text = document_data.get("text", "")
    text_lower = text.lower()
    image_page_count = document_data.get("image_page_count", 0) or 0

    raw_sections = _extract_raw_sections(text_lower, text)

    # Disponibilidade — extração baseada em sentenças com termos específicos.
    evidence = _extract_availability_evidence(text)

    # Inferência indireta para itens de disponibilidade sem evidência direta.
    for key in _AVAILABILITY_KEYS:
        if not evidence.get(key):
            inferred = _infer_availability(key, text)
            if inferred:
                evidence[key] = inferred

    return {
        "hsts_claimed":         _extract_hsts(raw_sections, text_lower),
        "tls_versions_claimed": _extract_tls_versions(text),
        "ssl_cert_claimed":     _extract_bool_claim(raw_sections.get("ssl_cert", ""), text_lower),
        "os_versions":          _extract_os_versions(text),
        "virtualization":       _extract_virtualization(text_lower),
        "firewall_waf":         _extract_firewall(text_lower),
        "backup_claimed":       True if evidence.get("backup") else None,
        "redundancy_claimed":   True if evidence.get("redundancy") else None,
        "energy_redundancy":    True if evidence.get("energy") else None,
        "monitoring_url":       _extract_monitoring_url(raw_sections.get("monitoramento", ""), text),
        "open_ports_declared":  _extract_ports(text),
        "update_routine":       _extract_update_routine(raw_sections.get("atualizacao", ""), text_lower),
        "datacenter":           _extract_datacenter(text_lower),
        "evidence": {
            "hsts":       [],
            "ssl_cert":   [],
            "backup":     evidence.get("backup", []),
            "redundancy": evidence.get("redundancy", []),
            "energy":     evidence.get("energy", []),
        },
        "raw_sections":     raw_sections,
        "image_page_count": image_page_count,
    }


# ── Helpers para respostas inline e sentenças curtas ─────────────────────────

def _extract_inline_response(sentence: str) -> str | None:
    """
    Quando uma sentença começa com texto de template/pergunta mas contém a
    resposta do leiloeiro após um separador (: ; — →), extrai apenas a
    parte da resposta. Retorna None se não houver resposta identificável.

    Ex.: "Informar a existência de backup: Sim, possuímos backup diário."
         → "Sim, possuímos backup diário."
    """
    # Tenta separadores comuns
    for sep in (":", " — ", " - ", "→", ";"):
        idx = sentence.find(sep)
        if idx < 0:
            continue
        after = sentence[idx + len(sep):].strip()
        if len(after) < 15:
            continue
        # A parte extraída NÃO pode ser ela própria texto metodológico
        after_low = after.lower()
        if any(marker in after_low for marker in _METHODOLOGY_MARKERS):
            continue
        # A parte após o separador deve conter algum indicador de resposta
        if _has_positive_indicator(after_low) or any(
            re.search(p, after, re.IGNORECASE)
            for patterns in _AVAILABILITY_TERMS.values()
            for p in patterns
        ):
            return after
    return None


def _has_positive_indicator(text: str) -> bool:
    """True se o texto contém indicador positivo de resposta do leiloeiro."""
    low = text.lower()
    return any(re.search(p, low) for p in _POSITIVE)


# ── Disponibilidade — coleta de múltiplas evidências ─────────────────────────

def _extract_availability_evidence(text: str) -> dict[str, list[str]]:
    """
    Para cada item de disponibilidade, devolve TODAS as sentenças do
    documento que contêm termos do item. Cada sentença é mantida verbatim
    (apenas whitespace normalizado) e deduplicada.
    """
    sentences = _split_sentences(text)
    out: dict[str, list[str]] = {k: [] for k in _AVAILABILITY_KEYS}

    for sentence in sentences:
        if _is_noise(sentence):
            continue

        # Template com resposta inline: "Informar backup: Sim, possuímos..."
        # → extrai apenas a parte DEPOIS do separador como evidência.
        effective = sentence
        if _looks_like_template(sentence):
            after = _extract_inline_response(sentence)
            if after:
                effective = after
            else:
                continue

        # Evita capturar enunciados puros do tipo "Backup e recuperação =>"
        # sem qualquer conteúdo após o rótulo.
        stripped = re.sub(r"\s+", " ", effective).strip(" -=>•·")
        if len(stripped) < 20:
            continue
        # Sentenças curtas (20-39 chars) só passam se contêm indicador positivo
        if len(stripped) < 40 and not _has_positive_indicator(stripped):
            continue

        for key, patterns in _AVAILABILITY_TERMS.items():
            if any(re.search(p, effective, re.IGNORECASE) for p in patterns):
                cleaned = _clean_quote(effective)
                if cleaned and cleaned not in out[key]:
                    out[key].append(cleaned)

    # Hard cap por item para não inflar a Ficha — 8 evidências distintas é
    # mais do que suficiente para qualquer relatório real.
    for key in out:
        out[key] = out[key][:8]
    return out


def _infer_availability(key: str, text: str) -> list[str]:
    """
    Quando não há evidência direta, busca menção a provedor que implica o
    item por SLA contratual. Devolve lista com UMA entrada com prefixo
    [INFERIDO] explicando a inferência.
    """
    for pattern, reason in _AVAILABILITY_INFERENCE.get(key, []):
        match = pattern.search(text)
        if not match:
            continue
        snippet = _surrounding_sentence(text, match.start(), match.end())
        snippet = _clean_quote(snippet)
        if not snippet:
            continue
        return [f"{_INFERIDO_PREFIX}{reason}. Trecho do documento: \"{snippet}\""]
    return []


def _split_sentences(text: str) -> list[str]:
    """
    Divide o texto em sentenças tolerando bullets, listas numeradas e
    quebras de linha duplas. Mantém o texto original (não lowercase).
    """
    if not text:
        return []
    # Junta múltiplas quebras com separador estável e normaliza bullets
    normalized = re.sub(r"\r\n", "\n", text)
    # Quebra por: ponto/?/! seguido de espaço; quebras duplas; bullets ou
    # marcadores no início de linha (a., 1., •, *, -).
    parts = re.split(
        r"(?<=[.;!?])\s+|\n{2,}|\n(?=\s*(?:[a-zA-Z]\.\s|\d+[.)]\s|[•*\-]\s))",
        normalized,
    )
    out: list[str] = []
    for p in parts:
        if not p:
            continue
        chunk = p.strip()
        if not chunk:
            continue
        # Sentenças muito longas são quebradas adicionalmente em ":" / ";"
        if len(chunk) > 600:
            out.extend(s.strip() for s in re.split(r"(?<=[;:])\s+", chunk) if s.strip())
        else:
            out.append(chunk)
    return out


def _looks_like_template(sentence: str) -> bool:
    """
    True quando a sentença é claramente do template/metodologia, e não da
    resposta do leiloeiro.

    Critérios (qualquer um):
      - 2+ marcadores do template do TJ aparecem juntos na sentença;
      - presença de marcador metodológico (verificação da existência,
        análise dos procedimentos, etc.).
    """
    low = sentence.lower()
    if any(marker in low for marker in _METHODOLOGY_MARKERS):
        return True
    hits = sum(1 for frag in _TEMPLATE_FRAGMENTS if frag in low)
    return hits >= 2


def _is_noise(sentence: str) -> bool:
    return any(p.search(sentence) for p in _NOISE_PATTERNS)


def _clean_quote(text: str) -> str:
    """Normaliza whitespace e remove pontuação solta nas bordas."""
    if not text:
        return ""
    cleaned = re.sub(r"\s+", " ", text).strip()
    cleaned = cleaned.strip(" \t-=>•·;:")
    # Tira marcadores de lista soltos no começo (ex: "a. ", "1) ", "- ")
    cleaned = re.sub(r"^(?:[a-zA-Z]\.|[•*\-]|\d+[.)])\s+", "", cleaned)
    return cleaned.strip()


def _surrounding_sentence(text: str, start: int, end: int) -> str:
    """Recorta a sentença que envolve o intervalo [start, end]."""
    left_break = max(
        text.rfind("\n\n", 0, start),
        text.rfind(". ", 0, start),
        text.rfind("; ", 0, start),
    )
    right_break_candidates = [
        pos for pos in [
            text.find("\n\n", end),
            text.find(". ", end),
            text.find("; ", end),
        ] if pos != -1
    ]
    left = max(0, left_break + 1) if left_break >= 0 else max(0, start - 200)
    right = min(right_break_candidates) + 1 if right_break_candidates else min(len(text), end + 200)
    return text[left:right]


# ── raw_sections — mantido para HSTS, TLS, certificado, etc. ─────────────────

def _extract_raw_sections(text_lower: str, text_original: str) -> dict[str, str]:
    """
    Para cada chave em _SECTION_KEYWORDS, captura janelas curtas de contexto
    com o termo. Usado pelos extratores que NÃO são de disponibilidade
    (hsts, tls, ssl_cert, etc.).
    """
    sections: dict[str, str] = {}
    for section, keywords in _SECTION_KEYWORDS.items():
        frags: list[str] = []
        seen_positions: set[int] = set()

        for kw in keywords:
            try:
                pat = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
            except re.error:
                continue
            for m in pat.finditer(text_lower):
                if len(frags) >= 6:
                    break
                idx = m.start()
                if any(abs(idx - p) < 100 for p in seen_positions):
                    continue
                frag_start = max(0, idx - 120)
                frag_end   = min(len(text_original), idx + 280)
                frag_text  = text_original[frag_start:frag_end]
                if any(p.search(frag_text) for p in _NOISE_PATTERNS):
                    continue
                seen_positions.add(idx)
                frags.append(frag_text.strip())

        if frags:
            sections[section] = " [...] ".join(frags[:4])
    return sections


# ── Extratores individuais de campos não-disponibilidade ─────────────────────

def _extract_hsts(raw_sections: dict[str, str], text_lower: str) -> bool | None:
    section_text = raw_sections.get("hsts", "").lower()
    if not section_text:
        if "hsts" not in text_lower and "http strict transport" not in text_lower:
            return None
        section_text = text_lower

    for pattern in _NEGATIVE:
        if re.search(pattern, section_text):
            return False
    for pattern in _POSITIVE:
        if re.search(pattern, section_text):
            return True
    return None


def _extract_tls_versions(text: str) -> list[str]:
    found = set()
    for m in _RE_TLS.finditer(text):
        found.add(f"TLS {m.group(1)}")
    text_lower = text.lower()
    for v in ("1.3", "1.2", "1.1", "1.0"):
        if f"tls {v}" in text_lower or f"tls{v}" in text_lower:
            found.add(f"TLS {v}")
    return sorted(found, reverse=True)


def _extract_os_versions(text: str) -> list[str]:
    found: list[str] = []
    for m in _RE_OS_WINDOWS.finditer(text):
        version = f"Windows Server {m.group(1).strip().title()}"
        if version not in found:
            found.append(version)
    for m in _RE_OS_LINUX.finditer(text):
        if m.group(0) not in found:
            found.append(m.group(0).strip())
    return found


def _extract_virtualization(text_lower: str) -> list[str]:
    found: list[str] = []
    for name, keywords in _VIRT_MAP.items():
        if any(kw in text_lower for kw in keywords):
            found.append(name)
    return found


def _extract_firewall(text_lower: str) -> list[str]:
    found: list[str] = []
    for term in _FIREWALL_TERMS:
        if term in text_lower and term not in found:
            found.append(_FIREWALL_DISPLAY.get(term, term.title()))
    return found


def _extract_bool_claim(section_text: str, text_lower: str) -> bool | None:
    if not section_text:
        return None
    ctx = section_text.lower()
    for pattern in _NEGATIVE:
        if re.search(pattern, ctx):
            return False
    for pattern in _POSITIVE:
        if re.search(pattern, ctx):
            return True
    return None


def _extract_monitoring_url(section_text: str, text_original: str) -> str | None:
    for source in [section_text, text_original]:
        for m in _RE_URL.finditer(source):
            url = m.group(0).rstrip(".,;)")
            url_lower = url.lower()
            if any(kw in url_lower for kw in ["monit", "uptime", "kuma", "health",
                                              "status", "nagios", "zabbix"]):
                return url
    return None


def _extract_ports(text: str) -> list[int]:
    found: set[int] = set()
    for m in _RE_PORT_LABEL.finditer(text):
        found.add(int(m.group(1)))
    for m in _RE_PORT_TCP.finditer(text):
        found.add(int(m.group(1)))
    text_lower = text.lower()
    if "porta 80" in text_lower or "port 80" in text_lower or "80/tcp" in text_lower:
        found.add(80)
    if "porta 443" in text_lower or "port 443" in text_lower or "443/tcp" in text_lower:
        found.add(443)
    return sorted(found)


def _extract_update_routine(section_text: str, text_lower: str) -> str | None:
    ctx = section_text.lower() if section_text else text_lower
    has_auto = any(kw in ctx for kw in ["automático", "automática", "automaticamente",
                                         "atualização automática", "auto update"])
    has_manual = any(kw in ctx for kw in ["manual", "manualmente", "forma manual",
                                           "período noturno"])
    if has_auto and has_manual:
        return "manual e automatico"
    if has_auto:
        return "automatico"
    if has_manual:
        return "manual"
    return None


def _extract_datacenter(text_lower: str) -> list[str]:
    found: list[str] = []
    for term in _DATACENTER_TERMS:
        if term in text_lower:
            found.append(term.title())
    return found
