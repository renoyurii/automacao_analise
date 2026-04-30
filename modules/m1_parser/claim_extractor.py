"""
Extrator de alegações estruturadas a partir do texto bruto do documento.

Estratégia conservadora: identifica seções por palavras-chave e extrai o
contexto textual relevante, sem tentar parsear valores exatos de texto livre.
O M3 (motor de decisão) é quem decide "conforme/não conforme" — o M1 apenas
mapeia o que foi declarado e onde.

Estrutura de saída (claimed_data):
    {
        "hsts_claimed":           bool | None,
        "tls_versions_claimed":   list[str],       # e.g. ["TLS 1.2", "TLS 1.3"]
        "ssl_cert_claimed":       bool | None,
        "os_versions":            list[str],
        "virtualization":         list[str],
        "firewall_waf":           list[str],
        "backup_claimed":         bool | None,
        "redundancy_claimed":     bool | None,
        "energy_redundancy":      bool | None,
        "monitoring_url":         str | None,
        "open_ports_declared":    list[int],
        "update_routine":         str | None,      # "manual" | "automatico" | None
        "datacenter":             list[str],
        "raw_sections":           dict[str, str],  # Texto bruto por seção
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
    "backup":        ["backup", "cópia de segurança", "raid", "replicação",
                      "snapshot", "rotina de backup"],
    "redundancia":   ["redundância", "alta disponibilidade", "sem pontos únicos",
                      "redundante", "failover", "balanceador de carga",
                      "balanceamento de carga"],
    "energia":       ["nobreak", "ups", "gerador", "energia ininterrupta",
                      "alimentação ininterrupta", "no-break",
                      "energia elétrica", "interrupções de energia",
                      "fonte de energia", "dupla fonte"],
    "monitoramento": ["monitoramento", "uptime", "uptime kuma", "zabbix", "nagios",
                      "grafana", "painel de monitoramento"],
    "portas":        ["porta", "port", "nmap", "80/tcp", "443/tcp"],
    "atualizacao":   ["atualização", "atualizações", "patches", "updates",
                      "atualizado", "manutenção de segurança"],
    "datacenter":    ["datacenter", "data center", "ascenty", "equinix", "locaweb",
                      "aws", "azure", "google cloud", "hospedagem", "servidor"],
}

# Indicadores FORTEMENTE positivos — têm prioridade sobre negativos genéricos.
# São padrões de alta especificidade que indicam inequivocamente que o item
# está implementado, mesmo que o texto contenha "não" em outro contexto
# (ex: "não impactar o andamento" ≠ "não temos backup").
_STRONG_POSITIVE = [
    # Backup
    r"rotina.*backup", r"rotinas.*backup", r"backup.*agendamento",
    r"agendamento.*backup", r"backups completos", r"backup completo",
    r"procedimento.*backup", r"norma.*backup", r"política.*backup",
    r"backup.*diári", r"diári.*backup",
    # Redundância / HA
    r"alta disponibilidade", r"sem pontos únicos de falha",
    r"replicação constante", r"espelha os dados",
    r"balanceador\s+de\s+carga", r"balanceamento\s+de\s+carga",
    r"servidores?\s+redundantes?",
    # Energia
    r"fonte.*redundante", r"redundância.*energia", r"energia.*redundante",
    # Genérico (técnico assertivo)
    r"\braid\b", r"agendamento diário", r"rotina específica",
    r"garantia da continuidade",
]

# Indicadores booleanos positivos (o leiloeiro AFIRMA que possui/implementou)
_POSITIVE = [
    r"\bsim\b", r"\byes\b", r"está ativ", r"implementad", r"habilitad",
    r"configurad", r"possu", r"contamos com", r"trabalhamos com",
    r"utilizamos", r"adotamos", r"conta com", r"está em uso",
    r"com redundância",
]

# Indicadores booleanos negativos (o leiloeiro NÃO possui / recomendação não atendida)
_NEGATIVE = [
    r"\bnão\b", r"\bnao\b", r"\bnot\b", r"não habilit", r"não implement",
    r"não possu", r"recomenda-se a implementação",  # = ainda não feito
    r"recomendamos a implementação",
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

# Nomes de exibição corretos para siglas e marcas com capitalização especial
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

# Inferência indireta — quando a seção explícita está vazia, procura por sinais
# que IMPLICAM o atendimento do item, mesmo sem palavra-chave direta.
# Cada entrada: (palavra-chave_lower, motivo_da_inferência)
_INFERENCE_KEYWORDS: dict[str, list[tuple[str, str]]] = {
    # Energia: datacenter / cloud sempre tem UPS+gerador por SLA contratual.
    "energia": [
        ("kinghost",            "hospedagem em datacenter KingHost — UPS/gerador inclusos no SLA"),
        ("ascenty",             "hospedagem em datacenter Ascenty (Tier III)"),
        ("equinix",             "hospedagem em datacenter Equinix (Tier III/IV)"),
        ("locaweb",             "hospedagem em datacenter Locaweb"),
        ("uolhost",             "hospedagem em datacenter UOL Host"),
        ("uol host",            "hospedagem em datacenter UOL Host"),
        ("hostgator",           "hospedagem em provedor HostGator"),
        ("hostinger",           "hospedagem em provedor Hostinger"),
        ("godaddy",             "hospedagem em provedor GoDaddy"),
        ("amazon web services", "hospedagem na AWS — energia redundante por SLA"),
        ("aws",                 "hospedagem na AWS — energia redundante por SLA"),
        ("microsoft azure",     "hospedagem no Microsoft Azure — energia redundante por SLA"),
        ("azure",               "hospedagem no Microsoft Azure — energia redundante por SLA"),
        ("google cloud",        "hospedagem no Google Cloud — energia redundante por SLA"),
        (" gcp ",               "hospedagem no GCP — energia redundante por SLA"),
        ("oracle cloud",        "hospedagem na Oracle Cloud"),
        ("ibm cloud",           "hospedagem na IBM Cloud"),
        ("digitalocean",        "hospedagem na DigitalOcean"),
        ("linode",              "hospedagem na Linode"),
        ("vultr",               "hospedagem na Vultr"),
        ("hetzner",             "hospedagem na Hetzner"),
        ("data center",         "hospedagem em datacenter — UPS/gerador por SLA padrão"),
        ("datacenter",          "hospedagem em datacenter — UPS/gerador por SLA padrão"),
    ],
    # Redundância: cloud providers / Tier III+ implicam HA nativa.
    "redundancia": [
        ("amazon web services", "AWS oferece alta disponibilidade nativa (multi-AZ)"),
        ("aws",                 "AWS oferece alta disponibilidade nativa (multi-AZ)"),
        ("microsoft azure",     "Azure oferece alta disponibilidade nativa"),
        ("azure",               "Azure oferece alta disponibilidade nativa"),
        ("google cloud",        "Google Cloud oferece alta disponibilidade nativa"),
        (" gcp ",               "GCP oferece alta disponibilidade nativa"),
        ("tier iii",            "datacenter Tier III — alta disponibilidade por design"),
        ("tier 3",              "datacenter Tier III — alta disponibilidade por design"),
        ("tier iv",             "datacenter Tier IV — alta disponibilidade por design"),
        ("tier 4",              "datacenter Tier IV — alta disponibilidade por design"),
        ("load balancer",       "balanceador de carga mencionado — implica redundância"),
        ("balanceador de carga", "balanceador de carga mencionado — implica redundância"),
        ("balanceamento de carga", "balanceamento de carga mencionado — implica redundância"),
        ("kubernetes",          "orquestração Kubernetes — alta disponibilidade nativa"),
    ],
    # Backup: inferência fraca; só aceitamos provedores que têm backup nativo OBRIGATÓRIO.
    # Datacenter genérico NÃO implica backup (é responsabilidade do cliente).
    # Mantemos vazio por padrão para forçar declaração explícita.
    "backup": [],
}

_INFERIDO_PREFIX = "[INFERIDO] "

# Detecção de "cluster de demandas" — quando as 3 keywords de disponibilidade
# (redundância, backup, energia) aparecem clusterizadas em ~200 chars, é o
# template da pergunta do TJ ("Informar a existência de: ● redundância; ● backup;
# ● energia"). Quando só 1 das 3 aparece numa janela, é resposta legítima.
_DISP_CLUSTER_KEYWORDS: dict[str, list[str]] = {
    "redundancia": ["redundância", "redundancia", "alta disponibilidade",
                    "redundante", "failover"],
    "backup":      ["backup", "cópia de segurança", "copia de seguranca",
                    "rotina de backup"],
    "energia":     ["nobreak", "no-break", " ups ", "gerador",
                    "energia ininterrupta", "alimentação ininterrupta",
                    "energia elétrica", "energia eletrica",
                    "interrupções de energia", "interrupcoes de energia",
                    "fonte de energia", "recurso contínuo de energia",
                    "recurso continuo de energia"],
}

_AVAILABILITY_LABEL_PATTERNS: dict[str, list[str]] = {
    "redundancia": [
        r"redund[âa]ncia\s+de\s+servi[çc]o",
        r"redund[âa]ncia\s+operacional",
    ],
    "backup": [
        r"backup\s+e\s+recupera[çc][ãa]o",
        r"rotina\s+de\s+backup",
        r"backup",
    ],
    "energia": [
        r"recurso\s+cont[íi]nuo\s+de\s+energia",
        r"redund[âa]ncia\s+de\s+energia(?:\s+el[ée]trica)?",
    ],
}

_AVAILABILITY_SEARCH_PATTERNS: dict[str, list[str]] = {
    "redundancia": [
        r"redund[âa]ncia", r"alta\s+disponibilidade", r"failover",
        r"balanceador(?:es)?\s+de\s+carga", r"balanceamento\s+de\s+carga",
        r"replica[çc][ãa]o", r"servidores?\s+redundantes?",
        r"sem\s+pontos?\s+[úu]nicos?\s+de\s+falha",
    ],
    "backup": [
        r"\bbackup\b", r"backups", r"c[óo]pia\s+de\s+seguran[çc]a",
        r"snapshot", r"restaura[çc][ãa]o", r"recupera[çc][ãa]o\s+de\s+dados",
        r"reten[çc][ãa]o", r"agendamento\s+di[áa]rio",
    ],
    "energia": [
        r"alta\s+disponibilidade\s+el[ée]trica",
        r"disponibilidade\s+el[ée]trica",
        r"energia\s+ininterrupta", r"alimenta[çc][ãa]o\s+ininterrupta",
        r"nobreak", r"no-break", r"\bups\b", r"gerador",
        r"dupla\s+fonte", r"fonte\s+redundante",
        r"transfer[êe]ncia\s+autom[áa]tica\s+de\s+energia",
        r"interrup[çc][õo]es\s+de\s+energia",
        r"conting[êe]ncia\s+para\s+interrup[çc][õo]es\s+de\s+energia",
    ],
}

_AVAILABILITY_GENERIC_PATTERNS = [
    r"\besta\s+etapa\s+compreende\b",
    r"\bverifica[çc][ãa]o\s+da\s+exist[êe]ncia\b",
    r"\bavalia[çc][ãa]o\s+da\s+exist[êe]ncia\b",
    r"\ban[áa]lise\s+dos\s+procedimentos\b",
    r"\bo\s+leiloeiro\s+deve\s+apresentar\b",
    r"\bdeve\s+apresentar\b",
    r"\bdever[áa]\s+apresentar\b",
    r"\bde\s+modo\s+a\s+comprovar\b",
    r"\brequisitos?\s+m[íi]nimos?\b",
    r"\bprocesso\s+de\s+homologa[çc][ãa]o\b",
    r"\bmetodologia\s+e\s+etapas\s+de\s+avalia[çc][ãa]o\b",
    r"\bcritérios?\s+adotados\b",
    r"\bsolicita-se\b",
    r"\binformar\s+a\s+exist[êe]ncia\b",
]

_AVAILABILITY_ASSERTIVE_PATTERNS = [
    r"\bdeclara\b", r"\bpossui\b", r"\bconta\s+com\b", r"\bmant[ée]m\b",
    r"\butiliza\b", r"\badota\b", r"\btem\b", r"\bhospedad[ao]\b",
    r"\bambiente\s+de\b", r"\bplano\s+de\b", r"\brotina\s+de\b",
    r"\bagendamento\b", r"\bdi[áa]ri[ao]\b", r"\bs[ãa]o\s+realizados\b",
    r"\brealizados?\b", r"\bautomatizad[ao]\b", r"\bgarantindo\b",
]


# ── Interface pública ────────────────────────────────────────────────────────

def extract_claims(document_data: dict[str, Any]) -> dict[str, Any]:
    """
    Recebe o dict de read_pdf() ou read_docx() e retorna claimed_data.
    """
    text = document_data.get("text", "")
    text_lower = text.lower()
    image_page_count = document_data.get("image_page_count", 0) or 0

    raw_sections = _extract_raw_sections(text_lower, text)
    availability_sections = _extract_availability_sections(text_lower, text)
    for key in _DISP_CLUSTER_KEYWORDS:
        raw_sections.pop(key, None)
        if availability_sections.get(key):
            raw_sections[key] = availability_sections[key]

    # Inferência indireta — para cada seção sem match direto, busca sinais
    # contextuais (provedor de hospedagem, datacenter, recursos cloud) que
    # implicam o atendimento do item.
    for section_key in _INFERENCE_KEYWORDS:
        if section_key in _DISP_CLUSTER_KEYWORDS:
            continue
        if not raw_sections.get(section_key):
            inferred = _extract_inference(section_key, text_lower, text)
            if inferred:
                raw_sections[section_key] = inferred

    return {
        "hsts_claimed":        _extract_hsts(raw_sections, text_lower),
        "tls_versions_claimed": _extract_tls_versions(text),
        "ssl_cert_claimed":    _extract_bool_claim(raw_sections.get("ssl_cert", ""), text_lower),
        "os_versions":         _extract_os_versions(text),
        "virtualization":      _extract_virtualization(text_lower),
        "firewall_waf":        _extract_firewall(text_lower),
        "backup_claimed":      _extract_bool_claim(raw_sections.get("backup", ""), text_lower),
        "redundancy_claimed":  _extract_bool_claim(raw_sections.get("redundancia", ""), text_lower),
        "energy_redundancy":   _extract_bool_claim(raw_sections.get("energia", ""), text_lower),
        "monitoring_url":      _extract_monitoring_url(raw_sections.get("monitoramento", ""), text),
        "open_ports_declared": _extract_ports(text),
        "update_routine":      _extract_update_routine(raw_sections.get("atualizacao", ""), text_lower),
        "datacenter":          _extract_datacenter(text_lower),
        "raw_sections":        raw_sections,
        "image_page_count":    image_page_count,
    }


# ── Extratores individuais ───────────────────────────────────────────────────

def _extract_raw_sections(text_lower: str, text_original: str) -> dict[str, str]:
    """
    Para cada seção mapeada, extrai janelas de contexto (300 chars cada).

    Estratégia em três camadas:
    1. Se o documento tem seção explícita '1. Disponibilidade', os itens de
       disponibilidade são buscados PRIMEIRAMENTE dentro dessa janela — evita
       que conteúdo de outras seções (patches, auditoria) contamine a evidência.
    2. Fragmentos com padrões FORTEMENTE POSITIVOS são priorizados na exibição
       (aparecem antes dos fragmentos introdutórios/cabeçalhos).
    3. Sumário/índice (linhas com '......'), cabeçalhos repetidos de norma
       ('CÓDIGO N.xxx NORMA VERSÃO V.001') e numerações de página soltas são
       sempre descartados.
    """
    # Janela da seção "1. Disponibilidade" explícita (se existir no documento)
    disp_block_lower, disp_block_orig = _extract_disp_block(text_lower, text_original)

    sections: dict[str, str] = {}
    for section, keywords in _SECTION_KEYWORDS.items():
        strong_frags: list[str] = []  # contêm padrão fortemente positivo
        weak_frags:   list[str] = []
        seen_positions: set[int] = set()

        # Para seções de disponibilidade, busca primeiro na janela explícita
        search_spaces: list[tuple[str, str]] = []
        if section in _DISP_CLUSTER_KEYWORDS and disp_block_lower:
            search_spaces.append((disp_block_lower, disp_block_orig))
        search_spaces.append((text_lower, text_original))

        for src_lower, src_orig in search_spaces:
            for kw in keywords:
                try:
                    pat = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
                except re.error:
                    continue

                for m in pat.finditer(src_lower):
                    if len(strong_frags) + len(weak_frags) >= 8:
                        break
                    idx = m.start()
                    # Converte idx para posição no texto global (para cluster check)
                    global_idx = idx if src_lower is text_lower else (
                        text_lower.find(src_lower[idx:idx+20], max(0, idx-10))
                    )
                    if section in _DISP_CLUSTER_KEYWORDS and \
                       _is_question_context(text_lower, global_idx, current_section=section):
                        continue
                    if any(abs(idx - p) < 100 for p in seen_positions):
                        continue
                    frag_start = max(0, idx - 120)
                    frag_end   = min(len(src_orig), idx + 300)
                    frag_text  = _snap_to_word_boundary(src_orig, frag_start, frag_end)
                    # Descarta sumário/TOC (linhas com pontos .........)
                    if re.search(r'\.{5,}', frag_text):
                        continue
                    # Descarta cabeçalho de norma interna repetido por página
                    if re.search(r'CÓDIGO\s+N\.\d+\s*[\n\r]+\s*NORMA\s+VERSÃO', frag_text):
                        continue
                    # Descarta numeração de página solta (ex: "8\n1\n")
                    if re.match(r'^\s*\d{1,3}\s*\n\s*\d{1,3}\s*\n', frag_text):
                        continue
                    seen_positions.add(idx)
                    if any(re.search(p, frag_text, re.IGNORECASE) for p in _STRONG_POSITIVE):
                        strong_frags.append(frag_text)
                    else:
                        weak_frags.append(frag_text)

        # Fragmentos fortemente positivos primeiro; cap em 4
        all_frags = (strong_frags + weak_frags)[:4]
        if all_frags:
            sections[section] = " [...] ".join(all_frags)

    return sections


def _extract_availability_sections(text_lower: str, text_original: str) -> dict[str, str]:
    """
    Extrai apenas evidências reais para os campos de disponibilidade.

    Diferente do extrator genérico, esta rotina evita usar texto metodológico,
    perguntas do TJ ou trechos de template como evidência. A prioridade é:
      1. resposta imediatamente após rótulos como "Backup e recuperação =>";
      2. trecho assertivo do relatório técnico com termos específicos do item.
    """
    sections: dict[str, str] = {}
    disp_lower, disp_orig = _extract_disp_block(text_lower, text_original)
    labeled_source = disp_orig if disp_orig else text_original

    for key in _DISP_CLUSTER_KEYWORDS:
        labeled = _extract_labeled_availability_evidence(labeled_source, key)
        if labeled is not None:
            if _is_real_availability_evidence(labeled, key):
                sections[key] = labeled
                continue
            if _is_missing_evidence(labeled):
                continue

        candidate = _find_availability_candidate(text_original, key)
        if candidate:
            sections[key] = candidate

    return sections


def _extract_labeled_availability_evidence(text: str, key: str) -> str | None:
    labels = _AVAILABILITY_LABEL_PATTERNS[key]
    label_union = "|".join(f"(?:{p})" for p in labels)
    all_label_union = "|".join(
        f"(?:{p})"
        for patterns in _AVAILABILITY_LABEL_PATTERNS.values()
        for p in patterns
    )

    pattern = re.compile(
        rf"(?P<label>{label_union})\s*(?:=>|:|-)?\s*(?P<body>.*?)"
        rf"(?=(?:\n\s*(?:{all_label_union})\s*(?:=>|:|-)?)|(?:\n\s*\d+\s*[.)]\s*)|\Z)",
        re.IGNORECASE | re.DOTALL,
    )
    match = pattern.search(text)
    if not match:
        return None

    body = _clean_labeled_evidence(match.group("body"))
    if _is_missing_evidence(body):
        return ""
    return body


def _find_availability_candidate(text_original: str, key: str) -> str | None:
    candidates: list[tuple[int, str]] = []

    for candidate in _structured_availability_candidates(text_original, key):
        if _is_real_availability_evidence(candidate, key):
            candidates.append((_availability_score(candidate, key) + 10, candidate))

    patterns = _AVAILABILITY_SEARCH_PATTERNS[key]
    for pat in patterns:
        for match in re.finditer(pat, text_original, flags=re.IGNORECASE):
            chunk = _availability_chunk(text_original, match.start(), match.end())
            chunk = _clean_labeled_evidence(chunk)
            if not _is_real_availability_evidence(chunk, key):
                continue
            candidates.append((_availability_score(chunk, key), chunk))

    if not candidates:
        return None

    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _structured_availability_candidates(text_original: str, key: str) -> list[str]:
    candidates: list[str] = []

    for item in _iter_list_items(text_original):
        cleaned = _clean_labeled_evidence(item)
        if _is_real_availability_evidence(cleaned, key):
            candidates.append(cleaned)

    if key == "backup":
        section = _extract_numbered_section(text_original, r"pol[íi]tica\s+de\s+backup")
        if section:
            candidates.extend(_backup_section_candidates(section))

    if key in {"redundancia", "energia"}:
        section = _extract_numbered_section(
            text_original,
            r"recupera[çc][ãa]o\s+e\s+continuidade\s+operacional",
        )
        if section:
            for item in _iter_list_items(section):
                cleaned = _clean_labeled_evidence(item)
                if _is_real_availability_evidence(cleaned, key):
                    candidates.append(cleaned)
            intro = _first_sentence_with_terms(section, key)
            if intro:
                candidates.append(intro)

    return _dedupe_preserve_order(candidates)


def _iter_list_items(text: str) -> list[str]:
    pattern = re.compile(
        r"(?:^|\n)\s*(?:[a-z]\.|[•*-])\s+(.+?)"
        r"(?=(?:\n\s*(?:[a-z]\.|[•*-])\s+)|(?:\n\s*\d+\.\s+[A-ZÁÉÍÓÚÃÕÇ])|(?:\n\s*Página\s+\d+)|\Z)",
        re.IGNORECASE | re.DOTALL,
    )
    return [m.group(1) for m in pattern.finditer(text)]


def _extract_numbered_section(text: str, heading_pattern: str) -> str:
    pattern = re.compile(
        rf"(?:^|\n)\s*\d+\.\s+{heading_pattern}\s*(?P<body>.*?)"
        r"(?=(?:\n\s*\d+\.\s+[A-ZÁÉÍÓÚÃÕÇ])|\Z)",
        re.IGNORECASE | re.DOTALL,
    )
    match = pattern.search(text)
    return match.group("body") if match else ""


def _backup_section_candidates(section: str) -> list[str]:
    candidates: list[str] = []
    first = _first_sentence_with_terms(section, "backup")
    if first:
        candidates.append(first)
    for item in _iter_list_items(section):
        cleaned = _clean_labeled_evidence(item)
        if _is_real_availability_evidence(cleaned, "backup"):
            candidates.append(cleaned)
    return candidates


def _first_sentence_with_terms(text: str, key: str) -> str | None:
    sentences = re.split(r"(?<=[.;])\s+", re.sub(r"\s+", " ", text).strip())
    for sentence in sentences:
        cleaned = _clean_labeled_evidence(sentence)
        if _is_real_availability_evidence(cleaned, key):
            return cleaned
    return None


def _availability_chunk(text: str, start: int, end: int) -> str:
    left = max(
        text.rfind("\n\n", 0, start),
        text.rfind(". ", 0, start),
        text.rfind("; ", 0, start),
        text.rfind(":\n", 0, start),
    )
    if left < 0 or start - left > 260:
        left = max(0, start - 120)
    else:
        left += 1

    right_candidates = [
        pos for pos in [
            text.find("\n\n", end),
            text.find(". ", end),
            text.find("; ", end),
            text.find("\n2.", end),
            text.find("\n3.", end),
        ]
        if pos != -1 and pos > end
    ]
    right = min(right_candidates) + 1 if right_candidates else min(len(text), end + 360)
    return _snap_to_word_boundary(text, left, right)


def _clean_labeled_evidence(text: str) -> str:
    cleaned = re.sub(r"\s+", " ", text or "").strip()
    cleaned = re.sub(r"^(?:=>|:|-|[a-z]\.)\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(
        r"^(?:DOC\.\d+-\d+|Documento Restrito|Endere[çc]o: Tribunal de Justi[çc]a[^.]*)(?:\s+|$)",
        "",
        cleaned,
        flags=re.IGNORECASE,
    ).strip()
    return cleaned.strip(" ;:.,")


def _is_missing_evidence(text: str) -> bool:
    compact = re.sub(r"\s+", " ", text or "").strip().lower()
    return not compact or compact in {"não informado", "nao informado", "-", "—"}


def _is_real_availability_evidence(text: str, key: str) -> bool:
    if _is_missing_evidence(text):
        return False
    lower = text.lower()
    if len(lower) < 12:
        return False
    if re.search(r"\.{5,}", text):
        return False
    if any(re.search(p, lower, re.IGNORECASE) for p in _AVAILABILITY_GENERIC_PATTERNS):
        return False
    if key == "redundancia" and re.search(
        r"energia|el[ée]trica|ups|gerador|nobreak|no-break|\bats\b",
        lower,
    ):
        return False
    if "=>" in text and len(text) < 80:
        return False
    has_specific_term = any(
        re.search(p, lower, re.IGNORECASE)
        for p in _AVAILABILITY_SEARCH_PATTERNS[key]
    )
    has_assertive = any(re.search(p, lower, re.IGNORECASE) for p in _AVAILABILITY_ASSERTIVE_PATTERNS)
    return has_specific_term and (has_assertive or len(lower) <= 360)


def _availability_score(text: str, key: str) -> int:
    lower = text.lower()
    score = 0
    score += 8 if any(re.search(p, lower, re.IGNORECASE) for p in _AVAILABILITY_SEARCH_PATTERNS[key]) else 0
    score += 4 if any(re.search(p, lower, re.IGNORECASE) for p in _AVAILABILITY_ASSERTIVE_PATTERNS) else 0
    score += 2 if len(text) <= 380 else 0
    score -= 4 if len(text) > 650 else 0
    if key == "backup":
        score += 5 if re.search(r"backups?\s+s[ãa]o\s+realizados|automatizad[ao]|di[áa]ri[ao]", lower) else 0
        score -= 3 if re.search(r"\baws\s+storage\b|\bovh\s+storage\b", lower) else 0
    elif key == "redundancia":
        score += 5 if re.search(r"ponto\s+[úu]nico\s+de\s+falha|balanceador|alta\s+disponibilidade", lower) else 0
        score -= 4 if re.search(r"\bbackup|backups|storage\b", lower) else 0
    elif key == "energia":
        score += 5 if re.search(r"ups|geradores?|ats|disponibilidade\s+el[ée]trica|energia\s+ininterrupta", lower) else 0
    return score


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        normalized = re.sub(r"\W+", "", item.lower())[:120]
        if normalized in seen:
            continue
        seen.add(normalized)
        out.append(item)
    return out


def _extract_disp_block(text_lower: str, text_original: str) -> tuple[str, str]:
    """
    Localiza a seção '1. Disponibilidade' explícita no documento (se existir)
    e retorna uma janela de ~2000 chars como espaço de busca prioritária para
    os itens redundância, backup e energia.

    Se não encontrar, retorna ('', '').
    """
    m = re.search(
        r'(?:^|\n)\s*1\s*[.)\-]\s*disponibilidade',
        text_lower,
    )
    if not m:
        return "", ""
    start = m.start()
    end   = min(len(text_original), start + 2000)
    block = text_original[start:end]
    return block.lower(), block


def _extract_hsts(raw_sections: dict[str, str], text_lower: str) -> bool | None:
    section_text = raw_sections.get("hsts", "").lower()
    if not section_text:
        # Tenta busca direta no texto completo
        if "hsts" not in text_lower and "http strict transport" not in text_lower:
            return None
        section_text = text_lower

    # Negativo explícito tem prioridade (recomendação = ainda não implementado)
    for pattern in _NEGATIVE:
        if re.search(pattern, section_text):
            return False

    for pattern in _POSITIVE:
        if re.search(pattern, section_text):
            return True

    # Keyword presente mas sem indicador claro
    return None


def _extract_tls_versions(text: str) -> list[str]:
    found = set()
    for m in _RE_TLS.finditer(text):
        found.add(f"TLS {m.group(1)}")

    # Detecção por padrões textuais comuns nas declarações
    text_lower = text.lower()
    if "tls 1.3" in text_lower or "tls1.3" in text_lower:
        found.add("TLS 1.3")
    if "tls 1.2" in text_lower or "tls1.2" in text_lower:
        found.add("TLS 1.2")
    if "tls 1.1" in text_lower or "tls1.1" in text_lower:
        found.add("TLS 1.1")
    if "tls 1.0" in text_lower or "tls1.0" in text_lower:
        found.add("TLS 1.0")

    return sorted(found, reverse=True)  # Ordem decrescente de versão


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
        return None  # Seção não encontrada — não declara nada
    # Inferência indireta — sinaliza presença com base em contexto correlato.
    if section_text.startswith(_INFERIDO_PREFIX):
        return True
    ctx = section_text.lower()
    # Padrões fortemente positivos: verificados apenas no fragmento extraído.
    # Buscar no documento inteiro gera falso positivo quando o arquivo contém
    # textos metodológicos/template, e não uma evidência declarada pelo leiloeiro.
    for pattern in _STRONG_POSITIVE:
        if re.search(pattern, ctx):
            return True
    for pattern in _NEGATIVE:
        if re.search(pattern, ctx):
            return False
    for pattern in _POSITIVE:
        if re.search(pattern, ctx):
            return True
    return None


def _extract_inference(section: str, text_lower: str, text_original: str) -> str | None:
    """
    Procura sinais indiretos de presença do item quando a seção explícita
    está vazia. Retorna texto descritivo prefixado com [INFERIDO] ou None.
    """
    candidates = _INFERENCE_KEYWORDS.get(section, [])
    for keyword, reason in candidates:
        start_search = 0
        while True:
            idx = text_lower.find(keyword, start_search)
            if idx < 0:
                break
            if _is_question_context(text_lower, idx, current_section=section):
                start_search = idx + 1
                continue
            ctx_start = max(0, idx - 60)
            ctx_end   = min(len(text_original), idx + 180)
            snippet   = _snap_to_word_boundary(text_original, ctx_start, ctx_end)
            snippet   = re.sub(r"\s+", " ", snippet).strip()
            return f"{_INFERIDO_PREFIX}{reason}. Trecho do documento: \"{snippet}\""
    return None


def _is_question_context(text_lower: str, idx: int, current_section: str | None = None) -> bool:
    """
    Detecta se a posição idx está dentro do TEMPLATE DA DEMANDA (lista de itens
    perguntados pelo TJ) em vez da resposta do leiloeiro.

    Heurística: o template é caracterizado pela CO-OCORRÊNCIA das 3 categorias
    de disponibilidade (redundância, backup, energia) numa janela próxima.
    Se 2+ categorias DIFERENTES da atual aparecem em ±200 chars, é template.
    Se só uma categoria aparece, é resposta legítima.
    """
    look_start = max(0, idx - 220)
    look_end   = min(len(text_lower), idx + 220)
    window = text_lower[look_start:look_end]

    other_sections = 0
    for section, kws in _DISP_CLUSTER_KEYWORDS.items():
        if section == current_section:
            continue
        if any(kw in window for kw in kws):
            other_sections += 1

    return other_sections >= 2


def _snap_to_word_boundary(text: str, start: int, end: int) -> str:
    """
    Recorta text[start:end] alinhando o início ao próximo espaço/início de
    sentença, evitando começar no meio de uma palavra.
    """
    # Se já está no início absoluto, mantém
    if start == 0:
        return text[start:end]
    # Se o caractere anterior já é um separador, mantém
    if text[start - 1] in " \n\t\r":
        return text[start:end]
    # Procura próximo espaço dentro de uma janela razoável (até 40 chars)
    look_until = min(end, start + 40)
    nxt_space = text.find(" ", start, look_until)
    if nxt_space != -1:
        return text[nxt_space + 1:end]
    return text[start:end]


def _extract_monitoring_url(section_text: str, text_original: str) -> str | None:
    # Busca URL de monitoramento na seção específica primeiro
    for source in [section_text, text_original]:
        for m in _RE_URL.finditer(source):
            url = m.group(0).rstrip(".,;)")
            # Filtra URLs que parecem ser de monitoramento ou health-check
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

    # Portas mencionadas diretamente por número em contexto web
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
