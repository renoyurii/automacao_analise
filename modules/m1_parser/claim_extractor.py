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


# ── Interface pública ────────────────────────────────────────────────────────

def extract_claims(document_data: dict[str, Any]) -> dict[str, Any]:
    """
    Recebe o dict de read_pdf() ou read_docx() e retorna claimed_data.
    """
    text = document_data.get("text", "")
    text_lower = text.lower()
    image_page_count = document_data.get("image_page_count", 0) or 0

    raw_sections = _extract_raw_sections(text_lower, text)

    # Inferência indireta — para cada seção sem match direto, busca sinais
    # contextuais (provedor de hospedagem, datacenter, recursos cloud) que
    # implicam o atendimento do item.
    for section_key in _INFERENCE_KEYWORDS:
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
    # Padrões fortemente positivos: verificados tanto nos fragmentos extraídos
    # quanto no documento inteiro. Isso evita falsos negativos quando o extrator
    # captura seções introdutórias/cabeçalhos e não chega ao conteúdo real
    # (ex: política de backup cujas regras de rotina estão na seção 7, não no OBJETIVO).
    for pattern in _STRONG_POSITIVE:
        if re.search(pattern, ctx) or re.search(pattern, text_lower):
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
