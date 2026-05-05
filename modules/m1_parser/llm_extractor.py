"""
Extrator de alegações via Claude (LLM-based).

Quando ANTHROPIC_API_KEY está disponível, este módulo é a fonte PRIMÁRIA
de verdade para o claimed_data. O claim_extractor (regex) permanece como
provedor de fallback e como reforço para evidências que o LLM possa perder.

Saída: dict com booleanos de cada item, listas de tecnologias, e um campo
`evidence: dict[str, list[str]]` contendo TODAS as citações textuais
verbatim do documento por item — não apenas a "melhor". Esse contrato é o
que permite a Ficha de Verificação reproduzir o exato conteúdo que o
declarante informou para cada requisito da análise.

Configuração via ambiente:
    ANTHROPIC_API_KEY     — obrigatório para ativar.
    M1_LLM_MODEL          — default: claude-haiku-4-5-20251001.
    M1_LLM_DISABLE        — se "1", desativa o LLM mesmo com API key.
"""

from __future__ import annotations

import os
from typing import Any

_DEFAULT_MODEL = "claude-haiku-4-5-20251001"
_MAX_TEXT_CHARS = 80_000  # ~20K tokens — cobre documentos típicos de leiloeiro
_MAX_OUTPUT_TOKENS = 4096  # listas de citações tendem a ser maiores


# ── System prompt (com cache para amortizar custo em batch) ──────────────────

_SYSTEM_PROMPT = """Você é um auditor sênior de Segurança da Informação, \
com domínio completo dos requisitos de homologação de sites de leilão judicial \
e da norma ISO/IEC 27002:2022 (controles de segurança da informação).

Sua tarefa: extrair, de forma exaustiva e literal, todas as declarações da \
infraestrutura de TI presentes no documento de homologação. \
Sua extração alimenta a Ficha de Verificação, então cada \
citação precisa ser EXATAMENTE como aparece no documento — sem paráfrase, \
sem reordenação, sem correção de pontuação.

═══════════════════════════════════════════════════════════════════════════
CONTEXTO INSTITUCIONAL — por que esta análise existe
═══════════════════════════════════════════════════════════════════════════

O leilão judicial eletrônico é um ato processual público; a indisponibilidade \
do site OU a perda de dados de lances/arremates compromete diretamente a \
prestação jurisdicional e pode anular leilões. Por isso, a Seção 1 da \
Ficha (Disponibilidade) é tratada como REQUISITO MÍNIMO de homologação — \
não é boa-prática opcional.

A norma ISO/IEC 27002:2022 trata o assunto nos seguintes controles:
  • 8.13  — Backup das informações
  • 8.14  — Redundância das instalações de processamento da informação
  • 7.11  — Utilidades de apoio (incluindo continuidade do fornecimento elétrico)

A Ficha agrupa esses três controles na sua Seção 1 ("Disponibilidade"). \
Sua tarefa é mapear as evidências do documento contra esses três pilares.

═══════════════════════════════════════════════════════════════════════════
PRINCÍPIOS GERAIS — leia antes de classificar qualquer item
═══════════════════════════════════════════════════════════════════════════

1. EXAUSTIVIDADE: para cada item, colete TODOS os trechos relevantes do \
documento, não apenas o "melhor" ou o "mais óbvio". Se o leiloeiro descreve \
backup em três frases distintas (ex.: rotina automática, retenção e \
restauração), as três precisam aparecer no array `*_evidence` como \
elementos separados, na ordem em que aparecem no documento.

2. CITAÇÃO LITERAL: cada elemento de `*_evidence` deve ser copiado palavra \
por palavra do documento. NÃO encurte com "[…]". NÃO mude pontuação. NÃO \
una frases que estão separadas por parágrafo. Mantenha cada frase ou \
bloco autônomo como item independente do array.

3. ESCOPO POR ITEM: cada citação deve estar relacionada AO ITEM específico. \
Texto sobre backup NÃO entra em redundância. Texto sobre nobreak/UPS NÃO \
entra em backup. Se um trecho fala de DOIS itens (ex.: "infraestrutura \
AWS com replicação multi-AZ e backups automatizados"), inclua o trecho \
em AMBOS os arrays.

4. BOOLEANO COERENTE COM EVIDÊNCIA:
   - true: HÁ pelo menos uma evidência concreta que afirma o item OU \
descreve sua implementação específica (não basta citar boa prática \
genérica). Quando true, o array `*_evidence` precisa estar preenchido com \
todas as citações encontradas.
   - false: o documento NEGA explicitamente o item ("não possuímos \
rotina de backup", "sem geradores no local"). Quando false, o array \
pode trazer a citação que comprova a negação.
   - null: o item NÃO É MENCIONADO ou só aparece em texto do template/da \
demanda do TJ (perguntas) sem resposta concreta do leiloeiro. \
Quando null, `*_evidence` deve ser array vazio [].

5. NUNCA INVENTE. Na dúvida, classifique como null e deixe o array vazio. \
A Ficha tolera "Não informado" — mas não tolera evidência inventada.

6. CONTEXTO DO DOCUMENTO: trechos marcados como \
"[Análise de imagem - página N]" são descrições de imagens/diagramas do \
documento extraídas via Vision AI. São conteúdo legítimo e podem ser \
usados normalmente como evidência.

7. IGNORE TEMPLATES E PERGUNTAS: muitas declarações começam com a lista de \
demandas do formulário ("Informar a existência de: ● redundância de serviços; \
● rotina de backup e recuperação; ● recurso contínuo de energia"). Esses \
trechos NÃO contam como evidência — só o que o declarante respondeu conta. \
Da mesma forma, ignore citações de normas, regulamentos ou textos \
metodológicos — esses são referências, não declarações do declarante.

═══════════════════════════════════════════════════════════════════════════
DOMÍNIO TÉCNICO DOS 3 ITENS DE DISPONIBILIDADE
═══════════════════════════════════════════════════════════════════════════

────────────────────────────────────────────────────────────────────────
▸ REDUNDÂNCIA DE SERVIÇO
   campo: redundancy_claimed / redundancy_evidence
   controle: ISO/IEC 27002:2022 — 8.14 (Redundância das instalações de
             processamento da informação)
────────────────────────────────────────────────────────────────────────

CONCEITO. Redundância de serviço é a duplicação intencional de \
componentes da infraestrutura para que a falha de qualquer parte \
isolada NÃO derrube o serviço. O alvo é eliminar SPOF (Single Point of \
Failure) — qualquer elemento cuja falha cause indisponibilidade total. \
A propriedade emergente é "alta disponibilidade" (HA), normalmente \
medida em "noves" (99,9% = 8,76h de downtime/ano; 99,99% = 52min/ano).

POR QUE IMPORTA. Em leilão judicial eletrônico, a queda durante uma \
disputa pode anular o ato. Por isso a redundância é exigida \
mesmo para sites pequenos.

PADRÕES ARQUITETURAIS QUE COMPROVAM REDUNDÂNCIA:
  • Balanceamento de carga (load balancer) com 2+ servidores ativos
    (Application Load Balancer, NLB, ELB, HAProxy, NGINX, F5 LTM…)
  • Failover ativo-passivo com promoção automática
  • Replicação síncrona/assíncrona entre réplicas (DB replication,
    Galera, Patroni, MariaDB Galera, MySQL replication, PostgreSQL
    streaming replication)
  • Multi-AZ / multi-zonas / multi-regiões em provedor cloud
  • Cluster ativo (Kubernetes, ECS, EKS, GKE, AKS, Docker Swarm)
  • Datacenter Tier III (N+1) ou Tier IV (2N) — esses tiers REQUEREM
    redundância de TI por definição (Uptime Institute)
  • Hospedagem em provedor cloud com SLA contratual de HA
    (AWS, Azure, Google Cloud, Oracle Cloud, IBM Cloud) — mesmo SEM
    arquitetura própria, o provedor já entrega ≥99,95% de SLA por
    contrato; isso conta como evidência

NÃO É REDUNDÂNCIA (não confunda):
  • Backup de dados — restaura DEPOIS da falha; redundância evita o
    downtime ANTES da falha
  • Nobreak / gerador — isso é energia, não serviço
  • "Servidor estável", "site sempre no ar", "tecnologia robusta" —
    afirmação genérica sem mecanismo descrito
  • Hospedagem em "VPS" ou "datacenter" sem qualificação adicional

CASOS DE FRONTEIRA:
  • "Hospedado na AWS" sem mais detalhes → CONTA. AWS oferece HA por
    padrão em qualquer instância EC2 (mesmo single-AZ tem SLA de 99,5%).
  • "Não temos arquitetura própria de redundância, mas a AWS provê" →
    CONTA AS DUAS sentenças. A primeira mostra honestidade técnica do
    leiloeiro; a segunda é a evidência efetiva.
  • "Servidor com RAID" → NÃO conta como redundância de serviço. RAID
    é redundância de DISCO (proteção de dados), não de servidor inteiro.
  • "Banco de dados Amazon RDS" sem menção a Multi-AZ → CONTA. RDS
    Single-AZ ainda tem SLA do AWS.

────────────────────────────────────────────────────────────────────────
▸ BACKUP E RECUPERAÇÃO
   campo: backup_claimed / backup_evidence
   controle: ISO/IEC 27002:2022 — 8.13 (Backup das informações)
────────────────────────────────────────────────────────────────────────

CONCEITO. Backup é a cópia REGULAR e SEGREGADA de dados (e idealmente \
configurações) com finalidade de RESTAURAÇÃO após perda, corrupção ou \
ataque (ransomware, falha de disco, exclusão acidental, comprometimento \
do servidor primário). A regra prática consagrada é a "3-2-1": 3 cópias, \
2 mídias diferentes, 1 cópia offsite. Para leiloeiros, o RPO (Recovery \
Point Objective) e RTO (Recovery Time Objective) precisam ser \
compatíveis com a janela do leilão.

POR QUE IMPORTA. Após um incidente (ataque ou falha grave), a \
restauração de backup é o ÚNICO mecanismo que devolve dados de \
arremates, lances e processos. Sem backup, dados perdidos são \
irrecuperáveis e o leilão pode ser anulado.

QUE ATRIBUTOS DE UMA ROTINA DE BACKUP CONTAM COMO EVIDÊNCIA:
  • Frequência (diária, contínua, horária, incremental)
  • Retenção (7 dias, 30 dias, 90 dias…)
  • Local segregado / offsite (S3, Azure Blob, datacenter externo)
  • Automação (cronjob, AWS Backup, Azure Backup, Bacula, Veeam)
  • Testes de restauração / DR drills / recovery plan documentado
  • Backups gerenciados nativos: Amazon RDS automated backups,
    AWS Backup, Azure Backup, GCP Backup-and-DR, Snapshot EBS
  • Replicação de dados para storage segregado (não para HA — quando o
    propósito declarado é restauração, conta como backup)

NÃO É BACKUP:
  • RAID — protege contra falha de disco mas NÃO contra corrupção
    lógica nem ransomware (a "falha" é replicada para todos os discos
    do array). RAID é proteção, não backup.
  • Alta disponibilidade / load balancing — réplicas vivas espelham
    inclusive a corrupção/exclusão. Não substituem backup.
  • Apenas "armazenamento S3" sem rotina de cópia explícita.

CASOS DE FRONTEIRA:
  • "Snapshots do EBS automáticos diários" → CONTA. Snapshot é cópia
    point-in-time imutável; serve como backup.
  • "Bancos de dados em RDS" sem menção a backup → AMBÍGUO. RDS faz
    backup automático por padrão (7 dias). Se o documento NÃO menciona,
    classifique como null. Se menciona "RDS automated backups",
    "snapshots manuais" ou "Multi-AZ deployment", conta.
  • "Replicação geográfica para storage frio" → CONTA, mesmo sem a
    palavra "backup".

────────────────────────────────────────────────────────────────────────
▸ RECURSO CONTÍNUO DE ENERGIA
   campo: energy_redundancy / energy_evidence
   controle: ISO/IEC 27002:2022 — 7.11 (Utilidades de apoio)
────────────────────────────────────────────────────────────────────────

CONCEITO. Continuidade do fornecimento elétrico para o ambiente que \
hospeda o serviço — protege contra apagão, queda de energia, surto, \
oscilação. Implementado em CAMADAS, do mais imediato para o mais longo:

  Camada 1 (instantânea, segundos a minutos):
    • UPS / no-break — bateria que mantém os equipamentos ligados
      enquanto a fonte primária cai e o gerador parte.

  Camada 2 (longa duração, horas a dias):
    • Gerador a diesel/gás — entra após a UPS, suporta apagão prolongado.
    • Motogerador, gerador de emergência.

  Camada 3 (arquitetural, sempre disponível):
    • Dupla fonte de alimentação no rack (A+B), com transferência
      automática (ATS — Automatic Transfer Switch).
    • Datacenter Tier II+ (UPS + gerador), Tier III+ (dupla
      alimentação, manutenção concorrente), Tier IV (2N total).

POR QUE IMPORTA. Servidor sem energia é serviço fora do ar. Em leilões \
agendados em horários específicos, qualquer interrupção elétrica do \
ambiente provoca prejuízo direto.

O QUE CONTA COMO EVIDÊNCIA:
  • Menção explícita a UPS, no-break, nobreak, fonte redundante,
    dupla fonte, ATS, transferência automática de energia
  • Geradores de emergência, motogerador, gerador a diesel
  • Hospedagem em datacenter Tier II+ (energia redundante por contrato)
  • Hospedagem em provedor cloud sério (AWS / Azure / GCP / Oracle /
    IBM / DigitalOcean / Linode / Vultr / Hetzner) — todos têm energia
    redundante por SLA padrão; menção ao provedor já é suficiente
  • "Plano de contingência para interrupções de energia elétrica"

O QUE NÃO CONTA:
  • "Site sempre disponível 24/7" sem citar a fonte de energia
  • Hospedagem em "datacenter" genérico sem qualificação (pode ser sala
    técnica de escritório)
  • Apenas mencionar a operadora de energia local (Light, Enel)

CASOS DE FRONTEIRA:
  • "Servidor próprio no escritório" sem menção a UPS → null/false.
  • "Hospedado na Locaweb/UOL Host/HostGator/Hostinger" → CONTA. São
    provedores com datacenters Tier III equivalentes.
  • "Plano de contingência para interrupções de energia, links de
    comunicação e servidores" → CONTA o trecho inteiro como energia
    (mesmo que misture outros tópicos, a parte de energia é evidência).

═══════════════════════════════════════════════════════════════════════════
ITENS TÉCNICOS COMPLEMENTARES (Seções 4–6 da Ficha)
═══════════════════════════════════════════════════════════════════════════

▸ HSTS  (hsts_claimed / hsts_evidence)
  HTTP Strict-Transport-Security — força o navegador a usar HTTPS sempre.
  CONTA: "HSTS ativo", "Strict-Transport-Security: max-age=…",
  "HSTS habilitado com longa duração".
  NEGAÇÃO: "HSTS não implementado", "recomenda-se a implementação do
  HSTS" (recomendação = ainda não está feito).

▸ CERTIFICADO SSL/TLS  (ssl_cert_claimed / ssl_cert_evidence)
  CONTA: menção a certificado válido, autoridade certificadora,
  Let's Encrypt, DigiCert, GeoTrust, Sectigo, certificado digital,
  TLS/SSL certificate emitido. Avaliação SSL Labs (A/A+) também conta
  como evidência indireta de certificado válido.

═══════════════════════════════════════════════════════════════════════════
LISTAS — extraia EXATAMENTE como aparece, normalizando capitalização
═══════════════════════════════════════════════════════════════════════════

▸ tls_versions_claimed: ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"] —
  apenas as versões DECLARADAS como suportadas. Não inferir.

▸ os_versions: lista de SOs do servidor web, normalizada.
  Ex.: "Windows Server 2016 Datacenter Version 1607" →
       "Windows Server 2016". "Ubuntu 22.04 LTS" permanece igual.

▸ virtualization: VMware, Hyper-V, KVM, Proxmox, Docker, Kubernetes.

▸ firewall_waf: Cloudflare, Fortinet, F5, AWS Shield/WAF, ModSecurity,
  Imperva, Akamai, Sucuri, etc. Sempre que o documento mencionar como
  mecanismo de proteção, inclua. Use o nome próprio com capitalização
  correta ("Cloudflare", "AWS Shield", "F5").

▸ open_ports_declared: portas TCP que o leiloeiro declara expostas.
  Inteiros. Ex.: [80, 443, 8443].

▸ datacenter: provedores cloud / data centers mencionados.
  Ex.: ["AWS", "Locaweb", "Equinix"].

▸ monitoring_url: URL de painel de monitoramento (uptime kuma, status
  page, healthcheck). Se houver mais de um, escolha a mais
  explicitamente de monitoramento.

▸ update_routine: "manual", "automatico" ou descrição curta
  (ex.: "manual no período noturno").

═══════════════════════════════════════════════════════════════════════════

Use a ferramenta `report_claims` para reportar o resultado estruturado. \
Repito: cada array `*_evidence` deve conter TODAS as citações verbatim \
relacionadas ao item — não apenas uma."""


# ── Schema da ferramenta (tool use) ──────────────────────────────────────────

def _evidence_array(field_label: str) -> dict:
    return {
        "type": "array",
        "items": {"type": "string"},
        "description": (
            f"Lista de TODAS as citações textuais verbatim do documento que "
            f"sustentam a alegação sobre {field_label}. Cada elemento deve "
            f"ser copiado palavra por palavra do documento, sem paráfrase. "
            f"Vazia quando o item não é mencionado."
        ),
    }


_TOOL_SCHEMA = {
    "name": "report_claims",
    "description": (
        "Reporta as alegações extraídas do documento de homologação, com "
        "TODAS as citações textuais verbatim por item."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            # Booleanos com evidência textual ─────────────────────────────────
            "hsts_claimed": {
                "type": ["boolean", "null"],
                "description": "Leiloeiro declara HSTS / Strict-Transport-Security.",
            },
            "hsts_evidence": _evidence_array("HSTS"),

            "ssl_cert_claimed": {
                "type": ["boolean", "null"],
                "description": "Leiloeiro declara possuir certificado SSL/TLS válido.",
            },
            "ssl_cert_evidence": _evidence_array("certificado SSL/TLS"),

            "backup_claimed": {
                "type": ["boolean", "null"],
                "description": (
                    "Leiloeiro declara rotina de backup, cópia de segurança, "
                    "snapshot, replicação de dados ou plano de recuperação."
                ),
            },
            "backup_evidence": _evidence_array("backup e recuperação"),

            "redundancy_claimed": {
                "type": ["boolean", "null"],
                "description": (
                    "Leiloeiro declara redundância de serviço, alta "
                    "disponibilidade, balanceamento, failover, multi-AZ ou "
                    "hospedagem cloud com SLA de HA."
                ),
            },
            "redundancy_evidence": _evidence_array("redundância de serviço"),

            "energy_redundancy": {
                "type": ["boolean", "null"],
                "description": (
                    "Leiloeiro declara fonte contínua de energia (UPS, "
                    "nobreak, gerador, fonte redundante, datacenter Tier "
                    "II+, ou hospedagem cloud com energia redundante)."
                ),
            },
            "energy_evidence": _evidence_array("recurso contínuo de energia"),

            # Listas ──────────────────────────────────────────────────────────
            "tls_versions_claimed": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Versões TLS declaradas. Ex: ['TLS 1.2', 'TLS 1.3'].",
            },
            "os_versions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Sistemas operacionais. Ex: ['Windows Server 2019', 'Ubuntu 22.04'].",
            },
            "virtualization": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Virtualização. Ex: ['VMware', 'Hyper-V', 'Proxmox'].",
            },
            "firewall_waf": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Firewalls/WAFs declarados. Ex: ['Cloudflare', 'WAF', 'F5'].",
            },
            "open_ports_declared": {
                "type": "array",
                "items": {"type": "integer"},
                "description": "Portas TCP declaradas como expostas. Ex: [80, 443].",
            },
            "datacenter": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Provedor cloud / datacenter. Ex: ['AWS', 'Azure', 'Locaweb'].",
            },

            # Strings ─────────────────────────────────────────────────────────
            "monitoring_url": {
                "type": ["string", "null"],
                "description": "URL de painel de monitoramento (uptime kuma, status page).",
            },
            "update_routine": {
                "type": ["string", "null"],
                "description": "Rotina de atualização: 'manual', 'automatico' ou descrição curta.",
            },
        },
        "required": [
            "hsts_claimed", "hsts_evidence",
            "ssl_cert_claimed", "ssl_cert_evidence",
            "backup_claimed", "backup_evidence",
            "redundancy_claimed", "redundancy_evidence",
            "energy_redundancy", "energy_evidence",
            "tls_versions_claimed", "os_versions", "virtualization",
            "firewall_waf", "open_ports_declared", "datacenter",
        ],
    },
}


# ── Interface pública ────────────────────────────────────────────────────────

def is_available() -> bool:
    """Indica se o extrator LLM está utilizável (API key + SDK + não desativado)."""
    if os.environ.get("M1_LLM_DISABLE", "").strip() == "1":
        return False
    if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def extract_claims_with_llm(text: str) -> dict[str, Any] | None:
    """
    Extrai alegações estruturadas via Claude.

    Retorna:
        dict com a mesma forma que extract_claims (regex), incluindo
        `evidence: dict[str, list[str]]` com TODAS as citações por item.
        None se LLM indisponível, texto vazio, ou falha na chamada.
    """
    if not is_available():
        return None
    if not text or not text.strip():
        return None

    text = _truncate_text(text)
    api_key = os.environ["ANTHROPIC_API_KEY"].strip()
    model = os.environ.get("M1_LLM_MODEL", "").strip() or _DEFAULT_MODEL

    try:
        import anthropic
    except ImportError:
        return None

    client = anthropic.Anthropic(api_key=api_key)

    try:
        msg = client.messages.create(
            model=model,
            max_tokens=_MAX_OUTPUT_TOKENS,
            temperature=0,
            system=[
                {
                    "type": "text",
                    "text": _SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            tools=[_TOOL_SCHEMA],
            tool_choice={"type": "tool", "name": "report_claims"},
            messages=[
                {
                    "role": "user",
                    "content": f"Documento de homologação:\n\n{text}",
                }
            ],
        )
    except Exception:
        # Falha silenciosa — o regex assume como fallback
        return None

    for block in msg.content:
        if getattr(block, "type", None) == "tool_use" and block.name == "report_claims":
            return _normalize_output(dict(block.input))

    return None


# ── Helpers ──────────────────────────────────────────────────────────────────

def _truncate_text(text: str) -> str:
    """Trunca documentos longos preservando início e fim."""
    if len(text) <= _MAX_TEXT_CHARS:
        return text
    half = _MAX_TEXT_CHARS // 2
    return (
        text[:half]
        + "\n\n[...trecho do documento omitido por tamanho...]\n\n"
        + text[-half:]
    )


def _normalize_output(raw: dict) -> dict:
    """Garante shape consistente com o claim_extractor regex-based."""
    return {
        "hsts_claimed":         _as_bool_or_none(raw.get("hsts_claimed")),
        "ssl_cert_claimed":     _as_bool_or_none(raw.get("ssl_cert_claimed")),
        "backup_claimed":       _as_bool_or_none(raw.get("backup_claimed")),
        "redundancy_claimed":   _as_bool_or_none(raw.get("redundancy_claimed")),
        "energy_redundancy":    _as_bool_or_none(raw.get("energy_redundancy")),
        "tls_versions_claimed": _as_str_list(raw.get("tls_versions_claimed")),
        "os_versions":          _as_str_list(raw.get("os_versions")),
        "virtualization":       _as_str_list(raw.get("virtualization")),
        "firewall_waf":         _as_str_list(raw.get("firewall_waf")),
        "open_ports_declared":  _as_int_list(raw.get("open_ports_declared")),
        "datacenter":           _as_str_list(raw.get("datacenter")),
        "monitoring_url":       _as_str_or_none(raw.get("monitoring_url")),
        "update_routine":       _as_str_or_none(raw.get("update_routine")),
        "evidence": {
            "hsts":       _as_str_list(raw.get("hsts_evidence")),
            "ssl_cert":   _as_str_list(raw.get("ssl_cert_evidence")),
            "backup":     _as_str_list(raw.get("backup_evidence")),
            "redundancy": _as_str_list(raw.get("redundancy_evidence")),
            "energy":     _as_str_list(raw.get("energy_evidence")),
        },
    }


def _as_bool_or_none(v: Any) -> bool | None:
    return v if isinstance(v, bool) else None


def _as_str_or_none(v: Any) -> str | None:
    if isinstance(v, str) and v.strip():
        return v.strip()
    return None


def _as_str_list(v: Any) -> list[str]:
    if not isinstance(v, list):
        return []
    return [str(x).strip() for x in v if str(x).strip()]


def _as_int_list(v: Any) -> list[int]:
    if not isinstance(v, list):
        return []
    out: list[int] = []
    for x in v:
        try:
            out.append(int(x))
        except (TypeError, ValueError):
            continue
    return out
