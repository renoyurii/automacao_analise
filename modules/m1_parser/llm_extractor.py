"""
Extrator de alegações via Claude (LLM-based).

Quando ANTHROPIC_API_KEY está disponível, este módulo é a fonte PRIMÁRIA
de verdade para o claimed_data. O claim_extractor (regex) permanece como
fallback e como provedor de raw_sections para evidências no M4.

Por que LLM em vez de regex puro?
- Leiloeiros usam frases livres, não padrões fixos. Regex é frágil.
- Documentos misturam texto e imagens (diagramas) — o vision_extractor
  descreve as imagens em texto antes do LLM ver, então tudo fica unificado.
- Homologação precisa de DECISÃO + EVIDÊNCIA. Tool use garante JSON válido
  com schema fixo e citação textual para cada item declarado.

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


# ── System prompt (com cache para amortizar custo em batch) ──────────────────

_SYSTEM_PROMPT = """Você é um analista de segurança da informação do TJRJ \
revisando documentos de homologação de leiloeiros judiciais.

Sua tarefa: extrair declarações estruturadas sobre a infraestrutura de TI \
do leiloeiro a partir do texto do documento. Seu output será usado para \
gerar uma ficha oficial de conformidade.

REGRAS:

1. CAMPOS BOOLEANOS:
   - true: o documento AFIRMA o item OU o descreve concretamente.
     "realizamos backup diário" → backup_claimed=true.
     "garantimos a continuidade dos dados via cópias agendadas" → \
backup_claimed=true (descrição concreta).
     "Cloudflare Pro" no contexto de proteção → firewall_waf inclui Cloudflare.
   - false: o documento NEGA o item explicitamente.
     "não possuímos rotina de backup" → backup_claimed=false.
   - null: o documento NÃO MENCIONA ou apenas cita boas práticas genéricas \
sem afirmar implementação concreta.

2. CAMPOS DE LISTA: inclua apenas itens explicitamente mencionados, \
normalizados.
   "Windows Server 2019 Standard Edition" → "Windows Server 2019".
   Portas mencionadas em texto livre ou tabelas → inteiros.

3. CONSIDERE O CONTEXTO COMPLETO:
   - "Hospedado na AWS com múltiplas regiões" → redundancy_claimed=true \
(alta disponibilidade implícita), datacenter inclui "AWS".
   - "Datacenter Tier III certificado" → energy_redundancy=true \
(Tier III implica redundância energética por definição).
   - "Servidor com nobreak e gerador" → energy_redundancy=true.
   - Trechos marcados como "[Análise de imagem - página N]" são \
descrições de imagens do documento — trate como conteúdo legítimo.

4. EVIDÊNCIA: para cada campo booleano definido como true ou false, \
forneça uma citação textual direta do documento (até 250 caracteres). \
Quando o campo for null, deixe a evidência vazia. Use a citação do \
trecho mais decisivo.

5. NÃO INVENTE: na dúvida, prefira null. É melhor classificar como \
não-mencionado do que afirmar algo que o documento não diz.

Use a ferramenta `report_claims` para reportar o resultado estruturado."""


# ── Schema da ferramenta (tool use) ──────────────────────────────────────────

_TOOL_SCHEMA = {
    "name": "report_claims",
    "description": "Reporta as alegações extraídas do documento de homologação.",
    "input_schema": {
        "type": "object",
        "properties": {
            # Booleanos com evidência textual ─────────────────────────────────
            "hsts_claimed": {
                "type": ["boolean", "null"],
                "description": "Leiloeiro declara HSTS / Strict-Transport-Security.",
            },
            "hsts_evidence": {"type": "string"},

            "ssl_cert_claimed": {
                "type": ["boolean", "null"],
                "description": "Leiloeiro declara possuir certificado SSL/TLS válido.",
            },
            "ssl_cert_evidence": {"type": "string"},

            "backup_claimed": {
                "type": ["boolean", "null"],
                "description": (
                    "Leiloeiro declara rotina de backup, cópia de segurança, "
                    "snapshot, replicação de dados ou plano de recuperação."
                ),
            },
            "backup_evidence": {"type": "string"},

            "redundancy_claimed": {
                "type": ["boolean", "null"],
                "description": (
                    "Leiloeiro declara redundância de serviço, alta disponibilidade, "
                    "balanceamento de carga, failover, múltiplas regiões/zonas, "
                    "ou hospedagem em CDN com proteção (Cloudflare etc)."
                ),
            },
            "redundancy_evidence": {"type": "string"},

            "energy_redundancy": {
                "type": ["boolean", "null"],
                "description": (
                    "Leiloeiro declara fonte contínua de energia (UPS, nobreak, "
                    "gerador, fonte redundante) OU hospedagem em datacenter "
                    "Tier II+ que implica redundância energética."
                ),
            },
            "energy_evidence": {"type": "string"},

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
            "hsts_claimed", "ssl_cert_claimed", "backup_claimed",
            "redundancy_claimed", "energy_redundancy",
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
        dict com a mesma forma que extract_claims (regex), incluindo o campo
        adicional `llm_evidence` (citações por item booleano).
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
            max_tokens=2048,
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
        "llm_evidence": {
            "hsts":       (raw.get("hsts_evidence")       or "").strip(),
            "ssl_cert":   (raw.get("ssl_cert_evidence")   or "").strip(),
            "backup":     (raw.get("backup_evidence")     or "").strip(),
            "redundancy": (raw.get("redundancy_evidence") or "").strip(),
            "energy":     (raw.get("energy_evidence")     or "").strip(),
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
