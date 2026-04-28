"""
Consulta WHOIS de domínios.

Para domínios .com.br: consulta socket direta ao whois.registro.br (porta 43).
O formato de saída do Registro.br é estável e parseável com regex simples.
Isso replica exatamente o bloco "INFORMAÇÕES DE REDE" da Ficha de Verificação.

Para outros TLDs: usa python-whois como fallback.
"""

from __future__ import annotations

import re
import socket
from typing import Any


_REGISTRO_BR_HOST = "whois.registro.br"
_WHOIS_PORT = 43
_TIMEOUT = 15
_ENCODING = "latin-1"   # Registro.br usa latin-1, não UTF-8


def scan_whois(domain: str) -> dict[str, Any]:
    """
    Retorna:
    {
        "domain":       str,
        "owner":        str | None,
        "owner_c":      str | None,     # Código do contato responsável
        "tech_c":       str | None,
        "nameservers":  list[str],
        "created":      str | None,     # Formato AAAAMMDD
        "changed":      str | None,
        "expires":      str | None,
        "status":       str | None,
        "raw":          str,            # Texto bruto para bloco da Ficha
        "error":        str | None,
    }
    """
    clean = _clean_domain(domain)

    if clean.endswith(".br"):
        return _whois_registro_br(clean)
    else:
        return _whois_generic(clean)


# ── Registro.br (.com.br, .org.br, .net.br, etc.) ────────────────────────────

def _whois_registro_br(domain: str) -> dict[str, Any]:
    try:
        raw = _query_socket(_REGISTRO_BR_HOST, domain)
    except Exception as e:
        return _error_result(domain, str(e))

    parsed = _parse_registro_br(raw)
    parsed["raw"] = raw
    parsed["error"] = None
    return parsed


def _query_socket(host: str, query: str) -> str:
    with socket.create_connection((host, _WHOIS_PORT), timeout=_TIMEOUT) as sock:
        sock.sendall(f"{query}\r\n".encode(_ENCODING))
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode(_ENCODING, errors="replace")


def _parse_registro_br(raw: str) -> dict[str, Any]:
    """
    Parseia o formato de texto do Registro.br.
    Exemplo de campo: "owner:      JORGE LUIZ DE CAMPOS"
    """
    def _field(key: str) -> str | None:
        m = re.search(rf"^{re.escape(key)}:\s*(.+)$", raw, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else None

    # Nameservers podem aparecer múltiplas vezes
    ns_matches = re.findall(r"^nserver:\s*(.+)$", raw, re.MULTILINE | re.IGNORECASE)
    nameservers = [ns.strip() for ns in ns_matches]

    # "created" no Registro.br vem com sufixo numérico: "20210929 #23488767"
    created_raw = _field("created")
    created = created_raw.split()[0] if created_raw else None

    return {
        "domain":      _field("domain"),
        "owner":       _field("owner"),
        "owner_c":     _field("owner-c"),
        "tech_c":      _field("tech-c"),
        "nameservers": nameservers,
        "created":     created,
        "changed":     _field("changed"),
        "expires":     _field("expires"),
        "status":      _field("status"),
    }


# ── Domínios genéricos (.com, .net, .org, etc.) ───────────────────────────────

def _whois_generic(domain: str) -> dict[str, Any]:
    try:
        import whois
        w = whois.whois(domain)
        ns = w.name_servers or []
        if isinstance(ns, str):
            ns = [ns]

        created = _normalize_date(w.creation_date)
        expires = _normalize_date(w.expiration_date)

        return {
            "domain":      domain,
            "owner":       w.get("registrant_name") or w.get("org"),
            "owner_c":     None,
            "tech_c":      None,
            "nameservers": [n.lower() for n in ns],
            "created":     created,
            "changed":     None,
            "expires":     expires,
            "status":      str(w.status[0]) if w.status else None,
            "raw":         str(w),
            "error":       None,
        }
    except Exception as e:
        return _error_result(domain, str(e))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _clean_domain(domain: str) -> str:
    """Remove protocolo e path, mantém apenas o domínio puro."""
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].split(":")[0]
    # Remove "www." para consulta WHOIS (Registro.br não aceita www.)
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.lower().strip()


def _normalize_date(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0]
    try:
        return value.strftime("%Y%m%d")
    except AttributeError:
        return str(value)


def _error_result(domain: str, error: str) -> dict[str, Any]:
    return {
        "domain":      domain,
        "owner":       None,
        "owner_c":     None,
        "tech_c":      None,
        "nameservers": [],
        "created":     None,
        "changed":     None,
        "expires":     None,
        "status":      None,
        "raw":         "",
        "error":       error,
    }
