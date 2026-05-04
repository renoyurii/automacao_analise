"""
Extração de conteúdo de páginas com imagens via Claude Vision API.

Quando um PDF tem páginas sem texto (diagramas de arquitetura, fluxos de
backup, capturas de tela de painel), este módulo converte essas páginas em
imagens e envia ao Claude para descrever a infraestrutura representada.

Requisitos:
    pip install anthropic pillow
    Variável de ambiente ANTHROPIC_API_KEY deve estar definida.

Uso interno — chamado pelo pdf_reader quando image_page_count > 0.
"""

from __future__ import annotations

import base64
import io
import os
from typing import Any

_PROMPT = """Você está analisando uma imagem de um documento técnico de segurança de TI de um leiloeiro judicial.

Descreva em português o que a imagem representa em termos de infraestrutura de TI, focando especificamente em:

1. **Backup e Cópia de Segurança**: Há indicação de backup periódico, cópia de segurança, rotinas de backup, armazenamento externo, nuvem de backup?
2. **Redundância e Alta Disponibilidade**: Há balanceamento de carga, failover, replicação, múltiplos servidores, clustering, CDN, Cloudflare ou serviços equivalentes com SLA de uptime?
3. **Energia Redundante**: Há nobreak, UPS, gerador, fonte redundante de energia, datacenter com energia ininterrupta?
4. **Arquitetura de Nuvem**: Há uso de cloud (AWS, Azure, GCP, Cloudflare), infraestrutura distribuída, múltiplos datacenters?

Se a imagem não contiver informações técnicas relevantes (logotipos, fotos sem conteúdo técnico, texto decorativo), diga apenas "Imagem sem conteúdo técnico relevante."

Responda de forma objetiva e técnica, citando o que está visível na imagem."""


def extract_text_from_image_pages(
    pdf_path: str,
    image_page_indices: list[int],
) -> str:
    """
    Converte páginas de PDF (por índice 0-based) em imagens e usa Claude
    Vision para extrair descrições de infraestrutura.

    Retorna string com as descrições concatenadas, prontas para serem
    adicionadas ao texto do documento antes da extração de alegações.

    Retorna string vazia se:
    - ANTHROPIC_API_KEY não estiver configurado
    - nenhuma página for processável
    - qualquer erro silencioso
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return ""

    try:
        import pdfplumber
    except ImportError:
        return ""

    try:
        import anthropic as _anthropic
    except ImportError:
        return ""

    client = _anthropic.Anthropic(api_key=api_key)
    descriptions: list[str] = []

    try:
        with pdfplumber.open(pdf_path) as pdf:
            for idx in image_page_indices:
                if idx >= len(pdf.pages):
                    continue
                page = pdf.pages[idx]
                try:
                    img = page.to_image(resolution=150).original
                    buf = io.BytesIO()
                    img.save(buf, format="PNG")
                    img_b64 = base64.standard_b64encode(buf.getvalue()).decode()
                except Exception:
                    continue

                try:
                    _vision_model = os.environ.get("M1_LLM_MODEL", "").strip() or "claude-haiku-4-5-20251001"
                    msg = client.messages.create(
                        model=_vision_model,
                        max_tokens=600,
                        messages=[
                            {
                                "role": "user",
                                "content": [
                                    {
                                        "type": "image",
                                        "source": {
                                            "type": "base64",
                                            "media_type": "image/png",
                                            "data": img_b64,
                                        },
                                    },
                                    {"type": "text", "text": _PROMPT},
                                ],
                            }
                        ],
                    )
                    text = msg.content[0].text.strip()
                    if text and "sem conteúdo técnico" not in text.lower():
                        descriptions.append(
                            f"[Análise de imagem — página {idx + 1}]\n{text}"
                        )
                except Exception:
                    continue
    except Exception:
        return ""

    return "\n\n".join(descriptions)
