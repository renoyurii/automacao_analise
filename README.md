# Automação da Análise de Segurança — Homologação de Sites

Pipeline automatizado para conferência de segurança da informação de sites, conforme requisitos de homologação institucional. Recebe a declaração documental (PDF/DOCX) e a URL pública do site, executa varredura ativa, cruza com regras de conformidade e gera a Ficha de Verificação em `.docx` e `.pdf`.

## Pipeline

```
Declaração (PDF/DOCX) + URL
              │
              ▼
   ┌──────────────────────────┐
   │  M1 — Parser             │   Vision AI + LLM (tool use) + regex fallback
   │  Extrai claimed_data     │
   └──────────────────────────┘
              │
              ▼
   ┌──────────────────────────┐
   │  M2 — Scanner            │   Headers · Wappalyzer · SSL Labs
   │  Varredura ativa         │   Shodan · WHOIS · Portas
   └──────────────────────────┘
              │
              ▼
   ┌──────────────────────────┐
   │  M3 — Engine             │   Cruza claimed × scan
   │  Decisão de conformidade │   EOL (informativo) · regras OWASP
   └──────────────────────────┘
              │
              ▼
   ┌──────────────────────────┐
   │  M4 — Reporter           │   Gera Ficha em .docx + .pdf nativo
   │  Ficha de Verificação    │
   └──────────────────────────┘
```

## Funcionalidades por módulo

### M1 — Parser de documentos
Extração estruturada de declarações a partir de arquivos PDF/DOCX. Arquitetura híbrida em camadas:

| Camada | Quando roda | O que faz |
|---|---|---|
| `pdf_reader` / `docx_reader` | Sempre | Texto bruto + detecção de páginas-imagem |
| `vision_extractor` | `ANTHROPIC_API_KEY` + páginas sem texto | Descreve diagramas/fluxos via Claude Vision |
| `claim_extractor` (regex) | Sempre | Baseline + `raw_sections` para evidências no M4 |
| `llm_extractor` (Tool Use) | `ANTHROPIC_API_KEY` configurada | **Fonte primária** de verdade — Schema fixo + citação textual por item |

Output (`claimed_data`): booleanos auditáveis (`backup_claimed`, `redundancy_claimed`, …), listas de tecnologias declaradas, e — quando o LLM rodou — `llm_evidence` com a citação exata do documento usada para cada decisão.

### M2 — Scanner de varredura ativa
- **Headers HTTP** — IP, CDN/WAF (Cloudflare, Akamai, Fastly, AWS CloudFront…), redirect chain
- **Wappalyzer scan** — 40+ assinaturas (CMS, frameworks, JS bundles, CDNs, payment, analytics) via HTML/headers/cookies
- **SSL Labs** (Qualys) — grade, protocolos TLS/SSL, HSTS, cifras, SNI
- **Shodan** (opcional, requer `SHODAN_API_KEY`) — portas abertas
- **WHOIS** — proprietário, expiração de domínio
- **Port scan** — fallback nativo quando Shodan indisponível

### M3 — Engine de decisão
Cruza o `claimed_data` (M1) com `scan_data` (M2) e produz status por item:

| Status | Significado |
|---|---|
| `CONFORME` | Verificado e dentro do esperado |
| `NÃO CONFORME` | Verificado e fora do esperado (com severidade: `CRITICO`/`ALTO`/`MEDIO`/`BAIXO`) |
| `NÃO VERIFICÁVEL` | Não é possível confirmar via scan externo |
| `ATENÇÃO` | Tecnicamente conforme, mas com ressalva (ex: tecnologia EOL informativa) |

Regra de ouro: varredura ativa tem **prioridade absoluta** quando consegue verificar. Nunca marca `NÃO CONFORME` por falta de evidência.

### M4 — Reporter
- **DOCX** (`ficha_builder.py`) — segue o modelo institucional
- **PDF** (`pdf_builder.py`) — gerado nativamente via `fpdf2`, sem dependência de LibreOffice/Word, com paginação correta via API `table()`

## Requisitos

- Python 3.8+
- Dependências em `requirements.txt`: `pdfplumber`, `pypdf`, `python-docx`, `anthropic`, `pillow`, `requests`, `beautifulsoup4`, `shodan`, `python-whois`, `builtwith`, `streamlit`, `pandas`, `python-dotenv`, `tqdm`, `colorama`, `fpdf2`

## Instalação

```bash
git clone <repo-url>
cd automacao_analise
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edite .env com suas chaves
```

### Configuração de chaves

| Variável | Status | Função |
|---|---|---|
| `ANTHROPIC_API_KEY` | **Recomendado** | Ativa Vision AI + LLM extractor (extração robusta) |
| `SHODAN_API_KEY` | Opcional | Ativa scan de portas via Shodan (fallback: scan TCP nativo) |
| `M1_LLM_MODEL` | Opcional | Default `claude-haiku-4-5-20251001`. Use Sonnet para mais precisão |
| `M1_LLM_DISABLE` | Opcional | `=1` força fallback regex mesmo com a key configurada |

> **Custo estimado com Claude Haiku 4.5**: ~$0.002 por análise completa (Vision + LLM com prompt cache).

## Uso

**Interface web** (Streamlit):
```bash
streamlit run app_ui.py
```
Suba a URL do site e o(s) PDF(s) da declaração. A análise leva ~3 minutos (gargalo: SSL Labs). Saída na própria página: Ficha em `.docx` e `.pdf`, tabelas de verificações e tecnologias, dados brutos.

**Linha de comando**:
```bash
python3 main.py --url https://www.exemplo.com.br --doc caminho/para/declaracao.pdf
```

## Estrutura

```
automacao_analise/
├── modules/
│   ├── m1_parser/              # Extração de declaração
│   │   ├── pdf_reader.py
│   │   ├── docx_reader.py
│   │   ├── vision_extractor.py # Claude Vision (imagens)
│   │   ├── claim_extractor.py  # Regex (baseline)
│   │   └── llm_extractor.py    # Claude Tool Use (autoritativo)
│   ├── m2_scanner/             # Varredura ativa
│   │   ├── headers_scan.py
│   │   ├── wappalyzer_scan.py
│   │   ├── ssl_labs.py
│   │   ├── shodan_scan.py
│   │   ├── whois_lookup.py
│   │   └── port_scan.py
│   ├── m3_engine/              # Decisão de conformidade
│   │   ├── comparator.py
│   │   └── eol_checker.py
│   └── m4_reporter/            # Geração de relatório
│       ├── ficha_builder.py    # DOCX
│       └── pdf_builder.py      # PDF nativo
├── docs/referencia/            # Documentos de referência (gitignored)
├── output/                     # Fichas geradas
├── tests/                      # Testes automatizados
├── app_ui.py                   # Interface Streamlit
├── main.py                     # CLI
├── config.py                   # Configurações compartilhadas
├── requirements.txt
└── .env.example
```

## Testes

```bash
python3 -m pytest tests/
```

## Licença

Uso interno.
