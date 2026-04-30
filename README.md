# Automação de Análise

Sistema automatizado para análise de documentos e segurança com geração de relatórios estruturados.

## 🎯 Funcionalidades

- **M1 - Parser**: Extração híbrida de dados de documentos (PDF, DOCX) — regex baseline + Claude LLM (tool use) quando `ANTHROPIC_API_KEY` está configurada. Inclui Vision AI para páginas-imagem.
- **M2 - Scanner**: Análise de segurança (Shodan, SSL Labs, Whois, Wappalyzer, Headers)
- **M3 - Engine**: Comparação de dados e verificação de EOL
- **M4 - Reporter**: Geração de relatórios e fichas estruturadas

## 📋 Requisitos

- Python 3.8+
- Dependências listadas em `requirements.txt`

## 🚀 Instalação

1. Clone o repositório:
```bash
git clone https://github.com/seu-usuario/automacao_analise.git
cd automacao_analise
```

2. Crie um ambiente virtual:
```bash
python -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```

4. Configure as variáveis de ambiente (se necessário):
```bash
cp .env.example .env
# Edite o arquivo .env com suas configurações
```

### Extração via Claude (recomendado)

Para documentos com phrasing variado ou conteúdo em diagramas, configure `ANTHROPIC_API_KEY` no `.env`. Isso ativa simultaneamente:

- **Vision AI** — descreve páginas-imagem (diagramas, fluxos) em texto
- **Extração via LLM** — substitui o regex como fonte primária, com Tool Use estruturado e citação textual por item declarado (auditável)

Variáveis opcionais:
- `M1_LLM_MODEL` — default `claude-haiku-4-5-20251001`. Use Sonnet para mais precisão.
- `M1_LLM_DISABLE=1` — força fallback regex mesmo com a key configurada.

## 💻 Uso

Para iniciar a interface web:
```bash
python3 -m streamlit run app_ui.py
```

Para usar pela linha de comando:
```bash
python3 main.py --url https://www.exemplo.com.br --doc caminho/para/declaracao.pdf
```

## 📁 Estrutura do Projeto

```
automacao_analise/
├── modules/
│   ├── m1_parser/          # Extração de dados
│   ├── m2_scanner/         # Análise de segurança
│   ├── m3_engine/          # Processamento e comparação
│   └── m4_reporter/        # Geração de relatórios
├── output/                 # Arquivos de saída
├── tests/                  # Testes automatizados
├── config.py              # Configurações
├── main.py                # Entrada principal
└── app_ui.py              # Interface gráfica
```

## 🧪 Testes

Execute os testes com:
```bash
python -m pytest tests/
```

## 📝 Configuração

Edite `config.py` para personalizar comportamentos e conexões.

## 📄 Licença



## ✉️ Contato

