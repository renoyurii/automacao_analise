import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env", override=True)

# ── APIs externas ─────────────────────────────────────────────────────────────
# Nota: load_dotenv com override=True garante que os valores do .env prevalecem
# sobre variáveis de ambiente vazias herdadas da shell.
SHODAN_API_KEY: str     = os.getenv("SHODAN_API_KEY", "")
ANTHROPIC_API_KEY: str  = os.getenv("ANTHROPIC_API_KEY", "")

# ── Qualys SSL Labs ───────────────────────────────────────────────────────────
SSL_LABS_API_BASE = "https://api.ssllabs.com/api/v3"
SSL_LABS_POLL_INTERVAL_SEC = 15    # Intervalo entre consultas durante análise
SSL_LABS_MAX_WAIT_SEC = 240        # Tempo máximo de espera total

# ── End-of-Life API ──────────────────────────────────────────────────────────
EOL_API_BASE = "https://endoflife.date/api"

# ── Portas consideradas "padrão" para um site (não geram alerta) ─────────────
EXPECTED_PORTS = {80, 443}

# ── Portas oficialmente suportadas pelo Cloudflare como proxy ─────────────────
# Fonte: https://developers.cloudflare.com/fundamentals/reference/network-ports/
# Sites atrás do Cloudflare vão mostrar essas portas abertas — é comportamento normal.
CLOUDFLARE_PROXY_PORTS = {
    80, 8080, 8880, 2052, 2082, 2086, 2095,    # HTTP
    443, 8443, 2053, 2083, 2087, 2096,          # HTTPS
}

# ── Portas que exigem banner para confirmar abertura (evita falsos positivos) ─
# Cloudflare aceita TCP em qualquer porta mas só serve essas acima.
# Portas de serviço (FTP, SSH, RDP...) devem retornar um banner real.
BANNER_REQUIRED_PORTS = {21, 22, 23, 25, 110, 143, 3306, 3389, 5432, 5900, 6379, 27017}

# ── Cabeçalho institucional fixo do relatório ───────────────────────────────
# Configurar via variáveis de ambiente ou sobrescrever em .env
REPORT_HEADER_LINE1 = os.getenv(
    "REPORT_HEADER_LINE1",
    "Considerando a legislação vigente que dispõe sobre credenciamento de "
    "leiloeiros públicos e procedimentos para realização de leilão judicial;",
)
REPORT_HEADER_LINE2 = os.getenv(
    "REPORT_HEADER_LINE2",
    "Considerando a norma ISO/IEC 27002:2022, que dispõe sobre o código de "
    "práticas para gestão de segurança da informação.",
)
REPORT_FOOTER = os.getenv(
    "REPORT_FOOTER",
    "Departamento de Segurança da Informação",
)
