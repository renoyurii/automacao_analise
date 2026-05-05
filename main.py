"""
Sistema de Análise Automatizada de Segurança.

Uso:
    python main.py --url <URL> --doc <declaracao.pdf|.docx>

Fluxo:
    M1 e M2 executam em paralelo (ThreadPoolExecutor).
    M3 cruza os resultados.
    M4 gera a Ficha de Verificação em .docx.
"""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

from modules.m1_parser import parse_document
from modules.m2_scanner import scan_all
from modules.m3_engine import evaluate
from modules.m4_reporter import generate_ficha, generate_pdf


def main() -> None:
    args = _parse_args()

    _banner()

    url     = args.url
    domain  = _extract_domain(url)
    doc_path = Path(args.doc)

    if not doc_path.exists():
        print(f"{Fore.RED}[ERRO] Arquivo não encontrado: {doc_path}{Style.RESET_ALL}")
        sys.exit(1)

    # ── M1 e M2 em paralelo ────────────────────────────────────────────────────
    print(f"{Fore.CYAN}[→] Iniciando M1 (parsing) e M2 (varredura) em paralelo...{Style.RESET_ALL}\n")

    claimed_data: dict = {}
    scan_data: dict    = {}
    errors: list[str]  = []

    with ThreadPoolExecutor(max_workers=2) as ex:
        fut_m1 = ex.submit(parse_document, str(doc_path))
        fut_m2 = ex.submit(scan_all, url)

        for fut in as_completed([fut_m1, fut_m2]):
            try:
                if fut is fut_m1:
                    claimed_data = fut.result()
                    print(f"{Fore.GREEN}[M1] Parsing concluído.{Style.RESET_ALL}")
                else:
                    scan_data = fut.result()
            except Exception as e:
                errors.append(str(e))
                print(f"{Fore.RED}[ERRO] {e}{Style.RESET_ALL}")

    if errors and not claimed_data:
        print(f"\n{Fore.RED}Falha crítica no M1. Encerrando.{Style.RESET_ALL}")
        sys.exit(1)

    # ── M3: Motor de Decisão ──────────────────────────────────────────────────
    print(f"\n{Fore.CYAN}[→] M3: Cruzando dados...{Style.RESET_ALL}")
    result_data = evaluate(claimed_data, scan_data, url, domain)
    _print_summary(result_data)

    # ── M4: Geração da Ficha ──────────────────────────────────────────────────
    print(f"\n{Fore.CYAN}[→] M4: Gerando Ficha de Verificação...{Style.RESET_ALL}")
    output_path = _build_output_path(domain)
    ficha_path  = generate_ficha(result_data, output_path)
    print(f"{Fore.GREEN}[✓] DOCX: {ficha_path}{Style.RESET_ALL}")

    pdf_path = Path(str(output_path).replace(".docx", ".pdf"))
    try:
        generate_pdf(result_data, pdf_path)
        print(f"{Fore.GREEN}[✓] PDF:  {pdf_path}{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] PDF não gerado: {e}{Style.RESET_ALL}\n")


# ── Apresentação dos resultados ───────────────────────────────────────────────

def _print_summary(rd: dict) -> None:
    overall = rd.get("overall_status", "?")
    color   = Fore.GREEN if overall == "CONFORME" else Fore.RED

    print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
    print(f"  Domínio  : {rd.get('domain', '?')}")
    print(f"  Data     : {rd.get('analysis_date', date.today().isoformat())}")
    print(f"  Resultado: {color}{overall}{Style.RESET_ALL}")
    print(f"  Conclusão: {rd.get('conclusao', '')}")
    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")

    checks = rd.get("checks", {})
    print(f"\n  {'Seção':<28} {'Status':<18} {'Sev.'}")
    print(f"  {'─' * 52}")

    for section, check in checks.items():
        if isinstance(check, dict) and "status" in check:
            _print_check_row(section, check)
        elif isinstance(check, dict):
            for sub, v in check.items():
                if isinstance(v, dict) and "status" in v:
                    _print_check_row(f"{section}/{sub}", v)

    print()


def _print_check_row(label: str, check: dict) -> None:
    status = check.get("status", "?")
    sev    = check.get("severity") or "—"
    colors = {
        "CONFORME":        Fore.GREEN,
        "NÃO CONFORME":    Fore.RED,
        "ATENÇÃO":         Fore.YELLOW,
        "NÃO VERIFICÁVEL": Fore.WHITE,
    }
    c = colors.get(status, Fore.WHITE)
    print(f"  {label:<28} {c}{status:<18}{Style.RESET_ALL} {sev}")


# ── Utilitários ───────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Análise automatizada de segurança de sites."
    )
    parser.add_argument("--url", required=True, help="URL do site a analisar")
    parser.add_argument("--doc", required=True, help="Caminho para PDF ou DOCX da declaração")
    return parser.parse_args()


def _extract_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.netloc or parsed.path
    return host.lstrip("www.").split(":")[0]


def _build_output_path(domain: str) -> Path:
    safe_domain = domain.replace(".", "_")
    filename    = f"ficha_verificacao_{safe_domain}_{date.today().isoformat()}.docx"
    return Path(__file__).parent / "output" / filename


def _banner() -> None:
    print(f"\n{Fore.CYAN}{'─' * 60}")
    print("  Homologação — Análise de Segurança")
    print("  Sistema de Análise Automatizada v1.0")
    print(f"{'─' * 60}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
