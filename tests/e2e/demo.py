#!/usr/bin/env python3
"""Prepares the live demonstration of SentinelScope against the laboratory target.

The demonstration shows a "before and after" comparison: the laboratory target is first served
in its `vulnerable` variant and analysed, then restarted as `partial` (the /search page fixed,
/profile still vulnerable) so the presenter runs the second analysis live and compares the two.

    python tests/e2e/demo.py                 # prepare, then keep the target running as `partial`
    python tests/e2e/demo.py --depois fixed  # keep the target running as `fixed` instead
    python tests/e2e/demo.py --limpar        # first delete the demo data left by earlier rehearsals

What it does, through the web interface only (exactly as a user would):
  1. checks that the application answers and that ALLOW_PRIVATE_TARGETS=true in .env;
  2. registers "Loja de testes (laboratório)" -> http://127.0.0.1:8765/ and, for the failure
     demonstration, "Site fora do ar" -> an address where nothing listens (once; reused later);
  3. starts the target as `vulnerable` and runs the complete (safe-active) "before" analysis;
  4. restarts the target in the "after" variant and keeps it running until Ctrl+C.

Requires Apache and MariaDB running and the application installed (docs/INSTALLATION_AND_USER_MANUAL.md).
"""
from __future__ import annotations

import argparse
import html
import pathlib
import re
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from run_system_tests import (  # noqa: E402
    ENV_FILE, LAB_SCRIPT, Database, Web, analysis_id_from, page_score, port_open,
)

LAB_NAME = "Loja de testes (laboratório)"
DOWN_NAME = "Site fora do ar"


def say(message: str) -> None:
    print(message, flush=True)


def private_targets_allowed() -> bool:
    if not ENV_FILE.exists():
        return False
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("ALLOW_PRIVATE_TARGETS="):
            return line.split("=", 1)[1].strip().lower() in ("true", "1", "yes", "on")
    return False


def application_id(web: Web, name: str) -> int | None:
    """The id of the newest card with this name on the dashboard, or None."""
    pattern = rf"<h2>{re.escape(html.escape(name))}</h2>.*?name=\"application_id\" value=\"(\d+)\""
    match = re.search(pattern, web.get().text, re.S)
    return int(match.group(1)) if match else None


def ensure_application(web: Web, name: str, url: str) -> int:
    existing = application_id(web, name)
    if existing is not None:
        say(f"  • '{name}' já cadastrada (#{existing}).")
        return existing
    reply = web.register(name, url)
    if reply.status != 302:
        raise SystemExit(f"Não foi possível cadastrar '{name}' (HTTP {reply.status}).")
    created = application_id(web, name)
    say(f"  • '{name}' cadastrada (#{created}) → {url}")
    return created


def clean_previous_runs(mysql: str) -> None:
    """Removes the demo applications and their analyses, so a rehearsal does not clutter the
    history shown to the audience. The interface has no delete action, hence the mysql client
    (as root, the XAMPP default); findings go with their analyses (ON DELETE CASCADE)."""
    names = ", ".join(f"X'{name.encode().hex()}'" for name in (LAB_NAME, DOWN_NAME))
    db = Database(mysql)
    db.query(f"DELETE FROM analyses WHERE application_id IN (SELECT id FROM applications WHERE name IN ({names}))")
    db.query(f"DELETE FROM applications WHERE name IN ({names})")
    say("  • Dados de ensaios anteriores removidos.")


def start_lab(port: int, variant: str) -> subprocess.Popen:
    process = subprocess.Popen([sys.executable, str(LAB_SCRIPT), "--port", str(port), "--variant", variant])
    deadline = time.time() + 10
    while not port_open(port):
        if process.poll() is not None or time.time() > deadline:
            raise SystemExit(f"O site de testes não iniciou na porta {port}.")
        time.sleep(0.1)
    return process


def stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=10)


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepara a demonstração ao vivo do SentinelScope.")
    parser.add_argument("--app-url", default="http://localhost/www/Ciber/public/")
    parser.add_argument("--porta", type=int, default=8765, help="porta do site de testes")
    parser.add_argument("--porta-fora-do-ar", type=int, default=8799,
                        help="porta sem serviço, usada na demonstração de falha")
    parser.add_argument("--depois", choices=["partial", "fixed"], default="partial",
                        help="versão do site que fica no ar para a análise ao vivo")
    parser.add_argument("--limpar", action="store_true",
                        help="apaga antes os cadastros e análises de ensaios anteriores da demonstração")
    parser.add_argument("--mysql", default=r"C:\xampp\mysql\bin\mysql.exe")
    args = parser.parse_args()

    web = Web(args.app_url)
    say("1. Conferindo o ambiente")
    try:
        page = web.get(timeout=15)
    except OSError as error:
        raise SystemExit(f"A aplicação não respondeu em {args.app_url}: {error}. Inicie Apache e MySQL no XAMPP.")
    if "Encontre o risco" not in page.text:
        raise SystemExit(f"A aplicação respondeu HTTP {page.status} sem o painel. Confira o .env e o banco.")
    if not private_targets_allowed():
        raise SystemExit("Defina ALLOW_PRIVATE_TARGETS=true no .env (apenas durante a demonstração).")
    for port in (args.porta, args.porta_fora_do_ar):
        if port_open(port):
            raise SystemExit(f"A porta {port} já está em uso. Feche o programa que a usa ou escolha outra porta.")
    say("  • Aplicação no ar e alvos locais liberados.")

    say("2. Cadastrando os sites da demonstração")
    if args.limpar:
        clean_previous_runs(args.mysql)
    lab_id = ensure_application(web, LAB_NAME, f"http://127.0.0.1:{args.porta}/")
    ensure_application(web, DOWN_NAME, f"http://127.0.0.1:{args.porta_fora_do_ar}/")

    say("3. Rodando a análise 'antes' (site vulnerável, modo completo)")
    lab = start_lab(args.porta, "vulnerable")
    try:
        reply = web.run(lab_id, active=True)
    finally:
        stop(lab)
    before = analysis_id_from(reply)
    if before is None:
        raise SystemExit(f"A análise não foi iniciada (HTTP {reply.status}).")
    result = web.get(f"page=result&id={before}")
    say(f"  • Análise #{before} concluída, pontuação {page_score(result)}: "
        f"{args.app_url}index.php?page=result&id={before}")

    say(f"4. Site de testes no ar na versão '{args.depois}' — pronto para a demonstração")
    say(f"   No painel, em '{LAB_NAME}', marque a análise completa e a autorização e clique em")
    say("   'Executar análise'. Depois escolha as duas análises e clique em 'Comparar'.")
    say(f"   Para a falha, rode a análise de '{DOWN_NAME}'.")
    say("   Ctrl+C encerra o site de testes. Ao terminar, volte ALLOW_PRIVATE_TARGETS para false.")
    lab = start_lab(args.porta, args.depois)
    try:
        lab.wait()
    except KeyboardInterrupt:
        stop(lab)
        say("Site de testes encerrado.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
