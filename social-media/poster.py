#!/usr/bin/env python3
"""
Kambo Social Media Poster — Cross-platform (Windows / macOS / Linux)
Publica o post do dia no Threads automaticamente.

Uso:
  python poster.py today               # Post de hoje
  python poster.py today --dry-run     # Visualiza sem publicar
  python poster.py day 5               # Post do dia 5
  python poster.py list                # Lista todos os posts
  python poster.py setup               # Configura .env interativamente

Agendamento:
  Windows: python poster.py schedule install
  Linux/macOS: python poster.py schedule install
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Optional

# Carrega .env se existir
try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass  # dotenv opcional; variáveis de ambiente diretas também funcionam


# ─────────────────────────────────────────────────
# Configuração
# ─────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
POSTS_DIR = BASE_DIR / "posts"
LOG_FILE = BASE_DIR / "post-log.jsonl"
START_DATE_FILE = BASE_DIR / ".start-date"
REPO_URL = os.getenv("REPO_URL", "https://github.com/ktfth/kambo")

# Mapa dia (1-30) → arquivo de post relativo a POSTS_DIR
POST_MAP: dict[int, str] = {
    1: "twitter/dia-01-lancamento.md",
    2: "twitter/dia-02-problema.md",
    3: "linkedin/dia-03-solucao.md",
    4: "twitter/dia-04-arquitetura.md",
    5: "twitter/dia-05-instalacao.md",
    6: "linkedin/dia-06-claudecode.md",
    7: "twitter/dia-07-recap1.md",
    8: "twitter/dia-08-recon.md",
    9: "twitter/dia-09-scanning.md",
    10: "linkedin/dia-10-vulns.md",
    11: "twitter/dia-11-evidence.md",
    12: "linkedin/dia-12-api.md",
    13: "twitter/dia-13-cloud.md",
    14: "instagram/dia-14-recap2.md",
    15: "linkedin/dia-15-workflow.md",
    16: "twitter/dia-16-scope.md",
    17: "twitter/dia-17-cvss.md",
    18: "linkedin/dia-18-selfimprove.md",
    19: "twitter/dia-19-calibration.md",
    20: "twitter/dia-20-postexploit.md",
    21: "instagram/dia-21-recap3.md",
    22: "linkedin/dia-22-contribuir.md",
    23: "twitter/dia-23-tools.md",
    24: "twitter/dia-24-ctf.md",
    25: "twitter/dia-25-metrics.md",
    26: "linkedin/dia-26-report.md",
    27: "twitter/dia-27-tip-ssrf.md",
    28: "twitter/dia-28-tip-takeover.md",
    29: "linkedin/dia-29-roadmap.md",
    30: "twitter/dia-30-cta.md",
}


# ─────────────────────────────────────────────────
# Utilitários de data e ciclo
# ─────────────────────────────────────────────────
def get_start_date() -> date:
    """Retorna (e salva se for a primeira vez) a data de início do ciclo."""
    env_date = os.getenv("KAMBO_START_DATE", "")
    if env_date:
        return date.fromisoformat(env_date)

    if START_DATE_FILE.exists():
        return date.fromisoformat(START_DATE_FILE.read_text().strip())

    today = date.today()
    START_DATE_FILE.write_text(today.isoformat())
    return today


def get_cycle_day() -> int:
    """Retorna o dia do ciclo atual (1–30) baseado na data de início."""
    start = get_start_date()
    diff = (date.today() - start).days
    return (diff % 30) + 1


# ─────────────────────────────────────────────────
# Extração de texto do Markdown
# ─────────────────────────────────────────────────
def extract_post_text(markdown_path: Path) -> str:
    """
    Extrai o texto do primeiro bloco de código ```...``` do arquivo.
    Esse bloco contém o texto limpo pronto para publicar.
    """
    content = markdown_path.read_text(encoding="utf-8")

    # Procura blocos de código: ```\n...\n```
    pattern = re.compile(r"```\n(.*?)\n```", re.DOTALL)
    matches = pattern.findall(content)

    if not matches:
        raise ValueError(f"Nenhum bloco de código encontrado em {markdown_path}")

    # Usa o primeiro bloco (post principal)
    text = matches[0].strip()

    # Garante que o link do repositório está presente
    if REPO_URL not in text and "github.com/ktfth/kambo" not in text:
        text += f"\n\n🔗 {REPO_URL}"

    return text


def get_platform_label(post_path: str) -> str:
    """Retorna o emoji e nome da plataforma baseado no caminho."""
    if "twitter" in post_path:
        return "🐦 Twitter / X"
    elif "linkedin" in post_path:
        return "💼 LinkedIn"
    elif "instagram" in post_path:
        return "📸 Instagram"
    return "📣 Social Media"


# ─────────────────────────────────────────────────
# Log de publicações
# ─────────────────────────────────────────────────
def log_post(day: int, post_path: str, result: dict) -> None:
    """Registra a publicação no JSONL de log."""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "day": day,
        "post_path": post_path,
        "platform": get_platform_label(post_path),
        "result": result,
    }
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ─────────────────────────────────────────────────
# Publicação
# ─────────────────────────────────────────────────
async def publish_day(day: int, dry_run: bool = False) -> None:
    """Carrega e publica o post do dia especificado."""
    if day < 1 or day > 30:
        print(f"❌ Dia inválido: {day}. Use um valor entre 1 e 30.")
        sys.exit(1)

    post_path = POST_MAP[day]
    full_path = POSTS_DIR / post_path

    if not full_path.exists():
        print(f"❌ Arquivo não encontrado: {full_path}")
        sys.exit(1)

    text = extract_post_text(full_path)
    platform_label = get_platform_label(post_path)

    # ── Exibe o post ──────────────────────────────
    separator = "─" * 60
    print(f"\n{separator}")
    print(f"🐸 KAMBO — Dia {day:02d}/30 | {datetime.now().strftime('%d/%m/%Y %H:%M')}")
    print(f"   {platform_label}")
    print(f"{separator}")
    print(f"\n{text}\n")
    print(f"{separator}")
    print(f"📊 Caracteres: {len(text)} / 500 (limite Threads)")
    print(f"{separator}\n")

    if dry_run:
        print("🔍 Modo dry-run: post NÃO foi publicado.")
        return

    # ── Publica no Threads ────────────────────────
    try:
        from threads_client import publish_to_threads

        result = await publish_to_threads(text)

        if result["success"]:
            print(f"✅ Publicado com sucesso no Threads!")
            if result.get("url"):
                print(f"   URL: {result['url']}")
            if result.get("screenshot"):
                print(f"   Screenshot: {result['screenshot']}")
            log_post(day, post_path, result)
        else:
            print("❌ Falha ao publicar.")
            sys.exit(1)

    except ImportError:
        print(
            "⚠️  threads_client.py não encontrado.\n"
            "   Execute: pip install -r requirements-social.txt"
        )
        sys.exit(1)
    except Exception as e:
        print(f"❌ Erro ao publicar: {e}")
        log_post(day, post_path, {"success": False, "error": str(e)})
        sys.exit(1)


# ─────────────────────────────────────────────────
# Configuração interativa
# ─────────────────────────────────────────────────
def run_setup() -> None:
    """Guia interativo para criar o arquivo .env."""
    env_path = BASE_DIR / ".env"
    example_path = BASE_DIR / ".env.example"

    print("\n🔧 Configuração do Kambo Social Media Poster")
    print("─" * 50)

    if env_path.exists():
        overwrite = input("⚠️  .env já existe. Sobrescrever? (s/N): ").strip().lower()
        if overwrite != "s":
            print("Configuração cancelada.")
            return

    # Copia o exemplo como base
    shutil.copy(example_path, env_path)

    print("\nEscolha o modo de publicação:")
    print("  1. browser — Chrome com seu perfil (recomendado, sem API key)")
    print("  2. api     — API oficial do Threads (precisa de token)")
    mode_choice = input("\nOpção (1/2) [1]: ").strip() or "1"
    mode = "browser" if mode_choice != "2" else "api"

    lines = env_path.read_text().splitlines()
    new_lines = []

    for line in lines:
        if line.startswith("POSTER_MODE="):
            line = f"POSTER_MODE={mode}"
        new_lines.append(line)

    if mode == "api":
        user_id = input("THREADS_USER_ID: ").strip()
        token = input("THREADS_ACCESS_TOKEN: ").strip()
        new_lines2 = []
        for line in new_lines:
            if line.startswith("THREADS_USER_ID="):
                line = f"THREADS_USER_ID={user_id}"
            elif line.startswith("THREADS_ACCESS_TOKEN="):
                line = f"THREADS_ACCESS_TOKEN={token}"
            new_lines2.append(line)
        new_lines = new_lines2

    env_path.write_text("\n".join(new_lines))

    print(f"\n✅ .env criado em: {env_path}")
    print("\nPróximo passo:")
    if mode == "browser":
        print("  1. Instale as dependências:  pip install -r requirements-social.txt")
        print("  2. Instale o Chrome do Playwright: playwright install chrome")
        print("  3. Teste: python poster.py today --dry-run")
        print("  4. Publique: python poster.py today")
    else:
        print("  1. Instale as dependências: pip install -r requirements-social.txt")
        print("  2. Teste: python poster.py today --dry-run")
        print("  3. Publique: python poster.py today")


# ─────────────────────────────────────────────────
# Agendamento
# ─────────────────────────────────────────────────
def schedule_windows_install() -> None:
    """Instala o agendamento no Windows Task Scheduler (18h diário)."""
    script = Path(__file__).resolve()
    python = sys.executable
    task_name = "KamboSocialPoster"
    working_dir = str(BASE_DIR)

    # Verifica se schtasks está disponível
    if not shutil.which("schtasks"):
        print("❌ schtasks não encontrado. Certifique-se de estar no Windows.")
        sys.exit(1)

    # Remove task existente (ignora erro se não existe)
    subprocess.run(
        ["schtasks", "/Delete", "/TN", task_name, "/F"],
        capture_output=True,
    )

    # Cria nova task
    cmd = [
        "schtasks", "/Create",
        "/TN", task_name,
        "/TR", f'"{python}" "{script}" today',
        "/SC", "DAILY",
        "/ST", "18:00",
        "/RL", "HIGHEST",
        "/F",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"✅ Task Scheduler configurado: {task_name}")
        print(f"   Executa todo dia às 18h00")
        print(f"   Script: {script}")
        print(f"\nPara verificar: schtasks /Query /TN {task_name}")
        print(f"Para remover:   python poster.py schedule uninstall")
    else:
        print(f"❌ Erro ao criar task: {result.stderr}")
        print("   Tente executar o terminal como Administrador.")
        sys.exit(1)


def schedule_windows_uninstall() -> None:
    """Remove o agendamento do Windows Task Scheduler."""
    task_name = "KamboSocialPoster"
    result = subprocess.run(
        ["schtasks", "/Delete", "/TN", task_name, "/F"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        print(f"✅ Task '{task_name}' removida do Task Scheduler.")
    else:
        print(f"ℹ️  Task não encontrada ou já removida.")


def schedule_unix_install() -> None:
    """Instala o cron job (Linux/macOS) para executar às 18h."""
    script = Path(__file__).resolve()
    python = sys.executable
    cron_line = f"0 18 * * * cd {BASE_DIR} && {python} {script} today >> {LOG_FILE} 2>&1"

    # Lê crontab atual
    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    current = result.stdout if result.returncode == 0 else ""

    if "KamboSocialPoster" in current or str(script) in current:
        print("⚠️  Cron job já está instalado.")
        return

    new_crontab = current.rstrip() + f"\n# KamboSocialPoster\n{cron_line}\n"
    proc = subprocess.run(["crontab", "-"], input=new_crontab, text=True, capture_output=True)

    if proc.returncode == 0:
        print(f"✅ Cron job instalado: 18h00 diário")
        print(f"   Script: {script}")
        print(f"   Log: {LOG_FILE}")
        print(f"\nPara verificar: crontab -l")
        print(f"Para remover:   python poster.py schedule uninstall")
    else:
        print(f"❌ Erro ao instalar cron: {proc.stderr}")


def schedule_unix_uninstall() -> None:
    """Remove o cron job do Linux/macOS."""
    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    if result.returncode != 0:
        print("ℹ️  Nenhum crontab encontrado.")
        return

    lines = [
        l for l in result.stdout.splitlines()
        if "KamboSocialPoster" not in l and "poster.py" not in l
    ]
    new_crontab = "\n".join(lines) + "\n"
    subprocess.run(["crontab", "-"], input=new_crontab, text=True)
    print("✅ Cron job removido.")


def schedule_status() -> None:
    """Mostra o status do agendamento atual."""
    system = platform.system()
    print(f"\n📊 Status do Kambo Social Poster")
    print(f"   Sistema: {system}")
    print(f"   Python:  {sys.executable}")
    print(f"   Ciclo:   Dia {get_cycle_day()}/30 (início: {get_start_date()})")
    print()

    if system == "Windows":
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", "KamboSocialPoster", "/FO", "LIST"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print("🟢 Task Scheduler: ATIVO")
            for line in result.stdout.splitlines()[:10]:
                print(f"   {line}")
        else:
            print("🔴 Task Scheduler: INATIVO")
            print("   Execute: python poster.py schedule install")
    else:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        if result.returncode == 0 and "poster.py" in result.stdout:
            print("🟢 Cron job: ATIVO (18h00 diário)")
        else:
            print("🔴 Cron job: INATIVO")
            print("   Execute: python poster.py schedule install")

    # Últimas publicações
    print()
    if LOG_FILE.exists():
        print("📝 Últimas 5 publicações:")
        lines = LOG_FILE.read_text().strip().splitlines()
        for line in lines[-5:]:
            try:
                entry = json.loads(line)
                ts = entry.get("timestamp", "?")[:16]
                day = entry.get("day", "?")
                plat = entry.get("platform", "?")
                ok = "✅" if entry.get("result", {}).get("success") else "❌"
                print(f"   {ok} {ts} | Dia {day:02d} | {plat}")
            except Exception:
                pass
    else:
        print("📝 Nenhuma publicação registrada ainda.")
    print()


# ─────────────────────────────────────────────────
# Listar posts disponíveis
# ─────────────────────────────────────────────────
def list_posts() -> None:
    print("\n📅 Posts disponíveis (30 dias):\n")
    for day, path in POST_MAP.items():
        full = POSTS_DIR / path
        status = "✅" if full.exists() else "❌"
        label = get_platform_label(path)
        marker = " ← HOJE" if day == get_cycle_day() else ""
        print(f"  Dia {day:02d}: {status} {label:<20} {path}{marker}")
    print()


# ─────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kambo Social Media Poster — publica no Threads às 18h",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python poster.py today                   # Publica o post de hoje
  python poster.py today --dry-run         # Visualiza sem publicar
  python poster.py day 5                   # Publica o dia 5
  python poster.py list                    # Lista todos os posts
  python poster.py setup                   # Configura .env interativamente
  python poster.py schedule install        # Agenda às 18h diário
  python poster.py schedule uninstall      # Remove o agendamento
  python poster.py schedule status         # Verifica o agendamento
        """,
    )

    subparsers = parser.add_subparsers(dest="command")

    # today
    p_today = subparsers.add_parser("today", help="Publica o post de hoje")
    p_today.add_argument(
        "--dry-run", action="store_true", help="Exibe sem publicar"
    )

    # day N
    p_day = subparsers.add_parser("day", help="Publica o post do dia N")
    p_day.add_argument("n", type=int, help="Número do dia (1-30)")
    p_day.add_argument(
        "--dry-run", action="store_true", help="Exibe sem publicar"
    )

    # list
    subparsers.add_parser("list", help="Lista todos os posts disponíveis")

    # setup
    subparsers.add_parser("setup", help="Configura o .env interativamente")

    # schedule
    p_sched = subparsers.add_parser("schedule", help="Gerencia o agendamento")
    p_sched.add_argument(
        "action",
        choices=["install", "uninstall", "status"],
        help="Ação de agendamento",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    if args.command == "today":
        day = get_cycle_day()
        asyncio.run(publish_day(day, dry_run=args.dry_run))

    elif args.command == "day":
        asyncio.run(publish_day(args.n, dry_run=args.dry_run))

    elif args.command == "list":
        list_posts()

    elif args.command == "setup":
        run_setup()

    elif args.command == "schedule":
        system = platform.system()
        if args.action == "install":
            if system == "Windows":
                schedule_windows_install()
            else:
                schedule_unix_install()
        elif args.action == "uninstall":
            if system == "Windows":
                schedule_windows_uninstall()
            else:
                schedule_unix_uninstall()
        elif args.action == "status":
            schedule_status()


if __name__ == "__main__":
    main()
