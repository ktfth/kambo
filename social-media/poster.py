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
  Windows:      python poster.py schedule install
  Linux/macOS:  python poster.py schedule install
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path

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

# Mapa dia (1-30) → arquivo de post relativo a POSTS_DIR.
# Fonte única de verdade: posts-map.json. Não edite aqui.
_MAP_FILE = BASE_DIR / "posts-map.json"
with _MAP_FILE.open(encoding="utf-8") as _f:
    POST_MAP: dict[int, str] = {int(k): v for k, v in json.load(_f).items()}


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
    Extrai o texto do primeiro bloco de código do arquivo.
    Suporta language tags (```txt, ```python …) e line-endings CRLF.
    """
    content = markdown_path.read_text(encoding="utf-8")

    # Aceita fence com tag de linguagem opcional e CRLF ou LF
    pattern = re.compile(r"```[^\r\n]*\r?\n(.*?)\r?\n```", re.DOTALL)
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

    try:
        from threads_client import publish_to_threads

        result = await publish_to_threads(text)

        if result["success"]:
            print("✅ Publicado com sucesso no Threads!")
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

    shutil.copy(example_path, env_path)

    print("\nEscolha o modo de publicação:")
    print("  1. browser — Chrome com seu perfil (recomendado, sem API key)")
    print("  2. api     — API oficial do Threads (precisa de token)")
    mode_choice = input("\nOpção (1/2) [1]: ").strip() or "1"
    mode = "browser" if mode_choice != "2" else "api"

    lines = env_path.read_text().splitlines()
    new_lines = [
        f"POSTER_MODE={mode}" if line.startswith("POSTER_MODE=") else line
        for line in lines
    ]

    if mode == "api":
        user_id = input("THREADS_USER_ID: ").strip()
        token = input("THREADS_ACCESS_TOKEN: ").strip()
        new_lines = [
            f"THREADS_USER_ID={user_id}" if line.startswith("THREADS_USER_ID=")
            else f"THREADS_ACCESS_TOKEN={token}" if line.startswith("THREADS_ACCESS_TOKEN=")
            else line
            for line in new_lines
        ]

    env_path.write_text("\n".join(new_lines))
    print(f"\n✅ .env criado em: {env_path}")

    if mode == "browser":
        print("\nPróximos passos:")
        print("  1. pip install -r requirements-social.txt")
        print("  2. playwright install chrome")
        print("  3. python poster.py today --dry-run")
    else:
        print("\nPróximos passos:")
        print("  1. pip install -r requirements-social.txt")
        print("  2. python poster.py today --dry-run")


# ─────────────────────────────────────────────────
# Agendamento — Windows
# ─────────────────────────────────────────────────
def schedule_windows_install() -> None:
    """Instala o agendamento no Windows Task Scheduler (18h diário)."""
    if not shutil.which("schtasks"):
        print("❌ schtasks não encontrado. Certifique-se de estar no Windows.")
        sys.exit(1)

    # sys.executable e Path(__file__) são caminhos de sistema confiáveis,
    # não controláveis por entrada do usuário — sem risco de injeção.
    script = Path(__file__).resolve()
    python = sys.executable
    task_name = "KamboSocialPoster"

    subprocess.run(
        ["schtasks", "/Delete", "/TN", task_name, "/F"],
        capture_output=True,
    )

    # /TR requires a Windows command-line string; list2cmdline correctly quotes
    # paths with spaces (e.g. "C:\Program Files\..."). Both `python`
    # (sys.executable) and `script` (Path(__file__).resolve()) are trusted
    # system values — not user-controlled input.
    tr_value = subprocess.list2cmdline(  # nosec B603 B607
        [str(python), str(script), "today"]
    )
    cmd = [
        "schtasks", "/Create",
        "/TN", task_name,
        "/TR", tr_value,
        "/SC", "DAILY",
        "/ST", "18:00",
        "/RL", "HIGHEST",
        "/F",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)  # nosec B603

    if result.returncode == 0:
        print(f"✅ Task Scheduler configurado: {task_name}")
        print("   Executa todo dia às 18h00")
        print(f"   Script: {script}")
        print(f"\nPara verificar: schtasks /Query /TN {task_name}")
        print("Para remover:   python poster.py schedule uninstall")
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
        print("ℹ️  Task não encontrada ou já removida.")


# ─────────────────────────────────────────────────
# Agendamento — Unix (Linux / macOS)
# ─────────────────────────────────────────────────
def schedule_unix_install() -> None:
    """Instala o cron job (Linux/macOS) para executar às 18h."""
    script = Path(__file__).resolve()
    python = sys.executable
    # shlex.quote garante que caminhos com espaços ou caracteres especiais
    # sejam corretamente escapados no crontab (POSIX shell).
    cron_line = (
        f"0 18 * * * "
        f"cd {shlex.quote(str(BASE_DIR))} && "
        f"{shlex.quote(str(python))} {shlex.quote(str(script))} today "
        f">> {shlex.quote(str(LOG_FILE))} 2>&1"
    )

    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    current = result.stdout if result.returncode == 0 else ""

    if "KamboSocialPoster" in current:
        print("⚠️  Cron job já está instalado.")
        return

    new_crontab = current.rstrip() + f"\n# KamboSocialPoster\n{cron_line}\n"
    proc = subprocess.run(["crontab", "-"], input=new_crontab, text=True, capture_output=True)

    if proc.returncode == 0:
        print("✅ Cron job instalado: 18h00 diário")
        print(f"   Script: {script}")
        print(f"   Log: {LOG_FILE}")
        print("\nPara verificar: crontab -l")
        print("Para remover:   python poster.py schedule uninstall")
    else:
        print(f"❌ Erro ao instalar cron: {proc.stderr}")


def schedule_unix_uninstall() -> None:
    """Remove o cron job do Linux/macOS.

    Remove apenas as linhas marcadas com '# KamboSocialPoster' e a linha
    imediatamente seguinte (o cron entry), evitando apagar jobs não relacionados.
    """
    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    if result.returncode != 0:
        print("ℹ️  Nenhum crontab encontrado.")
        return

    lines = result.stdout.splitlines()
    new_lines: list[str] = []
    skip_next = False
    for line in lines:
        if skip_next:
            skip_next = False
            continue
        if "# KamboSocialPoster" in line:
            skip_next = True  # pula também a próxima linha (o cron entry)
            continue
        new_lines.append(line)

    new_crontab = "\n".join(new_lines) + "\n"
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
        if result.returncode == 0 and "KamboSocialPoster" in result.stdout:
            print("🟢 Cron job: ATIVO (18h00 diário)")
        else:
            print("🔴 Cron job: INATIVO")
            print("   Execute: python poster.py schedule install")

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
    today_day = get_cycle_day()
    for day, path in POST_MAP.items():
        full = POSTS_DIR / path
        status = "✅" if full.exists() else "❌"
        label = get_platform_label(path)
        marker = " ← HOJE" if day == today_day else ""
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

    p_today = subparsers.add_parser("today", help="Publica o post de hoje")
    p_today.add_argument("--dry-run", action="store_true", help="Exibe sem publicar")

    p_day = subparsers.add_parser("day", help="Publica o post do dia N")
    p_day.add_argument("n", type=int, help="Número do dia (1-30)")
    p_day.add_argument("--dry-run", action="store_true", help="Exibe sem publicar")

    subparsers.add_parser("list", help="Lista todos os posts disponíveis")
    subparsers.add_parser("setup", help="Configura o .env interativamente")

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
        asyncio.run(publish_day(get_cycle_day(), dry_run=args.dry_run))
    elif args.command == "day":
        asyncio.run(publish_day(args.n, dry_run=args.dry_run))
    elif args.command == "list":
        list_posts()
    elif args.command == "setup":
        run_setup()
    elif args.command == "schedule":
        system = platform.system()
        if args.action == "install":
            schedule_windows_install() if system == "Windows" else schedule_unix_install()
        elif args.action == "uninstall":
            schedule_windows_uninstall() if system == "Windows" else schedule_unix_uninstall()
        elif args.action == "status":
            schedule_status()


if __name__ == "__main__":
    main()
