"""
Threads Publisher — Dois modos:
  - API:     usa a API Graph oficial do Threads (Meta)
  - Browser: abre o Chrome com seu perfil logado e posta via Playwright

Uso direto:
  python threads_client.py --text "seu post aqui" --mode api
  python threads_client.py --text "seu post aqui" --mode browser
"""

from __future__ import annotations

import asyncio
import os
import platform
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

# ─────────────────────────────────────────────────
# Constantes
# ─────────────────────────────────────────────────
THREADS_API_BASE = "https://graph.threads.net/v1.0"
THREADS_URL = "https://www.threads.net"
MAX_CHARS = 500  # limite do Threads


# ─────────────────────────────────────────────────
# Helpers de perfil do Chrome por OS
# ─────────────────────────────────────────────────
def default_chrome_profile() -> Path:
    """Retorna o caminho padrão do perfil do Chrome para o OS atual."""
    system = platform.system()
    home = Path.home()

    if system == "Windows":
        return home / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
    elif system == "Darwin":  # macOS
        return home / "Library" / "Application Support" / "Google" / "Chrome"
    else:  # Linux
        return home / ".config" / "google-chrome"


# ─────────────────────────────────────────────────
# Modo API — Threads Graph API
# ─────────────────────────────────────────────────
@dataclass
class ThreadsAPIClient:
    user_id: str
    access_token: str

    async def post(self, text: str) -> dict:
        """Publica um post de texto no Threads via API oficial."""
        if len(text) > MAX_CHARS:
            print(f"⚠️  Texto tem {len(text)} chars (limite: {MAX_CHARS}). Truncando...")
            text = text[: MAX_CHARS - 3] + "..."

        async with httpx.AsyncClient(timeout=30) as client:
            # 1. Cria o container de mídia
            print("📤 Criando container no Threads...")
            resp = await client.post(
                f"{THREADS_API_BASE}/{self.user_id}/threads",
                params={
                    "media_type": "TEXT",
                    "text": text,
                    "access_token": self.access_token,
                },
            )
            resp.raise_for_status()
            container_id = resp.json()["id"]
            print(f"✅ Container criado: {container_id}")

            # 2. Aguarda o container ficar pronto (até 30s)
            print("⏳ Aguardando processamento...")
            for attempt in range(10):
                await asyncio.sleep(3)
                status_resp = await client.get(
                    f"{THREADS_API_BASE}/{container_id}",
                    params={
                        "fields": "status,error_message",
                        "access_token": self.access_token,
                    },
                )
                status_resp.raise_for_status()
                status = status_resp.json().get("status", "")
                if status == "FINISHED":
                    break
                if status == "ERROR":
                    error_msg = status_resp.json().get("error_message", "Erro desconhecido")
                    raise RuntimeError(f"Container com erro: {error_msg}")
                print(f"   Status: {status} (tentativa {attempt + 1}/10)")
            else:
                raise TimeoutError("Container não ficou pronto em 30 segundos.")

            # 3. Publica o container
            print("🚀 Publicando...")
            pub_resp = await client.post(
                f"{THREADS_API_BASE}/{self.user_id}/threads_publish",
                params={
                    "creation_id": container_id,
                    "access_token": self.access_token,
                },
            )
            pub_resp.raise_for_status()
            post_id = pub_resp.json()["id"]

            return {
                "success": True,
                "post_id": post_id,
                "url": f"https://www.threads.net/post/{post_id}",
                "mode": "api",
            }


# ─────────────────────────────────────────────────
# Modo Browser — Playwright + Chrome
# ─────────────────────────────────────────────────
async def post_via_browser(
    text: str,
    profile_dir: Path | None = None,
    profile_name: str = "Default",
    headless: bool = False,
) -> dict:
    """
    Publica no Threads abrindo o Chrome com seu perfil já logado.
    Não precisa de API key — usa a sessão existente do navegador.
    """
    try:
        from playwright.async_api import async_playwright, TimeoutError as PWTimeout
    except ImportError:
        raise ImportError(
            "Playwright não instalado. Execute:\n"
            "  pip install playwright\n"
            "  playwright install chrome"
        )

    if len(text) > MAX_CHARS:
        print(f"⚠️  Texto tem {len(text)} chars (limite: {MAX_CHARS}). Truncando...")
        text = text[: MAX_CHARS - 3] + "..."

    profile_dir = profile_dir or Path(
        os.getenv("CHROME_PROFILE_DIR", "") or default_chrome_profile()
    )
    profile_name = os.getenv("CHROME_PROFILE_NAME", profile_name)
    headless_env = os.getenv("CHROME_HEADLESS", str(headless)).lower()
    headless = headless_env in ("true", "1", "yes")

    print(f"🌐 Abrindo Chrome com perfil: {profile_dir / profile_name}")
    print(f"   Headless: {headless}")

    async with async_playwright() as p:
        # Abre o Chrome com o perfil do usuário (já logado no Threads)
        context = await p.chromium.launch_persistent_context(
            user_data_dir=str(profile_dir),
            channel="chrome",
            headless=headless,
            args=["--profile-directory=" + profile_name],
            viewport={"width": 1280, "height": 900},
            locale="pt-BR",
        )

        page = context.pages[0] if context.pages else await context.new_page()

        try:
            # ── Navega para o Threads ──────────────────────────────
            print("📍 Navegando para threads.net...")
            await page.goto(THREADS_URL, wait_until="networkidle", timeout=30_000)
            await page.wait_for_timeout(2000)

            # Verifica se está logado
            if "login" in page.url.lower() or "signup" in page.url.lower():
                raise RuntimeError(
                    "❌ Chrome não está logado no Threads.\n"
                    "   Abra o Chrome manualmente, faça login em threads.net,\n"
                    "   e execute o poster novamente."
                )

            # ── Clica no botão de novo post ────────────────────────
            print("✏️  Abrindo formulário de novo post...")

            # Tenta encontrar o botão de composição (vários seletores possíveis)
            compose_selectors = [
                'a[href="/compose"]',
                '[aria-label="New thread"]',
                '[aria-label="Novo thread"]',
                'svg[aria-label="New thread"]',
                'div[role="button"]:has-text("New thread")',
                'div[role="button"]:has-text("Novo thread")',
                # Botão de composição na barra lateral
                'nav a[href*="compose"]',
            ]

            compose_btn = None
            for selector in compose_selectors:
                try:
                    compose_btn = await page.wait_for_selector(
                        selector, timeout=3000, state="visible"
                    )
                    if compose_btn:
                        print(f"   Encontrado: {selector}")
                        break
                except PWTimeout:
                    continue

            if not compose_btn:
                # Tenta via URL direta
                print("   Tentando via URL /compose...")
                await page.goto(f"{THREADS_URL}/compose", wait_until="networkidle")
                await page.wait_for_timeout(2000)
            else:
                await compose_btn.click()
                await page.wait_for_timeout(1500)

            # ── Escreve o texto ────────────────────────────────────
            print("⌨️  Digitando o post...")

            text_area_selectors = [
                '[contenteditable="true"]',
                'textarea[placeholder*="thread"]',
                'textarea[placeholder*="Thread"]',
                'div[role="textbox"]',
            ]

            text_area = None
            for selector in text_area_selectors:
                try:
                    text_area = await page.wait_for_selector(
                        selector, timeout=5000, state="visible"
                    )
                    if text_area:
                        print(f"   Campo encontrado: {selector}")
                        break
                except PWTimeout:
                    continue

            if not text_area:
                # Screenshot para debug
                screenshot_path = Path(__file__).parent / "debug-screenshot.png"
                await page.screenshot(path=str(screenshot_path))
                raise RuntimeError(
                    f"❌ Campo de texto não encontrado.\n"
                    f"   Screenshot salvo em: {screenshot_path}\n"
                    f"   A interface do Threads pode ter mudado."
                )

            await text_area.click()
            await page.wait_for_timeout(500)

            # Usa clipboard para preservar emojis e caracteres especiais
            await page.evaluate(
                """(text) => {
                    const el = document.querySelector('[contenteditable="true"], textarea[placeholder*="thread"], div[role="textbox"]');
                    if (el) {
                        el.focus();
                        document.execCommand('insertText', false, text);
                    }
                }""",
                text,
            )
            await page.wait_for_timeout(1000)

            # ── Clica em Publicar ──────────────────────────────────
            print("🚀 Publicando...")

            publish_selectors = [
                'button:has-text("Post")',
                'button:has-text("Publicar")',
                'div[role="button"]:has-text("Post")',
                'div[role="button"]:has-text("Publicar")',
                '[aria-label="Post"]',
                '[aria-label="Publicar"]',
            ]

            publish_btn = None
            for selector in publish_selectors:
                try:
                    publish_btn = await page.wait_for_selector(
                        selector, timeout=3000, state="visible"
                    )
                    if publish_btn:
                        is_enabled = await publish_btn.is_enabled()
                        if is_enabled:
                            print(f"   Botão encontrado: {selector}")
                            break
                        publish_btn = None
                except PWTimeout:
                    continue

            if not publish_btn:
                screenshot_path = Path(__file__).parent / "debug-screenshot-publish.png"
                await page.screenshot(path=str(screenshot_path))
                raise RuntimeError(
                    f"❌ Botão 'Publicar' não encontrado ou desabilitado.\n"
                    f"   Screenshot salvo em: {screenshot_path}"
                )

            await publish_btn.click()
            await page.wait_for_timeout(3000)

            # ── Confirmação ────────────────────────────────────────
            # Tira screenshot de confirmação
            screenshot_path = Path(__file__).parent / f"post-confirma-{int(time.time())}.png"
            await page.screenshot(path=str(screenshot_path))
            print(f"📸 Screenshot de confirmação: {screenshot_path}")

            return {
                "success": True,
                "post_id": None,  # Não temos o ID via browser
                "url": THREADS_URL,
                "mode": "browser",
                "screenshot": str(screenshot_path),
            }

        finally:
            await context.close()


# ─────────────────────────────────────────────────
# Função principal (pode ser chamada por poster.py)
# ─────────────────────────────────────────────────
async def publish_to_threads(text: str, mode: str = "auto") -> dict:
    """
    Publica no Threads.
    mode: "api" | "browser" | "auto" (tenta API, fallback para browser)
    """
    env_mode = os.getenv("POSTER_MODE", mode)
    if env_mode != "auto":
        mode = env_mode

    if mode in ("api", "auto"):
        user_id = os.getenv("THREADS_USER_ID", "")
        token = os.getenv("THREADS_ACCESS_TOKEN", "")

        if user_id and token:
            try:
                client = ThreadsAPIClient(user_id=user_id, access_token=token)
                return await client.post(text)
            except Exception as e:
                if mode == "api":
                    raise
                print(f"⚠️  API falhou: {e}")
                print("↩️  Tentando modo browser como fallback...")
        elif mode == "api":
            raise RuntimeError(
                "THREADS_USER_ID e THREADS_ACCESS_TOKEN não configurados no .env"
            )

    # Modo browser
    return await post_via_browser(text)


# ─────────────────────────────────────────────────
# CLI direto
# ─────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Posta texto no Threads")
    parser.add_argument("--text", required=True, help="Texto do post")
    parser.add_argument(
        "--mode",
        choices=["api", "browser", "auto"],
        default="auto",
        help="Modo de publicação (padrão: auto)",
    )
    args = parser.parse_args()

    result = asyncio.run(publish_to_threads(args.text, args.mode))

    if result["success"]:
        print(f"\n✅ Post publicado com sucesso!")
        print(f"   Modo: {result['mode']}")
        if result.get("url"):
            print(f"   URL: {result['url']}")
    else:
        print(f"\n❌ Falha ao publicar")
        sys.exit(1)
