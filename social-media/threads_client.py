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
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

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
# Helpers compartilhados
# ─────────────────────────────────────────────────
def truncate_for_threads(text: str) -> Tuple[str, bool]:
    """Trunca o texto ao limite do Threads se necessário.

    Retorna (texto, foi_truncado).
    """
    if len(text) <= MAX_CHARS:
        return text, False
    return text[: MAX_CHARS - 3] + "...", True


def default_chrome_profile() -> Path:
    """Retorna o caminho padrão do perfil do Chrome para o OS atual."""
    system = platform.system()
    home = Path.home()
    if system == "Windows":
        return home / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
    elif system == "Darwin":
        return home / "Library" / "Application Support" / "Google" / "Chrome"
    else:
        return home / ".config" / "google-chrome"


def _debug_screenshot_path(label: str = "debug") -> Path:
    """Gera um caminho único para screenshot de debug (nunca sobrescreve)."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    return Path(__file__).parent / f"{label}-{ts}.png"


# ─────────────────────────────────────────────────
# Helper de browser: primeiro seletor visível
# ─────────────────────────────────────────────────
async def first_visible(page, selectors: list[str], timeout_ms: int = 3000):
    """Tenta cada seletor e retorna (element, selector) para o primeiro visível.

    Retorna (None, None) se nenhum for encontrado.
    """
    try:
        from playwright.async_api import TimeoutError as PWTimeout
    except ImportError:
        raise ImportError("Playwright não instalado. Execute: pip install playwright")

    for selector in selectors:
        try:
            el = await page.wait_for_selector(selector, timeout=timeout_ms, state="visible")
            if el:
                return el, selector
        except PWTimeout:
            continue
    return None, None


# ─────────────────────────────────────────────────
# Modo API — Threads Graph API
# ─────────────────────────────────────────────────
@dataclass
class ThreadsAPIClient:
    user_id: str
    access_token: str

    async def _wait_for_container_ready(
        self, client: httpx.AsyncClient, container_id: str
    ) -> None:
        """Aguarda o container de mídia ficar pronto para publicação (até 30s)."""
        print("⏳ Aguardando processamento...")
        for attempt in range(10):
            await asyncio.sleep(3)
            resp = await client.get(
                f"{THREADS_API_BASE}/{container_id}",
                params={"fields": "status,error_message", "access_token": self.access_token},
            )
            resp.raise_for_status()
            data = resp.json()
            status = data.get("status", "")
            if status == "FINISHED":
                return
            if status == "ERROR":
                raise RuntimeError(f"Container com erro: {data.get('error_message', 'desconhecido')}")
            print(f"   Status: {status} (tentativa {attempt + 1}/10)")
        raise TimeoutError("Container não ficou pronto em 30 segundos.")

    async def post(self, text: str) -> dict:
        """Publica um post de texto no Threads via API oficial."""
        text, was_truncated = truncate_for_threads(text)
        if was_truncated:
            print(f"⚠️  Texto truncado para {MAX_CHARS} caracteres.")

        async with httpx.AsyncClient(timeout=30) as client:
            # 1. Cria o container de mídia
            print("📤 Criando container no Threads...")
            resp = await client.post(
                f"{THREADS_API_BASE}/{self.user_id}/threads",
                params={"media_type": "TEXT", "text": text, "access_token": self.access_token},
            )
            resp.raise_for_status()
            container_id = resp.json()["id"]
            print(f"✅ Container criado: {container_id}")

            # 2. Aguarda o container ficar pronto
            await self._wait_for_container_ready(client, container_id)

            # 3. Publica
            print("🚀 Publicando...")
            pub_resp = await client.post(
                f"{THREADS_API_BASE}/{self.user_id}/threads_publish",
                params={"creation_id": container_id, "access_token": self.access_token},
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
    profile_dir: Optional[Path] = None,
    profile_name: str = "Default",
    headless: bool = False,
) -> dict:
    """Publica no Threads abrindo o Chrome com o perfil já logado."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise ImportError(
            "Playwright não instalado. Execute:\n"
            "  pip install playwright\n"
            "  playwright install chrome"
        )

    text, was_truncated = truncate_for_threads(text)
    if was_truncated:
        print(f"⚠️  Texto truncado para {MAX_CHARS} caracteres.")

    profile_dir = profile_dir or Path(
        os.getenv("CHROME_PROFILE_DIR", "") or default_chrome_profile()
    )
    profile_name = os.getenv("CHROME_PROFILE_NAME", profile_name)
    headless = os.getenv("CHROME_HEADLESS", str(headless)).lower() in ("true", "1", "yes")

    print(f"🌐 Abrindo Chrome com perfil: {profile_dir / profile_name}")
    print(f"   Headless: {headless}")

    async with async_playwright() as p:
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

            if "login" in page.url.lower() or "signup" in page.url.lower():
                raise RuntimeError(
                    "❌ Chrome não está logado no Threads.\n"
                    "   Abra o Chrome manualmente, faça login em threads.net,\n"
                    "   e execute o poster novamente."
                )

            # ── Abre o composer ────────────────────────────────────
            print("✏️  Abrindo formulário de novo post...")
            compose_selectors = [
                'a[href="/compose"]',
                '[aria-label="New thread"]',
                '[aria-label="Novo thread"]',
                'svg[aria-label="New thread"]',
                'div[role="button"]:has-text("New thread")',
                'div[role="button"]:has-text("Novo thread")',
                'nav a[href*="compose"]',
            ]
            compose_btn, used = await first_visible(page, compose_selectors)
            if compose_btn:
                print(f"   Encontrado: {used}")
                await compose_btn.click()
                await page.wait_for_timeout(1500)
            else:
                print("   Tentando via URL /compose...")
                await page.goto(f"{THREADS_URL}/compose", wait_until="networkidle")
                await page.wait_for_timeout(2000)

            # ── Campo de texto ─────────────────────────────────────
            print("⌨️  Digitando o post...")
            text_area_selectors = [
                '[contenteditable="true"]',
                'textarea[placeholder*="thread"]',
                'textarea[placeholder*="Thread"]',
                'div[role="textbox"]',
            ]
            text_area, used = await first_visible(page, text_area_selectors, timeout_ms=5000)
            if not text_area:
                screenshot_path = _debug_screenshot_path("debug-no-textarea")
                await page.screenshot(path=str(screenshot_path))
                raise RuntimeError(
                    f"❌ Campo de texto não encontrado.\n"
                    f"   Screenshot salvo em: {screenshot_path}\n"
                    f"   A interface do Threads pode ter mudado."
                )
            print(f"   Campo encontrado: {used}")

            await text_area.click()
            await page.wait_for_timeout(500)
            await page.evaluate(
                """(text) => {
                    const el = document.querySelector('[contenteditable="true"]')
                           || document.querySelector('div[role="textbox"]')
                           || document.querySelector('textarea');
                    if (el) { el.focus(); document.execCommand('insertText', false, text); }
                }""",
                text,
            )
            await page.wait_for_timeout(1000)

            # ── Publica ────────────────────────────────────────────
            print("🚀 Publicando...")
            publish_selectors = [
                'button:has-text("Post")',
                'button:has-text("Publicar")',
                'div[role="button"]:has-text("Post")',
                'div[role="button"]:has-text("Publicar")',
                '[aria-label="Post"]',
                '[aria-label="Publicar"]',
            ]
            publish_btn, used = await first_visible(page, publish_selectors)
            if publish_btn and not await publish_btn.is_enabled():
                publish_btn = None  # botão desabilitado não conta

            if not publish_btn:
                screenshot_path = _debug_screenshot_path("debug-no-publish-btn")
                await page.screenshot(path=str(screenshot_path))
                raise RuntimeError(
                    f"❌ Botão 'Publicar' não encontrado ou desabilitado.\n"
                    f"   Screenshot salvo em: {screenshot_path}"
                )
            print(f"   Botão encontrado: {used}")
            await publish_btn.click()
            await page.wait_for_timeout(3000)

            # ── Confirmação ────────────────────────────────────────
            screenshot_path = _debug_screenshot_path("post-confirma")
            await page.screenshot(path=str(screenshot_path))
            print(f"📸 Screenshot de confirmação: {screenshot_path}")

            return {
                "success": True,
                "post_id": None,
                "url": THREADS_URL,
                "mode": "browser",
                "screenshot": str(screenshot_path),
            }

        finally:
            await context.close()


# ─────────────────────────────────────────────────
# Dispatcher principal
# ─────────────────────────────────────────────────
async def publish_to_threads(text: str, mode: str = "auto") -> dict:
    """Publica no Threads. mode: 'api' | 'browser' | 'auto'."""
    mode = os.getenv("POSTER_MODE", mode)

    if mode in ("api", "auto"):
        user_id = os.getenv("THREADS_USER_ID", "")
        token = os.getenv("THREADS_ACCESS_TOKEN", "")
        if user_id and token:
            try:
                return await ThreadsAPIClient(user_id=user_id, access_token=token).post(text)
            except Exception as e:
                if mode == "api":
                    raise
                print(f"⚠️  API falhou: {e}")
                print("↩️  Tentando modo browser como fallback...")
        elif mode == "api":
            raise RuntimeError("THREADS_USER_ID e THREADS_ACCESS_TOKEN não configurados no .env")

    return await post_via_browser(text)


# ─────────────────────────────────────────────────
# CLI direto
# ─────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Posta texto no Threads")
    parser.add_argument("--text", required=True, help="Texto do post")
    parser.add_argument(
        "--mode", choices=["api", "browser", "auto"], default="auto",
        help="Modo de publicação (padrão: auto)",
    )
    args = parser.parse_args()

    result = asyncio.run(publish_to_threads(args.text, args.mode))

    if result["success"]:
        print(f"\n✅ Post publicado com sucesso! (modo: {result['mode']})")
        if result.get("url"):
            print(f"   URL: {result['url']}")
    else:
        print("\n❌ Falha ao publicar")
        sys.exit(1)
