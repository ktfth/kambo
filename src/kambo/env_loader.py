"""Zero-dependency .env loader.

The MCP server reads credentials (HACKERONE_API_USER / HACKERONE_API_TOKEN,
etc.) from ``os.environ`` at call time. When the server is launched by a
runner that does not inject the project's ``.env`` file, those variables are
missing and platform tools fail with "credentials not set". This module loads
the repo-root ``.env`` at server startup, without overriding any value that is
already present in the real process environment.

Kept dependency-free on purpose: it must work immediately on the next server
restart without requiring an extra ``pip install``.
"""

from __future__ import annotations

import os
from pathlib import Path


def find_env_file() -> Path | None:
    """Locate the ``.env`` file: repo root (two levels above this package) then cwd."""
    candidates = [
        Path(__file__).resolve().parents[2] / ".env",  # repo root
        Path.cwd() / ".env",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


def load_dotenv(path: Path | None = None, *, override: bool = False) -> list[str]:
    """Populate ``os.environ`` from a ``.env`` file.

    Args:
        path: Explicit ``.env`` path. Defaults to :func:`find_env_file`.
        override: When False (default), existing environment variables are
            preserved. When True, file values overwrite them.

    Returns:
        The list of keys that were set (empty if no file was found).

    Blank lines, ``#`` comments, and malformed lines (no ``=``) are skipped.
    A leading ``export`` and surrounding single/double quotes are stripped.
    """
    env_path = path or find_env_file()
    if env_path is None or not env_path.is_file():
        return []

    loaded: list[str] = []
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if override or key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded
