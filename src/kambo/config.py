"""Configuration management for Kambo MCP Server."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings


class KamboConfig(BaseSettings):
    """Server configuration loaded from environment variables."""

    model_config = {"env_prefix": "KAMBO_"}

    # Docker
    container_name: str = "kambo-kali"
    docker_timeout: int = 300
    docker_request_timeout: int = 30

    # Paths
    output_dir: Path = Field(default_factory=lambda: Path("./output"))
    wordlists_dir: Path = Field(default_factory=lambda: Path("./wordlists"))
    db_path: Path = Field(default_factory=lambda: Path("./output/kambo.db"))

    # Rate limiting
    recon_rate_limit: int = 10  # requests per second
    exploit_rate_limit: int = 5

    # Defaults
    default_context: Literal["pentest", "bug_bounty", "ctf"] = "pentest"
    max_concurrent_tools: int = 5

    # Network mode for the container
    network_mode: str = "host"


def get_config() -> KamboConfig:
    """Return singleton config instance."""
    return KamboConfig()
