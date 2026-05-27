"""Tests for KamboConfig — defaults and environment variable overrides."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from kambo.config import KamboConfig, get_config


class TestKamboConfigDefaults:
    def test_default_container_name(self) -> None:
        cfg = KamboConfig()
        assert cfg.container_name == "kambo-kali"

    def test_default_docker_timeout(self) -> None:
        cfg = KamboConfig()
        assert cfg.docker_timeout == 300

    def test_default_rate_limits(self) -> None:
        cfg = KamboConfig()
        assert cfg.recon_rate_limit == 10
        assert cfg.exploit_rate_limit == 5

    def test_default_context(self) -> None:
        cfg = KamboConfig()
        assert cfg.default_context == "pentest"

    def test_default_max_concurrent_tools(self) -> None:
        cfg = KamboConfig()
        assert cfg.max_concurrent_tools == 5

    def test_output_dir_is_path(self) -> None:
        cfg = KamboConfig()
        assert isinstance(cfg.output_dir, Path)

    def test_db_path_is_path(self) -> None:
        cfg = KamboConfig()
        assert isinstance(cfg.db_path, Path)
        assert cfg.db_path.name == "kambo.db"


class TestKamboConfigEnvOverride:
    def test_env_prefix(self) -> None:
        with patch.dict(os.environ, {"KAMBO_CONTAINER_NAME": "test-container"}):
            cfg = KamboConfig()
            assert cfg.container_name == "test-container"

    def test_env_timeout_override(self) -> None:
        with patch.dict(os.environ, {"KAMBO_DOCKER_TIMEOUT": "600"}):
            cfg = KamboConfig()
            assert cfg.docker_timeout == 600

    def test_env_context_override(self) -> None:
        with patch.dict(os.environ, {"KAMBO_DEFAULT_CONTEXT": "bug_bounty"}):
            cfg = KamboConfig()
            assert cfg.default_context == "bug_bounty"


class TestGetConfig:
    def test_returns_kambo_config(self) -> None:
        cfg = get_config()
        assert isinstance(cfg, KamboConfig)
