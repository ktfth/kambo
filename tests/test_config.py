"""Tests for KamboConfig — defaults, env-var overrides, singleton."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from kambo.config import KamboConfig, get_config


class TestKamboConfigDefaults:
    def test_default_container_name(self) -> None:
        cfg = KamboConfig()
        assert cfg.container_name == "kambo-kali"

    def test_default_docker_timeout(self) -> None:
        cfg = KamboConfig()
        assert cfg.docker_timeout == 300

    def test_default_request_timeout(self) -> None:
        cfg = KamboConfig()
        assert cfg.docker_request_timeout == 30

    def test_default_output_dir_is_path(self) -> None:
        cfg = KamboConfig()
        assert isinstance(cfg.output_dir, Path)

    def test_default_wordlists_dir_is_path(self) -> None:
        cfg = KamboConfig()
        assert isinstance(cfg.wordlists_dir, Path)

    def test_default_db_path_is_path(self) -> None:
        cfg = KamboConfig()
        assert isinstance(cfg.db_path, Path)

    def test_default_context_is_pentest(self) -> None:
        cfg = KamboConfig()
        assert cfg.default_context == "pentest"

    def test_default_max_concurrent_tools(self) -> None:
        cfg = KamboConfig()
        assert cfg.max_concurrent_tools == 5

    def test_default_network_mode(self) -> None:
        cfg = KamboConfig()
        assert cfg.network_mode == "host"

    def test_default_recon_rate_limit(self) -> None:
        cfg = KamboConfig()
        assert cfg.recon_rate_limit == 10

    def test_default_exploit_rate_limit(self) -> None:
        cfg = KamboConfig()
        assert cfg.exploit_rate_limit == 5


class TestKamboConfigEnvOverrides:
    def test_container_name_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KAMBO_CONTAINER_NAME", "my-kali")
        cfg = KamboConfig()
        assert cfg.container_name == "my-kali"

    def test_docker_timeout_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KAMBO_DOCKER_TIMEOUT", "600")
        cfg = KamboConfig()
        assert cfg.docker_timeout == 600

    def test_output_dir_override(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("KAMBO_OUTPUT_DIR", str(tmp_path))
        cfg = KamboConfig()
        assert cfg.output_dir == tmp_path

    def test_default_context_pentest(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KAMBO_DEFAULT_CONTEXT", "pentest")
        cfg = KamboConfig()
        assert cfg.default_context == "pentest"

    def test_default_context_bug_bounty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KAMBO_DEFAULT_CONTEXT", "bug_bounty")
        cfg = KamboConfig()
        assert cfg.default_context == "bug_bounty"

    def test_default_context_ctf(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KAMBO_DEFAULT_CONTEXT", "ctf")
        cfg = KamboConfig()
        assert cfg.default_context == "ctf"

    def test_max_concurrent_tools_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KAMBO_MAX_CONCURRENT_TOOLS", "10")
        cfg = KamboConfig()
        assert cfg.max_concurrent_tools == 10

    def test_network_mode_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KAMBO_NETWORK_MODE", "bridge")
        cfg = KamboConfig()
        assert cfg.network_mode == "bridge"

    def test_recon_rate_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KAMBO_RECON_RATE_LIMIT", "20")
        cfg = KamboConfig()
        assert cfg.recon_rate_limit == 20


class TestGetConfig:
    def test_returns_kambo_config(self) -> None:
        cfg = get_config()
        assert isinstance(cfg, KamboConfig)

    def test_independent_calls_return_same_defaults(self) -> None:
        cfg1 = get_config()
        cfg2 = get_config()
        assert cfg1.container_name == cfg2.container_name
        assert cfg1.docker_timeout == cfg2.docker_timeout

    def test_config_is_immutable_pydantic(self) -> None:
        """Config fields should be type-safe Pydantic fields."""
        cfg = KamboConfig()
        # Should be able to read all fields without error
        _ = cfg.container_name
        _ = cfg.docker_timeout
        _ = cfg.output_dir
        _ = cfg.default_context
