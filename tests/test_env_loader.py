"""Tests for the zero-dependency .env loader."""

from __future__ import annotations

import os

import pytest

from kambo.env_loader import find_env_file, load_dotenv


@pytest.fixture
def cleanup_env():
    """Remove KAMBO_T_* keys this test may have set, before and after."""
    def _purge():
        for k in [k for k in os.environ if k.startswith("KAMBO_T_")]:
            os.environ.pop(k, None)
    _purge()
    yield
    _purge()


class TestLoadDotenv:
    def test_sets_unset_keys(self, tmp_path, cleanup_env) -> None:
        env = tmp_path / ".env"
        env.write_text("KAMBO_T_A=hello\nKAMBO_T_B=world\n")
        loaded = load_dotenv(env)
        assert set(loaded) == {"KAMBO_T_A", "KAMBO_T_B"}
        assert os.environ["KAMBO_T_A"] == "hello"
        assert os.environ["KAMBO_T_B"] == "world"

    def test_does_not_override_existing_by_default(self, tmp_path, cleanup_env) -> None:
        os.environ["KAMBO_T_A"] = "real"
        env = tmp_path / ".env"
        env.write_text("KAMBO_T_A=from_file\n")
        loaded = load_dotenv(env)
        assert "KAMBO_T_A" not in loaded
        assert os.environ["KAMBO_T_A"] == "real"

    def test_override_true_replaces(self, tmp_path, cleanup_env) -> None:
        os.environ["KAMBO_T_A"] = "real"
        env = tmp_path / ".env"
        env.write_text("KAMBO_T_A=from_file\n")
        loaded = load_dotenv(env, override=True)
        assert "KAMBO_T_A" in loaded
        assert os.environ["KAMBO_T_A"] == "from_file"

    def test_strips_quotes(self, tmp_path, cleanup_env) -> None:
        env = tmp_path / ".env"
        env.write_text("KAMBO_T_A=\"quoted value\"\nKAMBO_T_B='single quoted'\n")
        load_dotenv(env)
        assert os.environ["KAMBO_T_A"] == "quoted value"
        assert os.environ["KAMBO_T_B"] == "single quoted"

    def test_handles_export_prefix(self, tmp_path, cleanup_env) -> None:
        env = tmp_path / ".env"
        env.write_text("export KAMBO_T_A=exported\n")
        load_dotenv(env)
        assert os.environ["KAMBO_T_A"] == "exported"

    def test_value_with_equals_sign(self, tmp_path, cleanup_env) -> None:
        # Tokens/base64 often contain '='; only the first '=' splits key/value.
        env = tmp_path / ".env"
        env.write_text("KAMBO_T_A=abc==def==\n")
        load_dotenv(env)
        assert os.environ["KAMBO_T_A"] == "abc==def=="

    def test_skips_comments_blank_and_malformed(self, tmp_path, cleanup_env) -> None:
        env = tmp_path / ".env"
        env.write_text("# a comment\n\n   \nNOEQUALSHERE\nKAMBO_T_A=ok\n")
        loaded = load_dotenv(env)
        assert loaded == ["KAMBO_T_A"]
        assert os.environ["KAMBO_T_A"] == "ok"

    def test_missing_file_returns_empty(self, tmp_path, cleanup_env) -> None:
        assert load_dotenv(tmp_path / "does_not_exist.env") == []


class TestFindEnvFile:
    def test_returns_path_or_none(self) -> None:
        # Must not raise and must return a Path or None (repo .env may exist).
        result = find_env_file()
        assert result is None or result.name == ".env"
