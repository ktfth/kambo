"""Tests for input sanitization module."""

from __future__ import annotations

import pytest

from kambo.sanitize import (
    shell_quote,
    validate_port_spec,
    validate_severity,
    validate_shell_arg,
    validate_timing,
)


class TestShellQuote:
    def test_simple_string(self):
        result = shell_quote("example.com")
        assert "example.com" in result
        assert ";" not in result or result.startswith("'")  # safe

    def test_string_with_spaces(self):
        assert shell_quote("hello world") == "'hello world'"

    def test_string_with_single_quote(self):
        result = shell_quote("it's")
        assert "'" in result
        assert "it" in result
        assert "s" in result

    def test_command_injection_semicolon(self):
        result = shell_quote("example.com; rm -rf /")
        assert result.startswith("'")
        assert result.endswith("'")
        assert "rm" in result  # literal string, not executed

    def test_command_injection_backtick(self):
        result = shell_quote("example.com`whoami`")
        assert "`" in result

    def test_command_injection_dollar_paren(self):
        result = shell_quote("example.com$(whoami)")
        assert "$(" in result

    def test_command_injection_pipe(self):
        result = shell_quote("example.com | cat /etc/passwd")
        assert "|" in result

    def test_command_injection_ampersand(self):
        result = shell_quote("example.com && curl attacker.com")
        assert "&&" in result

    def test_empty_string(self):
        result = shell_quote("")
        assert result == "''"

    def test_url_with_special_chars(self):
        result = shell_quote("http://example.com/path?a=1&b=2")
        assert "?" in result
        assert "&" in result


class TestValidateShellArg:
    def test_valid_arg(self):
        result = validate_shell_arg("example.com", "target")
        assert "example.com" in result

    def test_null_byte_rejected(self):
        with pytest.raises(ValueError, match="null byte"):
            validate_shell_arg("example\x00.com", "target")

    def test_max_length_rejected(self):
        with pytest.raises(ValueError, match="exceeds maximum length"):
            validate_shell_arg("x" * 5000, "target")

    def test_custom_max_length(self):
        with pytest.raises(ValueError, match="exceeds maximum length"):
            validate_shell_arg("x" * 100, "target", max_length=50)


class TestValidatePortSpec:
    def test_single_port(self):
        assert validate_port_spec("80") == "80"

    def test_port_range(self):
        assert validate_port_spec("1-1024") == "1-1024"

    def test_port_list(self):
        assert validate_port_spec("80,443,8080") == "80,443,8080"

    def test_all_ports(self):
        assert validate_port_spec("-") == "-"

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError, match="Invalid port"):
            validate_port_spec("80; rm -rf /")

    def test_rejects_backtick(self):
        with pytest.raises(ValueError, match="Invalid port"):
            validate_port_spec("80`whoami`")

    def test_rejects_alpha(self):
        with pytest.raises(ValueError, match="Invalid port"):
            validate_port_spec("abc")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="Empty port"):
            validate_port_spec("")


class TestValidateSeverity:
    def test_valid_severity(self):
        assert validate_severity("critical,high") == "critical,high"

    def test_single_severity(self):
        assert validate_severity("critical") == "critical"

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError, match="Invalid severity"):
            validate_severity("critical; rm -rf /")

    def test_rejects_space_injection(self):
        with pytest.raises(ValueError, match="Invalid severity"):
            validate_severity("critical --something")


class TestValidateTiming:
    def test_valid_values(self):
        for i in range(6):
            assert validate_timing(i) == i

    def test_negative_rejected(self):
        with pytest.raises(ValueError, match="Invalid timing"):
            validate_timing(-1)

    def test_too_high_rejected(self):
        with pytest.raises(ValueError, match="Invalid timing"):
            validate_timing(6)
