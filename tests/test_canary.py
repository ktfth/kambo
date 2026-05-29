"""Tests for orthogonal canary markers (doctrine P1 / I2)."""

from __future__ import annotations

from kambo.canary import (
    is_orthogonal_marker,
    make_arithmetic_canary,
    make_entropy_token,
)


class TestArithmeticCanary:
    def test_product_is_computed_not_hardcoded(self) -> None:
        c = make_arithmetic_canary(31337, 1337)
        assert c.expression == "31337*1337"
        assert c.expected_render == str(31337 * 1337)
        # Sanity: the doctrine's illustrative product is recomputed correctly here.
        assert c.expected_render == "41897569"

    def test_default_marker_is_orthogonal(self) -> None:
        c = make_arithmetic_canary()
        assert is_orthogonal_marker(c.expected_render)

    def test_custom_factors(self) -> None:
        c = make_arithmetic_canary(99991, 1009)
        assert c.expected_render == str(99991 * 1009)


class TestEntropyToken:
    def test_deterministic(self) -> None:
        assert make_entropy_token("param=q#1") == make_entropy_token("param=q#1")

    def test_unique_per_input(self) -> None:
        assert make_entropy_token("a") != make_entropy_token("b")

    def test_token_is_orthogonal(self) -> None:
        assert is_orthogonal_marker(make_entropy_token("param=q#nonce42"))


class TestIsOrthogonalMarker:
    def test_rejects_empty(self) -> None:
        assert not is_orthogonal_marker("")
        assert not is_orthogonal_marker("   ")

    def test_rejects_small_numbers(self) -> None:
        # The canonical SSTI anti-pattern: {{7*7}} → 49.
        assert not is_orthogonal_marker("49")
        assert not is_orthogonal_marker("12345")

    def test_rejects_repdigits(self) -> None:
        # {{7*'7'}} → 7777777 has only one distinct digit.
        assert not is_orthogonal_marker("7777777")

    def test_rejects_dictionary_words(self) -> None:
        for word in ("admin", "test", "iam", "root", "true", "ADMIN"):
            assert not is_orthogonal_marker(word)

    def test_rejects_plain_words(self) -> None:
        assert not is_orthogonal_marker("welcome")
        assert not is_orthogonal_marker("dashboard")

    def test_accepts_large_varied_number(self) -> None:
        assert is_orthogonal_marker("41897569")

    def test_accepts_high_entropy_token(self) -> None:
        assert is_orthogonal_marker("kc8f3a91be2c4d7e0")

    def test_rejects_short_token(self) -> None:
        assert not is_orthogonal_marker("ab12")
