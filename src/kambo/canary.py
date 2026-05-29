"""Orthogonal canary markers — doctrine P1 / invariant I2.

A detection marker must be *statistically impossible to occur naturally* in a
page's content or markup. Markers that appear in natural language or markup
(``49``, ``iam``, ``test``, ``admin``, small numbers, dictionary words) are
banned: they produce the field's canonical false positives ("``49`` appears 14×
organically in country IDs / SVG paths").

Two orthogonal-marker strategies are provided:

* **Improbable arithmetic** — ``{{31337*1337}}`` renders to a large product that
  no template would emit by coincidence. Used to prove template/expression
  *evaluation* (SSTI, EL, etc.). The product is computed here, never hardcoded,
  so the expected render is always arithmetically correct.
* **High-entropy token** — a unique per-request token derived from a caller
  identifier. Used to prove reflection/propagation without colliding with
  natural content.

This module is deterministic by construction (no RNG) so canaries are
reproducible across a payload/control request pair and inside tests.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass

# Prime-ish factors chosen so the product is large, non-round, and carries many
# distinct digits — maximally unlikely to appear as organic page content.
_ARITH_LEFT = 31337
_ARITH_RIGHT = 1337

# Markers that look like detections but occur constantly in real content.
# Lower-cased; matched exactly against a candidate marker.
_BANNED_WORDS: frozenset[str] = frozenset(
    {
        "admin",
        "test",
        "iam",
        "root",
        "user",
        "true",
        "false",
        "null",
        "error",
        "password",
        "secret",
        "token",
        "id",
        "name",
    }
)

_TOKEN_PREFIX = "kc"  # kambo canary — keeps tokens greppable in raw output

# Thresholds for orthogonality.
_MIN_NUMERIC_DIGITS = 8  # a marker shorter than this is a "small number"
_MIN_DISTINCT_DIGITS = 5  # rejects repdigits and low-variety numbers (zips, prices)
_MIN_TOKEN_LEN = 10
_MIN_TOKEN_ENTROPY = 3.0  # bits/char (Shannon)


@dataclass(frozen=True)
class ArithmeticCanary:
    """An improbable-arithmetic canary: a payload expression and its render."""

    expression: str  # e.g. "31337*1337" — inject inside the relevant template syntax
    expected_render: str  # e.g. "41897569" — what evaluation must produce


def make_arithmetic_canary(
    left: int = _ARITH_LEFT, right: int = _ARITH_RIGHT
) -> ArithmeticCanary:
    """Build an arithmetic canary whose expected render is computed, not assumed.

    The caller wraps ``expression`` in the engine-specific delimiters, e.g.
    ``f"{{{{{c.expression}}}}}"`` → ``{{31337*1337}}`` for Jinja2/Twig.
    """
    product = left * right
    return ArithmeticCanary(expression=f"{left}*{right}", expected_render=str(product))


def make_entropy_token(unique_input: str) -> str:
    """Derive a unique high-entropy marker from a caller-supplied identifier.

    Deterministic: the same ``unique_input`` always yields the same token, so the
    payload request and its negative control can both reference it. Pass a value
    that is unique per detection attempt (parameter name + nonce, request id).
    """
    digest = hashlib.sha256(unique_input.encode("utf-8", errors="replace")).hexdigest()
    return f"{_TOKEN_PREFIX}{digest[:16]}"


def _shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_orthogonal_marker(marker: str) -> bool:
    """Return True iff ``marker`` is safe to use as a detection canary (I2).

    Rejects: empty/whitespace, banned dictionary words, small or repetitive
    numbers, and low-entropy alphanumeric tokens.
    """
    if not marker or not marker.strip():
        return False
    candidate = marker.strip()

    if candidate.lower() in _BANNED_WORDS:
        return False

    # Pure numeric markers: must be long AND have several distinct digits.
    if candidate.isdigit():
        if len(candidate) < _MIN_NUMERIC_DIGITS:
            return False  # small number — occurs organically
        if len(set(candidate)) < _MIN_DISTINCT_DIGITS:
            return False  # repdigit / low variety, e.g. 7777777
        return True

    # Pure alphabetic markers that read like words are not orthogonal.
    if candidate.isalpha():
        return False

    # Mixed alphanumeric tokens: require length + entropy.
    if len(candidate) < _MIN_TOKEN_LEN:
        return False
    return _shannon_entropy(candidate) >= _MIN_TOKEN_ENTROPY
