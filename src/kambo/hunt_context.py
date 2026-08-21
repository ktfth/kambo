"""Scope-clean, token-budgeted engagement briefing assembly.

Pure logic for :mod:`kambo.tools.context`: scope projection, per-budget item
caps, honest section envelopes, token estimation and the small derivations
(inferred phase, evidence gap) the briefing needs. No MCP surface, no I/O.

Two invariants drive every helper here:

* **Out-of-scope surface is omitted, never echoed.** A suppressed value does
  not appear in the result, in a reason, or in an error message — only in a
  closed-vocabulary counter, keyed by an opaque digest so the same value seen by
  several section builders counts once. ``ScopeViolationError`` stringifies the
  target, so it is classified, never rendered.
* **Failure and healthy-empty are distinct states.** ``available: false``
  always carries a reason; ``available: true`` never does. A source that
  returned nothing is not a source that broke.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from kambo.models import Confidence, Phase
from kambo.scope import ScopeViolationError, get_scope_manager

# ── budget ───────────────────────────────────────────────────────────────────

BUDGETS: tuple[str, ...] = ("tight", "normal", "deep")
MODES: tuple[str, ...] = ("brief", "resume", "scope", "evidence")

_BUDGET_LIMITS: dict[str, dict[str, int]] = {
    "tight": {"surface": 5, "board": 3, "findings": 3, "next_moves": 3,
              "evidence": 3, "scope_targets": 10, "untouched": 5},
    "normal": {"surface": 15, "board": 8, "findings": 10, "next_moves": 5,
               "evidence": 8, "scope_targets": 25, "untouched": 12},
    "deep": {"surface": 40, "board": 25, "findings": 30, "next_moves": 10,
             "evidence": 25, "scope_targets": 100, "untouched": 25},
}

# Normalisation of pipeline suggestion order (priority 0 = strongest) onto the
# same 0-100 scale the notes ROI score uses, so both sources can be ranked in
# one list without pretending the pipeline order is an ROI estimate.
_PIPELINE_BASE_SCORE = 60
_PIPELINE_STEP_DECAY = 10

# Weight thresholds from models.EvidenceChain.weight_confidence.
_FIRM_WEIGHT = 1.0
_CONFIRMED_WEIGHT = 2.0

# Closed vocabulary for suppression reasons — never a raw exception string.
REASON_EXCLUDED = "excluded"
REASON_NOT_IN_SCOPE = "not_in_scope"
REASON_MALFORMED = "malformed"

# Value kinds returned by :func:`classify_value`.
KIND_HOST = "host"          # locational — must be validated against the scope
KIND_FREE = "free"          # not locational (bare port, request path) — passes free
KIND_MALFORMED = "malformed"  # looks locational but no host can be extracted

_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_AUTHORITY_SPLIT = re.compile(r"[/?#]")
_BRACKETED_V6 = re.compile(r"^\[(?P<v6>[0-9A-Fa-f:.]+)\](?::\d+)?$")
_HOST_PORT = re.compile(r"^(?P<host>[^:]+):\d+$")
_DIGITS = re.compile(r"^\d+$")
# A hostname label set: letters, digits, dot, hyphen, underscore (``_dmarc``).
_HOSTNAME = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9._\-]*[A-Za-z0-9_])?$")


def budget_limits(budget: str) -> dict[str, int]:
    """Per-section item caps for ``budget``. Unknown names fall back to
    ``normal`` rather than raising — invalid input is answered, never thrown.
    Returns a copy so callers cannot mutate the table."""
    return dict(_BUDGET_LIMITS.get(budget, _BUDGET_LIMITS["normal"]))


# ── scope ────────────────────────────────────────────────────────────────────


class ScopeFilterResult(BaseModel):
    """Outcome of projecting a list of values onto the authorised scope.

    ``kept`` holds only in-scope (or non-locational) values. Suppressed values
    are recorded as opaque ``reason:sha256`` marks — never as the value itself,
    so serialising this object can never leak a forbidden target — and the marks
    are what makes the counter *value*-based: the same host suppressed by three
    different section builders folds into one suppression, not three.
    """

    model_config = {"frozen": True}

    kept: list[str] = Field(default_factory=list)
    suppressed_marks: tuple[str, ...] = Field(default_factory=tuple)

    @property
    def suppressed(self) -> int:
        """Number of *distinct* values suppressed."""
        return len(self.suppressed_marks)

    @property
    def reasons(self) -> dict[str, int]:
        """Distinct suppressions per closed reason code."""
        out: dict[str, int] = {}
        for mark in self.suppressed_marks:
            code = mark.split(":", 1)[0]
            out[code] = out.get(code, 0) + 1
        return out


def suppression_mark(reason: str, identity: str) -> str:
    """An opaque, stable mark for one suppressed value.

    The identity is hashed so two builders that saw the same value produce the
    same mark (enabling de-duplication) while the value itself never survives
    into a serialisable field.
    """
    digest = hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()
    return f"{reason}:{digest}"


def _dedupe(marks: Iterable[str]) -> tuple[str, ...]:
    """Distinct marks in a stable order."""
    return tuple(sorted(set(marks)))


def _host_key(host: str) -> str:
    """The validated, normalised host of ``host``, or ``""`` when it is not a
    well-formed host.

    Accepts IPv4/IPv6 literals (via :mod:`ipaddress`) and hostnames restricted
    to the DNS charset. A leading ``*.`` wildcard label is dropped so a wildcard
    SAN is checked against its base domain. Anything else — a blob with spaces,
    an embedded URL, a stray delimiter — is rejected rather than forwarded to
    ``ScopeManager.validate``, whose matcher would happily find an in-scope host
    *inside* it.
    """
    candidate = host.strip().rstrip(".").lower()
    if candidate.startswith("*."):
        candidate = candidate[2:]
    if not candidate:
        return ""
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    return candidate if _HOSTNAME.match(candidate) else ""


def classify_value(value: str) -> tuple[str, str]:
    """Classify a surface value as ``(kind, key)``.

    * ``KIND_HOST`` — locational; ``key`` is the bare host to validate.
    * ``KIND_FREE`` — not locational (a bare port, a request path); it passes
      free and is never counted, because validating ``443`` would suppress it as
      out-of-scope and corrupt the counter.
    * ``KIND_MALFORMED`` — it occupies a locational field but no host can be
      extracted from it. It is suppressed, never emitted: failing closed is the
      only safe answer for a value whose locality cannot be established.

    Locality is derived by parsing, not by string shape: a protocol-relative
    ``//host/path`` is a URL (not a path), an IPv6 literal is a host (not an
    opaque token), and ``attacker.test/redir?to=https://in.scope/`` yields
    ``attacker.test`` (not the host embedded in its query string).
    """
    raw = value.strip()
    if not raw:
        return KIND_MALFORMED, raw
    if raw.startswith("//"):
        raw = "https:" + raw  # protocol-relative URL — locational, not a path
    elif raw.startswith("/"):
        return KIND_FREE, ""  # request path, not a host

    if _SCHEME.match(raw):
        key = _host_key(urlsplit(raw).hostname or "")
        return (KIND_HOST, key) if key else (KIND_MALFORMED, value.strip())

    authority = _AUTHORITY_SPLIT.split(raw, maxsplit=1)[0]
    if not authority:
        return KIND_MALFORMED, value.strip()

    bracketed = _BRACKETED_V6.match(authority)
    if bracketed:
        key = _host_key(bracketed.group("v6"))
        return (KIND_HOST, key) if key else (KIND_MALFORMED, value.strip())

    with_port = _HOST_PORT.match(authority)
    if with_port:
        authority = with_port.group("host")
    if _DIGITS.match(authority):
        return KIND_FREE, ""  # bare port number

    key = _host_key(authority)
    return (KIND_HOST, key) if key else (KIND_MALFORMED, value.strip())


def scope_key(value: str) -> str | None:
    """The validatable host of a surface value, or ``None`` when the value is
    not locational at all. Malformed values have no key either — use
    :func:`classify_value` when the difference matters."""
    kind, key = classify_value(value)
    return key if kind == KIND_HOST else None


def _classify(exc: ScopeViolationError) -> str:
    """Map a violation onto a closed reason code. The exception message embeds
    the target (and the full authorised list) — only ``reason`` is inspected,
    and only its shape, never its text."""
    return REASON_EXCLUDED if exc.reason.startswith("Matches") else REASON_NOT_IN_SCOPE


def filter_scope(values: Iterable[str]) -> ScopeFilterResult:
    """Project ``values`` onto the active scope, preserving input order.

    Non-locational values are kept and not counted; values that occupy a
    locational field but carry no extractable host are suppressed as
    ``malformed``; anything ``ScopeManager.validate`` rejects is dropped and
    counted under a closed reason code. Suppressions are recorded per distinct
    value, so re-filtering the same list twice does not double the counter.
    """
    manager = get_scope_manager()
    kept: list[str] = []
    marks: list[str] = []

    for raw in values:
        value = str(raw)
        kind, key = classify_value(value)
        if kind == KIND_FREE:
            kept.append(value)
            continue
        if kind == KIND_MALFORMED:
            marks.append(suppression_mark(REASON_MALFORMED, value))
            continue
        try:
            manager.validate(key)
        except ScopeViolationError as exc:
            marks.append(suppression_mark(_classify(exc), key))
            continue
        kept.append(value)

    return ScopeFilterResult(kept=kept, suppressed_marks=_dedupe(marks))


def combine(*results: ScopeFilterResult) -> ScopeFilterResult:
    """Fold several filter results into one: kept lists are concatenated and
    suppression marks are *unioned* — a value suppressed by two sections is one
    suppression, not two."""
    kept: list[str] = []
    marks: list[str] = []
    for result in results:
        kept.extend(result.kept)
        marks.extend(result.suppressed_marks)
    return ScopeFilterResult(kept=kept, suppressed_marks=_dedupe(marks))


def merge_suppression(*results: ScopeFilterResult) -> dict[str, Any]:
    """The payload-level suppression counter: total plus per-reason tallies
    (zeros omitted)."""
    merged = combine(*results)
    return {
        "count": merged.suppressed,
        "reasons": {code: count for code, count in merged.reasons.items() if count > 0},
    }


# ── sections ─────────────────────────────────────────────────────────────────


def list_section(
    items: list[Any], limit: int, *, available: bool = True, reason: str = ""
) -> tuple[dict[str, Any], int]:
    """A list envelope plus the number of items the budget cut.

    ``count`` is the length *after* truncation; the pre-truncation total is
    ``count + n_omitted``.
    """
    if not available:
        return {"available": False, "reason": reason or "source unavailable",
                "count": 0, "items": []}, 0
    capped = list(items[: max(0, limit)])
    omitted = max(0, len(items) - len(capped))
    return {"available": True, "reason": "", "count": len(capped), "items": capped}, omitted


def map_section(
    data: dict[str, Any], *, available: bool = True, reason: str = ""
) -> dict[str, Any]:
    """A map envelope. ``data`` is empty whenever the section is unavailable."""
    if not available:
        return {"available": False, "reason": reason or "source unavailable", "data": {}}
    return {"available": True, "reason": "", "data": dict(data)}


def unavailable(reason: str, *, as_map: bool = False) -> dict[str, Any]:
    """An honestly empty section. ``reason`` is never blank when unavailable."""
    stated = reason or "source unavailable"
    if as_map:
        return map_section({}, available=False, reason=stated)
    section, _ = list_section([], 0, available=False, reason=stated)
    return section


def source_failure(source: str, exc: Exception, *, as_map: bool = False) -> dict[str, Any]:
    """Section for a source that raised — the failure is named, not masked as
    an empty result (the silent-zero bug class)."""
    return unavailable(f"{source} unavailable: {type(exc).__name__}: {exc}", as_map=as_map)


# ── tokens ───────────────────────────────────────────────────────────────────


def estimate_tokens(payload: dict[str, Any]) -> int:
    """Declared approximation: serialized characters // 4.

    The serialization mirrors the one the MCP transport actually writes
    (``json.dumps(result, indent=2, default=str)`` in :mod:`kambo.server`) —
    estimating against a compact dump understated the real cost by ~1.5x, which
    is worst exactly where the budget matters: deep nesting and long lists.
    Called before the ``estimated_tokens`` key itself exists, so it never counts
    itself.
    """
    return len(json.dumps(payload, indent=2, default=str)) // 4


def finalize(payload: dict[str, Any], truncated: dict[str, int]) -> dict[str, Any]:
    """Attach the truncation report and the token estimate. Returns a new dict;
    the input is left untouched."""
    out = dict(payload)
    out["truncated"] = {key: count for key, count in truncated.items() if count > 0}
    out["estimated_tokens"] = estimate_tokens(out)
    return out


# ── derivations ──────────────────────────────────────────────────────────────

_VULN_ASSETS = ("finding", "url", "endpoint", "parameter")
_SCAN_ASSETS = ("port", "subdomain", "ip")


def infer_phase(pipeline_summary: dict[str, Any]) -> str:
    """Infer the engagement phase from what the pipeline has accumulated."""
    counts = pipeline_summary.get("asset_counts") or {}
    if any(counts.get(key) for key in _VULN_ASSETS):
        return Phase.VULN_ANALYSIS.value
    if any(counts.get(key) for key in _SCAN_ASSETS):
        return Phase.SCANNING.value
    return Phase.RECON.value


def evidence_gap(chain_summary: dict[str, Any]) -> dict[str, Any]:
    """What is missing to raise this evidence chain one confidence tier.

    When a ceiling is in force the remaining weight is still reported, but
    ``blocked_by_ceiling`` and the advice say plainly that piling on signals
    will not move the confidence: the gate has to be cleared first.

    A summary flagged ``parsed: False`` (the stored chain could not be rebuilt)
    never produces "add more weight" advice: an unknown ceiling fails closed and
    the gap says the chain is unreadable.
    """
    weight = float(chain_summary.get("total_weight") or 0.0)
    ceiling = str(chain_summary.get("ceiling") or Confidence.CONFIRMED.value)
    gates = [str(gate) for gate in (chain_summary.get("gates") or [])]
    to_firm = round(max(0.0, _FIRM_WEIGHT - weight), 2)
    to_confirmed = round(max(0.0, _CONFIRMED_WEIGHT - weight), 2)
    blocked = ceiling != Confidence.CONFIRMED.value
    unreadable = chain_summary.get("parsed", True) is False

    if unreadable:
        advice = (
            "evidence chain unreadable — the stored chain could not be parsed, so "
            "no ceiling, gate or weight can be trusted here. Re-read the finding "
            "before acting on it."
        )
    elif blocked:
        gate_text = "; ".join(gates) if gates else "no gate recorded"
        advice = (
            f"confidence is capped at '{ceiling}': adding more signals does not "
            f"raise it. Clear the gate first — {gate_text}."
        )
    elif to_confirmed == 0.0:
        advice = "evidence weight already reaches CONFIRMED — write it up."
    elif to_firm > 0.0:
        advice = (
            f"add {to_firm} more evidence weight to reach FIRM, {to_confirmed} to "
            "reach CONFIRMED."
        )
    else:
        advice = f"add {to_confirmed} more evidence weight to reach CONFIRMED."

    return {
        "to_firm": to_firm,
        "to_confirmed": to_confirmed,
        "blocked_by_ceiling": blocked,
        "ceiling": ceiling,
        "gates": gates,
        "chain_unreadable": unreadable,
        "advice": advice,
    }
