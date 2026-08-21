"""Tests for the hunt_context assembly engine (scope filter, budget, tokens).

Pure-logic layer only — no MCP surface, no I/O. Reserved domains only.
"""

from __future__ import annotations

import json

import pytest

from kambo.hunt_context import (
    _BUDGET_LIMITS,
    BUDGETS,
    KIND_FREE,
    KIND_HOST,
    KIND_MALFORMED,
    ScopeFilterResult,
    budget_limits,
    classify_value,
    combine,
    estimate_tokens,
    evidence_gap,
    filter_scope,
    finalize,
    infer_phase,
    list_section,
    map_section,
    merge_suppression,
    scope_key,
    unavailable,
)
from kambo.models import Confidence, EngagementScope, EvidenceChain, ScopeTarget
from kambo.scope import get_scope_manager


class TestScopeFilter:
    """Out-of-scope surface is omitted and only counted — never echoed."""

    async def test_filter_scope_keeps_in_scope_hosts(self) -> None:
        res = filter_scope(["api.example.com", "https://x.example.com/a"])
        assert res.kept == ["api.example.com", "https://x.example.com/a"]
        assert res.suppressed == 0
        assert res.reasons == {}

    async def test_filter_scope_omits_out_of_scope_and_never_leaks(self) -> None:
        res = filter_scope(["api.example.com", "evil.invalid"])
        assert res.kept == ["api.example.com"]
        assert res.suppressed == 1
        assert "evil.invalid" not in json.dumps(res.model_dump())

    async def test_filter_scope_classifies_exclusion_vs_not_in_scope(self) -> None:
        get_scope_manager().set_scope(EngagementScope(
            engagement_id="EXC-001",
            targets=[ScopeTarget(target="*.example.com")],
            exclusions=["admin.example.com"],
        ))
        res = filter_scope(["admin.example.com", "evil.invalid"])
        assert res.kept == []
        assert res.reasons == {"excluded": 1, "not_in_scope": 1}

    async def test_filter_scope_no_scope_configured(self) -> None:
        get_scope_manager().clear_scope()
        res = filter_scope(["api.example.com", "x.target.com"])
        assert res.kept == []
        assert res.suppressed == 2
        assert set(res.reasons) <= {"not_in_scope", "excluded", "malformed"}

    async def test_scope_key_strips_port_and_passes_bare_port(self) -> None:
        assert scope_key("api.example.com:8443") == "api.example.com"
        assert scope_key("443") is None
        assert scope_key("") is None

    async def test_filter_scope_bare_port_not_counted_as_suppressed(self) -> None:
        res = filter_scope(["443", "8080"])
        assert res.kept == ["443", "8080"]
        assert res.suppressed == 0

    async def test_filter_scope_blank_counted_as_malformed(self) -> None:
        res = filter_scope(["", "   "])
        assert res.kept == []
        assert res.reasons == {"malformed": 2}

    async def test_filter_scope_does_not_mutate_input(self) -> None:
        values = ["api.example.com", "evil.invalid"]
        filter_scope(values)
        assert values == ["api.example.com", "evil.invalid"]

    async def test_merge_suppression_sums_and_drops_zeros(self) -> None:
        a = filter_scope(["evil.invalid"])
        b = filter_scope(["", "other.invalid"])
        merged = merge_suppression(a, b)
        assert merged["count"] == 3
        assert merged["reasons"] == {"not_in_scope": 2, "malformed": 1}
        assert all(v > 0 for v in merged["reasons"].values())

    async def test_merge_suppression_empty_is_zeroed(self) -> None:
        merged = merge_suppression(ScopeFilterResult())
        assert merged == {"count": 0, "reasons": {}}


class TestSections:
    """Envelopes are honest: failure and healthy-empty are distinct states."""

    async def test_list_section_truncates_and_reports_omitted(self) -> None:
        section, omitted = list_section(list(range(30)), 10)
        assert section["count"] == 10
        assert omitted == 20
        assert section["available"] is True
        assert section["reason"] == ""

    async def test_list_section_no_truncation_reports_zero(self) -> None:
        items = [1, 2, 3]
        section, omitted = list_section(items, 10)
        assert omitted == 0
        assert section["count"] == len(items)

    async def test_list_section_empty_is_available(self) -> None:
        section, omitted = list_section([], 10)
        assert section["available"] is True
        assert section["count"] == 0
        assert omitted == 0

    async def test_map_section_unavailable_has_empty_data(self) -> None:
        section = map_section({"a": 1}, available=False, reason="db gone")
        assert section["data"] == {}
        assert section["reason"] == "db gone"

    async def test_unavailable_always_carries_reason(self) -> None:
        for section in (unavailable("boom"), unavailable("boom", as_map=True)):
            assert section["available"] is False
            assert section["reason"] != ""


class TestBudget:
    async def test_budget_limits_monotonic(self) -> None:
        tight = budget_limits("tight")
        normal = budget_limits("normal")
        deep = budget_limits("deep")
        for key in tight:
            assert tight[key] < normal[key] < deep[key], key

    async def test_budget_limits_keys_match_table(self) -> None:
        for name in BUDGETS:
            assert budget_limits(name) == _BUDGET_LIMITS[name]

    async def test_budget_limits_unknown_is_keyerror_free(self) -> None:
        assert budget_limits("nonsense") == _BUDGET_LIMITS["normal"]

    async def test_budget_limits_returns_a_copy(self) -> None:
        limits = budget_limits("normal")
        limits["surface"] = 999
        assert _BUDGET_LIMITS["normal"]["surface"] != 999


class TestTokensAndFinalize:
    async def test_estimate_tokens_positive_and_scales(self) -> None:
        small = {"a": 1}
        big = {"a": [f"item-{i}" for i in range(200)]}
        assert estimate_tokens(small) > 0
        assert estimate_tokens(big) > 0
        assert estimate_tokens(small) < estimate_tokens(big)

    async def test_finalize_omits_zero_truncation_and_is_pure(self) -> None:
        payload = {"sections": {"a": {}, "b": {}}}
        out = finalize(payload, {"a": 3, "b": 0})
        assert out["truncated"] == {"a": 3}
        assert "estimated_tokens" in out
        assert out["estimated_tokens"] > 0
        assert "truncated" not in payload
        assert "estimated_tokens" not in payload

    async def test_finalize_empty_truncation_is_empty_dict(self) -> None:
        out = finalize({"sections": {}}, {})
        assert out["truncated"] == {}


class TestDerivations:
    async def test_infer_phase_from_asset_counts(self) -> None:
        assert infer_phase({}) == "recon"
        assert infer_phase({"asset_counts": {}}) == "recon"
        assert infer_phase({"asset_counts": {"port": 3}}) == "scanning"
        assert infer_phase({"asset_counts": {"subdomain": 2}}) == "scanning"
        assert infer_phase({"asset_counts": {"finding": 1}}) == "vulnerability_analysis"
        assert infer_phase({"asset_counts": {"subdomain": 2, "url": 1}}) == "vulnerability_analysis"

    async def test_evidence_gap_weight_thresholds(self) -> None:
        chain = EvidenceChain().add("probe", "tool", weight=0.5)
        gap = evidence_gap(chain.summary())
        assert gap["to_firm"] == 0.5
        assert gap["to_confirmed"] == 1.5
        assert gap["blocked_by_ceiling"] is False
        assert gap["ceiling"] == "confirmed"

    async def test_evidence_gap_saturated_weight_reports_zero(self) -> None:
        chain = EvidenceChain().add("a", "t", weight=1.5).add("b", "t", weight=1.5)
        gap = evidence_gap(chain.summary())
        assert gap["to_firm"] == 0.0
        assert gap["to_confirmed"] == 0.0

    async def test_evidence_gap_ceiling_blocks_advice(self) -> None:
        chain = (
            EvidenceChain()
            .add("reflected marker", "vuln_xss", weight=1.5)
            .cap(Confidence.FIRM, "no out-of-band callback observed")
        )
        gap = evidence_gap(chain.summary())
        assert gap["blocked_by_ceiling"] is True
        assert gap["ceiling"] == "firm"
        assert gap["gates"]
        assert "does not raise" in gap["advice"].lower()
        assert "no out-of-band callback observed" in gap["advice"]

    async def test_evidence_gap_handles_missing_keys(self) -> None:
        gap = evidence_gap({})
        assert gap["to_firm"] == 1.0
        assert gap["to_confirmed"] == 2.0
        assert gap["blocked_by_ceiling"] is False
        assert gap["gates"] == []
        assert gap["advice"] != ""


class TestLocalityIsParsedNotGuessed:
    """Regression: locality was inferred from string shape, so anything that did
    not *look* like a host slipped past ``validate()`` uncounted."""

    async def test_protocol_relative_url_is_a_host_not_a_path(self) -> None:
        assert classify_value("//telemetry.attacker.test/v1/collect") == (
            KIND_HOST, "telemetry.attacker.test"
        )
        res = filter_scope(["//telemetry.attacker.test/v1/collect", "/api/v1/users"])
        assert res.kept == ["/api/v1/users"]  # a real request path still passes free
        assert res.suppressed == 1
        assert res.reasons == {"not_in_scope": 1}

    async def test_request_path_still_passes_free(self) -> None:
        assert classify_value("/api/v1/users") == (KIND_FREE, "")
        assert filter_scope(["/api/v1/users"]).suppressed == 0

    async def test_ipv6_literal_is_locational(self) -> None:
        assert classify_value("2001:db8::1")[0] == KIND_HOST
        res = filter_scope(["api.example.com", "2001:db8::1"])
        assert res.kept == ["api.example.com"]
        assert res.suppressed == 1

    async def test_bracketed_ipv6_with_port_is_locational(self) -> None:
        assert classify_value("[2001:db8::1]:443") == (KIND_HOST, "2001:db8::1")
        assert filter_scope(["[2001:db8::1]:443"]).kept == []

    async def test_dotless_internal_host_fails_closed(self) -> None:
        assert classify_value("internal-jira") == (KIND_HOST, "internal-jira")
        res = filter_scope(["internal-jira", "localhost"])
        assert res.kept == []
        assert res.suppressed == 2

    async def test_bare_port_is_still_free(self) -> None:
        assert classify_value("443") == (KIND_FREE, "")
        assert filter_scope(["443", "8080"]).suppressed == 0

    async def test_in_scope_ip_literal_survives(self) -> None:
        assert filter_scope(["192.168.1.7", "10.0.0.5"]).kept == ["192.168.1.7", "10.0.0.5"]


class TestNoHostIsInferredFromRawText:
    """Regression: raw text was forwarded to ``ScopeManager.validate``, whose
    matcher would find an in-scope host *inside* the blob and accept it whole."""

    async def test_embedded_in_scope_url_does_not_launder_the_host(self) -> None:
        kind, key = classify_value("attacker.test/redir?to=https://api.example.com/")
        assert (kind, key) == (KIND_HOST, "attacker.test")
        res = filter_scope(["attacker.test/redir?to=https://api.example.com/"])
        assert res.kept == []
        assert res.reasons == {"not_in_scope": 1}

    async def test_blob_ending_in_an_in_scope_suffix_is_malformed(self) -> None:
        assert classify_value("evil.attacker.test api.example.com")[0] == KIND_MALFORMED
        res = filter_scope(["evil.attacker.test api.example.com"])
        assert res.kept == []
        assert res.reasons == {"malformed": 1}

    async def test_url_with_junk_authority_is_malformed(self) -> None:
        res = filter_scope(["https://evil.attacker.test api.example.com/"])
        assert res.kept == []
        assert res.suppressed == 1

    async def test_wildcard_san_is_checked_against_its_base_domain(self) -> None:
        assert filter_scope(["*.example.com"]).kept == ["*.example.com"]
        assert filter_scope(["*.attacker.test"]).kept == []


class TestSuppressionIsCountedPerValue:
    """Regression: the counter was call-based, so one host filtered by four
    section builders was reported as four suppressions."""

    async def test_same_value_filtered_twice_counts_once(self) -> None:
        first = filter_scope(["evil.invalid"])
        second = filter_scope(["evil.invalid"])
        assert merge_suppression(first, second) == {"count": 1, "reasons": {"not_in_scope": 1}}

    async def test_distinct_values_still_add_up(self) -> None:
        merged = merge_suppression(filter_scope(["a.invalid"]), filter_scope(["b.invalid"]))
        assert merged["count"] == 2

    async def test_combine_unions_marks_and_concatenates_kept(self) -> None:
        merged = combine(
            filter_scope(["api.example.com", "evil.invalid"]),
            filter_scope(["api.example.com", "evil.invalid"]),
        )
        assert merged.kept == ["api.example.com", "api.example.com"]
        assert merged.suppressed == 1

    async def test_suppressed_value_never_survives_serialisation(self) -> None:
        res = filter_scope(["evil.invalid", "attacker.test/x"])
        dumped = json.dumps(res.model_dump())
        assert "evil.invalid" not in dumped
        assert "attacker.test" not in dumped


class TestTokenEstimateMatchesTheWire:
    """Regression: the estimate used a compact dump while the transport writes
    ``indent=2``, understating the real cost by ~1.5x."""

    async def test_estimate_mirrors_indented_serialization(self) -> None:
        payload = {
            "sections": {
                "surface": {"items": [f"host{i}.example.com" for i in range(40)]},
                "board": {"items": [{"vector": "xss", "targets": ["a.example.com"]}]},
            }
        }
        assert estimate_tokens(payload) == len(
            json.dumps(payload, indent=2, default=str)
        ) // 4

    async def test_estimate_is_not_the_compact_estimate(self) -> None:
        payload = {"sections": {"a": {"items": [{"k": i} for i in range(50)]}}}
        assert estimate_tokens(payload) > len(json.dumps(payload, default=str)) // 4


class TestEvidenceGapOnUnreadableChain:
    """Regression: a chain that failed to parse was replaced by a default one,
    resetting the ceiling to CONFIRMED and advising 'add more weight'."""

    async def test_unreadable_chain_never_advises_adding_weight(self) -> None:
        gap = evidence_gap({
            "total_weight": 0.0, "ceiling": "tentative", "gates": [], "parsed": False,
        })
        assert gap["chain_unreadable"] is True
        assert gap["blocked_by_ceiling"] is True
        assert "unreadable" in gap["advice"]
        assert "more evidence weight" not in gap["advice"]

    async def test_parsed_chain_keeps_the_normal_advice(self) -> None:
        gap = evidence_gap({"total_weight": 0.5, "ceiling": "confirmed", "gates": []})
        assert gap["chain_unreadable"] is False
        assert "more evidence weight" in gap["advice"]
