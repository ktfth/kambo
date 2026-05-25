"""Tests for the six improvements identified in the refine pass.

1. confidence_pct formula — correct tier mapping
2. validate_xss — closed <script> tag not treated as active context
3. validate_ssrf — 307/308 status codes accepted
4. validate_graphql — new validator
5. validate_race_condition — new validator
6. scan_directories — WAF integration (import-level check)
"""

from __future__ import annotations

import pytest

from kambo.models import Confidence, EvidenceChain
from kambo.validation import (
    validate_graphql,
    validate_race_condition,
    validate_ssrf,
    validate_xss,
)


# ---------------------------------------------------------------------------
# Fix 1: confidence_pct tier mapping
# ---------------------------------------------------------------------------

class TestConfidencePct:
    """TENTATIVE 10–39%, FIRM 50–79%, CONFIRMED 85–99%."""

    def _chain(self, weight: float) -> EvidenceChain:
        chain = EvidenceChain()
        if weight > 0:
            chain = chain.add(signal="test", source="test", weight=weight)
        return chain

    def test_tentative_range(self) -> None:
        pct = self._chain(0.3).confidence_pct
        assert 10 <= pct <= 39, f"TENTATIVE pct {pct} out of expected 10–39 range"

    def test_tentative_boundary(self) -> None:
        pct = self._chain(0.99).confidence_pct
        assert 10 <= pct <= 49

    def test_firm_starts_at_50(self) -> None:
        pct = self._chain(1.0).confidence_pct
        assert pct >= 50, f"FIRM pct {pct} should be >= 50"

    def test_firm_range(self) -> None:
        pct = self._chain(1.5).confidence_pct
        assert 50 <= pct <= 79, f"FIRM pct {pct} out of expected 50–79 range"

    def test_confirmed_starts_at_85(self) -> None:
        pct = self._chain(2.0).confidence_pct
        assert pct >= 85, f"CONFIRMED pct {pct} should be >= 85"

    def test_confirmed_never_100(self) -> None:
        # CONFIRMED caps at 99 — certainty is never absolute
        pct = self._chain(10.0).confidence_pct
        assert pct <= 99, f"CONFIRMED pct {pct} should never reach 100"

    def test_confirmed_grows_with_weight(self) -> None:
        pct_min = self._chain(2.0).confidence_pct
        pct_mid = self._chain(2.5).confidence_pct
        assert pct_mid >= pct_min

    def test_empty_chain_is_zero(self) -> None:
        chain = EvidenceChain()
        assert chain.confidence_pct == 0

    def test_tiers_dont_overlap(self) -> None:
        # Just below FIRM threshold should be < 50
        pct_tentative_max = self._chain(0.99).confidence_pct
        # At FIRM threshold should be >= 50
        pct_firm_min = self._chain(1.0).confidence_pct
        assert pct_tentative_max < pct_firm_min, (
            f"Tier boundary overlap: tentative_max={pct_tentative_max}, firm_min={pct_firm_min}"
        )


# ---------------------------------------------------------------------------
# Fix 2: validate_xss — closed <script> tag
# ---------------------------------------------------------------------------

class TestXssScriptContext:
    """Closed <script> tags must NOT trigger the 'in_script' branch."""

    def test_closed_script_not_flagged_as_script_context(self) -> None:
        payload = '<img src=x onerror=alert(1)>'
        # Payload appears AFTER a closed script block — must NOT be flagged as in_script
        response = f'<script>var x = 1;</script><p>Hello {payload}</p>'
        chain = validate_xss(response, payload, "q")
        signals = [item.signal.lower() for item in chain.items]
        # The "inside <script> block" signal must NOT appear
        assert not any("script" in s and "inside" in s for s in signals), (
            f"Closed <script> incorrectly flagged as active context. Signals: {chain.items}"
        )

    def test_open_script_correctly_flagged(self) -> None:
        payload = "'; alert(1); //"
        response = f"<script>var user = '{payload}';</script>"
        chain = validate_xss(response, payload, "q")
        has_script_signal = any(
            "script" in item.signal.lower() and "inside" in item.signal.lower()
            for item in chain.items
        )
        assert has_script_signal, "Open <script> context not detected"

    def test_unclosed_comment_blocks_xss(self) -> None:
        payload = "<script>alert(1)</script>"
        response = f"<!-- some comment {payload}"
        chain = validate_xss(response, payload, "q")
        fp_checks = " ".join(chain.false_positive_checks).lower()
        assert "comment" in fp_checks, "Unclosed HTML comment should be flagged as FP"

    def test_closed_comment_not_blocked(self) -> None:
        payload = "<script>alert(1)</script>"
        # Comment is closed before the payload — should NOT be treated as inside comment
        response = f"<!-- closed comment --> {payload}"
        chain = validate_xss(response, payload, "q")
        fp_checks = " ".join(chain.false_positive_checks).lower()
        assert "comment" not in fp_checks, (
            f"Closed HTML comment incorrectly blocked XSS. FP checks: {chain.false_positive_checks}"
        )

    def test_multiple_script_tags_with_one_closed(self) -> None:
        payload = "alert(1)"
        # Two opens, two closes before payload — balanced, payload is NOT in script
        response = f"<script>a();</script><script>b();</script><p>{payload}</p>"
        chain = validate_xss(response, payload, "q")
        signals = [item.signal.lower() for item in chain.items]
        assert not any("script" in s and "inside" in s for s in signals), (
            f"Balanced script tags incorrectly flagged. Signals: {chain.items}"
        )


# ---------------------------------------------------------------------------
# Fix 3: validate_ssrf — 307/308 status codes
# ---------------------------------------------------------------------------

class TestSsrfRedirectCodes:
    """307 and 308 must be accepted as valid SSRF indicators."""

    def test_307_accepted(self) -> None:
        chain = validate_ssrf(
            payload="http://169.254.169.254/latest/meta-data/",
            status_code="307",
            response_body="ami-id: ami-12345678",
        )
        # Should have evidence (cloud metadata matched)
        assert chain.total_weight > 0

    def test_308_accepted(self) -> None:
        chain = validate_ssrf(
            payload="http://metadata.google.internal/",
            status_code="308",
            response_body="project-id: my-project instance-id: 123",
        )
        assert chain.total_weight > 0

    def test_307_redirect_with_no_metadata_is_weak(self) -> None:
        chain = validate_ssrf(
            payload="http://internal-host/",
            status_code="307",
            response_body="<html>redirect page</html>",
        )
        # Status alone gives 0.2 weight — tentative signal only
        assert chain.total_weight < 1.0

    def test_non_redirect_blocked(self) -> None:
        chain = validate_ssrf(
            payload="http://internal-host/",
            status_code="403",
            response_body="Access Denied",
        )
        assert chain.total_weight == 0.0
        assert any("blocked" in c.lower() for c in chain.false_positive_checks)

    def test_200_still_works(self) -> None:
        chain = validate_ssrf(
            payload="http://169.254.169.254/",
            status_code="200",
            response_body="ami-id: ami-12345 iam: role-name security-credentials: key",
        )
        assert chain.total_weight >= 1.5


# ---------------------------------------------------------------------------
# Feature 4a: validate_graphql — introspection
# ---------------------------------------------------------------------------

class TestGraphqlIntrospection:
    """Introspection enabled = confirmed schema exposure."""

    def test_introspection_enabled_detected(self) -> None:
        introspection_resp = '{"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"}, "directives": []}}}'
        chain = validate_graphql(
            output="",
            introspection_response=introspection_resp,
        )
        assert chain.total_weight >= 1.0, f"Introspection should give FIRM+ confidence, got {chain.total_weight}"

    def test_disabled_introspection_is_fp(self) -> None:
        chain = validate_graphql(
            output='{"errors": [{"message": "GraphQL introspection is not allowed"}]}',
            introspection_response='{"errors": [{"message": "GraphQL introspection is not allowed"}]}',
        )
        fp_checks = " ".join(chain.false_positive_checks).lower()
        assert "disabled" in fp_checks or "not allowed" in fp_checks

    def test_large_schema_gets_bonus_weight(self) -> None:
        # Build a schema with >5 named types
        types = [f'"name": "Type{i}"' for i in range(10)]
        introspection_resp = '{' + ', '.join(types) + ', "__schema": {"queryType": {"name": "Query"}}}'
        chain = validate_graphql(
            output="",
            introspection_response=introspection_resp,
        )
        assert chain.total_weight >= 1.5

    def test_not_graphql_endpoint_flagged(self) -> None:
        chain = validate_graphql(output="404 Not Found")
        assert chain.total_weight == 0 or len(chain.false_positive_checks) > 0


class TestGraphqlErrors:
    """Error verbosity exposes schema info."""

    def test_suggestion_error_high_weight(self) -> None:
        error_resp = '{"errors": [{"message": "Did you mean \\"userName\\"?"}]}'
        chain = validate_graphql(output="", error_response=error_resp)
        assert chain.total_weight >= 0.8

    def test_field_error_medium_weight(self) -> None:
        error_resp = '{"errors": [{"message": "Cannot query field \\"password\\" on type \\"User\\""}]}'
        chain = validate_graphql(output="", error_response=error_resp)
        assert chain.total_weight >= 0.5

    def test_generic_error_no_schema_leak(self) -> None:
        error_resp = '{"errors": [{"message": "An error occurred"}]}'
        chain = validate_graphql(output="", error_response=error_resp)
        # Generic error = no schema info leaked = low signal
        assert chain.total_weight < 0.5


class TestGraphqlInjection:
    """Injection detection via parse errors."""

    def test_db_error_via_graphql(self) -> None:
        injection_resp = '{"errors": [{"message": "sql error: syntax error near \'injected\'"}]}'
        chain = validate_graphql(output="", injection_response=injection_resp)
        assert chain.total_weight >= 1.0  # DB error = high weight

    def test_parse_error_from_injection(self) -> None:
        injection_resp = '{"errors": [{"message": "Expected Name, got <EOF>"}]}'
        chain = validate_graphql(output="", injection_response=injection_resp)
        assert chain.total_weight >= 0.5


# ---------------------------------------------------------------------------
# Feature 4b: validate_race_condition
# ---------------------------------------------------------------------------

class TestRaceCondition:
    """Race condition detection via parallel response analysis."""

    def test_multiple_successes_detected(self) -> None:
        # 5 parallel requests, all succeeded — expected only 1
        responses = [("200", hash("success_body"), "success") for _ in range(5)]
        chain = validate_race_condition(
            responses=responses,
            expected_unique=1,
            action="redeem_coupon",
        )
        assert chain.total_weight >= 1.0
        assert chain.confidence in (Confidence.FIRM, Confidence.CONFIRMED)

    def test_single_success_is_not_vulnerable(self) -> None:
        # Only 1 out of 10 parallel requests succeeded — proper serialization
        responses = [("200", hash("success"), "ok")] + [("409", 0, "conflict") for _ in range(9)]
        chain = validate_race_condition(
            responses=responses,
            expected_unique=1,
        )
        assert chain.total_weight == 0
        assert any("correctly" in c.lower() or "properly" in c.lower() for c in chain.false_positive_checks)

    def test_all_failures_is_not_vulnerable(self) -> None:
        responses = [("409", 0, "conflict") for _ in range(10)]
        chain = validate_race_condition(responses=responses, expected_unique=1)
        assert chain.total_weight == 0
        assert len(chain.false_positive_checks) > 0

    def test_identical_success_bodies_strengthen_signal(self) -> None:
        # Identical bodies = same resource applied multiple times
        body_hash = hash("same_state")
        responses = [("200", body_hash, "same") for _ in range(3)]
        chain = validate_race_condition(responses=responses, expected_unique=1)
        signal_texts = " ".join(item.signal.lower() for item in chain.items)
        assert "identical" in signal_texts or "same" in signal_texts

    def test_varied_responses_add_variance_signal(self) -> None:
        responses = [
            ("200", hash("response_a"), "state_a"),
            ("200", hash("response_b"), "state_b"),
            ("200", hash("response_c"), "state_c"),
        ]
        chain = validate_race_condition(responses=responses, expected_unique=1)
        assert chain.total_weight > 0

    def test_empty_responses_is_fp(self) -> None:
        chain = validate_race_condition(responses=[], expected_unique=1)
        assert chain.total_weight == 0
        assert len(chain.false_positive_checks) > 0

    def test_baseline_count_comparison(self) -> None:
        responses = [("200", hash("ok"), "ok") for _ in range(4)]
        chain = validate_race_condition(
            responses=responses,
            expected_unique=1,
            baseline_count=1,
        )
        baseline_signals = [item.signal for item in chain.items if "baseline" in item.signal.lower()]
        assert len(baseline_signals) > 0

    def test_weight_scales_with_extra_successes(self) -> None:
        # More extra successes = higher weight
        responses_2 = [("200", hash("x"), "x") for _ in range(2)]
        responses_5 = [("200", hash("x"), "x") for _ in range(5)]
        chain_2 = validate_race_condition(responses=responses_2, expected_unique=1)
        chain_5 = validate_race_condition(responses=responses_5, expected_unique=1)
        assert chain_5.total_weight >= chain_2.total_weight


# ---------------------------------------------------------------------------
# Fix 6: scan_directories — rate_limiter import check
# ---------------------------------------------------------------------------

class TestScanDirectoriesRateLimiterIntegration:
    """Verify rate_limiter is imported and used in scan_directories."""

    def test_rate_limiter_imported_in_scanning_module(self) -> None:
        import kambo.tools.scanning as scanning_module
        import kambo.rate_limiter as rl_module
        # The module should reference the rate limiter
        import inspect
        source = inspect.getsource(scanning_module)
        assert "get_rate_limiter" in source, "get_rate_limiter not used in scanning.py"
        assert "rate_limiter" in source.lower(), "rate_limiter not imported in scanning.py"

    def test_rate_limiter_singleton_accessible(self) -> None:
        from kambo.rate_limiter import get_rate_limiter
        limiter = get_rate_limiter()
        assert limiter is not None
        # Singleton: same instance
        assert get_rate_limiter() is limiter

    def test_rate_limiter_detect_waf_cloudflare(self) -> None:
        from kambo.rate_limiter import detect_waf
        response = "cloudflare protection cf-ray: 123"
        result = detect_waf(response)
        assert result is not None and "cloudflare" in result.lower()

    def test_rate_limiter_detect_waf_no_waf(self) -> None:
        from kambo.rate_limiter import detect_waf
        result = detect_waf("HTTP/1.1 200 OK\nContent-Type: text/html\n\nHello world")
        assert result is None

    def test_rate_limiter_record_request_returns_dict(self) -> None:
        from kambo.rate_limiter import get_rate_limiter
        limiter = get_rate_limiter()
        analysis = limiter.record_request(
            target="https://example.com",
            response_body="Hello world",
            status_code=200,
        )
        assert "waf_detected" in analysis
        assert "is_blocked" in analysis
        assert "recommended_delay_seconds" in analysis
