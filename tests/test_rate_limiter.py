"""Tests for rate limiter and WAF evasion."""

from __future__ import annotations

from kambo.rate_limiter import (
    RateLimiter,
    RateState,
    detect_block,
    detect_waf,
    evasion_recommendations,
    get_rate_limiter,
)


class TestDetectWaf:
    def test_detect_cloudflare(self) -> None:
        assert detect_waf("", "cf-ray: abc123") == "Cloudflare"

    def test_detect_cloudflare_in_body(self) -> None:
        assert detect_waf("Attention Required! | Cloudflare") == "Cloudflare"

    def test_detect_aws_waf(self) -> None:
        assert detect_waf("", "x-amzn-requestid: abc") == "AWS WAF"

    def test_detect_modsecurity(self) -> None:
        assert detect_waf("ModSecurity: Access denied") == "ModSecurity"

    def test_detect_imperva(self) -> None:
        assert detect_waf("Incapsula incident ID") == "Imperva/Incapsula"

    def test_no_waf(self) -> None:
        assert detect_waf("Normal response body", "content-type: text/html") is None


class TestDetectBlock:
    def test_429_is_blocked(self) -> None:
        assert detect_block("", status_code=429) is True

    def test_403_is_blocked(self) -> None:
        assert detect_block("", status_code=403) is True

    def test_rate_limit_text(self) -> None:
        assert detect_block("Rate limit exceeded. Please slow down.") is True

    def test_captcha_detection(self) -> None:
        assert detect_block("Please complete the captcha to continue") is True

    def test_normal_response(self) -> None:
        assert detect_block("Welcome to our site", status_code=200) is False


class TestRateState:
    def test_initial_state(self) -> None:
        state = RateState(target="example.com")
        assert state.requests_made == 0
        assert state.is_blocked is False
        assert state.consecutive_blocks == 0

    def test_record_block_increases_delay(self) -> None:
        state = RateState(target="example.com", current_delay_ms=100)
        state.record_block()
        assert state.current_delay_ms == 200  # doubled
        state.record_block()
        assert state.current_delay_ms == 400  # doubled again

    def test_record_success_decreases_delay(self) -> None:
        state = RateState(target="example.com", current_delay_ms=1000)
        state.record_success()
        assert state.current_delay_ms == 900  # 0.9x

    def test_max_delay_cap(self) -> None:
        state = RateState(target="example.com", current_delay_ms=4000, max_delay_ms=5000)
        state.record_block()
        assert state.current_delay_ms == 5000  # capped

    def test_min_delay_floor(self) -> None:
        state = RateState(target="example.com", current_delay_ms=60, min_delay_ms=50)
        state.record_success()
        assert state.current_delay_ms >= 50

    def test_is_blocked_after_3(self) -> None:
        state = RateState(target="example.com")
        state.record_block()
        state.record_block()
        assert state.is_blocked is False
        state.record_block()
        assert state.is_blocked is True

    def test_delay_has_jitter(self) -> None:
        state = RateState(target="example.com", current_delay_ms=100)
        delays = {state.delay_seconds for _ in range(10)}
        # With jitter, not all delays should be identical
        assert len(delays) > 1


class TestRateLimiter:
    def test_record_request(self) -> None:
        limiter = RateLimiter()
        result = limiter.record_request("example.com", "OK", 200)
        assert result["target"] == "example.com"
        assert result["is_blocked"] is False
        assert result["requests_made"] == 1

    def test_waf_detection_persists(self) -> None:
        limiter = RateLimiter()
        limiter.record_request("example.com", "", 200, "cf-ray: abc")
        result = limiter.record_request("example.com", "OK", 200)
        assert result["waf_detected"] == "Cloudflare"

    def test_blocking_triggers_backoff(self) -> None:
        limiter = RateLimiter()
        limiter.record_request("example.com", "Rate limit exceeded", 429)
        limiter.record_request("example.com", "Rate limit exceeded", 429)
        limiter.record_request("example.com", "Rate limit exceeded", 429)
        state = limiter.get_state("example.com")
        assert state.is_blocked is True
        assert state.current_delay_ms > 100  # increased from default

    def test_evasion_tips_on_waf(self) -> None:
        limiter = RateLimiter()
        result = limiter.record_request("example.com", "Cloudflare", 200)
        assert result["waf_detected"] == "Cloudflare"
        assert len(result["evasion_tips"]) > 0

    def test_summary(self) -> None:
        limiter = RateLimiter()
        limiter.record_request("a.example.com", "OK", 200)
        limiter.record_request("b.example.com", "OK", 200)
        summary = limiter.summary()
        assert "a.example.com" in summary
        assert "b.example.com" in summary

    def test_reset_target(self) -> None:
        limiter = RateLimiter()
        limiter.record_request("example.com", "OK", 200)
        limiter.reset("example.com")
        state = limiter.get_state("example.com")
        assert state.requests_made == 0

    def test_reset_all(self) -> None:
        limiter = RateLimiter()
        limiter.record_request("a.example.com", "OK", 200)
        limiter.record_request("b.example.com", "OK", 200)
        limiter.reset()
        assert limiter.summary() == {}


class TestEvasionRecommendations:
    def test_generic_recommendations(self) -> None:
        recs = evasion_recommendations("UnknownWAF")
        assert len(recs) >= 2  # at least generic ones

    def test_cloudflare_specific(self) -> None:
        recs = evasion_recommendations("Cloudflare")
        cf_recs = [r for r in recs if "Cloudflare" in r.get("description", "")]
        assert len(cf_recs) > 0

    def test_modsecurity_specific(self) -> None:
        recs = evasion_recommendations("ModSecurity")
        mod_recs = [r for r in recs if "ModSecurity" in r.get("description", "")]
        assert len(mod_recs) > 0
