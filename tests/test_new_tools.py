"""Tests for the 7 newly exposed vuln tools, PoC generator additions,
and the LearningsStore sort fix."""

from __future__ import annotations

import pytest

from kambo.learnings import Learning, LearningsStore
from kambo.models import Confidence, EvidenceChain
from kambo.poc_generator import generate_poc
from kambo.validation import (
    validate_csrf,
    validate_deserialization,
    validate_open_redirect,
    validate_path_traversal,
    validate_prototype_pollution,
    validate_rce,
    validate_xxe,
)


# ---------------------------------------------------------------------------
# validate_path_traversal
# ---------------------------------------------------------------------------

class TestPathTraversalValidator:
    def test_etc_passwd_content_confirms(self) -> None:
        body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
        chain = validate_path_traversal(body, "../../etc/passwd")
        assert chain.total_weight >= 1.0

    def test_literal_reflection_is_fp(self) -> None:
        chain = validate_path_traversal("../../etc/passwd", "../../etc/passwd")
        assert chain.total_weight == 0.0 or chain.confidence == Confidence.TENTATIVE

    def test_empty_body_is_fp(self) -> None:
        chain = validate_path_traversal("", "../../etc/passwd")
        assert chain.total_weight == 0.0

    def test_baseline_identical_is_fp(self) -> None:
        body = "root:x:0:0:root:/root:/bin/bash"
        chain = validate_path_traversal(body, "../../etc/passwd", baseline_body=body)
        assert chain.total_weight == 0.0

    def test_win_ini_signature(self) -> None:
        body = "[boot loader]\ntimeout=30\ndefault=multi(0)"
        chain = validate_path_traversal(body, "..\\..\\boot.ini")
        assert chain.total_weight >= 1.0

    def test_error_indicator_adds_weight(self) -> None:
        body = "failed to open stream: No such file or directory"
        chain = validate_path_traversal(body, "../../etc/passwd")
        assert chain.total_weight > 0


# ---------------------------------------------------------------------------
# validate_rce
# ---------------------------------------------------------------------------

class TestRceValidator:
    def test_uid_output_without_baseline_is_firm(self) -> None:
        # Without baseline differential, single-response RCE is capped at FIRM (doctrine I1)
        chain = validate_rce("uid=0(root) gid=0(root)", expected_output="uid=0(root)")
        assert chain.confidence == Confidence.FIRM
        assert chain.total_weight >= 1.0

    def test_uid_output_with_baseline_confirms(self) -> None:
        # With baseline differential (canary absent from baseline), CONFIRMED is permitted
        chain = validate_rce(
            "uid=0(root) gid=0(root)", expected_output="uid=0(root)", baseline_body="Welcome to the site"
        )
        assert chain.confidence == Confidence.CONFIRMED

    def test_empty_output_is_fp(self) -> None:
        chain = validate_rce("", oob_hit=False)
        assert chain.total_weight == 0.0

    def test_blocked_payload_is_fp(self) -> None:
        chain = validate_rce("access denied by WAF — blocked", payload="id")
        assert chain.total_weight == 0.0

    def test_oob_hit_confirms(self) -> None:
        chain = validate_rce("", oob_hit=True, oob_evidence="dns interaction from 1.2.3.4")
        assert chain.confidence == Confidence.CONFIRMED

    def test_time_based_delay_adds_weight(self) -> None:
        # Need non-empty output to get past the empty check; time-based is differential
        chain = validate_rce("HTTP/1.1 200 OK", response_time_ms=6000, baseline_time_ms=200)
        assert chain.total_weight >= 1.0

    def test_literal_reflection_without_exec_is_fp(self) -> None:
        chain = validate_rce("id", payload="id")
        assert chain.total_weight == 0.0


# ---------------------------------------------------------------------------
# validate_xxe
# ---------------------------------------------------------------------------

class TestXxeValidator:
    def test_passwd_content_without_baseline_is_firm(self) -> None:
        # Without baseline, single-response XXE is capped at FIRM (doctrine I1)
        body = "root:x:0:0:root:/root:/bin/bash"
        chain = validate_xxe(body, expected_content="root:x:0:0:")
        assert chain.confidence == Confidence.FIRM

    def test_passwd_content_with_baseline_confirms(self) -> None:
        # With baseline differential, CONFIRMED is permitted
        body = "root:x:0:0:root:/root:/bin/bash"
        chain = validate_xxe(body, expected_content="root:x:0:0:", baseline_body="<?xml version='1.0'?><response/>")
        assert chain.confidence == Confidence.CONFIRMED

    def test_entity_disabled_is_fp(self) -> None:
        chain = validate_xxe("external entities are disabled", payload="<!ENTITY xxe SYSTEM>")
        assert chain.total_weight == 0.0

    def test_oob_hit_confirms(self) -> None:
        chain = validate_xxe("", oob_hit=True, oob_evidence="dns interaction received")
        assert chain.confidence == Confidence.CONFIRMED

    def test_empty_no_oob_is_fp(self) -> None:
        chain = validate_xxe("")
        assert chain.total_weight == 0.0

    def test_error_disclosure_adds_weight(self) -> None:
        chain = validate_xxe("SAXParseException: external entity not allowed")
        assert chain.total_weight > 0


# ---------------------------------------------------------------------------
# validate_csrf
# ---------------------------------------------------------------------------

class TestCsrfValidator:
    def test_token_present_is_fp(self) -> None:
        chain = validate_csrf("", has_csrf_token=True)
        assert chain.total_weight == 0.0

    def test_samesite_strict_is_fp(self) -> None:
        chain = validate_csrf("", samesite_cookie="Strict")
        assert chain.total_weight == 0.0

    def test_no_token_no_samesite_adds_weight(self) -> None:
        chain = validate_csrf("", has_csrf_token=False, samesite_cookie="")
        assert chain.total_weight > 0

    def test_state_change_confirmed_increases_weight(self) -> None:
        c1 = validate_csrf("", has_csrf_token=False, state_change_confirmed=False)
        c2 = validate_csrf("", has_csrf_token=False, state_change_confirmed=True)
        assert c2.total_weight > c1.total_weight

    def test_json_with_restrictive_cors_is_fp(self) -> None:
        chain = validate_csrf(
            "", content_type="application/json", method="POST", cors_origin="https://same-origin.com"
        )
        assert chain.total_weight == 0.0


# ---------------------------------------------------------------------------
# validate_open_redirect
# ---------------------------------------------------------------------------

class TestOpenRedirectValidator:
    def test_redirect_to_injected_domain_confirms(self) -> None:
        chain = validate_open_redirect(
            output="HTTP/1.1 302 Found\r\nLocation: https://evil.example.com/path",
            redirect_url="https://evil.example.com/path",
            final_url="https://evil.example.com/path",
            status_code=302,
        )
        assert chain.total_weight >= 1.0

    def test_redirect_to_different_domain_is_fp(self) -> None:
        chain = validate_open_redirect(
            output="",
            redirect_url="https://evil.example.com",
            final_url="https://safe.example.com",
            status_code=302,
        )
        assert chain.total_weight == 0.0

    def test_redirect_to_login_is_fp(self) -> None:
        chain = validate_open_redirect(
            output="",
            redirect_url="https://evil.example.com",
            final_url="https://target.com/login",
            status_code=302,
        )
        assert chain.total_weight == 0.0

    def test_empty_output_is_fp(self) -> None:
        chain = validate_open_redirect("")
        assert chain.total_weight == 0.0

    def test_non_redirect_status_without_body_is_fp(self) -> None:
        chain = validate_open_redirect("some body", status_code=200)
        assert chain.total_weight == 0.0


# ---------------------------------------------------------------------------
# validate_prototype_pollution
# ---------------------------------------------------------------------------

class TestPrototypePollutionValidator:
    def test_canary_in_response_confirms(self) -> None:
        canary = "kambo_pp_canary_41897569"
        body = f'{{"result": "ok", "polluted": "{canary}"}}'
        chain = validate_prototype_pollution(body, "__proto__", canary, "")
        assert chain.total_weight >= 1.0

    def test_canary_absent_in_baseline_is_differential(self) -> None:
        canary = "kambo_pp_canary"
        response = f'{{"polluted": "{canary}"}}'
        baseline = '{"result": "ok"}'
        chain = validate_prototype_pollution(response, "__proto__", canary, baseline)
        assert confidence_meets_firm(chain)

    def test_json_parse_error_is_fp(self) -> None:
        chain = validate_prototype_pollution("SyntaxError: invalid JSON")
        assert chain.total_weight == 0.0

    def test_empty_output_is_fp(self) -> None:
        chain = validate_prototype_pollution("")
        assert chain.total_weight == 0.0

    def test_proto_key_in_response_adds_weight(self) -> None:
        chain = validate_prototype_pollution('{"__proto__": {"x": 1}}')
        assert chain.total_weight > 0


def confidence_meets_firm(chain: EvidenceChain) -> bool:
    from kambo.models import confidence_meets
    return confidence_meets(chain.confidence, Confidence.FIRM)


# ---------------------------------------------------------------------------
# validate_deserialization
# ---------------------------------------------------------------------------

class TestDeserializationValidator:
    def test_oob_hit_confirms(self) -> None:
        chain = validate_deserialization("", oob_hit=True, oob_evidence="dns interaction received")
        assert chain.confidence == Confidence.CONFIRMED

    def test_time_delay_adds_weight(self) -> None:
        chain = validate_deserialization("", response_time_ms=7000, baseline_time_ms=200)
        assert chain.total_weight >= 1.0

    def test_java_runtime_class_adds_weight(self) -> None:
        chain = validate_deserialization("java.lang.Runtime: exec() called")
        assert chain.total_weight > 0

    def test_explicitly_disabled_is_fp(self) -> None:
        chain = validate_deserialization("deserialization not supported by this endpoint")
        assert chain.total_weight == 0.0

    def test_empty_no_oob_no_timing_is_fp(self) -> None:
        chain = validate_deserialization("")
        assert chain.total_weight == 0.0

    def test_oob_body_reflection_without_hit_is_capped(self) -> None:
        chain = validate_deserialization("dns callback token: burpcollaborator.net", oob_hit=False)
        assert chain.confidence != Confidence.CONFIRMED


# ---------------------------------------------------------------------------
# PoC generator — new types
# ---------------------------------------------------------------------------

class TestPocGeneratorNewTypes:
    def test_ssti_poc_python(self) -> None:
        result = generate_poc("ssti", "https://target.com", parameter="q", payload="{{31337*1337}}")
        assert "31337*1337" in result["poc_script"] or "41897569" in result["poc_script"]
        assert result["language"] == "python"

    def test_deserialization_poc_python(self) -> None:
        result = generate_poc("deserialization", "https://target.com")
        assert "ysoserial" in result["poc_script"]
        assert "sleep" in result["poc_script"]

    def test_prototype_pollution_poc_python(self) -> None:
        result = generate_poc("prototype_pollution", "https://target.com", payload="kambo_canary")
        assert "__proto__" in result["poc_script"]
        assert "kambo_canary" in result["poc_script"]

    def test_java_deser_alias(self) -> None:
        result = generate_poc("java_deser", "https://target.com")
        assert "ysoserial" in result["poc_script"]

    def test_unknown_type_falls_back_to_generic(self) -> None:
        result = generate_poc("path_traversal", "https://target.com", parameter="file", payload="../../etc/passwd")
        assert "../../etc/passwd" in result["poc_script"] or "target.com" in result["poc_script"]


# ---------------------------------------------------------------------------
# LearningsStore sort fix — confidence desc, then newest first
# ---------------------------------------------------------------------------

class TestLearningsSortFix:
    def _store_with_entries(self, tmp_path) -> LearningsStore:
        store = LearningsStore(tmp_path / "learnings.jsonl")
        store.log(Learning(
            type="pattern", key="low_conf", insight="low confidence entry",
            confidence=3, source="test", skill="test",
            timestamp="2024-01-01T00:00:00+00:00",
        ))
        store.log(Learning(
            type="pattern", key="high_conf_old", insight="high confidence old",
            confidence=8, source="test", skill="test",
            timestamp="2024-06-01T00:00:00+00:00",
        ))
        store.log(Learning(
            type="pattern", key="high_conf_new", insight="high confidence new",
            confidence=8, source="test", skill="test",
            timestamp="2025-06-01T00:00:00+00:00",
        ))
        store.log(Learning(
            type="pattern", key="mid_conf", insight="mid confidence entry",
            confidence=6, source="test", skill="test",
            timestamp="2025-01-01T00:00:00+00:00",
        ))
        return store

    def test_highest_confidence_first(self, tmp_path) -> None:
        store = self._store_with_entries(tmp_path)
        results = store.search()
        confidences = [r["confidence"] for r in results]
        assert confidences == sorted(confidences, reverse=True)

    def test_same_confidence_newest_first(self, tmp_path) -> None:
        store = self._store_with_entries(tmp_path)
        results = store.search()
        high_conf_results = [r for r in results if r["original_confidence"] == 8]
        assert len(high_conf_results) == 2
        timestamps = [r["timestamp"] for r in high_conf_results]
        assert timestamps[0] > timestamps[1], "Newest entry should appear first for same confidence"

    def test_low_confidence_appears_last(self, tmp_path) -> None:
        store = self._store_with_entries(tmp_path)
        results = store.search()
        assert results[-1]["original_confidence"] == 3


# ---------------------------------------------------------------------------
# server registry — new tools present
# ---------------------------------------------------------------------------

class TestServerRegistryNewTools:
    def test_all_seven_tools_registered(self) -> None:
        from kambo.server import _TOOL_REGISTRY
        expected = {
            "vuln_path_traversal",
            "vuln_rce",
            "vuln_xxe",
            "vuln_csrf",
            "vuln_open_redirect",
            "vuln_prototype_pollution",
            "vuln_deserialization",
        }
        registered = set(_TOOL_REGISTRY.keys())
        missing = expected - registered
        assert not missing, f"Missing tools in registry: {missing}"

    def test_tools_have_dispatch_callable(self) -> None:
        from kambo.server import _TOOL_REGISTRY
        for name in ("vuln_path_traversal", "vuln_rce", "vuln_xxe"):
            entry = _TOOL_REGISTRY[name]
            assert callable(entry.dispatch), f"{name} dispatch is not callable"
