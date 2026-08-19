"""Tests for SSTI, Prototype Pollution, and Deserialization validators."""

from __future__ import annotations

from kambo.models import Confidence
from kambo.validation import (
    validate_deserialization,
    validate_prototype_pollution,
    validate_ssti,
)


# ---------------------------------------------------------------------------
# validate_ssti
# ---------------------------------------------------------------------------

class TestValidateSsti:
    def test_empty_output_is_fp(self) -> None:
        chain = validate_ssti("")
        assert chain.total_weight == 0
        assert len(chain.false_positive_checks) >= 1

    def test_literal_payload_reflection_is_fp(self) -> None:
        """{{7*7}} reflected verbatim without rendering → not SSTI."""
        chain = validate_ssti(
            output="Your input: {{7*7}} was received",
            payload="{{7*7}}",
            expected_render="49",
        )
        assert chain.total_weight == 0
        assert len(chain.false_positive_checks) >= 1

    def test_rendered_orthogonal_single_response_capped_firm(self) -> None:
        """Orthogonal render in a single response (no baseline) → FIRM, not CONFIRMED.

        Doctrine I1: one response proves the marker appeared, not that the
        payload caused it. CONFIRMED requires a differential.
        """
        chain = validate_ssti(
            output="Welcome! Result: 41897569 and more content here.",
            payload="{{31337*1337}}",
            expected_render="41897569",
        )
        assert chain.total_weight >= 2.0
        assert chain.confidence == Confidence.FIRM
        assert chain.is_capped
        assert any("I1" in g for g in chain.gates)

    def test_python_object_exposure(self) -> None:
        """Jinja2 object exposure via class introspection."""
        chain = validate_ssti(
            output="Response: <class 'str'> exposed from template",
            payload="{{''.__class__}}",
            expected_render="",
        )
        assert chain.total_weight >= 1.5
        assert chain.confidence in (Confidence.CONFIRMED, Confidence.FIRM)

    def test_exposure_plus_error_single_response_capped_firm(self) -> None:
        """I1: Python exposure (1.5) + error-based (0.8) = 2.3 would be CONFIRMED
        on raw weight, but with no baseline differential it must cap at FIRM —
        one response can't prove the payload caused the evidence."""
        chain = validate_ssti(
            output="<class 'str'> and org.springframework.expression error",
            payload="{{''.__class__}}",
            expected_render="",
            error_based=True,
        )
        assert chain.total_weight >= 2.0
        assert chain.confidence == Confidence.FIRM
        assert chain.is_capped
        assert any("I1" in g for g in chain.gates)

    def test_rendered_plus_baseline_diff(self) -> None:
        """Orthogonal render present in payload, absent in baseline → CONFIRMED.

        This is the differential the doctrine (I1) demands: the marker appears
        only in the payload response, proving causality.
        """
        chain = validate_ssti(
            output="Value=41897569 computed",
            payload="{{31337*1337}}",
            expected_render="41897569",
            baseline_body="Value=EXPRESSION computed",
        )
        assert chain.confidence == Confidence.CONFIRMED
        assert not chain.is_capped

    def test_engine_rejection_is_fp(self) -> None:
        chain = validate_ssti(
            output="expression invalid — template rejected",
            payload="{{7*7}}",
            expected_render="49",
        )
        assert chain.total_weight == 0

    def test_repdigit_marker_is_non_orthogonal_capped(self) -> None:
        """{{7*'7'}} → 7777777 is a repdigit — non-orthogonal marker (I2).

        Low digit variety means it can occur naturally; the marker is unsound
        and the finding is capped at TENTATIVE regardless of the render match.
        """
        chain = validate_ssti(
            output="output: 7777777 end",
            payload="{{7*'7'}}",
            expected_render="7777777",
        )
        assert chain.confidence == Confidence.TENTATIVE
        assert chain.is_capped
        assert any("I2" in g for g in chain.gates)

    def test_error_based_detection(self) -> None:
        chain = validate_ssti(
            output="org.springframework.expression.spel.SpelEvaluationException: stack",
            payload="${7*7}",
            expected_render="49",
            error_based=True,
        )
        # Error signal adds weight but not full confirmation without render
        assert chain.total_weight > 0

    def test_payload_and_render_both_present_not_fp(self) -> None:
        """Payload echoed literally AND render result present → not a FP.

        The FP guard only fires when payload is present but expected_render is
        absent. When both appear the template was rendered despite reflection.
        """
        chain = validate_ssti(
            output="Your input: {{7*7}} was received; result: 49",
            payload="{{7*7}}",
            expected_render="49",
        )
        assert chain.total_weight > 0

    def test_expected_render_in_baseline_is_fp(self) -> None:
        """If '49' already exists in the baseline, it's natural content, not SSTI."""
        page_content = (
            '<html><body>Country: {"id":"49","name":"Congo"}'
            " Price: R$49.90</body></html>"
        )
        chain = validate_ssti(
            output=page_content,
            payload="{{7*7}}",
            expected_render="49",
            baseline_body=page_content,
        )
        assert chain.total_weight == 0.0
        assert any("baseline" in fp.lower() for fp in chain.false_positive_checks)

    def test_expected_render_absent_from_baseline_is_real(self) -> None:
        """Orthogonal marker absent in baseline but present in payload → real SSTI."""
        baseline = "<html><body>Normal page without the number</body></html>"
        output = "<html><body>Result: 41897569</body></html>"
        chain = validate_ssti(
            output=output,
            payload="{{31337*1337}}",
            expected_render="41897569",
            baseline_body=baseline,
        )
        assert chain.total_weight >= 2.0
        assert chain.confidence == Confidence.CONFIRMED

    def test_error_patterns_gated_by_error_based_flag(self) -> None:
        """Spring/Twig error patterns only contribute weight when error_based=True."""
        # Output has org.springframework but NOT the literal payload — no FP reflection guard
        output = (
            "org.springframework.expression.spel.SpelEvaluationException: "
            "EL1004E: Method call: Method run() cannot be found"
        )
        chain_false = validate_ssti(
            output=output, payload="${7*7}", expected_render="49", error_based=False
        )
        chain_true = validate_ssti(
            output=output, payload="${7*7}", expected_render="49", error_based=True
        )
        assert chain_false.total_weight == 0          # gate is closed
        assert chain_true.total_weight > 0            # gate opens the error signal
        assert chain_true.total_weight >= chain_false.total_weight


# ---------------------------------------------------------------------------
# validate_prototype_pollution
# ---------------------------------------------------------------------------

class TestValidatePrototypePollution:
    def test_empty_output_is_fp(self) -> None:
        chain = validate_prototype_pollution("")
        assert chain.total_weight == 0
        assert len(chain.false_positive_checks) >= 1

    def test_json_parse_error_is_fp(self) -> None:
        chain = validate_prototype_pollution(
            output='{"error": "Invalid JSON: unexpected token"}',
            injected_value="polluted_value",
        )
        assert chain.total_weight == 0

    def test_injected_value_in_response(self) -> None:
        chain = validate_prototype_pollution(
            output='{"name": "user", "polluted_value": true, "role": "admin"}',
            injected_value="polluted_value",
        )
        assert chain.total_weight >= 1.5
        assert chain.confidence in (Confidence.CONFIRMED, Confidence.FIRM)

    def test_proto_key_in_response(self) -> None:
        chain = validate_prototype_pollution(
            output='{"__proto__": {"admin": true}, "user": "test"}',
            payload="__proto__",
        )
        assert chain.total_weight >= 1.0

    def test_object_prototype_exposed(self) -> None:
        chain = validate_prototype_pollution(
            output="Error: Object.prototype.polluted is already defined",
        )
        assert chain.total_weight >= 1.0

    def test_baseline_comparison_confirms(self) -> None:
        chain = validate_prototype_pollution(
            output='{"role": "admin", "myvalue": "injected"}',
            injected_value="myvalue",
            baseline_body='{"role": "user"}',
        )
        assert chain.total_weight >= 1.5

    def test_no_injection_signal_low_weight(self) -> None:
        chain = validate_prototype_pollution(
            output='{"user": "alice", "role": "user"}',
            injected_value="nonexistent",
        )
        assert chain.total_weight == 0

    def test_injected_value_only_in_error_message_is_fp(self) -> None:
        """Injected value inside an error message should not count as pollution.

        The guard checks for error/invalid/rejected/blocked in the first 200
        characters of the response before adding weight.
        """
        chain = validate_prototype_pollution(
            output='{"error": "injected key polluted_value is invalid"}',
            injected_value="polluted_value",
        )
        assert chain.total_weight == 0


# ---------------------------------------------------------------------------
# validate_deserialization
# ---------------------------------------------------------------------------

class TestValidateDeserialization:
    def test_empty_no_timing_is_fp(self) -> None:
        chain = validate_deserialization("")
        assert chain.total_weight == 0

    def test_explicitly_rejected(self) -> None:
        chain = validate_deserialization(
            output="deserialization not supported for this content type",
        )
        assert chain.total_weight == 0
        assert len(chain.false_positive_checks) >= 1

    def test_rce_via_expected_output_single_response_capped_firm(self) -> None:
        """I1: command output in a single response (no time differential / OOB)
        caps at FIRM."""
        chain = validate_deserialization(
            output="uid=33(www-data) gid=33(www-data) groups=33(www-data)",
            expected_output="www-data",
        )
        assert chain.total_weight >= 2.0
        assert chain.confidence == Confidence.FIRM
        assert any("I1" in g for g in chain.gates)

    def test_expected_output_with_baseline_differential_confirms(self) -> None:
        """A canary absent from the control response proves gadget causality."""
        chain = validate_deserialization(
            output="result: deser-kc9f2a",
            expected_output="deser-kc9f2a",
            baseline_body="result: not-run",
        )

        assert chain.confidence == Confidence.CONFIRMED
        assert not chain.is_capped

    def test_expected_output_already_in_baseline_is_not_evidence(self) -> None:
        """A marker shared with the control cannot support gadget execution."""
        chain = validate_deserialization(
            output="status: deser-kc9f2a",
            expected_output="deser-kc9f2a",
            baseline_body="status: deser-kc9f2a",
        )

        assert chain.total_weight == 0
        assert any("baseline" in check.lower() for check in chain.false_positive_checks)

    def test_oob_hit_confirms_deserialization(self) -> None:
        """A correlated OOB hit confirms blind deserialization (P3)."""
        chain = validate_deserialization(
            output="",
            payload_type="java",
            oob_hit=True,
            oob_evidence="DNS canary.oast.example received",
        )
        assert chain.confidence == Confidence.CONFIRMED

    def test_java_gadget_chain(self) -> None:
        chain = validate_deserialization(
            output="Caused by: org.apache.commons.collections.FunctorException: InvokerTransformer: The method 'exec' on 'java.lang.Runtime'",
            payload_type="java",
        )
        assert chain.total_weight >= 1.0

    def test_python_pickle_signal(self) -> None:
        chain = validate_deserialization(
            output="pickle protocol 2 loaded with __reduce__ method called",
            payload_type="python",
        )
        assert chain.total_weight >= 1.5

    def test_oob_token_in_body_does_not_confirm(self) -> None:
        """I3: OOB token echoed in the body is reflection, not a received
        callback — it does not confirm deserialization."""
        chain = validate_deserialization(
            output="DNS callback received from attacker.burpcollaborator.net",
        )
        assert chain.confidence == Confidence.TENTATIVE
        assert any("I3" in fp for fp in chain.false_positive_checks)

    def test_time_based_long_delay(self) -> None:
        chain = validate_deserialization(
            output="",
            response_time_ms=9000,
            baseline_time_ms=300,
        )
        assert chain.total_weight >= 1.5
        assert chain.confidence in (Confidence.CONFIRMED, Confidence.FIRM)

    def test_time_based_short_delay_not_confirmed(self) -> None:
        """Small delay below threshold should not trigger."""
        chain = validate_deserialization(
            output="",
            response_time_ms=2000,
            baseline_time_ms=300,
        )
        assert chain.total_weight == 0

    def test_java_not_serializable_partial_signal(self) -> None:
        chain = validate_deserialization(
            output="java.io.NotSerializableException: java.lang.Object",
        )
        # This is a partial signal — endpoint processes Java objects
        assert chain.total_weight > 0
        assert chain.confidence == Confidence.TENTATIVE

    def test_php_deserialization_hook(self) -> None:
        chain = validate_deserialization(
            output="PHP Notice: __wakeup called during deserialization of object",
            payload_type="php",
        )
        assert chain.total_weight >= 1.0

    def test_time_based_exactly_at_threshold_not_triggered(self) -> None:
        """delay = 5300 - 300 = 5000 ms. The guard is '> 5000', so 5000 must NOT trigger."""
        chain = validate_deserialization(
            output="",
            response_time_ms=5300,
            baseline_time_ms=300,
        )
        assert chain.total_weight == 0

    def test_time_based_just_over_threshold_triggers(self) -> None:
        """delay = 5301 - 300 = 5001 ms > 5000 ms. Must trigger at weight 1.0."""
        chain = validate_deserialization(
            output="",
            response_time_ms=5301,
            baseline_time_ms=300,
        )
        assert chain.total_weight > 0
        assert chain.confidence in (Confidence.TENTATIVE, Confidence.FIRM)
