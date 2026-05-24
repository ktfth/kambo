"""Tests for SSTI, Prototype Pollution, and Deserialization validators."""

from __future__ import annotations

import pytest

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

    def test_rendered_expression_confirmed(self) -> None:
        """{{7*7}} renders to 49 → CONFIRMED SSTI."""
        chain = validate_ssti(
            output="Welcome! Result: 49 and more content here.",
            payload="{{7*7}}",
            expected_render="49",
        )
        assert chain.confidence == Confidence.CONFIRMED
        assert chain.total_weight >= 2.0

    def test_python_object_exposure(self) -> None:
        """Jinja2 object exposure via class introspection."""
        chain = validate_ssti(
            output="Response: <class 'str'> exposed from template",
            payload="{{''.__class__}}",
            expected_render="",
        )
        assert chain.total_weight >= 1.5
        assert chain.confidence in (Confidence.CONFIRMED, Confidence.FIRM)

    def test_rendered_plus_baseline_diff(self) -> None:
        """Render confirmed + response differs from baseline → CONFIRMED."""
        chain = validate_ssti(
            output="Value=49 computed",
            payload="{{7*7}}",
            expected_render="49",
            baseline_body="Value=EXPRESSION computed",
        )
        assert chain.confidence == Confidence.CONFIRMED

    def test_engine_rejection_is_fp(self) -> None:
        chain = validate_ssti(
            output="expression invalid — template rejected",
            payload="{{7*7}}",
            expected_render="49",
        )
        assert chain.total_weight == 0

    def test_jinja2_python_variant(self) -> None:
        """{{7*'7'}} → 7777777 is Jinja2/Python specific."""
        chain = validate_ssti(
            output="output: 7777777 end",
            payload="{{7*'7'}}",
            expected_render="7777777",
        )
        assert chain.confidence == Confidence.CONFIRMED

    def test_error_based_detection(self) -> None:
        chain = validate_ssti(
            output="org.springframework.expression.spel.SpelEvaluationException: stack",
            payload="${7*7}",
            expected_render="49",
            error_based=True,
        )
        # Error signal adds weight but not full confirmation without render
        assert chain.total_weight > 0


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

    def test_rce_via_expected_output(self) -> None:
        chain = validate_deserialization(
            output="uid=33(www-data) gid=33(www-data) groups=33(www-data)",
            expected_output="www-data",
        )
        assert chain.confidence == Confidence.CONFIRMED
        assert chain.total_weight >= 2.0

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

    def test_oob_callback_signal(self) -> None:
        chain = validate_deserialization(
            output="DNS callback received from attacker.burpcollaborator.net",
        )
        assert chain.total_weight >= 1.5

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
