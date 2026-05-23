"""Tests for new validators: RCE, XXE, CSRF, Open Redirect."""

from __future__ import annotations

from kambo.models import Confidence
from kambo.validation import (
    validate_csrf,
    validate_open_redirect,
    validate_rce,
    validate_xxe,
)


class TestValidateRce:
    def test_empty_output_is_fp(self) -> None:
        chain = validate_rce("")
        assert chain.total_weight == 0
        assert len(chain.false_positive_checks) >= 1

    def test_blocked_injection(self) -> None:
        chain = validate_rce("command not found: ls")
        assert chain.total_weight == 0
        assert len(chain.false_positive_checks) >= 1

    def test_payload_reflected_without_execution(self) -> None:
        chain = validate_rce(
            output="Your search: ; ls -la",
            payload="; ls -la",
        )
        assert chain.total_weight == 0

    def test_os_identity_detected(self) -> None:
        chain = validate_rce("uid=0(root) gid=0(root) groups=0(root)")
        assert chain.confidence in (Confidence.CONFIRMED, Confidence.FIRM)
        assert chain.total_weight >= 1.0

    def test_expected_output_match(self) -> None:
        chain = validate_rce(
            output="uid=1000(www-data) gid=1000(www-data)",
            expected_output="www-data",
        )
        assert chain.confidence == Confidence.CONFIRMED
        assert chain.total_weight >= 2.0

    def test_time_based_detection(self) -> None:
        chain = validate_rce(
            output="HTTP/1.1 200 OK",
            response_time_ms=6000,
            baseline_time_ms=500,
        )
        assert chain.total_weight >= 1.0

    def test_oob_callback_detected(self) -> None:
        chain = validate_rce("DNS callback received from xyz.burpcollaborator.net")
        assert chain.total_weight >= 1.0

    def test_waf_block_is_fp(self) -> None:
        chain = validate_rce("Request blocked by WAF")
        assert chain.total_weight == 0


class TestValidateXxe:
    def test_empty_output_is_fp(self) -> None:
        chain = validate_xxe("")
        assert chain.total_weight == 0

    def test_entities_disabled(self) -> None:
        chain = validate_xxe("External entities are disabled for security")
        assert chain.total_weight == 0

    def test_file_content_detected(self) -> None:
        chain = validate_xxe("root:x:0:0:root:/root:/bin/bash")
        assert chain.total_weight >= 1.0

    def test_expected_content_match(self) -> None:
        chain = validate_xxe(
            output="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
            expected_content="root:x:0:0",
        )
        assert chain.confidence == Confidence.CONFIRMED

    def test_oob_callback(self) -> None:
        chain = validate_xxe("Received callback from xyz.oastify.com")
        assert chain.total_weight >= 1.0

    def test_ssrf_via_xxe(self) -> None:
        chain = validate_xxe("ami-id: ami-0123456789")
        assert chain.total_weight > 0

    def test_generic_error_is_fp(self) -> None:
        chain = validate_xxe("500 Internal Server Error\n<html>Something went wrong</html>")
        assert chain.total_weight == 0

    def test_baseline_comparison(self) -> None:
        chain = validate_xxe(
            output="root:x:0:0:root:/root:/bin/bash\n" + "x" * 200,
            baseline_body="Normal response body",
        )
        # Should have baseline diff signal
        assert any("baseline" in item.signal.lower() for item in chain.items)


class TestValidateCsrf:
    def test_csrf_token_present_is_fp(self) -> None:
        chain = validate_csrf("", has_csrf_token=True)
        assert chain.total_weight == 0

    def test_samesite_strict_is_fp(self) -> None:
        chain = validate_csrf("", samesite_cookie="Strict")
        assert chain.total_weight == 0

    def test_json_with_restrictive_cors_is_fp(self) -> None:
        chain = validate_csrf(
            "", content_type="application/json", method="POST", cors_origin="https://example.com"
        )
        assert chain.total_weight == 0

    def test_no_token_no_samesite(self) -> None:
        chain = validate_csrf("", has_csrf_token=False, samesite_cookie="")
        assert chain.total_weight > 0

    def test_state_change_confirmed(self) -> None:
        chain = validate_csrf(
            "Password changed successfully",
            has_csrf_token=False,
            samesite_cookie="None",
            state_change_confirmed=True,
        )
        assert chain.confidence in (Confidence.CONFIRMED, Confidence.FIRM)

    def test_permissive_cors_adds_weight(self) -> None:
        chain = validate_csrf(
            "", has_csrf_token=False, cors_origin="*"
        )
        signals = [item.signal for item in chain.items]
        assert any("CORS" in s for s in signals)

    def test_samesite_lax_reduces_weight(self) -> None:
        chain_none = validate_csrf("", has_csrf_token=False, samesite_cookie="None")
        chain_lax = validate_csrf("", has_csrf_token=False, samesite_cookie="Lax", method="POST")
        # Lax should have less weight due to negative signal
        assert chain_lax.total_weight < chain_none.total_weight


class TestValidateOpenRedirect:
    def test_empty_output_is_fp(self) -> None:
        chain = validate_open_redirect("")
        assert chain.total_weight == 0

    def test_same_domain_redirect_is_fp(self) -> None:
        chain = validate_open_redirect(
            output="Location: https://example.com/home",
            redirect_url="https://evil.com",
            final_url="https://example.com/home",
        )
        assert chain.total_weight == 0

    def test_login_redirect_is_fp(self) -> None:
        chain = validate_open_redirect(
            output="", redirect_url="https://evil.com", final_url="https://example.com/login"
        )
        assert chain.total_weight == 0

    def test_external_redirect_detected(self) -> None:
        chain = validate_open_redirect(
            output="HTTP/1.1 302 Found\nLocation: https://evil.com/phish",
            redirect_url="https://evil.com/phish",
            final_url="https://evil.com/phish",
            status_code=302,
        )
        assert chain.confidence == Confidence.CONFIRMED

    def test_javascript_redirect(self) -> None:
        chain = validate_open_redirect(
            output='<script>window.location = "https://evil.com"</script>',
            status_code=200,
        )
        assert chain.total_weight > 0

    def test_baseline_redirect_change(self) -> None:
        chain = validate_open_redirect(
            output="Location: https://evil.com",
            redirect_url="https://evil.com",
            final_url="https://evil.com",
            status_code=302,
            baseline_redirect="https://example.com/dashboard",
        )
        signals = [item.signal for item in chain.items]
        assert any("baseline" in s.lower() for s in signals)

    def test_non_redirect_status_is_fp(self) -> None:
        chain = validate_open_redirect(
            output="Normal page content",
            status_code=200,
        )
        assert chain.total_weight == 0


class TestNewValidatorFpChecks:
    """Verify all new validators have >= 3 FP checks each."""

    def test_rce_has_3_fp_checks(self) -> None:
        import re
        from pathlib import Path
        code = Path("src/kambo/validation.py").read_text()
        start = code.index("def validate_rce")
        end_match = re.search(r"\ndef [a-z_]", code[start + 10:])
        block = code[start:start + 10 + end_match.start()] if end_match else code[start:]
        assert block.count("add_fp_check") >= 3

    def test_xxe_has_3_fp_checks(self) -> None:
        import re
        from pathlib import Path
        code = Path("src/kambo/validation.py").read_text()
        start = code.index("def validate_xxe")
        end_match = re.search(r"\ndef [a-z_]", code[start + 10:])
        block = code[start:start + 10 + end_match.start()] if end_match else code[start:]
        assert block.count("add_fp_check") >= 3

    def test_csrf_has_3_fp_checks(self) -> None:
        import re
        from pathlib import Path
        code = Path("src/kambo/validation.py").read_text()
        start = code.index("def validate_csrf")
        end_match = re.search(r"\ndef [a-z_]", code[start + 10:])
        block = code[start:start + 10 + end_match.start()] if end_match else code[start:]
        assert block.count("add_fp_check") >= 3

    def test_open_redirect_has_3_fp_checks(self) -> None:
        import re
        from pathlib import Path
        code = Path("src/kambo/validation.py").read_text()
        start = code.index("def validate_open_redirect")
        end_match = re.search(r"\ndef [a-z_]", code[start + 10:])
        block = code[start:start + 10 + end_match.start()] if end_match else code[start:]
        assert block.count("add_fp_check") >= 3
