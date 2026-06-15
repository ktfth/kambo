"""Tests for validate_oauth() — OAuth 2.0 / SAML authentication flaw detection."""

import pytest

from kambo.models import Confidence
from kambo.validation import validate_oauth


AUTH_OK = "HTTP/1.1 200 OK\n{\"access_token\": \"abc123\", \"token_type\": \"bearer\"}"
AUTH_CODE = "HTTP/1.1 302 Found\nLocation: https://client.example.com/callback?code=AUTH_CODE_xyz"


def _signals(chain) -> list[str]:
    return [e.signal for e in chain.items]


def _has_signal(chain, keyword: str) -> bool:
    return any(keyword.lower() in s.lower() for s in _signals(chain))


def _is_fp(chain) -> bool:
    return len(chain.false_positive_checks) > 0 and chain.total_weight == 0.0


# ---------------------------------------------------------------------------
# State parameter (OAuth CSRF)
# ---------------------------------------------------------------------------

class TestStateCsrf:
    def test_missing_state_adds_signal(self):
        chain = validate_oauth("code", AUTH_OK, state_present=False, state_validated=False)
        assert chain.total_weight > 0
        assert _has_signal(chain, "state")

    def test_state_present_but_not_validated_is_worse(self):
        missing = validate_oauth("code", AUTH_OK, state_present=False, state_validated=False)
        decorative = validate_oauth("code", AUTH_OK, state_present=True, state_validated=False)
        assert decorative.total_weight > missing.total_weight

    def test_state_present_and_validated_no_signal(self):
        chain = validate_oauth("code", AUTH_OK, state_present=True, state_validated=True)
        assert not _has_signal(chain, "state")

    def test_unvalidated_state_reaches_firm(self):
        chain = validate_oauth("code", AUTH_OK, state_present=True, state_validated=False)
        assert chain.confidence in (Confidence.FIRM, Confidence.CONFIRMED)


# ---------------------------------------------------------------------------
# Redirect URI manipulation (open redirect / token theft)
# ---------------------------------------------------------------------------

class TestRedirectUri:
    ACCEPTED_RESPONSE = (
        "HTTP/1.1 302 Found\n"
        "Location: https://attacker.example.com/steal?code=AUTH_CODE_xyz\n\n"
    )
    REJECTED_RESPONSE = (
        "HTTP/1.1 400 Bad Request\n"
        "{\"error\": \"redirect_uri_mismatch\", \"error_description\": \"redirect_uri not allowed\"}"
    )

    def test_accepted_redirect_uri_high_weight(self):
        chain = validate_oauth(
            "code", AUTH_OK,
            redirect_uri_test=self.ACCEPTED_RESPONSE,
        )
        assert chain.total_weight >= 1.5

    def test_accepted_redirect_uri_firm_or_confirmed(self):
        chain = validate_oauth(
            "code", AUTH_OK,
            redirect_uri_test=self.ACCEPTED_RESPONSE,
        )
        assert chain.confidence in (Confidence.FIRM, Confidence.CONFIRMED)

    def test_rejected_redirect_uri_is_fp(self):
        chain = validate_oauth(
            "code", AUTH_OK,
            redirect_uri_test=self.REJECTED_RESPONSE,
        )
        assert len(chain.false_positive_checks) > 0
        assert chain.total_weight == 0.0

    def test_no_redirect_test_no_signal(self):
        chain = validate_oauth("code", AUTH_OK, redirect_uri_test="")
        assert not _has_signal(chain, "redirect")


# ---------------------------------------------------------------------------
# Implicit flow token in URL
# ---------------------------------------------------------------------------

class TestImplicitFlow:
    IMPLICIT_RESPONSE = (
        "HTTP/1.1 302 Found\n"
        "Location: https://client.example.com/cb#access_token=EYTOKEN&token_type=bearer\n"
    )

    def test_token_in_url_adds_signal(self):
        chain = validate_oauth("implicit", self.IMPLICIT_RESPONSE, token_in_url=True)
        assert _has_signal(chain, "implicit") or _has_signal(chain, "url")

    def test_implicit_token_capped_at_firm(self):
        chain = validate_oauth("implicit", self.IMPLICIT_RESPONSE, token_in_url=True)
        assert chain.confidence == Confidence.FIRM
        # Gate is recorded even when the ceiling equals the weight tier (cap prevents CONFIRMED)
        assert len(chain.gates) > 0

    def test_implicit_flow_no_token_in_url_no_leak_signal(self):
        chain = validate_oauth("implicit", self.IMPLICIT_RESPONSE, token_in_url=False)
        assert not _has_signal(chain, "url")


# ---------------------------------------------------------------------------
# PKCE (Proof Key for Code Exchange)
# ---------------------------------------------------------------------------

class TestPkce:
    def test_missing_pkce_on_code_flow(self):
        chain = validate_oauth("code", AUTH_OK, pkce_used=False, pkce_validated=False)
        assert _has_signal(chain, "pkce") or _has_signal(chain, "code_challenge")

    def test_pkce_bypass_higher_weight_than_missing(self):
        missing = validate_oauth("code", AUTH_OK, pkce_used=False, pkce_validated=False)
        bypass = validate_oauth("code", AUTH_OK, pkce_used=True, pkce_validated=False)
        assert bypass.total_weight > missing.total_weight

    def test_pkce_bypass_reaches_firm(self):
        chain = validate_oauth("code", AUTH_OK, pkce_used=True, pkce_validated=False)
        assert chain.confidence in (Confidence.FIRM, Confidence.CONFIRMED)

    def test_pkce_enforced_no_signal(self):
        chain = validate_oauth("code", AUTH_OK, pkce_used=True, pkce_validated=True)
        assert not _has_signal(chain, "pkce")

    def test_pkce_not_applicable_to_client_credentials(self):
        chain = validate_oauth("client_credentials", AUTH_OK, pkce_used=False, pkce_validated=False)
        assert not _has_signal(chain, "pkce")


# ---------------------------------------------------------------------------
# Authorization code reuse
# ---------------------------------------------------------------------------

class TestCodeReuse:
    REUSE_SUCCESS = "HTTP/1.1 200 OK\n{\"access_token\": \"new_token\", \"token_type\": \"bearer\"}"
    REUSE_REJECTED = "HTTP/1.1 400 Bad Request\n{\"error\": \"invalid_grant\", \"description\": \"code already used\"}"

    def test_code_reuse_accepted_high_weight(self):
        chain = validate_oauth("code", AUTH_OK, code_reuse_response=self.REUSE_SUCCESS)
        assert chain.total_weight >= 1.5

    def test_code_reuse_accepted_firm_or_confirmed(self):
        chain = validate_oauth("code", AUTH_OK, code_reuse_response=self.REUSE_SUCCESS)
        assert chain.confidence in (Confidence.FIRM, Confidence.CONFIRMED)

    def test_code_reuse_rejected_is_fp(self):
        chain = validate_oauth("code", AUTH_OK, code_reuse_response=self.REUSE_REJECTED)
        assert len(chain.false_positive_checks) > 0
        assert chain.total_weight == 0.0

    def test_no_code_reuse_no_signal(self):
        chain = validate_oauth("code", AUTH_OK, code_reuse_response="")
        assert not _has_signal(chain, "reuse") and not _has_signal(chain, "double")


# ---------------------------------------------------------------------------
# Scope bypass
# ---------------------------------------------------------------------------

class TestScopeBypass:
    ELEVATED_RESPONSE = "HTTP/1.1 200 OK\n{\"scope\": \"read write admin\", \"access_token\": \"tok\"}"
    NORMAL_RESPONSE = "HTTP/1.1 200 OK\n{\"scope\": \"read\", \"access_token\": \"tok\"}"

    def test_elevated_scope_granted_adds_signal(self):
        chain = validate_oauth(
            "code", AUTH_OK,
            scope_test=self.ELEVATED_RESPONSE,
            baseline_auth_response=self.NORMAL_RESPONSE,
        )
        assert _has_signal(chain, "scope")

    def test_elevated_scope_weight_positive(self):
        chain = validate_oauth(
            "code", AUTH_OK,
            scope_test=self.ELEVATED_RESPONSE,
            baseline_auth_response=self.NORMAL_RESPONSE,
        )
        assert chain.total_weight > 0

    def test_scope_test_no_elevation_no_signal(self):
        chain = validate_oauth(
            "code", AUTH_OK,
            scope_test=self.NORMAL_RESPONSE,
            baseline_auth_response=self.NORMAL_RESPONSE,
        )
        assert not _has_signal(chain, "scope")


# ---------------------------------------------------------------------------
# SAML signature wrapping
# ---------------------------------------------------------------------------

class TestSamlSignatureWrapping:
    WRAPPING_RESPONSE = (
        "<samlp:Response>"
        "<ds:Signature><SignatureValue>ORIGINAL</SignatureValue></ds:Signature>"
        "<ds:Signature><SignatureValue>WRAPPED</SignatureValue></ds:Signature>"
        "<saml:Assertion>admin=true</saml:Assertion>"
        "</samlp:Response>"
    )
    COMMENT_INJECTION = (
        "<samlp:Response>"
        "<ds:Signature><!-- injected comment --><SignatureValue>SIG</SignatureValue></ds:Signature>"
        "</samlp:Response>"
    )
    NORMAL_SAML = (
        "<samlp:Response>"
        "<ds:Signature><SignatureValue>VALIDHASH</SignatureValue></ds:Signature>"
        "</samlp:Response>"
    )

    def test_multiple_signatures_detected(self):
        chain = validate_oauth("code", AUTH_OK, saml_response=self.WRAPPING_RESPONSE)
        assert _has_signal(chain, "signature") or _has_signal(chain, "xsw")

    def test_multiple_signatures_reach_firm(self):
        chain = validate_oauth("code", AUTH_OK, saml_response=self.WRAPPING_RESPONSE)
        assert chain.confidence in (Confidence.FIRM, Confidence.CONFIRMED)

    def test_comment_injection_detected(self):
        chain = validate_oauth("code", AUTH_OK, saml_response=self.COMMENT_INJECTION)
        assert _has_signal(chain, "comment")

    def test_normal_saml_no_wrapping_signal(self):
        chain = validate_oauth("code", AUTH_OK, saml_response=self.NORMAL_SAML)
        assert not _has_signal(chain, "wrapping")

    def test_no_saml_no_signal(self):
        chain = validate_oauth("code", AUTH_OK, saml_response="")
        assert not _has_signal(chain, "saml")


# ---------------------------------------------------------------------------
# Empty / invalid input
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_auth_response_returns_fp(self):
        chain = validate_oauth("code", "")
        assert len(chain.false_positive_checks) > 0

    def test_clean_flow_no_signals(self):
        chain = validate_oauth(
            "code",
            AUTH_OK,
            state_present=True,
            state_validated=True,
            pkce_used=True,
            pkce_validated=True,
            redirect_uri_test="",
            code_reuse_response="",
            token_in_url=False,
            scope_test="",
            saml_response="",
        )
        assert not chain.items
        assert chain.total_weight == 0.0

    def test_multiple_flaws_accumulate(self):
        """Multiple OAuth flaws in one flow should accumulate weight."""
        chain = validate_oauth(
            "code",
            AUTH_OK,
            state_present=False,
            state_validated=False,
            pkce_used=False,
            pkce_validated=False,
        )
        single_flaw = validate_oauth("code", AUTH_OK, state_present=False, state_validated=False)
        assert chain.total_weight > single_flaw.total_weight
