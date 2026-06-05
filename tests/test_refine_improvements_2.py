"""Tests for the second refine pass (inDrive calibration session).

1. recon silent-zero — recon_subdomains / recon_certs distinguish a source
   outage from an authoritative empty result (reliability + warning).
2. validate_xss browser-verification ceiling — curl-only reflection caps at
   FIRM (never CONFIRMED); SPA frameworks cap at TENTATIVE.
3. api_test_misconfig — sub-threshold header-only noise is not recorded as a
   finding (record_finding gated at the same >= 0.5 as `vulnerable`).
"""

from __future__ import annotations

import pytest

from kambo.models import Confidence, ToolResult, Phase, _CONFIDENCE_RANK
from kambo.validation import validate_xss
from tests.conftest import patch_runner


# ---------------------------------------------------------------------------
# Fix 1: recon silent-zero — source failure must not look like ground truth
# ---------------------------------------------------------------------------

def _failed_result(tool_name: str) -> ToolResult:
    """A source that errored/timed out: non-zero exit, error set, no output."""
    return ToolResult(
        tool_name=tool_name,
        command="curl ...",
        target="example.com",
        phase=Phase.RECON,
        raw_output="",
        exit_code=1,
        error="timeout",
        duration_seconds=20.0,
    )


class TestReconSubdomainsSilentZero:
    @pytest.mark.asyncio
    async def test_empty_output_marks_unreliable(self) -> None:
        """A source that returns empty output (crt.sh HTTP 000 → curl|jq exits 0
        with nothing) must be flagged unreliable, not an authoritative zero."""
        from kambo.tools.recon import recon_subdomains
        with patch_runner({"recon_subdomains_crtsh": "", "recon_wildcard_check": ""}):
            result = await recon_subdomains("example.com", methods=["crtsh"])
        assert result["total"] == 0
        assert result["reliable"] is False
        assert result["warning"], "Expected a warning when the only source returned no data"
        assert result["sources"]["crtsh"] == "failed"

    @pytest.mark.asyncio
    async def test_explicit_error_marks_unreliable(self) -> None:
        from kambo.tools.recon import recon_subdomains
        with patch_runner(
            {"recon_subdomains_crtsh": _failed_result("recon_subdomains_crtsh"),
             "recon_wildcard_check": ""}
        ):
            result = await recon_subdomains("example.com", methods=["crtsh"])
        assert result["reliable"] is False
        assert "NOT authoritative" in result["warning"]

    @pytest.mark.asyncio
    async def test_found_subdomains_are_reliable(self) -> None:
        from kambo.tools.recon import recon_subdomains
        output = "api.example.com\nwww.example.com\nmail.example.com\n"
        with patch_runner({"recon_subdomains_subfinder": output, "recon_wildcard_check": ""}):
            result = await recon_subdomains("example.com", methods=["subfinder"])
        assert result["total"] >= 3
        assert result["reliable"] is True
        assert result["warning"] == ""
        assert result["sources"]["subfinder"] == "ok"

    @pytest.mark.asyncio
    async def test_genuine_empty_not_flagged_failed(self) -> None:
        """A source that ran cleanly (exit 0, non-empty body) but found nothing
        is 'empty', not 'failed' — and the result stays reliable."""
        from kambo.tools.recon import recon_subdomains
        clean_empty = ToolResult(
            tool_name="recon_subdomains_subfinder",
            command="subfinder ...",
            target="example.com",
            phase=Phase.RECON,
            raw_output="no results returned",  # non-empty, but no parseable domains
            exit_code=0,
        )
        with patch_runner(
            {"recon_subdomains_subfinder": clean_empty, "recon_wildcard_check": ""}
        ):
            result = await recon_subdomains("example.com", methods=["subfinder"])
        assert result["total"] == 0
        assert result["sources"]["subfinder"] == "empty"
        assert result["reliable"] is True
        assert result["warning"] == ""

    @pytest.mark.asyncio
    async def test_one_ok_one_failed_stays_reliable(self) -> None:
        """If at least one source delivered data, the result is usable."""
        from kambo.tools.recon import recon_subdomains
        with patch_runner({
            "recon_subdomains_subfinder": "api.example.com\nwww.example.com\n",
            "recon_subdomains_crtsh": "",
            "recon_wildcard_check": "",
        }):
            result = await recon_subdomains("example.com", methods=["subfinder", "crtsh"])
        assert result["reliable"] is True
        assert result["sources"]["subfinder"] == "ok"
        assert result["sources"]["crtsh"] == "failed"


class TestReconCertsSilentZero:
    @pytest.mark.asyncio
    async def test_empty_crtsh_marks_unreliable(self) -> None:
        from kambo.tools.recon import recon_certs
        with patch_runner({"recon_certs": ""}):
            result = await recon_certs("example.com")
        assert result["total"] == 0
        assert result["reliable"] is False
        assert result["warning"], "Expected a warning when crt.sh returns no data"

    @pytest.mark.asyncio
    async def test_certs_with_data_reliable(self) -> None:
        from kambo.tools.recon import recon_certs
        output = "api.example.com\nwww.example.com\nstaging.example.com\n"
        with patch_runner({"recon_certs": output}):
            result = await recon_certs("example.com")
        assert result["total"] >= 3
        assert result["reliable"] is True
        assert result["warning"] == ""


# ---------------------------------------------------------------------------
# Fix 2: validate_xss browser-verification ceiling
# ---------------------------------------------------------------------------

_PROBE = "kambo_probe_8f3"  # no HTML special chars → skips the encoding-FP check


class TestXssBrowserVerification:
    def test_curl_only_reflection_caps_at_firm(self) -> None:
        """A strong in-<script> reflection (weight 1.5) must cap at FIRM —
        curl cannot prove browser execution, so CONFIRMED is unreachable."""
        response = f'<script>var t = "{_PROBE}";</script>'
        chain = validate_xss(response, _PROBE, "q")
        assert chain.total_weight >= 1.0, "Expected FIRM-level weight from in-script reflection"
        assert chain.ceiling == Confidence.FIRM
        assert chain.confidence == Confidence.FIRM
        assert chain.confidence != Confidence.CONFIRMED
        assert "needs-browser-verification" in chain.flags

    def test_confirmed_is_unreachable_from_curl(self) -> None:
        """Even if weight piled up, the ceiling forbids CONFIRMED."""
        response = f'<script>var t = "{_PROBE}";</script>'
        chain = validate_xss(response, _PROBE, "q")
        assert _CONFIDENCE_RANK[chain.confidence] < _CONFIDENCE_RANK[Confidence.CONFIRMED]

    def test_spa_framework_caps_at_tentative(self) -> None:
        """SPA auto-escaping makes a curl reflection unproven — cap TENTATIVE."""
        response = f'<div id="__next"></div><script>var t = "{_PROBE}";</script>'
        chain = validate_xss(response, _PROBE, "q")
        assert chain.ceiling == Confidence.TENTATIVE
        assert chain.confidence == Confidence.TENTATIVE
        assert "needs-browser-verification" in chain.flags
        assert any("spa" in g.lower() for g in chain.gates)

    def test_webpack_marker_detected_as_spa(self) -> None:
        """New marker: a webpack-bundled app is treated as auto-escaping SPA."""
        response = f'<script>__webpack_require__(0);</script><p>{_PROBE}</p>'
        chain = validate_xss(response, _PROBE, "q")
        assert chain.ceiling == Confidence.TENTATIVE

    def test_reflection_always_flags_browser_verification(self) -> None:
        response = f'<p>hello {_PROBE}</p>'
        chain = validate_xss(response, _PROBE, "q")
        assert "needs-browser-verification" in chain.flags

    def test_non_reflected_payload_has_no_browser_flag(self) -> None:
        """No reflection → early return, no browser-verification flag."""
        chain = validate_xss("<p>nothing here</p>", _PROBE, "q")
        assert "needs-browser-verification" not in chain.flags
        assert any("not reflected" in c.lower() for c in chain.false_positive_checks)


# ---------------------------------------------------------------------------
# Fix 3: api_test_misconfig — sub-threshold noise is not a finding
# ---------------------------------------------------------------------------

class _FakeMetrics:
    def __init__(self) -> None:
        self.runs: list[str] = []
        self.findings: list[tuple] = []

    def record_run(self, name: str) -> None:
        self.runs.append(name)

    def record_finding(self, name: str, confidence, weight) -> None:
        self.findings.append((name, confidence, weight))


class TestApiMisconfigNoiseThreshold:
    @pytest.mark.asyncio
    async def test_missing_headers_only_is_not_recorded(self, monkeypatch) -> None:
        """Only a missing-headers signal (weight 0.2) → not a finding."""
        import kambo.tools.api_security as api
        fake = _FakeMetrics()
        monkeypatch.setattr(api, "get_metrics", lambda: fake)

        responses = {
            "api_test_misconfig_cors": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
            "api_test_misconfig_methods": "",          # no dangerous methods
            "api_test_misconfig_headers": "HTTP/1.1 200 OK\r\nServer: nginx\r\n",  # no sec headers
            "api_test_misconfig_errors": "404 Not Found",  # no verbose error
        }
        with patch_runner(responses):
            result = await api.api_test_misconfig("api.example.com")

        assert result["vulnerable"] is False
        assert result["evidence"]["total_weight"] < 0.5
        assert "api_test_misconfig" in fake.runs
        assert fake.findings == [], "Sub-threshold header noise must not be recorded as a finding"

    @pytest.mark.asyncio
    async def test_verbose_error_is_recorded(self, monkeypatch) -> None:
        """A real signal (verbose error, weight 0.5) IS recorded."""
        import kambo.tools.api_security as api
        fake = _FakeMetrics()
        monkeypatch.setattr(api, "get_metrics", lambda: fake)

        responses = {
            "api_test_misconfig_cors": "HTTP/1.1 200 OK\r\n",
            "api_test_misconfig_methods": "",
            "api_test_misconfig_headers": "HTTP/1.1 200 OK\r\n",
            "api_test_misconfig_errors": "Traceback (most recent call last): Exception at line 42",
        }
        with patch_runner(responses):
            result = await api.api_test_misconfig("api.example.com")

        assert result["evidence"]["total_weight"] >= 0.5
        assert result["vulnerable"] is True
        assert len(fake.findings) == 1
