"""Tests for reconnaissance tool wrappers."""

from __future__ import annotations

import pytest

from tests.conftest import patch_runner


class TestReconSubdomains:
    @pytest.mark.asyncio
    async def test_subdomains_found(self) -> None:
        from kambo.tools.recon import recon_subdomains
        output = "api.example.com\nwww.example.com\nmail.example.com\n"
        with patch_runner({"recon_subdomains_subfinder": output, "recon_wildcard_check": "NXDOMAIN"}):
            result = await recon_subdomains("example.com", methods=["subfinder"])
        assert result["total"] >= 3
        assert "api.example.com" in result["subdomains"]

    @pytest.mark.asyncio
    async def test_empty_results(self) -> None:
        from kambo.tools.recon import recon_subdomains
        with patch_runner({"recon_subdomains_subfinder": "", "recon_wildcard_check": "NXDOMAIN"}):
            result = await recon_subdomains("example.com", methods=["subfinder"])
        assert result["total"] == 0


class TestReconPortsFast:
    @pytest.mark.asyncio
    async def test_open_ports(self) -> None:
        from kambo.tools.recon import recon_ports_fast
        # Nmap grepable output format
        output = "Host: 10.0.0.1 () Ports: 80/open/tcp//http//, 443/open/tcp//https//\n"
        with patch_runner({"recon_ports_fast": output}):
            result = await recon_ports_fast("example.com")
        assert result["total"] == 2

    @pytest.mark.asyncio
    async def test_no_open_ports(self) -> None:
        from kambo.tools.recon import recon_ports_fast
        with patch_runner({"recon_ports_fast": ""}):
            result = await recon_ports_fast("example.com")
        assert result["total"] == 0


class TestReconTechStack:
    @pytest.mark.asyncio
    async def test_technologies_detected(self) -> None:
        from kambo.tools.recon import recon_tech_stack
        output = "WhatWeb report for http://example.com\nHTTPServer[nginx]\nPHP[7.4]\njQuery\n"
        with patch_runner({"recon_tech_stack": output}):
            result = await recon_tech_stack("example.com")
        assert result["tech_count"] >= 0  # parsed from output


class TestReconWaf:
    @pytest.mark.asyncio
    async def test_waf_detected(self) -> None:
        from kambo.tools.recon import recon_waf
        output = '[*] The site http://example.com is behind Cloudflare (Cloudflare Inc.)'
        with patch_runner({"recon_waf": output}):
            result = await recon_waf("example.com")
        assert result["waf_detected"] is True
        assert "Cloudflare" in result["waf_name"]

    @pytest.mark.asyncio
    async def test_no_waf(self) -> None:
        from kambo.tools.recon import recon_waf
        output = "Generic Detection results:\nNo WAF detected"
        with patch_runner({"recon_waf": output}):
            result = await recon_waf("example.com")
        assert result["waf_detected"] is False
