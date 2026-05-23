"""Tests for custom Nuclei template generation."""

from __future__ import annotations

import yaml

from kambo.nuclei_templates import (
    TemplateLibrary,
    generate_template,
    generate_template_from_finding,
    get_template_library,
)


class TestGenerateTemplate:
    def test_basic_template(self) -> None:
        result = generate_template(
            finding_id="FIND-001",
            vuln_type="sqli",
            target="http://example.com",
            path="/login",
            parameter="username",
            payload="' OR 1=1--",
            severity="critical",
        )
        parsed = yaml.safe_load(result)
        assert parsed["id"] == "kambo-sqli-find001"
        assert parsed["info"]["severity"] == "critical"
        assert parsed["info"]["metadata"]["finding_id"] == "FIND-001"
        assert "kambo" in parsed["info"]["tags"]
        assert len(parsed["http"]) == 1

    def test_get_request_with_parameter(self) -> None:
        result = generate_template(
            finding_id="FIND-002",
            vuln_type="xss",
            target="http://example.com",
            method="GET",
            path="/search",
            parameter="q",
            payload="<script>alert(1)</script>",
        )
        parsed = yaml.safe_load(result)
        http = parsed["http"][0]
        assert "q=" in http["path"][0]
        assert "{{BaseURL}}" in http["path"][0]

    def test_post_request_with_body(self) -> None:
        result = generate_template(
            finding_id="FIND-003",
            vuln_type="sqli",
            target="http://example.com",
            method="POST",
            path="/api/login",
            parameter="password",
            payload="' OR 1=1--",
        )
        parsed = yaml.safe_load(result)
        http = parsed["http"][0]
        assert http["method"] == "POST"
        assert "password=" in http["body"]

    def test_custom_match_patterns(self) -> None:
        result = generate_template(
            finding_id="FIND-004",
            vuln_type="sqli",
            target="http://example.com",
            match_patterns=["custom_error_message", "database_dump"],
        )
        parsed = yaml.safe_load(result)
        matchers = parsed["http"][0]["matchers"]
        word_matcher = next(m for m in matchers if m["type"] == "word")
        assert "custom_error_message" in word_matcher["words"]

    def test_custom_status_codes(self) -> None:
        result = generate_template(
            finding_id="FIND-005",
            vuln_type="open_redirect",
            target="http://example.com",
            status_codes=[301, 302],
        )
        parsed = yaml.safe_load(result)
        matchers = parsed["http"][0]["matchers"]
        status_matcher = next(m for m in matchers if m["type"] == "status")
        assert 302 in status_matcher["status"]

    def test_default_matchers_sqli(self) -> None:
        result = generate_template(
            finding_id="FIND-006", vuln_type="sqli", target="http://example.com"
        )
        parsed = yaml.safe_load(result)
        matchers = parsed["http"][0]["matchers"]
        assert any(m.get("type") == "word" for m in matchers)

    def test_default_matchers_xss(self) -> None:
        result = generate_template(
            finding_id="FIND-007", vuln_type="xss", target="http://example.com"
        )
        parsed = yaml.safe_load(result)
        matchers = parsed["http"][0]["matchers"]
        word_matcher = next(m for m in matchers if m["type"] == "word")
        assert "<script>" in word_matcher["words"]

    def test_default_matchers_rce(self) -> None:
        result = generate_template(
            finding_id="FIND-008", vuln_type="rce", target="http://example.com"
        )
        parsed = yaml.safe_load(result)
        matchers = parsed["http"][0]["matchers"]
        assert any(m.get("type") == "regex" for m in matchers)

    def test_custom_tags(self) -> None:
        result = generate_template(
            finding_id="FIND-009", vuln_type="sqli", target="http://example.com",
            tags=["sqli", "kambo", "regression"],
        )
        parsed = yaml.safe_load(result)
        assert "regression" in parsed["info"]["tags"]

    def test_no_parameter_path(self) -> None:
        result = generate_template(
            finding_id="FIND-010", vuln_type="cors", target="http://example.com",
            path="/api/data",
        )
        parsed = yaml.safe_load(result)
        assert "{{BaseURL}}/api/data" in parsed["http"][0]["path"][0]


class TestGenerateFromFinding:
    def test_from_finding_dict(self) -> None:
        finding = {
            "id": "FIND-100",
            "vuln_type": "ssrf",
            "target": "http://example.com",
            "path": "/proxy",
            "parameter": "url",
            "payload": "http://169.254.169.254/latest/meta-data/",
            "severity": "critical",
        }
        result = generate_template_from_finding(finding)
        parsed = yaml.safe_load(result)
        assert "ssrf" in parsed["id"]
        assert parsed["info"]["severity"] == "critical"


class TestTemplateLibrary:
    def test_add_and_get(self) -> None:
        lib = TemplateLibrary()
        lib.add("test-template", "id: test-template\n")
        assert lib.get("test-template") == "id: test-template\n"
        assert lib.count == 1

    def test_list_templates(self) -> None:
        lib = TemplateLibrary()
        lib.add("t1", "yaml1")
        lib.add("t2", "yaml2")
        assert set(lib.list_templates()) == {"t1", "t2"}

    def test_generate_and_store(self) -> None:
        lib = TemplateLibrary()
        yaml_content = lib.generate_and_store(
            finding_id="FIND-200",
            vuln_type="xss",
            target="http://example.com",
        )
        assert lib.count == 1
        assert "kambo-xss" in lib.list_templates()[0]

    def test_export_all(self) -> None:
        lib = TemplateLibrary()
        lib.add("t1", "id: t1")
        lib.add("t2", "id: t2")
        export = lib.export_all()
        assert "id: t1" in export
        assert "id: t2" in export

    def test_get_missing(self) -> None:
        lib = TemplateLibrary()
        assert lib.get("nonexistent") is None
