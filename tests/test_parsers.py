"""Tests for output parsers."""

import pytest

from kambo.parsers.nmap_parser import parse_nmap
from kambo.parsers.nuclei_parser import parse_nuclei
from kambo.parsers.subfinder_parser import parse_subfinder
from kambo.parsers.generic_parser import extract_ips, extract_urls, parse_lines


def test_parse_nmap_normal_output() -> None:
    raw = """Nmap scan report for 192.168.1.1
22/tcp   open  ssh     OpenSSH 8.9
80/tcp   open  http    Apache httpd 2.4.52
443/tcp  open  https   nginx 1.18.0

Nmap scan report for 192.168.1.2
3306/tcp open  mysql   MySQL 8.0.33
"""
    result = parse_nmap(raw)
    assert result["total_hosts"] == 2
    assert len(result["hosts"][0]["ports"]) == 3
    assert result["hosts"][0]["ports"][0]["port"] == 22


def test_parse_subfinder_plain() -> None:
    raw = """sub1.example.com
sub2.example.com
api.example.com
sub1.example.com
"""
    result = parse_subfinder(raw)
    assert result["total"] == 3  # deduplicated
    assert "api.example.com" in result["subdomains"]


def test_parse_nuclei_jsonl() -> None:
    raw = '{"template-id":"cve-2021-44228","info":{"name":"Log4Shell","severity":"critical"},"host":"http://target.com","matched-at":"http://target.com/api"}\n'
    result = parse_nuclei(raw)
    assert result["total"] == 1
    assert result["severity_counts"]["critical"] == 1
    assert result["findings"][0]["template_name"] == "Log4Shell"


def test_extract_ips() -> None:
    raw = "Connected to 192.168.1.1 via 10.0.0.1, response from 172.16.0.5"
    ips = extract_ips(raw)
    assert "192.168.1.1" in ips
    assert "10.0.0.1" in ips
    assert len(ips) == 3


def test_extract_urls() -> None:
    raw = 'Found: https://api.example.com/v1 and http://internal.local:8080/admin'
    urls = extract_urls(raw)
    assert "https://api.example.com/v1" in urls
    assert len(urls) == 2


def test_parse_lines() -> None:
    raw = "line1\n\nline2\n  line3  \n"
    result = parse_lines(raw)
    assert result == ["line1", "line2", "line3"]
