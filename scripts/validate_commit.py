"""Pre-commit validator — blocks program-specific data from entering the repo.

Two-layer validation:
  Layer 1 (fast): Pattern matching for known violations
  Layer 2 (smart): Content classification for ambiguous cases

Exit codes:
  0 = clean, commit allowed
  1 = violation found, commit blocked
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Layer 1: Blocked paths — these should NEVER be committed
# ---------------------------------------------------------------------------

BLOCKED_PATHS: list[str] = [
    "output/",
    "reports/",
    ".agents/",
    ".playwright-mcp/",
]

BLOCKED_EXTENSIONS: list[str] = [
    ".db",
    ".sqlite",
    ".sqlite3",
    ".log",
    ".env",
    ".env.local",
]

# ---------------------------------------------------------------------------
# Layer 1: Content patterns — indicate program-specific data
# ---------------------------------------------------------------------------

# IP addresses (not in test fixtures or code examples)
_IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Real domain patterns (not example.com or test fixtures)
_REAL_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:com|net|org|io|co|dev|app|cloud)\b",
    re.IGNORECASE,
)

# Known safe domains (test fixtures, examples, documentation)
SAFE_DOMAINS: set[str] = {
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "target.com",
    "evil.com",
    "localhost",
    "testcorp.com",
    "smallco.com",
    "bigcorp.com",
    "mid.com",
    "app.example.com",
    "api.example.com",
    "staging.app.com",
    "prod.app.com",
    "yourapp.com",
    "github.com",
    "pypi.org",
    "hackerone.com",
    "bugcrowd.com",
    "intigriti.com",
    "yeswehack.com",
    "garryslist.org",
}

# Patterns that indicate bounty report content
_REPORT_INDICATORS = [
    re.compile(r"## (Vulnerability|Finding|Impact|Remediation|Steps to Reproduce)", re.IGNORECASE),
    re.compile(r"(CVSS|severity):\s*(critical|high|medium|low)", re.IGNORECASE),
    re.compile(r"(proof of concept|reproduction steps|poc)", re.IGNORECASE),
    re.compile(r"program:\s*\w+", re.IGNORECASE),
]

# API keys, tokens, secrets
_SECRET_PATTERNS = [
    re.compile(r"(?:api[_-]?key|token|secret|password|credential)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_-]{16,}", re.IGNORECASE),
    re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}"),
    re.compile(r"-----BEGIN.*PRIVATE KEY-----"),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key
]

# Files that are always safe (code, tests, config)
SAFE_FILE_PATTERNS: list[str] = [
    "*.py",
    "*.toml",
    "*.cfg",
    "*.ini",
    "*.txt",
    "*.gitignore",
    "CLAUDE.md",
    "README.md",
    "SKILL.md",
]


# ---------------------------------------------------------------------------
# Validation engine
# ---------------------------------------------------------------------------

class Violation:
    def __init__(self, file: str, line: int, reason: str, severity: str = "BLOCK") -> None:
        self.file = file
        self.line = line
        self.reason = reason
        self.severity = severity  # BLOCK or WARN

    def __str__(self) -> str:
        return f"  [{self.severity}] {self.file}:{self.line} — {self.reason}"


def get_staged_files() -> list[str]:
    """Get list of files staged for commit."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True, text=True,
    )
    return [f.strip() for f in result.stdout.splitlines() if f.strip()]


def check_blocked_path(filepath: str) -> Violation | None:
    """Check if file is in a blocked directory."""
    for blocked in BLOCKED_PATHS:
        if filepath.startswith(blocked):
            return Violation(filepath, 0, f"Path '{blocked}' contains operational data — must not be committed", "BLOCK")
    return None


def check_blocked_extension(filepath: str) -> Violation | None:
    """Check for blocked file extensions."""
    for ext in BLOCKED_EXTENSIONS:
        if filepath.endswith(ext):
            return Violation(filepath, 0, f"Extension '{ext}' indicates data files — must not be committed", "BLOCK")
    return None


_SELF_SAFE_PATHS = {
    "scripts/validate_commit.py",  # contains detection patterns (not real data)
    "scripts/classify_file.py",
    "src/kambo/validation.py",  # contains regex patterns for detection (not real secrets/domains)
}


def check_content(filepath: str) -> list[Violation]:
    """Scan file content for program-specific data."""
    violations: list[Violation] = []

    # Skip the validator itself (contains detection patterns, not real data)
    if filepath.replace("\\", "/") in _SELF_SAFE_PATHS:
        return []

    # Skip binary files
    try:
        content = Path(filepath).read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return []

    lines = content.splitlines()

    for i, line in enumerate(lines, 1):
        # Skip comments in Python files
        stripped = line.strip()
        if stripped.startswith("#") and filepath.endswith(".py"):
            continue

        # Check for real IPs (not in test ranges)
        for match in _IP_PATTERN.finditer(line):
            ip = match.group()
            octets = ip.split(".")
            # Allow test/private ranges: 10.x, 192.168.x, 127.x, 0.0.0.0, 169.254.x
            first = int(octets[0])
            if first not in (10, 127, 0, 169) and not (first == 192 and octets[1] == "168"):
                violations.append(Violation(
                    filepath, i,
                    f"Public IP address detected: {ip}",
                    "BLOCK",
                ))

        # Check for real domains
        for match in _REAL_DOMAIN_PATTERN.finditer(line):
            domain = match.group().lower()
            # Extract root domain for safe-list check
            parts = domain.split(".")
            root = ".".join(parts[-2:]) if len(parts) >= 2 else domain
            if root not in SAFE_DOMAINS and domain not in SAFE_DOMAINS:
                # Allow domains in import statements and URLs in code
                if "import " in line or "from " in line:
                    continue
                # Allow pip/package references
                if "pypi.org" in line or "pip install" in line:
                    continue
                violations.append(Violation(
                    filepath, i,
                    f"Real domain detected: {domain} — use example.com for tests",
                    "WARN",
                ))

        # Check for secrets
        for pattern in _SECRET_PATTERNS:
            if pattern.search(line):
                violations.append(Violation(
                    filepath, i,
                    "Potential secret/credential detected",
                    "BLOCK",
                ))
                break

        # Check for bounty report content in non-report files
        if not filepath.startswith("reports/"):
            for pattern in _REPORT_INDICATORS:
                if pattern.search(line):
                    # Allow in SKILL.md files (they contain report templates)
                    if filepath.endswith("SKILL.md"):
                        continue
                    # Allow in reporting.py and tests (template code)
                    if "reporting" in filepath or "test_" in filepath:
                        continue
                    if "bounty_pricing" in filepath or "bounty_intel" in filepath:
                        continue
                    violations.append(Violation(
                        filepath, i,
                        f"Bounty report content detected in code file: {pattern.pattern[:40]}...",
                        "WARN",
                    ))
                    break

    return violations


def validate_staged_files() -> tuple[list[Violation], list[Violation]]:
    """Run all validations on staged files. Returns (blocks, warnings)."""
    files = get_staged_files()
    blocks: list[Violation] = []
    warnings: list[Violation] = []

    for filepath in files:
        # Path check
        v = check_blocked_path(filepath)
        if v:
            blocks.append(v)
            continue

        # Extension check
        v = check_blocked_extension(filepath)
        if v:
            blocks.append(v)
            continue

        # Content check
        for violation in check_content(filepath):
            if violation.severity == "BLOCK":
                blocks.append(violation)
            else:
                warnings.append(violation)

    return blocks, warnings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    blocks, warnings = validate_staged_files()

    if warnings:
        print("\nWARNING:  WARNINGS (review before committing):")
        for w in warnings:
            print(w)

    if blocks:
        print("\nBLOCKED: BLOCKED — commit contains program-specific data:")
        for b in blocks:
            print(b)
        print(f"\n{len(blocks)} violation(s) found. Commit blocked.")
        print("Fix: remove the data or add the path to .gitignore")
        return 1

    if not warnings and not blocks:
        print("OK: Pre-commit validation passed — no program data detected.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
