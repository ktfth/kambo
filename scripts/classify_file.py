"""Claude Code hook — classifies file writes to detect program-specific data.

Called as PreToolUse hook on Write/Edit operations.
Prints warnings to stderr when a file write targets a path that could
contain operational data from a specific bounty program.

Exit 0 always (advisory only — does not block Claude operations).
The git pre-commit hook (validate_commit.py) is the hard gate.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Paths that should never receive program-specific content
OPERATIONAL_PATHS = [
    "output/",
    "reports/",
    ".agents/",
]

# File patterns that indicate operational data
OPERATIONAL_PATTERNS = [
    "-report",
    "_ips.",
    "_domains.",
    "recon-",
    "probe-",
    "report-",
]


def classify(filepath: str) -> None:
    if not filepath:
        return

    path = Path(filepath)
    rel = str(path).replace("\\", "/")

    # Check blocked paths
    for blocked in OPERATIONAL_PATHS:
        if rel.startswith(blocked) or f"/{blocked}" in rel:
            print(
                f"WARNING:  Writing to '{blocked}' — this path contains operational data. "
                f"Ensure this file is in .gitignore and will not be committed.",
                file=sys.stderr,
            )
            return

    # Check operational file patterns
    name = path.name.lower()
    for pattern in OPERATIONAL_PATTERNS:
        if pattern in name:
            print(
                f"WARNING:  File '{name}' looks like operational data (matches '{pattern}'). "
                f"Ensure it won't be committed to the repository.",
                file=sys.stderr,
            )
            return


if __name__ == "__main__":
    if len(sys.argv) > 1:
        classify(sys.argv[1])
