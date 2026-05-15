"""Parser for ffuf JSON output."""

from __future__ import annotations

import json


def parse_ffuf(raw: str) -> dict:
    """Parse ffuf JSON output into structured results.

    Use ffuf with -o output.json -of json for structured output.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Fallback: parse text output
        return _parse_text(raw)

    results = []
    for result in data.get("results", []):
        results.append({
            "url": result.get("url", ""),
            "status": result.get("status", 0),
            "length": result.get("length", 0),
            "words": result.get("words", 0),
            "lines": result.get("lines", 0),
            "input": result.get("input", {}),
            "redirect_location": result.get("redirectlocation", ""),
        })

    return {
        "results": results,
        "total": len(results),
        "command_line": data.get("commandline", ""),
        "config": {
            "url": data.get("config", {}).get("url", ""),
            "method": data.get("config", {}).get("method", "GET"),
        },
    }


def _parse_text(raw: str) -> dict:
    """Fallback parser for non-JSON ffuf output."""
    results = []
    for line in raw.splitlines():
        # Typical ffuf line: /path [Status: 200, Size: 1234, Words: 56, Lines: 78]
        if "[Status:" in line:
            parts = line.split("[Status:")
            path = parts[0].strip()
            status_match = parts[1] if len(parts) > 1 else ""
            results.append({
                "url": path,
                "status_line": status_match.rstrip("]"),
            })

    return {"results": results, "total": len(results)}
