"""Generate Kambo session-viz diagrams (demo / reusable template).

Renders an attack-vector map, attack-surface mindmap, confidence tree, finding
flow, and tool scorecard via kambo.visualizer, then writes a combined dark-theme
HTML page. The data below is illustrative placeholder data (example.com) — swap
in real session data (or wire it to the findings DB) when generating live; the
real, target-specific output belongs under output/ (gitignored), not in source.

Run: python scripts/viz_session.py  ->  output/viz/session.html
"""
from __future__ import annotations

from pathlib import Path

from kambo.visualizer import attack_surface, confidence_tree, finding_flow, tool_scorecard

# --- Placeholder session data (example.com) --------------------------------

TARGET = "example.com"

FINDINGS = [
    {"title": "Exposed key (billing abuse)", "severity": "medium", "confidence": "firm",
     "phase": "vulnerability_analysis", "evidence": {"total_weight": 1.5, "signal_count": 4}},
    {"title": "Source maps exposed (prod)", "severity": "low", "confidence": "firm",
     "phase": "vulnerability_analysis", "evidence": {"total_weight": 1.3, "signal_count": 3}},
    {"title": "OAuth open-redirect (next)", "severity": "low", "confidence": "tentative",
     "phase": "vulnerability_analysis", "evidence": {"total_weight": 0.7, "signal_count": 3}},
]

HOSTS = [
    "app.example.com", "blog.example.com", "careers.example.com", "example.com",
    "couriers.example.com", "intercity.example.com", "movie.example.com",
    "url-checker.example.com", "docs.example.com", "brand.example.com",
    "node1.example.com", "node2.example.com", "auth.example.com",
]
TECH = ["Next.js", "istio-envoy", "CDN", "Django/social-auth",
        "nginx", "Apache", "Frontify", "Webflow"]

# Tool metrics (precision = clean-negative quality; illustrative)
TOOLS = {
    "vuln_subdomain_takeover": {"runs": 38, "findings": 5, "precision": 0.90},
    "vuln_cors":               {"runs": 41, "findings": 9, "precision": 0.65},
    "vuln_ssrf":               {"runs": 16, "findings": 8, "precision": 0.60},
    "vuln_xss":                {"runs": 27, "findings": 27, "precision": 0.20},
    "api_test_misconfig":      {"runs": 15, "findings": 14, "precision": 0.25},
    "vuln_nuclei_scan":        {"runs": 27, "findings": 0, "precision": 0.50},
    "recon_subdomains":        {"runs": 26, "findings": 0, "precision": 0.10},
}

# --- Custom attack-vector verdict map --------------------------------------

def vector_map() -> str:
    rows = [
        ("Subdomain takeover", "CLEAN 3/3", "clean"),
        ("CORS (api/blog)", "CLEAN static ACAO", "clean"),
        ("nuclei (old nginx)", "CLEAN 0 CVE", "clean"),
        ("React2Shell probe", "CLEAN no handler", "clean"),
        ("JS secrets (app)", "FINDING: exposed key", "find"),
        ("Source maps", "FINDING: prod maps", "find"),
        ("OAuth next", "TENTATIVE redirect", "tent"),
        ("url-checker SSRF", "BLOCKED / client-side", "gap"),
        ("TLS scan", "GAP empty output", "gap"),
        ("file-storage / docs", "DEFERRED authz", "defer"),
    ]
    lines = ["flowchart LR", '  T(("attack<br/>surface"))']
    for i, (vec, verdict, cls) in enumerate(rows):
        v, r = f"V{i}", f"R{i}"
        lines.append(f'  {v}["{vec}"]')
        lines.append(f'  {r}["{verdict}"]')
        lines.append(f"  T --> {v} --> {r}")
        lines.append(f"  class {r} {cls}")
    lines += [
        "  classDef clean fill:#1b5e20,color:#fff,stroke:#2e7d32",
        "  classDef find fill:#e65100,color:#fff,stroke:#f57c00",
        "  classDef tent fill:#424242,color:#fff,stroke:#757575",
        "  classDef gap fill:#37474f,color:#fff,stroke:#546e7a",
        "  classDef defer fill:#283593,color:#fff,stroke:#3949ab",
    ]
    return "\n".join(lines)

# --- Build diagrams ---------------------------------------------------------

DIAGRAMS = [
    ("Attack-Vector Verdict Map", vector_map()),
    ("Attack Surface (hosts / tech / findings)",
     attack_surface(TARGET, subdomains=HOSTS, technologies=TECH,
                    waf="CDN / WAF", findings=FINDINGS)),
    ("Confidence Tree", confidence_tree(FINDINGS)),
    ("Finding Flow (pipeline)", finding_flow(findings=FINDINGS, current_phase="vulnerability_analysis")),
    ("Tool Scorecard", tool_scorecard(TOOLS)),
]

# --- Combined HTML ----------------------------------------------------------

# mermaid library CDN (a legitimate runtime dependency for rendering, not a
# test target — a pre-commit "real domain" warning here is a false positive).
MERMAID_CDN = "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"

blocks = "\n".join(
    f'<h2>{t}</h2><div class="mermaid">\n{c}\n</div>' for t, c in DIAGRAMS
)
html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Kambo Viz — session</title>
<script src="{MERMAID_CDN}"></script>
<style>
 body{{background:#0d1117;color:#c9d1d9;font-family:-apple-system,Segoe UI,sans-serif;padding:2rem;margin:0}}
 h1{{color:#58a6ff}} h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:.3rem;margin-top:2rem}}
 .mermaid{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.5rem;margin:.5rem 0;overflow-x:auto}}
</style></head><body>
<h1>Kambo Viz — session</h1>
{blocks}
<script>mermaid.initialize({{startOnLoad:true,theme:'dark'}});</script>
</body></html>"""


def main() -> None:
    out = Path("output/viz/session.html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    for title, code in DIAGRAMS:
        print(f"@@@DIAGRAM::{title}\n{code}\n@@@END")
    print(f"@@@HTML::{out.resolve()}")


if __name__ == "__main__":
    main()
