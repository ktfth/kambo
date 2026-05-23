"""Mermaid diagram generator — visualize attack vectors, session flow, and findings.

Produces Mermaid.js syntax from session data that can be rendered
in browser, markdown, or exported as images.

Diagram types:
  1. attack_surface  — target map with domains, ports, services
  2. finding_flow    — recon → scan → vuln → exploit → report pipeline
  3. confidence_tree — findings grouped by confidence with evidence chains
  4. session_timeline — phase durations and tool executions
  5. roi_waterfall   — value breakdown per finding
  6. tool_scorecard  — tool performance radar
"""

from __future__ import annotations

from typing import Any


def attack_surface(
    target: str,
    subdomains: list[str] | None = None,
    ports: list[dict] | None = None,
    technologies: list[str] | None = None,
    waf: str | None = None,
    findings: list[dict] | None = None,
) -> str:
    """Generate attack surface mindmap.

    Shows the target hierarchy: domain → subdomains → services → findings.
    """
    lines = ["mindmap"]
    lines.append(f"  root(({target}))")

    # WAF layer
    if waf:
        lines.append(f"    {{{{WAF: {waf}}}}}")

    # Subdomains
    if subdomains:
        lines.append("    Subdomains")
        for sub in subdomains[:15]:  # cap for readability
            short = sub.replace(f".{target}", "")
            lines.append(f"      {short}")
        if len(subdomains) > 15:
            lines.append(f"      +{len(subdomains) - 15} more")

    # Ports / Services
    if ports:
        lines.append("    Services")
        for p in ports[:10]:
            port = p.get("port", "?")
            service = p.get("service", "unknown")
            lines.append(f"      :{port} {service}")

    # Technologies
    if technologies:
        lines.append("    Tech Stack")
        for tech in technologies[:8]:
            lines.append(f"      {tech}")

    # Findings overlay
    if findings:
        lines.append("    Findings")
        for f in findings[:10]:
            severity = f.get("severity", "info")
            title = f.get("title", "Unknown")
            icon = {"critical": "!!!!", "high": "!!!", "medium": "!!", "low": "!", "info": "i"}.get(severity, "?")
            lines.append(f"      {icon} {title}")

    return "\n".join(lines)


def finding_flow(
    findings: list[dict] | None = None,
    phases_completed: list[str] | None = None,
    current_phase: str = "",
) -> str:
    """Generate finding pipeline flowchart.

    Shows the flow from recon through reporting with findings at each stage.
    """
    phases = phases_completed or ["recon", "scanning", "vulnerability_analysis", "exploitation", "reporting"]

    phase_labels = {
        "recon": "Recon",
        "scanning": "Scanning",
        "vulnerability_analysis": "Vuln Analysis",
        "exploitation": "Exploitation",
        "post_exploitation": "Post-Exploit",
        "reporting": "Reporting",
    }

    lines = ["flowchart LR"]

    # Phase nodes
    for i, phase in enumerate(phases):
        label = phase_labels.get(phase, phase)
        node_id = f"P{i}"

        if phase == current_phase:
            lines.append(f"  {node_id}[[\"{label} *ACTIVE*\"]]")
        else:
            lines.append(f"  {node_id}[\"{label}\"]")

        if i > 0:
            lines.append(f"  P{i-1} --> {node_id}")

    # Findings attached to phases
    if findings:
        phase_findings: dict[str, list[dict]] = {}
        for f in findings:
            p = f.get("phase", "unknown")
            phase_findings.setdefault(p, []).append(f)

        for i, phase in enumerate(phases):
            pf = phase_findings.get(phase, [])
            for j, f in enumerate(pf[:5]):
                fid = f"F{i}_{j}"
                severity = f.get("severity", "info")
                confidence = f.get("confidence", "tentative")
                title = f.get("title", "Finding")[:30]

                shape = {
                    "confirmed": f'{fid}[/"{title}\\n{severity.upper()} | CONFIRMED"/]',
                    "firm": f'{fid}["{title}\\n{severity.upper()} | FIRM"]',
                    "tentative": f'{fid}("{title}\\n{severity.upper()} | TENTATIVE")',
                }.get(confidence, f'{fid}("{title}")')

                lines.append(f"  {shape}")
                lines.append(f"  P{i} -.-> {fid}")

    # Styling
    lines.append("")
    lines.append("  classDef critical fill:#d32f2f,color:#fff")
    lines.append("  classDef high fill:#f57c00,color:#fff")
    lines.append("  classDef medium fill:#fbc02d,color:#000")
    lines.append("  classDef low fill:#388e3c,color:#fff")
    lines.append("  classDef active fill:#1565c0,color:#fff")

    if findings:
        for i, phase in enumerate(phases):
            pf = phase_findings.get(phase, [])
            for j, f in enumerate(pf[:5]):
                sev = f.get("severity", "info")
                if sev in ("critical", "high", "medium", "low"):
                    lines.append(f"  class F{i}_{j} {sev}")

    for i, phase in enumerate(phases):
        if phase == current_phase:
            lines.append(f"  class P{i} active")

    return "\n".join(lines)


def confidence_tree(findings: list[dict]) -> str:
    """Generate confidence distribution tree diagram.

    Groups findings by confidence level with evidence chain details.
    """
    grouped: dict[str, list[dict]] = {"confirmed": [], "firm": [], "tentative": []}
    for f in findings:
        conf = f.get("confidence", "tentative")
        grouped.setdefault(conf, []).append(f)

    lines = ["flowchart TD"]
    lines.append("  ROOT[\"Session Findings\"]")

    colors = {
        "confirmed": "#2e7d32",
        "firm": "#f57c00",
        "tentative": "#757575",
    }

    for conf, items in grouped.items():
        if not items:
            continue
        cid = f"C_{conf}"
        lines.append(f"  {cid}[\"{conf.upper()} ({len(items)})\"]")
        lines.append(f"  ROOT --> {cid}")

        for i, f in enumerate(items[:8]):
            fid = f"{cid}_{i}"
            title = f.get("title", "Finding")[:25]
            severity = f.get("severity", "info").upper()
            weight = f.get("evidence", {}).get("total_weight", 0)
            signals = f.get("evidence", {}).get("signal_count", 0)

            lines.append(f'  {fid}["{title}\\n{severity} | W:{weight} | S:{signals}"]')
            lines.append(f"  {cid} --> {fid}")

    # Styles
    lines.append("")
    lines.append(f"  style C_confirmed fill:{colors['confirmed']},color:#fff")
    lines.append(f"  style C_firm fill:{colors['firm']},color:#fff")
    lines.append(f"  style C_tentative fill:{colors['tentative']},color:#fff")

    return "\n".join(lines)


def session_timeline(
    phases: dict[str, dict] | None = None,
    tools: dict[str, dict] | None = None,
    total_hours: float = 0,
) -> str:
    """Generate session timeline as Gantt chart.

    Shows phase durations and tool executions within each phase.
    """
    lines = ["gantt"]
    lines.append(f"  title Session Timeline ({total_hours:.1f}h)")
    lines.append("  dateFormat X")
    lines.append("  axisFormat %s")

    if not phases:
        lines.append("  section No Data")
        lines.append("  No phases recorded : 0, 1")
        return "\n".join(lines)

    cumulative = 0
    for phase_name, data in phases.items():
        minutes = data.get("total_minutes", 0)
        if minutes <= 0:
            continue

        lines.append(f"  section {phase_name}")
        start = int(cumulative * 60)
        end = int((cumulative + minutes) * 60)
        lines.append(f"  {phase_name} : {start}, {end}")

        # Tool breakdown within phase
        for tool in data.get("tools_used", []):
            tool_data = (tools or {}).get(tool, {})
            tool_min = tool_data.get("total_minutes", 0)
            if tool_min > 0:
                t_start = start
                t_end = t_start + int(tool_min * 60)
                lines.append(f"  {tool} : {t_start}, {t_end}")

        cumulative += minutes

    return "\n".join(lines)


def roi_waterfall(
    findings: list[dict],
    total_hours: float = 0,
) -> str:
    """Generate ROI waterfall showing value contribution per finding.

    Each finding shows its expected value and readiness status.
    """
    lines = ["flowchart LR"]

    if not findings:
        lines.append('  EMPTY["No findings to price"]')
        return "\n".join(lines)

    total_ev = 0
    lines.append('  START(["$0"])')
    prev = "START"

    for i, f in enumerate(findings):
        fid = f"F{i}"
        title = f.get("title", f.get("finding", "Finding"))[:20]
        ev = f.get("expected_value", f.get("pricing", {}).get("expected_value", 0))
        raw_readiness = f.get("readiness", "unknown")
        readiness = raw_readiness.get("status", "unknown") if isinstance(raw_readiness, dict) else raw_readiness
        total_ev += ev

        icon = {"ready": "+", "needs_poc": "~", "needs_verify": "?", "not_ready": "x"}.get(readiness, "?")

        lines.append(f'  {fid}["{icon} {title}\\n+${ev:,.0f}"]')
        lines.append(f"  {prev} --> {fid}")
        prev = fid

    lines.append(f'  TOTAL([["TOTAL: ${total_ev:,.0f}"]])')
    lines.append(f"  {prev} --> TOTAL")

    if total_hours > 0:
        dph = total_ev / total_hours
        lines.append(f'  ROI["$/hr: ${dph:,.0f}"]')
        lines.append("  TOTAL --> ROI")

    # Styling
    lines.append("")
    lines.append("  style TOTAL fill:#1b5e20,color:#fff,stroke-width:3px")
    if total_hours > 0:
        lines.append("  style ROI fill:#0d47a1,color:#fff")

    return "\n".join(lines)


def tool_scorecard(tools: dict[str, dict]) -> str:
    """Generate tool performance comparison as a quadrant chart.

    X-axis: finding rate (findings per run)
    Y-axis: precision (confirmed / reviewed)
    """
    lines = ["quadrantChart"]
    lines.append("  title Tool Performance")
    lines.append("  x-axis Low Yield --> High Yield")
    lines.append("  y-axis Low Precision --> High Precision")
    lines.append("  quadrant-1 Elite")
    lines.append("  quadrant-2 Precise but Slow")
    lines.append("  quadrant-3 Broken")
    lines.append("  quadrant-4 Noisy but Productive")

    for name, data in tools.items():
        runs = data.get("runs", 1)
        findings = data.get("findings", data.get("findings_per_run", 0))
        precision = data.get("precision", 0.5)

        if isinstance(findings, (int, float)) and runs > 0:
            finding_rate = findings / runs if findings > 1 else findings
        else:
            finding_rate = 0

        # Normalize to 0-1 range
        x = min(1.0, finding_rate)
        y = precision if isinstance(precision, float) else 0.5

        short_name = name.replace("vuln_", "").replace("api_test_", "").replace("exploit_", "ex:")
        lines.append(f"  {short_name}: [{x:.2f}, {y:.2f}]")

    return "\n".join(lines)


def render_html(mermaid_code: str, title: str = "Kambo Visualization") -> str:
    """Wrap Mermaid code in a standalone HTML page for browser rendering."""
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <style>
    body {{
      background: #0d1117;
      color: #c9d1d9;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 2rem;
      margin: 0;
    }}
    h1 {{
      color: #58a6ff;
      font-size: 1.4rem;
      margin-bottom: 1.5rem;
    }}
    .mermaid {{
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 2rem;
      max-width: 95vw;
      overflow-x: auto;
    }}
    .controls {{
      margin-top: 1rem;
      display: flex;
      gap: 0.5rem;
    }}
    button {{
      background: #21262d;
      color: #c9d1d9;
      border: 1px solid #30363d;
      padding: 0.4rem 1rem;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.85rem;
    }}
    button:hover {{ background: #30363d; }}
    .source {{
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 1rem;
      margin-top: 1rem;
      max-width: 90vw;
      overflow-x: auto;
      display: none;
      font-family: 'Cascadia Code', 'Fira Code', monospace;
      font-size: 0.8rem;
      white-space: pre;
    }}
  </style>
</head>
<body>
  <h1>{title}</h1>
  <div class="mermaid">
{mermaid_code}
  </div>
  <div class="controls">
    <button onclick="copySource()">Copy Mermaid</button>
    <button onclick="toggleSource()">View Source</button>
  </div>
  <pre class="source" id="source">{mermaid_code}</pre>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
  <script>
    mermaid.initialize({{
      startOnLoad: true,
      theme: 'dark',
      themeVariables: {{
        primaryColor: '#1f6feb',
        primaryTextColor: '#c9d1d9',
        primaryBorderColor: '#30363d',
        lineColor: '#58a6ff',
        secondaryColor: '#161b22',
        tertiaryColor: '#21262d',
      }}
    }});
    function copySource() {{
      navigator.clipboard.writeText(document.getElementById('source').textContent);
    }}
    function toggleSource() {{
      const el = document.getElementById('source');
      el.style.display = el.style.display === 'none' ? 'block' : 'none';
    }}
  </script>
</body>
</html>"""
