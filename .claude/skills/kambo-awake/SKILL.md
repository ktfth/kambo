---
name: kambo-awake
description: Interactive guided walkthrough of the Kambo methodology. Teaches the hunting workflow step-by-step, explains each tool, and walks the operator through their first session with live feedback.
triggers:
  - awake
  - tutorial
  - teach me
  - how to use kambo
  - walkthrough
  - getting started
---

# Kambo Awake — Guided Methodology Walkthrough

Interactive mentor that teaches the Kambo hunting methodology by walking
you through each phase. Adapts to your experience level and provides
live visualizations via `/kambo-viz`.

## Step 0: Welcome & Assessment

Ask the operator:

> Welcome to Kambo. I'll walk you through the hunting methodology.
>
> Before we start:
> 1. What's your experience level? (beginner / intermediate / advanced)
> 2. Do you have a target program ready, or should we use a practice scenario?
> 3. Which context? (bug_bounty / pentest / ctf)

Adapt depth based on response:
- **Beginner**: Explain every concept, show examples, confirm before each step
- **Intermediate**: Brief explanations, focus on Kambo-specific features
- **Advanced**: Skip basics, focus on evidence chains and metrics system

## Step 1: Understanding the Architecture

Explain the core concept:

> Kambo is different from running tools manually. Here's why:
>
> **Traditional**: Run nmap → read output → decide manually → run next tool
> **Kambo**: Run tool → evidence chain grades confidence automatically →
> metrics track accuracy → system learns from your feedback
>
> The key insight: every finding has a **confidence level** based on
> weighted evidence signals, not just "vulnerable: true/false".

Show the architecture with `/kambo-viz`:
```
Recon → Scanning → Vuln Analysis → Exploitation → Reporting
  |         |            |              |             |
  v         v            v              v             v
Evidence  Evidence    Evidence       Evidence      Pricing
Chains    Chains      Chains         Chains        + ROI
  |         |            |              |             |
  +-------- +----------- +------------- +-----------+ |
                         |                            |
                    Metrics Tracker                    |
                    (precision, FP rate)               |
                         |                            |
                    Learnings Store ← ← ← ← ← ← ← ←+
                    (cross-session memory)
```

**Confidence levels**:
- **CONFIRMED** (weight >= 2.0): Exploited and verified. Submit now.
- **FIRM** (weight >= 1.0): Strong indicators from multiple signals. Worth reporting.
- **TENTATIVE** (weight < 1.0): Single signal. Needs validation. DON'T report yet.

## Step 2: Setting Up — Scope & Timer

Walk through scope configuration:

> Every session starts with scope. This prevents accidental out-of-scope testing.

```
Tool: set_scope
Params:
  targets: ["*.target.com", "api.target.com"]
  context: "bug_bounty"
  platform: "hackerone"
  exclusions: ["admin.target.com"]
```

Then start the timer:

```
Tool: bounty_timer_start
Params: { phase: "recon" }
```

> The timer tracks your time per phase. At the end, we calculate $/hour ROI.

## Step 3: Phase 1 — Reconnaissance

> Recon is about mapping the attack surface. We're not looking for vulns yet —
> we're looking for SURFACE AREA where vulns might exist.

Walk through each recon tool:

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `recon_subdomains` | Find subdomains | Always first |
| `recon_dns` | Zone transfers, records | Always |
| `recon_ports_fast` | Quick port scan | After subdomains |
| `recon_tech_stack` | Identify technologies | After ports |
| `recon_waf` | Detect WAF/CDN | Before scanning |
| `recon_certs` | Certificate transparency | Supplement to subdomains |
| `recon_asn` | IP block discovery | For large targets |

After running recon, generate the attack surface visualization:

> Let's see what we found. I'll generate an attack surface map.

Use `/kambo-viz surface` to show the mindmap.

**CHECKPOINT**: Run `report_metrics` to see session stats.

> If we found subdomains and ports, we're ready for scanning.
> If the surface is small (< 3 subdomains, < 5 ports), we should
> try different recon methods before moving on.

## Step 4: Phase 2 — Scanning

> Now we look for entry points. Scanning is about finding THINGS TO TEST,
> not finding vulnerabilities directly.

Priority order for bug bounty:

1. **API endpoints first** (`scan_api_endpoints`) — highest ROI
2. **Hidden directories** (`scan_directories`) — expose admin panels, .git
3. **Hidden parameters** (`scan_parameters`) — expand attack surface
4. **Nuclei templates** (`scan_vulns`) — known CVEs

Explain the adaptive pivot:

> Kambo adapts based on what scanning finds:
> - Swagger/OpenAPI found → pivot to API security tests
> - .git exposed → run secret scan
> - Admin panel found → focus auth bypass
> - No interesting results → try vhost discovery

## Step 5: Phase 3 — Vulnerability Analysis

> This is where evidence chains matter most. Each tool produces SIGNALS
> that accumulate weight. Multiple independent signals = higher confidence.

Walk through the evidence chain concept with a live example:

```
Example: Testing SQL injection on /api/users?id=1

Signal 1: "Parameter id appears injectable" (weight: 1.5)
Signal 2: "DBMS identified: MySQL" (weight: 0.5)
Signal 3: "Injection technique: boolean-based blind" (weight: 0.5)

Total weight: 2.5 → CONFIRMED
FP checks: ["Not a WAP/generic response", "Response differs from baseline"]
```

> Compare with a false positive:
>
> Signal 1: "Suspicious parameter found" (weight: 0.3)
> Total weight: 0.3 → TENTATIVE
> FP checks: ["Response identical to baseline"]
>
> This is why we don't report TENTATIVE findings — they're usually noise.

Show confidence distribution with `/kambo-viz confidence`.

## Step 6: Phase 4 — Exploitation (FIRM/CONFIRMED only)

> We ONLY exploit findings with confidence >= FIRM.
> TENTATIVE findings get cross-validated first, not exploited.

Explain the exploitation workflow:

```
CONFIRMED → exploit to prove impact → report immediately
FIRM → exploit to upgrade to CONFIRMED → then report
TENTATIVE → cross-validate with different tool → re-assess
```

## Step 7: Phase 5 — Pricing & Reporting

> Before writing the report, we price each finding.

Walk through the pricing model:

```
Expected Value = Base Payout x Confidence x Acceptance x Downgrade x Bonus

Example: Critical SQLi on a $50K program
  Base:       $50,000
  Confidence: x 0.95 (CONFIRMED)
  Acceptance: x 0.95 (SQLi — high acceptance)
  Downgrade:  x 0.85 (30% chance of downgrade)
  Bonus:      x 1.0  (no bonus)
  = $38,356 expected value
```

Show the ROI waterfall with `/kambo-viz roi`.

> The readiness check tells you if the finding is ready to submit:
> - READY: Submit now (CONFIRMED + PoC + reproduction steps)
> - NEEDS_POC: Good evidence but needs documentation
> - NEEDS_VERIFY: TENTATIVE — manual verification first

## Step 8: Post-Session — Learning Loop

> After every session, the system learns from your feedback.

Walk through the feedback loop:

```
1. report_confirm_finding(finding_id, is_true_positive=True/False)
   → feeds the precision metrics

2. /kambo-refine → analyzes tool performance, finds drift

3. /kambo-calibrate → adjusts weights based on your feedback

4. Next session uses adjusted weights → better predictions
```

> This is what makes Kambo different: it gets better with every session.
> After 5+ sessions with feedback, the system calibrates itself.

## Step 9: Available Skills

Quick reference:

| Skill | When |
|-------|------|
| `/kambo-hunt` | Start autonomous hunting |
| `/kambo-refine` | Analyze and improve after session |
| `/kambo-calibrate` | Adjust weights from feedback |
| `/kambo-report` | Generate evidence-grade report |
| `/kambo-viz` | Visualize anything (surface, flow, ROI) |
| `/kambo-loop` | Continuous autonomous improvement |

## Adaptation

- If the operator asks "why?" → explain the evidence chain logic
- If confused → show a Mermaid diagram via `/kambo-viz`
- If advanced → skip to the specific phase they need
- If stuck → suggest the next highest-impact action
- If first time → go slow, confirm understanding at each checkpoint
