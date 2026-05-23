---
name: kambo-hunt
description: Autonomous bug bounty hunting workflow — evidence-driven, metrics-quantified, self-correcting. Runs the full hunting pipeline with automatic phase transitions based on findings quality.
triggers:
  - hunt
  - start hunting
  - bug bounty hunt
  - autonomous hunt
---

# Kambo Hunt — Autonomous Bug Bounty Workflow

Evidence-driven hunting pipeline that auto-advances through phases based on
finding quality, pauses when metrics indicate problems, and produces
report-ready findings with pricing estimates.

## Pre-Hunt Checklist

Before starting, verify:
1. Scope is configured (`set_scope` with targets and context=bug_bounty)
2. Program payouts are known (for pricing at the end)
3. Timer is reset (`bounty_timer_reset`)

## Phase 1: Intelligence Gathering

```
bounty_timer_start(phase="recon")
```

Run in parallel where possible:
1. `recon_subdomains` — enumerate attack surface
2. `recon_dns` — zone transfers, record enumeration
3. `recon_tech_stack` — identify technologies
4. `recon_waf` — detect defenses
5. `recon_certs` — certificate transparency

**CHECKPOINT**: After recon, run `report_metrics`.
- If 0 subdomains found → pivot to direct scanning
- If WAF detected → log pitfall, adjust approach
- If >100 subdomains → prioritize by wildcard detection

## Phase 2: Active Scanning

```
bounty_timer_start(phase="scanning")
```

Priority order:
1. `scan_api_endpoints` — API-first (highest ROI for bounties)
2. `scan_directories` — hidden paths
3. `scan_parameters` — hidden parameters
4. `scan_vulns` — Nuclei templates

**ADAPTIVE PIVOT**:
- IF Swagger found → prioritize API security tests (BOLA, BFLA)
- IF .git exposed → run `cloud_secret_scan`
- IF admin panel found → focus auth bypass

## Phase 3: Vulnerability Analysis

```
bounty_timer_start(phase="vulnerability_analysis")
```

Run based on recon intelligence:
1. `vuln_sqli` on parameterized endpoints
2. `vuln_xss` on reflection points
3. `vuln_cors` on API endpoints
4. `vuln_ssrf` if internal params found
5. `vuln_idor` on authenticated endpoints
6. `api_test_bola` + `api_test_bfla` on API targets

**EVIDENCE GATE**: After each tool, check confidence:
- TENTATIVE → cross-validate with second tool before proceeding
- FIRM → proceed to exploitation
- CONFIRMED → proceed directly to reporting

## Phase 4: Exploitation (FIRM/CONFIRMED only)

```
bounty_timer_start(phase="exploitation")
```

Only exploit findings with confidence >= FIRM:
1. `exploit_sqli` — extract data to prove impact
2. `exploit_ssrf` — access internal resources
3. `exploit_password_spray` — if default creds suspected

**STOP**: Never exploit TENTATIVE findings. Cross-validate first.

## Phase 5: Value Assessment & Reporting

```
bounty_timer_start(phase="reporting")
```

1. Run `bounty_estimate_value` for each finding
2. Run `bounty_session_value` for aggregate ROI
3. Run `report_metrics` for quality check
4. Generate reports with `report_bounty_template` (CONFIRMED + FIRM only)
5. Stop timer: `bounty_timer_stop`

## Self-Correction Rules

After EVERY phase:
1. Check `report_metrics` — if FP rate > 50%, STOP and cross-validate
2. If a tool has HIGH FP WARNING, skip it in this session
3. Log operational learnings for patterns discovered

## Post-Hunt

1. Confirm or reject findings with `report_confirm_finding`
2. This feeds the precision metrics for next session
3. Run `/kambo-calibrate` to adjust weights from feedback
