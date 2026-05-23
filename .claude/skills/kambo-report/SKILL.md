---
name: kambo-report
description: Evidence-grade bounty report generation with pricing, readiness assessment, and quality metrics. Produces submission-ready reports with ROI analysis.
triggers:
  - report
  - generate report
  - bounty report
  - submit findings
---

# Kambo Report — Evidence-Grade Bounty Reports

Generates submission-ready bug bounty reports with:
- Confidence-filtered findings (skip TENTATIVE)
- Pricing estimates per finding
- Session ROI analysis
- Quality metrics summary
- Readiness blockers identified

## Step 1: Quality Gate

Before generating any report:
1. Run `report_metrics` — check overall quality
2. If quality tier is "weak" (≥70% TENTATIVE): **STOP**
   - Recommend running `/kambo-refine` first
   - List findings that need cross-validation
3. If any tool has HIGH FP WARNING: flag those findings

## Step 2: Filter Findings

Only include findings with:
- Confidence ≥ FIRM (skip all TENTATIVE)
- Evidence chain with ≥2 signals
- At least 1 FP check performed

For CONFIRMED findings:
- Include full evidence chain
- Include raw proof (truncated)
- Mark as "submit now"

For FIRM findings:
- Include evidence with caveats
- Recommend additional verification steps
- Mark as "submit with notes"

## Step 3: Price Each Finding

For each included finding:
1. Run `bounty_estimate_value` with program payouts
2. Assess readiness (READY / NEEDS_POC / NEEDS_VERIFY)
3. Calculate $/hour if timer data available

## Step 4: Generate Report

Use `report_bounty_template` for each finding, enriched with:
- Confidence level and evidence weight
- Pricing estimate (expected value range)
- Readiness status and blockers
- Historical FP warning if applicable

## Step 5: Session Summary

At the end of the report:
1. Run `bounty_session_value` for aggregate ROI
2. Run `bounty_timer_stop` for timing breakdown
3. Include quality metrics (precision, FP rate, confidence distribution)
4. Generate per-phase time investment analysis

## Step 6: Persist Learnings

After report generation:
1. Run pattern analysis on this session's data
2. Save operational learnings (which tools/vuln types were most productive)
3. Save calibration signals if user confirms/rejects findings later

## Report Format

```markdown
# Bug Bounty Report — {Program Name}
## Session: {date} | Quality: {tier} | ROI: ${dollar_per_hour}/hr

### Finding 1: {title}
- Severity: {severity} | Confidence: {confidence}
- Expected Value: ${expected_value} (range: ${min} - ${max})
- Readiness: {status}
- Evidence: {signal_count} signals, {fp_checks} FP checks
- [Full evidence chain...]

### Session Summary
- Total Findings: {n} (CONFIRMED: {c}, FIRM: {f})
- Total Expected Value: ${total_ev}
- Time Invested: {hours}h ({phase_breakdown})
- ROI: ${dollar_per_hour}/hr
- Quality Score: {precision}% precision
```
