---
name: kambo-calibrate
description: Auto-calibrate confidence weights and acceptance rates from accumulated user feedback. Evidence-driven weight adjustment that closes the prediction-reality gap.
triggers:
  - calibrate
  - adjust weights
  - recalibrate
  - tune kambo
---

# Kambo Calibrate — Self-Tuning from Evidence

Reads historical metrics and user feedback to detect where Kambo's
predictions diverge from reality, then recommends specific weight
adjustments with confidence scores.

## When to Run

- After accumulating ≥5 user confirmations/rejections per tool
- When precision drops below 60% on any tool
- Before starting a new hunting campaign
- After `/kambo-refine` identifies calibration drift

## Step 1: Data Collection

Gather calibration inputs:
1. Load metrics via `report_metrics`
2. Load existing calibration learnings from store
3. Identify tools with ≥5 reviewed findings

## Step 2: Confidence Weight Calibration

For each tool with sufficient data:

### Compare predicted vs actual precision
- **Predicted**: `(confirmed × 0.95 + firm × 0.65 + tentative × 0.25) / total`
- **Actual**: `user_confirmed / (user_confirmed + user_rejected)`
- **Drift**: `actual - predicted`

### Generate adjustments
- If drift > +0.15: weights too conservative → recommend increase by damped factor
- If drift < -0.15: weights too aggressive → recommend decrease
- Within ±0.15: well-calibrated, no change needed

### Output per tool:
```
vuln_sqli:
  current_weights: {injectable_param: 1.5, dbms_detected: 0.5}
  adjustment_factor: 1.12
  recommended_weights: {injectable_param: 1.68, dbms_detected: 0.56}
  actual_precision: 85%
  expected_precision: 72%
  drift: +13%
  confidence_in_adjustment: 8/10 (8 reviewed findings)
```

## Step 3: Acceptance Rate Calibration

For bounty pricing accuracy:
- Map tool results to vuln types
- Compare default acceptance rates against actual confirmation rates
- Recommend damped adjustments (30% correction per cycle)

## Step 4: Review & Apply

**STOP — human review required before applying.**

Present the calibration report:
1. Tools needing adjustment (sorted by drift magnitude)
2. Current vs recommended weights
3. Impact estimate: how many findings would change classification
4. Confidence in each adjustment (based on sample size)

The operator decides which adjustments to accept.

## Step 5: Persist Learnings

Save accepted calibrations:
- Type: "calibration"
- Key: "weight_adj_{tool}" or "acceptance_adj_{vuln_type}"
- Confidence: min(9, sample_size)
- Data: current and recommended values

These learnings inform future sessions even before code changes.

## Safety Rails

1. **Never auto-apply weight changes** — always present for review
2. **Damped corrections** — only move 30-50% toward actual per cycle
3. **Minimum sample size** — require ≥5 reviewed findings per tool
4. **Confidence decay** — old calibrations lose relevance over time
5. **Revert path** — learnings store preserves history of all adjustments
