---
name: kambo-refine
description: Self-polish Kambo based on accumulated metrics and learnings. Identifies weak validators, noisy tools, and prediction drift. Generates actionable improvement tasks.
triggers:
  - refine
  - self-polish
  - improve kambo
  - auto-improve
---

# Kambo Refine — Evidence-Driven Self-Polishing

Analyzes accumulated session data to identify where Kambo can improve.
Uses pattern analysis, calibration drift detection, and learnings
to generate specific, actionable improvement tasks.

## Step 1: Load Current State

Read the current metrics and learnings:
1. Call `report_metrics` to get aggregate quality data
2. Search learnings store for existing patterns and pitfalls
3. Check calibration health

## Step 2: Run Pattern Analysis

Use the pattern analyzer to identify:

### Tool Performance Classification
For each tool with sufficient data (≥3 runs):
- **Elite**: Precision ≥80% → prioritize in hunting workflows
- **Reliable**: Precision ≥50% → use normally
- **Noisy**: Low confirmed ratio → needs validation improvement
- **Broken**: FP rate ≥70% → skip or cross-validate

### Confidence Distribution Health
- **Elite**: ≥50% CONFIRMED → ready for reporting
- **Solid**: ≥25% CONFIRMED → promote FIRM via exploitation
- **Weak**: ≥70% TENTATIVE → validation engine needs work
- **Moderate**: mixed → prioritize by evidence weight

### Efficiency Patterns
- Top 3 tools by confirmed-per-run → focus hunting workflow
- Zero-yield tools → deprioritize or remove from default workflow

## Step 3: Detect Calibration Drift

Compare predicted confidence against actual user feedback:
- If actual precision > expected → weights too conservative, increase
- If actual precision < expected → weights too aggressive, decrease
- Flag tools with drift > 15%

## Step 4: Generate Improvement Tasks

Based on analysis, create specific tasks:

### Validator Improvements
For each "noisy" or "broken" tool:
1. Identify which FP check is missing
2. Propose specific regex/pattern addition to validation.py
3. Estimate impact (how many FPs would be prevented)

### Weight Adjustments
For tools with calibration drift > 15%:
1. Document current vs recommended weights
2. Show sample findings that would be reclassified
3. Propose specific code changes

### Workflow Optimizations
Based on efficiency data:
1. Reorder tool execution in hunting workflow
2. Remove low-yield tools from default pipeline
3. Add cross-validation steps for noisy tools

## Step 5: Persist Learnings

Save all insights to learnings store:
- Patterns → type="pattern"
- Pitfalls → type="pitfall"
- Weight adjustments → type="calibration"
- Workflow changes → type="operational"

## Output

The refinement report should include:
1. **Quality Score**: overall session quality tier (elite/solid/moderate/weak)
2. **Tool Scorecard**: per-tool performance with trend (↑↓→)
3. **Drift Report**: calibration adjustments needed
4. **Action Items**: specific code changes ranked by impact
5. **Learnings**: new patterns persisted for future sessions

## When to Run

- After every hunting session (automated via post-session hook)
- Before starting a new hunting campaign
- When precision drops below 50% across tools
- Weekly for teams running multiple sessions
