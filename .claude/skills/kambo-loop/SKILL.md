---
name: kambo-loop
description: Autonomous crafter loop for Kambo — runs inside Ralph Loop to continuously self-improve the project through evidence-driven iterations. Each cycle identifies, implements, verifies, and persists one improvement.
triggers:
  - kambo loop
  - crafter loop
  - auto improve loop
  - self-improve
---

# Kambo Loop — Autonomous Crafter

Designed to run inside Ralph Loop. Each iteration is a self-contained
improvement cycle that leaves the project better than it found it.

## Iteration Protocol

Each iteration follows a strict 5-step protocol:

### Step 1: Assess — What needs improvement?

Read the current state:
```python
# 1. Load learnings from previous iterations
from kambo.learnings import get_learnings_store
store = get_learnings_store()
learnings = store.search(limit=20)

# 2. Run pattern analysis
from kambo.pattern_analyzer import (
    analyze_tool_performance,
    analyze_confidence_distribution,
    analyze_efficiency_patterns,
    detect_calibration_drift,
)

# 3. Check test results
# Run: python -m pytest --tb=short -q

# 4. Check code quality gaps
# Grep for TODO, FIXME, known weak patterns
```

Priority ranking for what to improve (pick ONE per iteration):

| Priority | Category | Detection Method |
|----------|----------|-----------------|
| P0 | Failing tests | pytest exit code != 0 |
| P1 | Security bugs | Hardcoded secrets, injection paths |
| P2 | Logic errors | Validator FP gaps, pricing formula bugs |
| P3 | Missing coverage | Modules without test files |
| P4 | Calibration drift | Confidence weights diverging from reality |
| P5 | Missing validators | Vuln types without evidence validation |
| P6 | Performance | Slow tools, inefficient patterns |
| P7 | Code quality | Large files, deep nesting, unclear names |

### Step 2: Plan — What exactly will change?

Before touching code:
1. Identify the single highest-priority improvement
2. Name the specific file(s) and function(s) to change
3. Describe the change in one sentence
4. Estimate: will this break existing tests?

**Rule**: ONE improvement per iteration. No scope creep.

### Step 3: Implement — Make the change

Execute the planned change:
1. Read the target file(s) first
2. Make the minimal edit
3. If adding a new module, write tests FIRST (TDD)
4. If fixing a bug, verify the fix with a targeted test

### Step 4: Verify — Did it work?

Run the full test suite:
```bash
python -m pytest --tb=short -q
```

**Gate**: If tests fail, fix them before proceeding.
- If the fix introduces a regression → revert and log as pitfall
- If tests pass → proceed to Step 5

### Step 5: Persist — What did we learn?

Log the iteration result:
```python
from kambo.learnings import Learning, get_learnings_store

store = get_learnings_store()
store.log(Learning(
    type="pattern" | "pitfall" | "calibration" | "operational",
    key="descriptive_key",
    insight="What was done and why",
    confidence=7,  # 1-10
    source="observed",
    skill="kambo-loop",
    data={"iteration": N, "files_changed": [...], "tests_added": N},
))
```

Then commit:
```bash
git add -A && git commit -m "refine: <description of improvement>"
```

## Iteration Selection Strategy

The loop uses a **diminishing returns** strategy:

### Early iterations (1-10): Foundation
- Fix any failing tests
- Add missing test files for untested modules
- Fix known logic errors identified by /kambo-refine

### Mid iterations (11-30): Calibration
- Add missing validators (path traversal, XXE, command injection)
- Expand parser coverage
- Add cross-validation logic between tools

### Late iterations (31+): Polish
- Code quality improvements (file size, naming, structure)
- Documentation accuracy
- Edge case handling

## Tracking Progress

Use a simple iteration counter in the learnings store:
- Key: `loop_iteration_N`
- Data: what was changed, impact assessment, test delta

To see progress:
```python
store.search(keyword="loop_iteration", limit=50)
```

## Completion Criteria

The loop can signal DONE when ALL of these are true:
1. All tests pass (200+ tests, 0 failures)
2. No HIGH priority items remain from /kambo-refine analysis
3. All tool modules have corresponding test files
4. All validators cover at least 3 FP checks each
5. Calibration health is "calibrated" (not "insufficient_data" or "needs_recalibration")
6. At least 15 learnings persisted with confidence >= 7

## Anti-Patterns to Avoid

- **Scope creep**: ONE change per iteration, no exceptions
- **Cosmetic changes**: Don't rename variables or add comments without functional impact
- **Duplicate work**: Check learnings store before starting — don't repeat past iterations
- **Over-engineering**: Simple fix > clever abstraction
- **Ignoring test failures**: NEVER commit with failing tests

## Integration with Ralph Loop

When invoked via Ralph Loop:
```
/ralph-loop "Use /kambo-loop to continuously improve the Kambo MCP" --max-iterations 30 --completion-promise DONE
```

Each Ralph iteration = one Kambo Loop cycle.
The learnings store provides continuity between iterations.
Git history provides rollback safety.
