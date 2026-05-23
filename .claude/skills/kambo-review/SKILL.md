---
name: kambo-review
description: Structural code review tailored to the Kambo MCP architecture. Validates evidence chains, validator quality, pricing accuracy, test coverage, data hygiene, and skill consistency. Not a generic linter — built for this codebase.
triggers:
  - kambo review
  - review kambo
  - code review
  - check quality
---

# Kambo Review — Architecture-Aware Code Review

Purpose-built reviewer for the Kambo MCP server. Checks what generic
linters and reviewers miss: evidence chain correctness, validator
completeness, pricing model coherence, and data hygiene.

## Review Protocol

Run ALL checks sequentially. Report a scorecard at the end.

### Check 1: Evidence Chain Integrity

Verify every tool in `src/kambo/tools/` that produces findings uses the evidence system correctly.

For each tool module (`vulns.py`, `exploit.py`, `cloud.py`, `post_exploit.py`, `api_security.py`):

```python
# MUST have:
chain = validate_*(...)           # Uses a validator
chain.total_weight                # Checks weight threshold
metrics.record_finding(...)       # Records to metrics
"confidence": chain.confidence    # Returns confidence level
"evidence": chain.summary()       # Returns evidence summary
```

**Violations**:
- Tool returns `vulnerable: True/False` without evidence chain → CRITICAL
- Tool uses hardcoded confidence instead of chain-computed → HIGH
- Tool skips `metrics.record_finding()` → MEDIUM
- Tool returns raw output without parsed evidence → LOW

### Check 2: Validator Completeness

For each validator in `src/kambo/validation.py`:

| Criterion | Minimum | Check |
|-----------|---------|-------|
| FP checks | >= 3 per validator | `chain.add_fp_check()` count |
| Evidence signals | >= 2 distinct weights | Different `weight=` values |
| Raw data capture | At least 1 signal with `raw_data` | Non-empty `raw_data=` |
| Baseline comparison | Where applicable (IDOR, BFLA) | `baseline` parameter used |

Run:
```bash
python -c "
import re
from pathlib import Path
code = Path('src/kambo/validation.py').read_text()
validators = re.findall(r'def (validate_\w+)', code)
for v in validators:
    start = code.index(f'def {v}')
    end_match = re.search(r'\ndef [a-z_]', code[start+10:])
    end = start + 10 + end_match.start() if end_match else len(code)
    block = code[start:end]
    fp = block.count('add_fp_check')
    signals = len(re.findall(r'weight=', block))
    raw = block.count('raw_data=')
    print(f'{v}: FP={fp} signals={signals} raw_data={raw}')
"
```

### Check 3: Pricing Model Coherence

Verify `src/kambo/bounty_pricing.py`:

1. Every vuln type in `_VULN_ACCEPTANCE_RATES` has a corresponding validator:
```python
# pricing has "sqli" → validation.py has validate_sqli()
# pricing has "path_traversal" → validation.py has validate_path_traversal()
# MISSING means pricing estimates but can't validate → unreliable
```

2. Confidence multipliers are ordered:
```python
CONFIRMED > FIRM > TENTATIVE  # must be strictly decreasing
```

3. Severity downgrade factors are ordered:
```python
CRITICAL.factor < HIGH.factor < MEDIUM.factor < LOW.factor  # higher sev = more downgrade risk
```

4. No acceptance rate > 0.98 or < 0.05 (unrealistic extremes)

### Check 4: Test Coverage Map

For each source module, verify a corresponding test file exists:

```bash
for f in src/kambo/*.py src/kambo/tools/*.py; do
  base=$(basename "$f" .py)
  [[ "$base" == "__init__" ]] && continue
  test_file="tests/test_${base}.py"
  [[ -f "$test_file" ]] && echo "OK: $test_file" || echo "MISSING: $test_file"
done
```

Coverage rules:
- Core modules (models, validation, metrics, database, scope) → **MUST** have tests
- Tool wrappers (vulns, exploit, recon, scanning) → **MUST** have tests
- Intelligence (bounty_intel, bounty_pricing, calibration, pattern_analyzer) → **MUST** have tests
- Infrastructure (config, docker_runner, server) → SHOULD have tests
- Parsers, resources, prompts → NICE to have tests

### Check 5: Data Hygiene

Verify no program-specific data leaked into the codebase:

```bash
# Run the pre-commit validator on all tracked files
python scripts/validate_commit.py
```

Additionally check:
- No real IPs in test fixtures (only 10.x, 192.168.x, 127.x)
- No real domains in test assertions (only example.com, test.com, target.com)
- No API keys, tokens, or credentials anywhere
- `output/`, `reports/`, `.agents/` are in `.gitignore`
- No `.db`, `.sqlite`, `.env` files tracked

### Check 6: Skill Consistency

For each skill in `.claude/skills/kambo-*/SKILL.md`:

1. Has valid frontmatter (`name`, `description`, `triggers`)
2. References only tools that exist in `server.py`
3. References only skills that exist in `.claude/skills/`
4. No hardcoded target names, IPs, or program data
5. Listed in `CLAUDE.md` skill routing table

```bash
echo "=== Skills ===" && for d in .claude/skills/kambo-*/; do
  name=$(basename "$d")
  skill_file="$d/SKILL.md"
  [[ -f "$skill_file" ]] && echo "OK: $name" || echo "MISSING SKILL.md: $name"
  # Check routing in CLAUDE.md
  grep -q "$name" CLAUDE.md && echo "  Routed in CLAUDE.md" || echo "  NOT in CLAUDE.md routing"
done
```

### Check 7: Metrics Pipeline

Verify the metrics pipeline is complete:

```
Tool execution → metrics.record_run() → metrics.record_finding() → 
flush_metrics() → database → load_metrics() on startup
```

Check:
- `server.py` calls `flush_metrics()` after each tool
- `server.py` calls `load_metrics()` on startup  
- `server.py` injects `_historical_warning` from metrics
- `report_confirm_finding` calls `record_user_feedback()`
- Dirty tracking works (only flush modified tools)

### Check 8: Learnings Integration

Verify the learning loop is wired:

1. `learnings.py` store is accessible via `get_learnings_store()`
2. `pattern_analyzer.py` can generate learnings from metrics
3. `calibration.py` can persist calibration learnings
4. Skills reference the learnings system in their workflows

## Scorecard Output

After running all checks, produce a scorecard:

```
KAMBO REVIEW SCORECARD
======================
Date: {date}
Commit: {hash}

Evidence Chains .... [PASS/FAIL] {details}
Validators ......... [PASS/FAIL] {details}
Pricing Model ...... [PASS/FAIL] {details}
Test Coverage ...... [PASS/FAIL] {x}/{y} modules covered
Data Hygiene ....... [PASS/FAIL] {details}
Skill Consistency .. [PASS/FAIL] {x}/{y} skills valid
Metrics Pipeline ... [PASS/FAIL] {details}
Learnings Loop ..... [PASS/FAIL] {details}

Overall: {PASS | PASS_WITH_WARNINGS | FAIL}
Issues: {count} (CRITICAL: {n}, HIGH: {n}, MEDIUM: {n}, LOW: {n})
```

## Severity Levels

- **CRITICAL**: Evidence chain broken — tool can produce ungraded findings
- **HIGH**: Validator missing FP checks — false positives reach reports
- **LOW**: Missing test file, minor inconsistency

## When to Run

- Before every commit (automated via `/kambo-loop`)
- After adding a new tool or validator
- After modifying pricing model or confidence weights
- Before starting a hunting campaign
- After `/kambo-refine` applies changes

## Integration

Can be called from other skills:
- `/kambo-loop` runs it as part of the assess step
- `/kambo-refine` runs checks 1-3 for quality analysis
- Pre-commit hook runs check 5 automatically
