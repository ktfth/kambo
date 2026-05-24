---
name: kambo-confidence
description: Adversarial self-questioning of findings — challenge confidence, evaluate exploitation impact, and decide if the finding is worth reporting or if exploitation could cause business damage exceeding the bounty value.
triggers:
  - confidence check
  - question findings
  - should I report
  - impact analysis
  - is it worth reporting
  - exploitation risk
  - business impact
---

# Kambo Confidence — Adversarial Finding Interrogation

Before you submit a report, stop and question everything.

This skill forces a structured adversarial analysis of every finding:
1. Is the vulnerability real, or am I seeing what I want to see?
2. If I exploit this, what breaks?
3. Is the bounty worth the risk of causing damage?
4. Would I bet my own money on this finding being accepted?

## When to Use

- Before submitting any CONFIRMED or FIRM finding
- When you have doubts about a finding's validity
- When exploitation could affect production data or availability
- Before investing time writing a full report
- When a finding feels "too easy" (often a sign of FP)

## Step 1: Evidence Interrogation

For each finding, answer these questions honestly:

### 1.1 — Is this real?

```
CHALLENGE: "Am I sure this isn't a false positive?"

Check:
- [ ] Did I get at least 2 independent signals? (not just one tool)
- [ ] Did I reproduce manually, not just with automated tools?
- [ ] Is the "vulnerable" response genuinely different from the baseline?
- [ ] Could this be a honeypot, WAF decoy, or intentional behavior?
- [ ] Did I check the FP indicators specific to this vuln type?
```

If ANY answer is "no" or "I'm not sure" → the finding is NOT ready.

Call `report_metrics` to see the FP rate for the tool that produced this finding.
If the tool's FP rate > 30%, apply extra scrutiny.

### 1.2 — Am I interpreting the evidence correctly?

```
CHALLENGE: "Could this evidence mean something else?"

Common misinterpretations:
- SQL error message = SQLi? Could be input validation echoing errors safely
- Reflected parameter = XSS? Could be properly encoded in HTML context
- Internal IP in response = SSRF? Could be a CDN/proxy header, not actual access
- Different response = IDOR? Could be personalized content, not unauthorized access
- Missing CSRF token = CSRF? Could have SameSite cookies or origin validation
- JWT with none algorithm = JWT bypass? Could be disabled server-side
- Open redirect via parameter = exploitable? Could only redirect to same domain
```

For each finding, state explicitly: "The alternative explanation is: ___"
If you can't rule out the alternative, the finding needs more evidence.

### 1.3 — Confidence gut check

Rate your personal confidence (separate from the evidence chain):

| Level | Description | Action |
|-------|-------------|--------|
| "I'd bet $500 on this" | You are certain | Report now |
| "I'd bet $100 on this" | Strong but not absolute | Report with caveats |
| "I'd bet $20 on this" | Uncertain | Get more evidence first |
| "I wouldn't bet on this" | Doubtful | Drop it or re-test completely |

If your gut says < $100 but the evidence chain says CONFIRMED → something is wrong.
Trust the mismatch. Re-examine the evidence.

## Step 2: Exploitation Impact Assessment

Before exploiting or demonstrating impact, evaluate what could go wrong.

### 2.1 — Impact classification

For the finding, classify the potential exploitation impact:

| Category | Examples | Risk Level |
|----------|----------|------------|
| **Read-only** | Data disclosure, config leak, version info | LOW — safe to demonstrate |
| **Data access** | PII exposure, credential dump, internal docs | MEDIUM — demonstrate minimally |
| **Data modification** | Account takeover, privilege escalation, data tampering | HIGH — demonstrate on test accounts only |
| **Availability** | DoS, resource exhaustion, service disruption | CRITICAL — never demonstrate, describe theoretically |
| **Cascading** | Lateral movement, supply chain, multi-tenant | CRITICAL — describe impact, do not chain exploits |

### 2.2 — The "$X vs Bounty" question

```
ASK: "If exploitation accidentally causes damage, is the bounty worth the risk?"

Formula:
  potential_damage = business_impact × probability_of_incident × recovery_cost
  bounty_value = expected_payout × acceptance_probability

  IF potential_damage > bounty_value × 10:
    → DO NOT exploit. Report with theoretical impact only.
    → State: "I chose not to exploit this to avoid potential business disruption."

  IF potential_damage > bounty_value × 3:
    → Exploit minimally. Use test data. Screenshot, don't extract.
    → State: "I limited exploitation to minimize risk."

  IF potential_damage <= bounty_value:
    → Safe to demonstrate fully with appropriate care.
```

### 2.3 — Scope of blast radius

Answer:
- **Who is affected?** Just me? One user? All users? Internal systems?
- **What data is exposed?** Test data? PII? Credentials? Financial?
- **Is this reversible?** Can I undo what I did? Or is it permanent?
- **Is this production?** Staging/dev environments have lower risk.
- **Does the program allow this?** Check rules of engagement explicitly.

If blast radius affects other users or production data → limit PoC to the minimum.

## Step 3: Report Worthiness Decision

### 3.1 — The triage matrix

Cross-reference severity with confidence to decide:

```
                    CONFIRMED       FIRM            TENTATIVE
  CRITICAL      ✓ Report now    ✓ Report w/notes   ✗ Verify first
  HIGH          ✓ Report now    ✓ Report w/notes   ✗ Verify first
  MEDIUM        ✓ Report        ~ Only if strong   ✗ Drop or verify
  LOW           ~ If impactful  ✗ Usually skip     ✗ Drop
  INFO          ✗ Skip          ✗ Skip             ✗ Skip
```

### 3.2 — Duplicate risk assessment

Before writing a full report, estimate duplicate risk:

Call `platform_check_duplicate` with the finding title and vuln type.

```
IF duplicate_risk == "high":
  → The vulnerability is likely known. Skip unless you have a unique angle.
  
IF duplicate_risk == "medium":
  → Report exists but may differ. Check if your PoC is meaningfully different.
  → Focus on impact differentiation: "My exploit achieves X that the existing report doesn't."

IF duplicate_risk == "low":
  → Proceed with full report.
```

### 3.3 — Time investment check

Call `bounty_estimate_value` for the finding.

```
IF expected_value / hours_spent < minimum_hourly_rate:
  → Consider: is this finding worth the remaining effort to report?
  → Factor: report writing takes 30-60 minutes for a quality submission.
  → Factor: triage response can take 1-4 weeks.
  → Decision: is your time better spent hunting for higher-value targets?
```

### 3.4 — Final decision

After Steps 1-3, classify the finding:

| Decision | Criteria | Next Action |
|----------|----------|-------------|
| **SUBMIT** | Real vuln, safe to demonstrate, good ROI | `/kambo-report` |
| **HOLD** | Needs more evidence or safer PoC approach | Continue testing |
| **PIVOT** | Not worth the effort at current confidence | Move to next target |
| **DROP** | Likely FP, low impact, or too risky to exploit | Log as learning and move on |

## Step 4: Document the Decision

For each finding that goes through this process, log the decision:

```python
from kambo.learnings import Learning, get_learnings_store

store = get_learnings_store()
store.log(Learning(
    type="operational",
    key=f"confidence_check_{finding_id}",
    insight="Finding X: [SUBMIT/HOLD/PIVOT/DROP] — reason: ...",
    confidence=8,
    source="kambo-confidence",
    skill="kambo-confidence",
    data={
        "finding_id": finding_id,
        "decision": "submit|hold|pivot|drop",
        "gut_confidence": "$100|$500|$20",
        "blast_radius": "read_only|data_access|data_modification|availability",
        "duplicate_risk": "low|medium|high",
        "time_invested_hours": N,
    },
))
```

This creates a decision trail that improves future calibration.

## Output Format

Present the analysis as a confidence report:

```
KAMBO CONFIDENCE REPORT
========================
Finding: {id} — {title}
Severity: {severity} | Confidence: {chain_confidence}

EVIDENCE INTERROGATION
  Signals: {count} | FP checks: {count} | Tool FP rate: {rate}%
  Alternative explanation: {text}
  Gut confidence: {$level}
  Verdict: REAL / UNCERTAIN / LIKELY FP

IMPACT ASSESSMENT
  Category: {read_only|data_access|data_modification|availability}
  Blast radius: {who affected}
  Damage potential: ${estimate}
  Bounty value: ${estimate}
  Risk ratio: {damage/bounty}
  Verdict: SAFE TO EXPLOIT / LIMIT POC / THEORETICAL ONLY

REPORT WORTHINESS
  Duplicate risk: {low|medium|high}
  ROI: ${expected_value}/hr
  Time remaining: ~{minutes} to write report
  
DECISION: {SUBMIT | HOLD | PIVOT | DROP}
Reason: {one-line justification}
```

## Integration with Other Skills

- After `/kambo-hunt` finds something → run `/kambo-confidence` before reporting
- `/kambo-report` should check: was confidence review done? If not, suggest it
- `/kambo-refine` uses confidence decisions to improve calibration
- Learnings from DROP decisions feed back into FP detection improvements

## Anti-Patterns

- **Confirmation bias**: "I spent 3 hours on this, it must be real" → irrelevant. Evaluate evidence, not effort.
- **Anchoring on severity**: "It's critical so I should report" → only if the evidence supports it.
- **Skipping the gut check**: if the chain says CONFIRMED but you feel uncertain, investigate why.
- **Over-exploiting**: demonstrating maximum impact when minimum would suffice → unnecessary risk.
- **Ignoring blast radius**: "I'll just try it quickly" → production damage can't be undone quickly.
