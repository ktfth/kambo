# ADR-0001 — Evidence-Grade Confidence Doctrine

**Status:** Accepted  
**Date:** 2026-05-29  
**Deciders:** ktfth

---

## Context

Early versions of Kambo accumulated evidence weights additively and reported CONFIRMED findings based on crossing a numeric threshold alone. This produced systematic false positives on:

- Cloudflare-protected targets (curl-only XSS reflection scored CONFIRMED when CSP/browser rendering would block execution)
- SPA frameworks (virtual DOM intercepts injection, no actual XSS)
- Blind SSRF (body keyword matching claimed CONFIRMED without a received OOB callback)
- SSTI with trivial markers (`{{7*7}}→49` echoed by template engines that don't evaluate, or that echo numeric literals)
- Dangling CNAMEs pointing at non-claimable AWS resources (ELB/NLB) scoring positive takeover confidence

Each false positive burned hunter credibility with programs and wasted report-writing time.

## Decision

Replace additive-only confidence scoring with a **cap/gate mechanism** layered on top of weight accumulation:

1. **`EvidenceChain.cap(level, reason)`** — lowers a hard ceiling; `chain.confidence = min(accumulated tier, ceiling)`. Caps are structural, not advisory.
2. **Doctrine gates I1–I5** — named invariants implemented as `chain.cap()` calls inside validators. Not configurable at runtime.
3. **`confidence_meets()` for verdicts** — code that decides "is this vulnerable?" calls `confidence_meets(chain.confidence, minimum)` rather than comparing raw `total_weight`, so a cap is always honored.

### Doctrine Gates

| Gate | Name | Rule |
|------|------|------|
| I1 | Causality or nothing | Single-response reflexive finding caps at FIRM; CONFIRMED requires baseline differential or correlated OOB hit |
| I2 | Orthogonal markers | SSTI canaries must be non-trivial arithmetic results; `{{7*7}}→49` banned |
| I3 | OOB body keywords ≠ execution | Finding OOB token in response body is reflection; only a received callback proves blind execution |
| I4 | Context-aware XSS | Reflection in HTML comments / JSON script blocks caps at TENTATIVE; curl-only caps at FIRM |
| I5 | CSP nonce/hash gate | CSP with nonce or hash in script-src caps XSS at TENTATIVE |

## Consequences

**Positive:**
- Structurally impossible to produce a CONFIRMED finding from a single HTTP response on reflexive classes (I1)
- Systematic Cloudflare/SPA FP class eliminated (I4, I5)
- Blind class FP class eliminated (I3)
- Trivial marker FP class eliminated (I2)
- Gates survive refactors — `cap()` is in the chain data, not in downstream display logic

**Negative:**
- True positives that were previously CONFIRMED may now surface as FIRM (requires follow-up with browser PoC or OOB correlation)
- Adds complexity to validator functions — every reflexive validator must call `cap_single_response_reflexive()` or equivalent

**Neutral:**
- Weight accumulation continues unchanged — caps only affect the reported tier, not the underlying evidence
- Existing tests that encoded pre-doctrine CONFIRMED behavior had to be updated when the gates were introduced
