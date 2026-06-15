# ADR-0003 — Cross-Session Learnings via Append-Only JSONL

**Status:** Accepted  
**Date:** 2026-05-30  
**Deciders:** ktfth

---

## Context

Kambo runs as an MCP server that is started and stopped per session. Between sessions, in-memory tool performance data and calibration insights are lost. Without persistence, the system cannot improve over time — each session starts from the same priors regardless of accumulated evidence.

Two options considered for persistence:
1. SQLite (already used for per-session metrics via `metrics.py`)
2. Append-only JSONL file

## Decision

Use an **append-only JSONL file** (`~/.kambo/learnings.jsonl`) for cross-session learnings, separate from the SQLite metrics store.

Rationale:
- JSONL is human-readable and inspectable without tooling — operators can audit what the system learned
- Append-only avoids write conflicts when multiple sessions run concurrently
- Simple deduplication by `(key, type)` tuple on load prevents redundant entries
- Time-based confidence decay (−1 point per 30 days) prevents stale learnings from dominating

SQLite continues to handle per-tool per-session numerical metrics (precision, FP rate, findings count) where relational queries are needed. Learnings store handles qualitative insights (patterns, pitfalls, calibration adjustments, operational observations).

### Learning Types
| Type | Examples |
|------|----------|
| `pattern` | "SPA framework detection improved XSS precision by 40%" |
| `pitfall` | "Dangling ELB CNAMEs produce false takeover confidence" |
| `calibration` | "vuln_xss weight needs −0.2 adjustment (predicted 80%, actual 40%)" |
| `operational` | "HackerOne /reports endpoint returns 401 even with valid credentials" |
| `tool_perf` | "recon_subdomains: 3 findings/run, 91% precision over 11 runs" |

## Consequences

**Positive:**
- Learnings persist across server restarts with no schema migrations
- Human-inspectable format — operators can add/remove entries manually
- Decay mechanism prevents the system from over-weighting old data
- Singleton `get_learnings_store()` ensures consistent path across all callers

**Negative:**
- JSONL grows unboundedly without explicit pruning (mitigated by `prune()` method)
- No relational queries across learning fields (use SQLite metrics for those)
- Path is user-home-relative; multi-user or containerized deployments need explicit `LEARNINGS_PATH` configuration

**Future consideration:**
- When learnings grow beyond ~10,000 entries, pruning by confidence threshold may be needed; `LearningsStore.prune()` handles this but is not yet called automatically.
