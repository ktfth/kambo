---
name: kambo-notes
description: Take and query engagement notes through an attack-vector lens. Per-session, ephemeral observation memory that tracks how far each vector has been pushed, suggests the next probe, surfaces blind spots, ranks vectors by ROI, and graduates confirmed notes into findings. Use when jotting observations during a session, deciding which vector to work next, checking coverage, or turning a note into a report.
triggers:
  - take a note
  - note this
  - vector notes
  - what should I work on next
  - which vector next
  - blind spots
  - coverage
  - notes board
  - promote note
  - jot down
---

# Kambo Notes — Vector-Centric Engagement Memory

A per-session, **ephemeral** notebook indexed by **attack vector** instead of by
time or tool. Nothing persists to disk unless `KAMBO_NOTES_PATH` is explicitly
set outside the repo — the data lives only for the session and can never
compromise the project. Three tools:

| Tool | Purpose |
|------|---------|
| `note_add` | record a vector-tagged observation (stance is evidence-backed) |
| `note_query` | read through the attacker's lens — list / by_vector / board / coverage / playbook |
| `note_promote` | graduate a confirmed note into a reportable Finding |

## The stance ladder — the path to viabilizing a vector

Every note carries a **stance** = how far that vector has been pushed:

```
untested → suspected → probing → confirmed        (ruled_out = closed negative)
```

The goal of a session is to walk promising vectors up this ladder. The tools
exist to make that walk explicit and guided.

## Taking notes

```
note_add(vector="idor", target="api.example.com/users/{id}",
         observation="sequential ids, no ownership check seen",
         stance="suspected", confidence=7)
```

**Evidence backs the stance — not gut feel.** Attach `evidence_signals` and the
evidence chain *caps* how strong a stance you may claim:

```
note_add(vector="sqli", target="api.example.com", observation="extracted db version",
         stance="confirmed",
         evidence_signals=[
           {"signal":"UNION reflected","source":"manual","weight":1.0},
           {"signal":"version() in response","source":"manual","weight":1.0}])
```

- Overclaim (e.g. `confirmed` with one weak signal) → stance is **capped** and a
  caveat returned.
- A strong stance with **no** evidence → recorded but flagged as a hunch.
- Reuse the same `note_id` to **progress** a note as you gather evidence
  (latest wins).

## Querying — change the perspective

```
note_query(mode="board")               # progress board, attention-ordered, with next-step hints
note_query(mode="board", order="roi")  # rank by expected value of advancing (which to do first)
note_query(mode="by_vector")           # pivot: one summary per vector
note_query(mode="coverage")            # blind spots: vectors you have NOT touched
note_query(mode="playbook", vector="ssrf")  # the full untested→confirmed recipe for one vector
note_query(mode="list", vector="idor", stance="probing")  # flat filtered notes
```

Use them as a loop:
1. **`coverage`** — what have I not even considered? (the defender's hope)
2. **`board` (order=roi)** — of what I've touched, which vector pays most to push next?
3. **`playbook`** — what is the concrete next probe for that vector?
4. **`note_add`** (same `note_id`) — record the result, advance the stance.
5. Repeat until a vector reaches `confirmed`.

## Promoting to a finding

When a vector is `confirmed` with evidence:

```
note_promote(note_id="idor-1", severity="high", impact="cross-account data read")
```

This rebuilds the note's evidence chain and creates a `Finding` via the normal
reporting pipeline (persisted to the gitignored `output/` workspace, never the
repo). The finding's confidence is derived **honestly** from the evidence — a
note with no evidence can never become a CONFIRMED finding.

## Discipline

- Record `ruled_out` too — knowing what you eliminated is as valuable as what you found.
- Keep stances honest; the evidence cap and the ROI score are only as good as the inputs.
- Playbook steps are non-destructive/proof-oriented — respect program rules of engagement.
- The store is per-session: export anything worth keeping into a finding before you stop.
