---
name: kambo-race
description: Test race conditions and TOCTOU vulnerabilities on critical endpoints. Send concurrent requests to abuse timing windows in financial transactions, coupon redemptions, vote counting, and resource allocation. When it works, it's P1/P2. Use when testing endpoints that change state (transfers, purchases, votes, likes, follows), when /kambo-logic-hunt identifies timing-sensitive flows, or when the user says "race condition", "TOCTOU", "concurrent requests", "double spend", "timing attack".
triggers:
  - race condition
  - TOCTOU
  - concurrent requests
  - double spend
  - timing attack
  - parallel requests
  - race test
---

# Kambo Race — Race Condition & TOCTOU Testing

The database said you had $100. You spent it twice. Both transactions succeeded.

Race conditions happen when two operations read the same state before either writes.
The server checks your balance (CHECK), processes the payment (USE), then deducts (WRITE).
If you send two payments between CHECK and WRITE, both see $100 and both succeed.

This is one of the most impactful bug classes in bug bounty — when it works, it's
direct financial impact, which means P1/P2 severity and top-tier payouts.

## When to Use

- On any endpoint that modifies a shared resource (balance, inventory, votes, credits)
- On coupon/discount redemption endpoints
- On transfer/payment endpoints
- On follow/like/vote endpoints (if count matters)
- When `/kambo-logic-hunt` identifies timing-sensitive business flows
- When you suspect "use once" logic isn't atomic

## Phase 1: Target Identification

### 1.1 — High-Value Race Targets

```
FINANCIAL OPERATIONS (highest payout):
  □ Money transfers between accounts
  □ Payment processing (pay once, get credited twice)
  □ Wallet top-up / withdrawal
  □ Coupon/promo code redemption
  □ Gift card redemption
  □ Referral bonus claiming
  □ Cashback processing
  □ Subscription billing

STATE-CHANGE OPERATIONS (medium payout):
  □ Vote/like/follow counting
  □ Inventory reservation (book same seat twice)
  □ File upload + processing
  □ Account creation (bypass unique constraint)
  □ Token generation (get multiple valid tokens)
  □ Rate limit counter increment

ACCESS CONTROL OPERATIONS:
  □ Role change + concurrent privileged action
  □ Account deletion + concurrent data access
  □ Permission revocation + concurrent authorized action
  □ Session invalidation + concurrent use
```

### 1.2 — Atomicity Check

Before testing, assess whether the endpoint is likely vulnerable:

```
LIKELY VULNERABLE:
  - Application-level logic (not database transactions)
  - REST API with separate read/check/write steps
  - Microservice architecture (state spread across services)
  - Caching layer between app and DB (reads from cache, writes to DB)
  - Eventual consistency patterns

UNLIKELY VULNERABLE:
  - Single SQL transaction with SELECT FOR UPDATE
  - Database-level unique constraints
  - Redis atomic operations (INCR, DECR)
  - Optimistic locking with version checks

TEST ANYWAY: even "unlikely" targets sometimes have implementation bugs.
```

## Phase 2: Attack Techniques

### 2.1 — HTTP/1.1 Last-Byte Sync

The classic technique — prepare N requests, hold the last byte, release simultaneously:

```
TECHNIQUE:
  1. Open N TCP connections to the target
  2. Send each request EXCEPT the final byte of the body
  3. Wait until all N connections are ready
  4. Release the final byte on ALL connections simultaneously
  5. All N requests arrive at the server within ~1ms of each other

WHY IT WORKS:
  Network latency is the enemy of race conditions.
  If requests arrive 100ms apart, the server processes sequentially.
  Last-byte sync eliminates network variance — only server-side
  processing time determines the window.

IMPLEMENTATION APPROACH:
  Use the Docker container's Python/curl capabilities:
  - Python asyncio with aiohttp for concurrent connections
  - Or curl with --parallel for simpler cases
  
  The key is: all requests must be "in flight" before any completes.
```

### 2.2 — HTTP/2 Single-Packet Attack

More powerful than last-byte sync on HTTP/2 targets:

```
TECHNIQUE:
  1. Open a single HTTP/2 connection
  2. Prepare N requests as HTTP/2 frames
  3. Send ALL frames in a single TCP packet
  4. Server receives and processes all N requests simultaneously

WHY IT'S BETTER:
  HTTP/2 multiplexes streams on one connection.
  A single TCP packet contains all requests — no network variance at all.
  The server's HTTP/2 implementation processes them as fast as it can parse.

CHECK: Does the target support HTTP/2?
  → scan_tls will show protocol support
  → curl --http2 to test
```

### 2.3 — Overflow Race

For endpoints with a limit (balance, inventory, quota):

```
SCENARIO: Balance = $100, Transfer costs $100

ATTACK:
  Send 10 concurrent transfers of $100 each.
  
EXPECTED (safe): 1 succeeds, 9 fail with "insufficient balance"
VULNERABLE:      2+ succeed (balance goes negative)

VARIATIONS:
  - Different amounts: 10x $100 AND 5x $50 AND 2x $200
  - Partial + full: some at $99, some at $100, some at $101
  - Mixed operations: transfer + withdrawal simultaneously
```

### 2.4 — Limit Bypass Race

For "use once" resources (coupons, referral codes, one-time links):

```
SCENARIO: Coupon "SAVE50" is single-use

ATTACK:
  Send 10 concurrent requests applying "SAVE50" to 10 different orders.

EXPECTED (safe): 1 order gets the discount, 9 fail
VULNERABLE:      2+ orders get the discount

THE PATTERN:
  CHECK: "Is coupon valid?" → YES (not yet used)
  USE:   "Apply coupon to order" → Applied
  MARK:  "Mark coupon as used" → Done
  
  If CHECK and MARK are not atomic, concurrent requests
  all pass the CHECK before any reaches MARK.
```

### 2.5 — State Transition Race

For endpoints where state change enables/disables access:

```
SCENARIO: User deletes account → data should be inaccessible

ATTACK:
  Request A: DELETE /api/account (delete account)
  Request B: GET /api/account/data (export all data)
  Send simultaneously.

VULNERABLE IF:
  Request B returns data even though deletion was "in progress"
  (the data export read happened before the deletion committed)

OTHER STATE TRANSITIONS TO RACE:
  - Downgrade subscription + use premium feature
  - Revoke API key + use API key
  - Change password + login with old password
  - Ban user + user performs action
```

## Phase 3: Execution

### 3.1 — Preparation

```
BEFORE SENDING RACE REQUESTS:

  1. MEASURE BASELINE:
     Send a single request → record response time
     Send another single request → confirm idempotent behavior
     Note: what does "success" vs "already used" look like?

  2. SET UP MONITORING:
     Note initial state (balance, coupon status, vote count)
     This is your "before" for the proof

  3. CHOOSE CONCURRENCY:
     Start with N=5 concurrent requests
     If no race: increase to N=10, N=20
     If still no race: try N=50 with HTTP/2 single-packet
     
  4. CONFIRM SCOPE:
     Is race condition testing allowed by the program?
     Some programs restrict "load testing" — race conditions are
     different (precision timing, not volume) but clarify if unsure
```

### 3.2 — Execute and Observe

```
SEND RACE REQUESTS

OBSERVE:
  - How many requests returned "success" (200 OK with positive result)?
  - How many returned "already used" / "insufficient balance" / error?
  - What is the final state? (balance, coupon status, vote count)

SUCCESS CRITERIA:
  IF more_successes_than_expected:
    → Race condition CONFIRMED
    → Document: sent N requests, M succeeded (expected 1)
    → Document: state before and after
    → Calculate: financial impact = (M-1) × value_per_operation

  IF exactly_one_success:
    → Server handles concurrency correctly
    → Try with higher N or different timing technique
    → After 3 attempts with no success → mark as NOT VULNERABLE

  IF inconsistent_results:
    → Race condition exists but window is tight
    → Note success rate (e.g., "works 2/10 attempts")
    → Document as FIRM confidence (not always reproducible)
```

### 3.3 — Evidence Collection

```
CAPTURE FOR EACH RACE:

  1. Initial state screenshot/response (balance=$100)
  2. All concurrent requests (with timestamps)
  3. All responses (with timestamps, showing 2+ successes)
  4. Final state screenshot/response (balance=-$100 or coupon used 3x)
  5. The timing: "window of ~Xms between check and write"

IMPORTANT:
  If testing on real financial endpoints:
  - Use minimum amounts ($0.01 if possible)
  - Reverse your actions after proving the bug
  - Document that you reversed the impact
  - If you can't reverse: report immediately with what happened
```

## Phase 4: Impact Quantification

### 4.1 — Financial Impact Formula

```
impact = (successful_concurrent - 1) × value_per_operation × scalability_factor

WHERE:
  successful_concurrent = number of operations that succeeded in one race
  value_per_operation = monetary value of each operation
  scalability_factor:
    1x   if race requires manual timing (hard to automate)
    10x  if race works reliably (>50% success rate)
    100x if race is trivially automated (script runs in loop)

EXAMPLE:
  3 concurrent $100 transfers succeeded (expected 1)
  → Raw impact: (3-1) × $100 = $200 per race
  → Works 7/10 times, easily scripted
  → Scaled impact: $200 × 100 = $20,000 potential
```

### 4.2 — Severity Classification

```
CRITICAL (P1):
  - Financial loss (transfers, payments, wallet)
  - Unlimited resource generation
  - Authentication bypass via race

HIGH (P2):
  - Coupon/discount abuse
  - Inventory double-booking
  - Rate limit bypass on sensitive operations

MEDIUM (P3):
  - Vote/like manipulation
  - Non-financial counter manipulation
  - Duplicate resource creation (non-destructive)

LOW:
  - Cosmetic duplication
  - Non-exploitable timing behavior
```

## Phase 5: Reporting

```
KAMBO RACE CONDITION REPORT
============================
Target: {target}
Endpoint: {url}
Method: {HTTP method}

VULNERABILITY:
  Type: Race Condition / TOCTOU
  Operation: {what the endpoint does}
  Expected behavior: {only 1 should succeed}
  Actual behavior: {N succeeded concurrently}

TIMING:
  Technique: {last-byte sync / HTTP/2 single-packet}
  Concurrency: {N requests}
  Success rate: {M/N attempts}
  Window estimate: ~{X}ms

IMPACT:
  Per-race: {value}
  Scalable: {yes/no}
  Estimated total: {maximum potential impact}

EVIDENCE:
  Before: {initial state}
  Race requests: {all N requests with timestamps}
  Race responses: {all N responses with timestamps}
  After: {final state showing double-spend/duplication}

REMEDIATION:
  - Use database-level transactions (SELECT ... FOR UPDATE)
  - Implement optimistic locking (version column)
  - Use atomic operations (Redis DECR, DB constraints)
  - Add idempotency keys for financial operations
```

## Integration with Other Skills

| Flow | Integration |
|------|-------------|
| `/kambo-logic-hunt` → timing-sensitive flow → `/kambo-race` | Logic analysis identifies race targets |
| `/kambo-race` → finding → `/kambo-chain` | Race condition as step in larger chain |
| `/kambo-race` → finding → `/kambo-confidence` | Validate reproducibility before reporting |
| `/kambo-race` → finding → `/kambo-report` | Generate race-specific report template |
| `/kambo-think-like-defense` → no atomicity → `/kambo-race` | Defense model identifies missing locks |

## Anti-Patterns

- **Confusing load testing with race testing**: race conditions require precision timing (5-10 requests), not volume (1000 requests). Don't DoS the target.
- **Testing without understanding the operation**: you need to know what "success" looks like vs. "already processed" to detect a race.
- **Giving up after one attempt**: race conditions are probabilistic. Test at least 3 times with N=10+ before concluding an endpoint is safe.
- **Not reversing impact**: if your race condition created real financial impact, document it AND try to reverse it (refund, delete duplicate, etc.).
- **Reporting without quantifying impact**: "race condition exists" is weak. "Race condition allows unlimited coupon redemption worth $50 each, works 70% of the time" is P1.
