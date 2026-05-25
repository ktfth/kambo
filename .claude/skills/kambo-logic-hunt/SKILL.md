---
name: kambo-logic-hunt
description: Hunt business logic vulnerabilities that automated scanners miss — race conditions, flow bypass, price manipulation, privilege escalation via workflow abuse, and broken state machines. These findings pay the highest bounties because they require human reasoning to discover. Use when hunting on targets with complex workflows (e-commerce, fintech, SaaS), when scanners return nothing interesting, when the user says "business logic", "logic bugs", "flow bypass", "price manipulation", "state machine", "workflow abuse", or when standard vuln tools produce only FPs on a hardened target.
triggers:
  - business logic
  - logic bugs
  - logic hunt
  - flow bypass
  - price manipulation
  - state machine
  - workflow abuse
  - checkout bypass
  - coupon abuse
  - privilege escalation via workflow
---

# Kambo Logic Hunt — Business Logic Vulnerability Discovery

Scanners find injection. Humans find logic bugs. Logic bugs pay more.

A business logic vulnerability is when the application does exactly what the code tells it
to do — but the code doesn't account for how a creative user would abuse the workflow.
No WAF catches this. No scanner detects it. The application validates every input perfectly,
handles every error gracefully, and still lets you buy a $500 item for $0.

These bugs require understanding the BUSINESS, not just the code.

## When to Use

- On targets with complex user workflows (e-commerce, fintech, SaaS, booking systems)
- When injection/XSS/SSRF scanning produces nothing (the target is well-hardened)
- When you need high-severity findings that justify the time investment
- After `/kambo-js-hunt` reveals the application's flow structure
- When `/kambo-think-like-defense` identifies business logic as a blind spot

## Phase 1: Workflow Mapping

Before hunting logic bugs, you need to understand the business flows.

### 1.1 — Critical Flow Identification

Map every flow that involves value exchange or state change:

```
MONEY FLOWS (highest bounty potential):
  □ Purchase/checkout flow
  □ Payment processing
  □ Refund/chargeback process
  □ Subscription management (upgrade/downgrade/cancel)
  □ Credit/wallet/balance system
  □ Coupon/discount application
  □ Gift card redemption
  □ Invoice generation

IDENTITY FLOWS:
  □ Registration → verification → activation
  □ Login → session → logout
  □ Password reset flow
  □ Email/phone change flow
  □ Account deletion flow
  □ Account merge/linking
  □ SSO/OAuth integration

AUTHORIZATION FLOWS:
  □ Role assignment/change
  □ Team/org membership
  □ Resource sharing/permissions
  □ API key generation/revocation
  □ Invitation system
  □ Approval workflows

DATA FLOWS:
  □ File upload → processing → storage
  □ Export/download functionality
  □ Import/bulk operations
  □ Search and filtering
  □ Reporting/analytics
```

### 1.2 — State Machine Extraction

For each critical flow, map the state machine:

```
EXAMPLE: Order Flow
  CREATED → PENDING_PAYMENT → PAID → PROCESSING → SHIPPED → DELIVERED
                                                           → RETURNED → REFUNDED

QUESTIONS TO ASK:
  - Can I skip states? (CREATED → SHIPPED without PAID?)
  - Can I go backwards? (SHIPPED → CREATED?)
  - Can I repeat states? (apply coupon twice?)
  - Can I reach invalid states? (REFUNDED but never PAID?)
  - What happens at each transition? (is validation per-transition or per-state?)
  - Who controls the transitions? (client-side or server-side?)
```

Use `scan_api_endpoints` and `/kambo-js-hunt` data to map the endpoints for each state transition.

## Phase 2: Attack Pattern Catalog

Test each mapped flow against these attack patterns:

### 2.1 — Price/Value Manipulation

```
TEST: Can I change the price between cart and payment?
  1. Add item to cart at $100
  2. Intercept the payment request
  3. Modify price parameter to $1 or $0 or -$100
  4. Does the server re-validate the price?

TEST: Negative quantities
  1. Add item with quantity = -1
  2. Does this credit my account?
  3. Does the total become negative?

TEST: Currency confusion
  1. If multi-currency supported, change currency code in request
  2. Pay 100 JPY instead of 100 USD?
  3. Does the server validate currency consistency?

TEST: Floating point abuse
  1. Set quantity to 0.0000001
  2. Does this round to 0 cost but 1 item?
  3. Set price to 99.999999999 — does it round down?

TEST: Coupon stacking
  1. Apply coupon code
  2. Apply same coupon again (in same or different request)
  3. Apply two "non-stackable" coupons via parallel requests
  4. Apply coupon, remove item, add different item — is coupon still applied?

TOOLS: scan_parameters to find hidden price/discount params
       api_test_bopla for mass assignment on price fields
```

### 2.2 — Flow Bypass / Step Skipping

```
TEST: Skip mandatory steps
  1. Map the multi-step flow (e.g., registration: email → verify → profile → done)
  2. Try accessing step 3 directly without completing step 1-2
  3. Try calling the final API endpoint without the intermediate ones
  4. Does the server track flow state, or just check individual step validity?

TEST: Replay attacks
  1. Complete a flow once (e.g., redeem a one-time code)
  2. Replay the exact same request
  3. Is the server checking "was this used?" or "is this valid?"

TEST: Parallel flow abuse
  1. Start the same flow in two browser sessions simultaneously
  2. Complete both — do you get double the benefit?
  3. Example: two simultaneous free trial activations

TEST: Parameter pollution
  1. Send duplicate parameters: ?role=user&role=admin
  2. Which value does the server use? First? Last? Array?
  3. Try in body, query, headers simultaneously
```

### 2.3 — Authorization Logic Bugs

```
TEST: Horizontal privilege escalation via workflow
  1. User A creates a resource
  2. User B starts the edit workflow for that resource
  3. Can User B complete the workflow even though they don't own it?
  4. The UI may hide the button, but does the API enforce it?

TEST: Vertical privilege via feature abuse
  1. Non-admin user triggers admin-only workflow via API
  2. Example: non-admin calls /api/users/bulk-delete
  3. The UI hides the feature, but the endpoint exists

TEST: Role transition abuse
  1. User downgrades from premium → free
  2. Are premium features immediately revoked?
  3. Or can I keep using cached premium tokens?
  4. Upgrade → use feature → request refund within window → keep feature?

TEST: Invitation system abuse
  1. Invite user with admin role
  2. Does the inviter need admin rights to grant admin?
  3. Self-invite: can I invite myself to gain elevated access?
  4. Invite manipulation: change the role in the invite request

TOOLS: api_test_bola for object-level auth
       api_test_bfla for function-level auth
       vuln_idor for ID-based access control
```

### 2.4 — Rate Limit & Resource Abuse

```
TEST: Rate limit bypass
  1. Test rate limit on sensitive endpoints (login, password reset, API)
  2. Bypass via: X-Forwarded-For header rotation
  3. Bypass via: case variation (User vs user vs USER)
  4. Bypass via: encoding (%75ser vs user)
  5. Bypass via: API versioning (/v1/ vs /v2/ same endpoint)
  6. Bypass via: HTTP method change (GET vs POST)

TEST: Resource exhaustion (with care)
  1. Trigger expensive operations (report generation, export, search)
  2. Can I trigger unlimited concurrent operations?
  3. Can I request an export of ALL data (no pagination limit)?
  4. Can I queue infinite background jobs?

TEST: Abuse of free features
  1. Free tier allows N operations
  2. Can I create multiple free accounts?
  3. Can I reset the counter by manipulating the request?
  4. Is the limit enforced per-account, per-IP, or per-session?

TOOLS: api_test_resource for rate limiting tests
       exploit_password_spray for login rate limits
```

### 2.5 — Time-Based Logic Bugs

```
TEST: TOCTOU (Time of Check, Time of Use)
  1. System checks balance → processes payment → deducts
  2. Between check and deduction, spend the balance elsewhere
  3. This requires fast parallel requests (race condition)

TEST: Expiration bypass
  1. Token/link has expiration time
  2. Is the expiration enforced server-side or client-side?
  3. Can I use an expired token if I replay the request?
  4. Does the server check "issued_at + ttl > now" or just "is this token valid"?

TEST: Timezone abuse
  1. If features are time-locked (e.g., flash sale, early access)
  2. Can I access by changing timezone headers?
  3. Does the server use UTC consistently?

TEST: Subscription timing
  1. Cancel subscription at end of billing period
  2. Continue using features until expiration
  3. Request refund for unused portion
  4. Re-subscribe with new account for fresh trial
```

## Phase 3: Evidence Collection

Logic bugs require strong evidence because they're easy to misinterpret.

### 3.1 — Before/After Proof

For each logic bug found:

```
DOCUMENT:
  1. Initial state (screenshot: balance = $100)
  2. Action taken (request capture with full headers/body)
  3. Final state (screenshot: balance = $100 + item received)
  4. Why this is wrong (expected: balance = $0 after purchase)

  The proof must show:
  - What SHOULD happen (per business logic)
  - What ACTUALLY happens (the bug)
  - Why this is exploitable (impact on business/users)
```

### 3.2 — Reproducibility

```
PROVIDE:
  1. Step-by-step reproduction guide
  2. Exact API requests (curl commands or request capture)
  3. Required preconditions (account type, feature flags, etc.)
  4. Whether it works on first try or requires timing

  Logic bugs that require race conditions:
  - Note the success rate (works 1/10 times? 9/10 times?)
  - Note the window of opportunity
  - Provide the parallelization method used
```

### 3.3 — Impact Assessment

```
FOR EACH finding, calculate business impact:

  FINANCIAL IMPACT:
    - Can this steal money? → CRITICAL
    - Can this get free products/services? → HIGH
    - Can this manipulate pricing for advantage? → HIGH
    - Can this abuse referral/reward systems? → MEDIUM

  DATA IMPACT:
    - Can this access other users' data? → HIGH-CRITICAL
    - Can this modify other users' data? → CRITICAL
    - Can this delete other users' data? → CRITICAL

  SCALE:
    - Exploitable once or infinitely? → multiplier
    - Requires authentication or anonymous? → multiplier
    - Automated or manual exploitation? → multiplier

  Use bounty_estimate_value with these factors
  Use report_cvss for formal severity scoring
```

## Phase 4: Synthesis & Reporting

### 4.1 — Finding Classification

```
KAMBO LOGIC HUNT REPORT
========================
Target: {target}
Workflows Mapped: {count}
Patterns Tested: {count}

FINDINGS:

  [L1] CRITICAL — {title}
       Flow: {checkout/auth/subscription/etc.}
       Pattern: {price manipulation/flow bypass/etc.}
       Impact: {financial/data/access}
       Reproducibility: {always/race condition/timing}
       Evidence: {request + before/after state}

  [L2] HIGH — {title}
       ...

WORKFLOWS TESTED (clean):
  ✓ Registration flow — no logic bypasses found
  ✓ Password reset — properly invalidates tokens
  ✗ Checkout — VULNERABLE (see L1)
  ✗ Coupon system — VULNERABLE (see L2)

RECOMMENDATIONS FOR NEXT STEPS:
  - Test with different account roles
  - Test with different payment methods
  - Re-test after deployment (logic may change)
```

### 4.2 — Pipeline Integration

```
FOR EACH logic_finding:
  → report_finding with category="business_logic"
  → bounty_estimate_value (logic bugs often pay 2-5x vs technical vulns)
  → /kambo-confidence before submitting (logic bugs need extra validation)

FOR EACH workflow_mapped:
  → pipeline_ingest as discovered asset (workflow metadata)
  → feed endpoints into vuln testing pipeline
```

## Integration with Other Skills

| Flow | Integration |
|------|-------------|
| `/kambo-hunt` → scanning phase → `/kambo-logic-hunt` | When scanners return little, pivot to logic hunting |
| `/kambo-js-hunt` → flow data → `/kambo-logic-hunt` | JS analysis reveals flow structure for logic testing |
| `/kambo-think-like-defense` → blind spots → `/kambo-logic-hunt` | Defense model identifies business logic as neglected area |
| `/kambo-logic-hunt` → finding → `/kambo-confidence` | Logic bugs need extra confidence validation |
| `/kambo-logic-hunt` → finding → `/kambo-report` | Generate report with business impact emphasis |
| `/kambo-logic-hunt` → `/kambo-chain` | Complex logic bugs may require chained exploitation |

## Anti-Patterns

- **Testing without understanding the business**: you can't find logic bugs if you don't understand what the correct logic IS. Map the flow first.
- **Reporting cosmetic issues as logic bugs**: "I can add negative quantity to cart but the server rejects it" is not a bug — the validation worked.
- **Skipping impact assessment**: "price can be changed in request" means nothing without proving the server processes the modified price.
- **Over-testing in production**: logic bugs involving financial transactions should be tested minimally. Don't actually complete $0 purchases — show the price was accepted, then cancel.
- **Ignoring race conditions**: many logic bugs only appear under concurrent requests. If a flow seems solid, test it with parallel requests before marking clean.
