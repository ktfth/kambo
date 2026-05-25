---
name: kambo-chain
description: Orchestrate multi-step exploit chains with stateful request sequencing. When a vulnerability requires multiple steps to exploit (login → extract token → use token on different endpoint → escalate), this skill manages the chain, tracks state between requests, and maximizes demonstrated impact. Use when a single finding isn't enough, when chaining vulns creates higher severity, when the user says "chain exploits", "multi-step", "combine findings", "escalate impact", "exploit chain", "attack chain".
triggers:
  - chain exploits
  - exploit chain
  - multi-step exploit
  - combine findings
  - escalate impact
  - attack chain
  - chain vulnerabilities
  - link findings
---

# Kambo Chain — Multi-Step Exploit Orchestration

One vulnerability is a finding. Two chained vulnerabilities are a story.

Bug bounty programs pay for impact. A self-XSS alone is informational.
A self-XSS → CSRF → account takeover is critical. The same vulnerability
becomes 10x more valuable when you demonstrate how an attacker would chain it
with other weaknesses to achieve maximum impact.

This skill helps you think in chains: connecting weak findings into strong exploit
narratives that demonstrate real-world attack scenarios.

## When to Use

- When you have multiple low/medium findings that individually aren't reportable
- When you need to demonstrate higher impact for a finding
- When `/kambo-confidence` says "the finding is real but impact is unclear"
- When you want to build an attack narrative for the report
- After `/kambo-logic-hunt` discovers workflow vulnerabilities that need chaining

## Phase 1: Finding Inventory

Before chaining, catalog what you have.

### 1.1 — Collect All Findings

```
FROM current session pipeline:
  → pipeline_status to see all findings
  → report_metrics for confidence levels

CLASSIFY each finding by type:
  
  ENTRY POINTS (how you get in):
    □ XSS (stored, reflected, DOM)
    □ Open redirect
    □ CSRF
    □ Clickjacking
    □ Phishing vector
    
  AMPLIFIERS (how you escalate):
    □ IDOR / BOLA
    □ Privilege escalation
    □ SSRF
    □ Path traversal
    □ Information disclosure
    
  OBJECTIVES (what you achieve):
    □ Account takeover
    □ Data exfiltration
    □ Remote code execution
    □ Administrative access
    □ Financial manipulation
```

### 1.2 — Map Relationships

```
FOR EACH finding pair (A, B):
  Can A's output feed B's input?
  
  Examples:
    XSS → steals session cookie → IDOR with stolen session
    SSRF → accesses internal API → extracts admin credentials
    Info disclosure → reveals admin endpoint → auth bypass
    Open redirect → phishing → credential theft → account takeover
    CORS miscfg → exfiltrates CSRF token → CSRF → account change

DRAW the relationship map:
  [Entry Point] → [Amplifier] → [Objective]
  
  The chain is only as strong as its weakest link.
  Each step must actually work — no theoretical jumps.
```

## Phase 2: Chain Construction Patterns

### 2.1 — Classic Chain Templates

```
CHAIN: XSS → Account Takeover
  1. Find XSS (reflected or stored)
  2. Craft payload that steals session token / changes email / changes password
  3. Deliver via social engineering vector (if self-XSS, need CSRF wrapper)
  4. Demonstrate: victim clicks link → attacker gains account access
  Impact: CRITICAL (P1)
  
CHAIN: SSRF → Internal Access → Data Breach
  1. Find SSRF (even partial/blind)
  2. Access cloud metadata (IMDS) → extract IAM credentials
  3. Use credentials to access internal services / S3 buckets
  4. Demonstrate: external request → internal data accessed
  Impact: CRITICAL (P1)

CHAIN: IDOR → Mass Data Exfiltration
  1. Find IDOR on single resource (e.g., /api/users/123)
  2. Enumerate IDs (sequential, UUID prediction, leaked in responses)
  3. Demonstrate: automated extraction of multiple users' data
  4. Calculate: total records accessible × sensitivity = impact
  Impact: HIGH-CRITICAL (P1-P2)

CHAIN: Info Disclosure → Privilege Escalation
  1. Find information leak (stack trace, config file, .env, source map)
  2. Extract: internal URLs, credentials, API keys, admin paths
  3. Use leaked info to access restricted functionality
  4. Demonstrate: public page → internal access
  Impact: HIGH (P2)

CHAIN: Open Redirect → OAuth Token Theft
  1. Find open redirect on trusted domain
  2. Abuse as OAuth redirect_uri (if validation is prefix-based)
  3. Intercept authorization code / token via redirect
  4. Demonstrate: victim authorizes → attacker gets token
  Impact: HIGH-CRITICAL (P1-P2)

CHAIN: CORS Misconfiguration → CSRF Bypass → Account Takeover
  1. Find CORS that reflects arbitrary origins with credentials
  2. Craft page on attacker domain that reads sensitive data cross-origin
  3. Extract CSRF tokens or session data
  4. Use extracted tokens to perform state-changing actions
  Impact: HIGH (P2)

CHAIN: Race Condition → Financial Impact
  1. Find endpoint vulnerable to race condition (coupon, transfer, vote)
  2. Send concurrent requests to abuse the timing window
  3. Demonstrate: multiplied benefit (double coupon, double credit)
  4. Calculate: potential financial loss = impact
  Impact: HIGH-CRITICAL (P1-P2)
```

### 2.2 — Chain Execution Protocol

For each chain you construct:

```
STEP 1: VALIDATE EACH LINK
  Before chaining, confirm each finding independently:
  - Does the XSS actually execute? (not just reflected)
  - Does the SSRF actually reach internal targets? (not just error)
  - Does the IDOR actually return other users' data? (not just 200 OK)
  
  IF any link is unconfirmed → do NOT chain.
  A chain with a broken link is a waste of time.

STEP 2: DOCUMENT THE FLOW
  Write the chain as numbered steps with exact requests:
  
  Request 1: GET /vulnerable?param=<XSS_PAYLOAD>
  → Response: XSS executes, steals cookie value ABC123
  
  Request 2: GET /api/admin/users (Cookie: session=ABC123)
  → Response: Returns all user data (admin access confirmed)
  
  Each step must show INPUT and OUTPUT.

STEP 3: PROVE CAUSALITY
  The reviewer must understand WHY each step enables the next.
  Don't just show "I sent request A, then request B."
  Show: "Request A returned TOKEN, which I used in Request B's header,
         which granted access because TOKEN has admin privileges."

STEP 4: CALCULATE COMBINED SEVERITY
  Individual findings:     XSS=Medium + IDOR=Medium = Medium? NO.
  Chained finding:         XSS→Cookie theft→Admin IDOR = CRITICAL
  
  The chain severity is determined by the OBJECTIVE achieved,
  not the average of individual findings.
  
  Use report_cvss on the final chain impact, not individual steps.
```

## Phase 3: State Management

Claude Code doesn't maintain HTTP state between tool calls. This is the challenge — and the solution.

### 3.1 — Manual State Tracking

```
MAINTAIN a state object across the chain:

STATE = {
  tokens: {},        // extracted tokens, cookies, session IDs
  endpoints: {},     // discovered endpoints with auth requirements
  credentials: {},   // extracted usernames, passwords, API keys
  data: {},          // extracted sensitive data for proof
  chain_position: N, // current step in the chain
}

AFTER EACH STEP:
  → Extract relevant data from the response
  → Update STATE
  → Pass STATE values into the next step's request

EXAMPLE:
  Step 1: Login → extract session_token → STATE.tokens.session = "abc123"
  Step 2: IDOR with session → STATE.data.leaked_user = {email, name}
  Step 3: Use leaked email for password reset → STATE.tokens.reset = "xyz789"
```

### 3.2 — Evidence Chain Construction

```
FOR THE REPORT, build an evidence chain:

  EVIDENCE_CHAIN = [
    {
      step: 1,
      action: "Send XSS payload to victim profile",
      request: "POST /api/profile/bio ...",
      response: "200 OK — payload stored",
      extracted: "N/A — setup step",
    },
    {
      step: 2, 
      action: "Victim views attacker profile",
      request: "GET /profile/attacker-user",
      response: "XSS fires, sends cookie to attacker",
      extracted: "session=abc123def456",
    },
    {
      step: 3,
      action: "Use stolen session to access admin API",
      request: "GET /api/admin/users (Cookie: session=abc123def456)",
      response: "200 OK — returns 1,547 user records",
      extracted: "Full PII for 1,547 users",
    },
  ]

  This evidence chain becomes the core of your bounty report.
```

## Phase 4: Impact Maximization

### 4.1 — Asking "What's the Worst Case?"

```
FOR EACH chain, push the impact to its maximum:

  Found SSRF?
    → Can it reach IMDS? → AWS credentials → S3 access → data breach
    → Can it reach internal APIs? → admin actions → full compromise
    → Can it reach other services? → lateral movement → wider blast

  Found XSS?
    → Can it steal admin cookies? → admin takeover
    → Can it modify DOM to phish? → credential theft
    → Can it access sensitive JS APIs? → data exfiltration
    → Can it chain with CSRF? → action on behalf of victim

  Found IDOR?
    → How many records accessible? 1? 100? All?
    → What data? Public info? PII? Credentials?
    → Can you modify, or just read? Read + Write = higher severity
    → Can you delete? Availability impact = even higher

  DON'T EXPLOIT MAXIMALLY — DEMONSTRATE MAXIMALLY.
  Show you COULD access 1000 records by accessing 2-3.
  Show you COULD steal admin access by proving the cookie works.
  Calculate the theoretical maximum, prove the first step.
```

### 4.2 — Report Structure for Chains

```
CHAIN REPORT TEMPLATE:

TITLE: [Objective Achieved] via [Entry Point] → [Amplifier]
  Example: "Account Takeover via Stored XSS → Session Hijacking"

SEVERITY: [Based on final impact, not individual findings]

SUMMARY:
  One paragraph describing the full attack in plain language.
  "An attacker can achieve [OBJECTIVE] by first [STEP1], which enables
   [STEP2], ultimately resulting in [IMPACT]."

ATTACK FLOW:
  [Numbered steps with screenshots/requests]

IMPACT:
  - Who is affected: [all users / admins / specific role]
  - What is compromised: [data / access / availability]
  - Scale: [single user / mass exploitation possible]
  - Business impact: [financial loss / regulatory / reputation]

REMEDIATION:
  Fix each link in the chain — breaking any one link prevents the attack.
  Prioritize: [which fix is most impactful / easiest]
```

## Phase 5: Chain Validation

Before reporting, validate the entire chain end-to-end.

```
VALIDATION CHECKLIST:
  □ Each individual step works independently
  □ Steps connect — output of N feeds input of N+1
  □ The chain achieves a meaningful objective
  □ Evidence is captured for every step
  □ The chain is reproducible (not dependent on timing luck)
  □ Impact is clearly articulated
  □ Remediation addresses the root cause

THEN: Run /kambo-confidence on the complete chain.
  The chain is only as confident as its weakest link.
```

## Integration with Other Skills

| Flow | Integration |
|------|-------------|
| `/kambo-hunt` → multiple findings → `/kambo-chain` | Connect findings for higher impact |
| `/kambo-logic-hunt` → workflow vuln → `/kambo-chain` | Chain logic bugs with technical vulns |
| `/kambo-js-hunt` → hidden endpoints → `/kambo-chain` | Use discovered endpoints in chains |
| `/kambo-chain` → validated chain → `/kambo-confidence` | Validate the complete chain |
| `/kambo-chain` → chain report → `/kambo-report` | Generate chain-format bounty report |
| `/kambo-think-like-defense` → gaps → `/kambo-chain` | Chain attacks through defensive blind spots |
| `/kambo-waf-evade` → bypass → `/kambo-chain` | WAF bypass enables the chain's entry point |

## Anti-Patterns

- **Theoretical chains**: "if A then B then C" without proving each step. Every link must be demonstrated.
- **Overcomplicating**: a 2-step chain is better than a 7-step chain. Simpler = more believable = faster triage.
- **Chaining unrelated findings**: XSS on subdomain A + IDOR on subdomain B isn't a chain unless A enables B.
- **Ignoring individual reporting**: sometimes a HIGH finding alone is better than a forced chain. Don't devalue a good finding by wrapping it in a weak chain.
- **Maximum exploitation**: demonstrate the minimum needed to prove maximum impact. Access 3 records to prove you could access 3 million. Don't actually dump everything.
