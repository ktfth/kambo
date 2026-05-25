---
name: kambo-think-like-defense
description: Reverse-engineer the defender's mindset to find what they missed. Analyzes visible defenses (WAF, CSP, auth, error handling) to infer the blue team's mental model, then maps blind spots, assumption gaps, and lateral vectors the defense never considered. Use when evaluating attack surface, planning exploitation angles, stuck on a hardened target, or when standard tools return nothing — thinking like the defense reveals what they left unguarded.
triggers:
  - think like defense
  - defender perspective
  - blue team blind spots
  - what did they miss
  - lateral vectors
  - assumption gaps
  - defense analysis
  - hardened target
  - bypass defenses
---

# Kambo Think Like Defense — Adversarial Defense Modeling

You are the attacker. But right now, stop attacking.

Instead, become the person who built this system. The developer who wrote the auth.
The DevOps engineer who configured the WAF. The security team that ran the pentest
before launch. Understand what they saw, what they tested, what they prioritized —
because everything they prioritized is hardened, and everything they ignored is open.

**Core principle**: defenses reveal the defender's mental model. A WAF with strong
SQLi rules tells you they fear injection — but did they think about SSRF? A strict
CSP tells you they fear XSS — but did they think about CORS? Every defense is a
confession of what they imagined an attacker would do. Your job is to be the
attacker they didn't imagine.

## When to Use

- After recon, before committing to attack vectors
- When a target feels "hardened" and standard tools return nothing
- When WAF/CDN blocks your usual approach
- When you want to prioritize which vulns to hunt (attack what they forgot)
- When pivoting after initial approaches failed

## Phase 1: Defense Fingerprinting

Gather evidence of what the defense looks like. Run these in parallel:

```
recon_waf        → WAF vendor, rules, bypass indicators
recon_tech_stack  → frameworks, languages, infrastructure
scan_tls          → TLS config, certificate details, HSTS
scan_api_endpoints → API structure, versioning, auth patterns
```

Also observe manually from recon data already collected:

| Signal | Where to Look |
|--------|---------------|
| **Error handling** | Do errors leak stack traces, or are they generic? Generic = security-aware team |
| **HTTP headers** | CSP, X-Frame-Options, CORS, Permissions-Policy — each one is a clue |
| **Auth mechanism** | OAuth2/OIDC = modern team. Session cookies only = legacy mindset |
| **Rate limiting** | Present on login? On API? On all endpoints? Gaps reveal priorities |
| **Input validation** | Client-side only? Server-side? Schema-based? Regex? |
| **API versioning** | v1 still active alongside v3? Old versions = forgotten attack surface |
| **Cookie flags** | HttpOnly, Secure, SameSite — missing flags reveal what they didn't test |

## Phase 2: Defensive Mindset Reconstruction

Now think: **who built this, and what were they worried about?**

### 2.1 — Profile the Security Team

Based on the evidence from Phase 1, classify the defense:

| Profile | Signals | Implications |
|---------|---------|--------------|
| **Framework-default** | Standard headers, no custom WAF, generic error pages | They relied on framework security. Hunt framework-specific bypasses and misconfigurations |
| **Checklist-driven** | OWASP top 10 covered, standard pen-test findings fixed | They fixed what a scanner found. Hunt business logic, race conditions, IDOR — things scanners miss |
| **WAF-dependent** | Heavy WAF rules, less server-side validation | They outsourced security to the WAF. Hunt WAF bypasses and anything the WAF can't inspect (WebSockets, gRPC, binary protocols) |
| **Cloud-native** | IAM, managed services, infrastructure-as-code | They trust cloud provider defaults. Hunt misconfigured permissions, SSRF to metadata, overprivileged roles |
| **Compliance-driven** | TLS 1.2+, specific cipher suites, security headers match compliance frameworks | They optimized for audit checkboxes. Hunt real vulns that compliance doesn't cover: BOLA, mass assignment, TOCTOU |
| **Battle-scarred** | Custom rate limiting, bot detection, aggressive IP blocking | They've been attacked before and patched reactively. Hunt attack vectors unlike past incidents — they patched the door, check the windows |

### 2.2 — Map Their Threat Model

Answer these questions about the defense team:

```
WHAT THEY FEARED (visible defenses exist):
  → List every defense you detected and the threat it addresses

WHAT THEY TESTED (standard pen-test artifacts):
  → OWASP top 10 covered? Common CVEs patched? Default creds changed?

WHAT THEY AUTOMATED (CI/CD security signals):
  → Dependency scanning? SAST? DAST? Container scanning?

WHAT THEY MONITOR (observable detection capabilities):
  → Rate limiting = brute force monitoring
  → Bot detection = credential stuffing monitoring
  → WAF logs = injection monitoring
  → What ISN'T monitored?
```

### 2.3 — Identify Their Cognitive Biases

Every security team has them:

| Bias | How It Manifests | Your Advantage |
|------|-----------------|----------------|
| **Recency bias** | Over-invested in defenses against their last incident | Attack vectors from 2+ years ago may be unpatched |
| **Tool bias** | Trust scanner results as complete coverage | Scanners miss business logic, auth flow, and multi-step vulns |
| **Perimeter bias** | Strong external defenses, weak internal controls | Once past the edge (SSRF, CORS), internal services are soft |
| **API blindness** | Secured the web app, forgot the API | Mobile app API, internal API, legacy API endpoints |
| **Frontend fixation** | CSP, XSS protection, CSRF tokens — all client-side | Server-side vulns: SSRF, deserialization, file upload, race conditions |
| **Auth tunnel vision** | Login is hardened, but post-auth flows aren't | Password reset, email change, role escalation, token refresh |
| **Versioning neglect** | v3 is secure, v1 is still running | Old API versions, deprecated endpoints, legacy admin panels |

## Phase 3: Blind Spot Mapping

This is where the skill delivers value. Cross-reference what you found in Phase 2 against the full attack surface.

### 3.1 — The Negative Space

List what is NOT defended. This is your attack map:

```
FOR EACH category in [injection, auth, access_control, business_logic,
                       infrastructure, api_security, client_side, supply_chain]:

  IF visible_defense_exists(category):
    → LOW PRIORITY: they thought about this
    → Exception: if defense is poorly implemented, it's actually HIGH PRIORITY
      (false confidence = worse than no defense)

  IF no_visible_defense(category):
    → HIGH PRIORITY: this is your entry point
    → They either didn't think about it, or think it doesn't apply
    → Test whether their assumption is correct
```

### 3.2 — Assumption Gap Analysis

The most valuable findings come from challenging the builder's assumptions:

| Assumption | Reality Check | Tool |
|------------|--------------|------|
| "Our API is internal-only" | Is it accessible via SSRF? Via mobile app? Via CORS? | `vuln_ssrf`, `vuln_cors` |
| "Users can only access their own data" | Test horizontal privilege escalation, IDOR | `vuln_idor`, `api_test_bola` |
| "Admin panel is behind VPN" | Check for exposed admin paths, default creds | `scan_directories`, `exploit_auth_bypass` |
| "File uploads are validated" | Test MIME type bypass, polyglot files, path traversal | `scan_parameters` |
| "Rate limiting prevents brute force" | Test per-endpoint, per-IP vs per-user, reset flow | `exploit_password_spray` |
| "HTTPS means data is secure" | Test for CORS misconfiguration, mixed content, header leaks | `vuln_cors`, `scan_tls` |
| "We use a modern framework, so we're safe" | Test framework-specific CVEs, misconfiguration | `vuln_nuclei_scan` |
| "Our WAF blocks everything" | Test encoding bypasses, HTTP smuggling, protocol-level | `recon_waf` bypass techniques |

### 3.3 — Lateral Vector Generation

Think beyond the obvious. For each hardened surface, ask: **what's adjacent?**

```
HARDENED: Login page (rate limited, CAPTCHA, MFA)
LATERAL:  → Password reset flow (same validation?)
          → OAuth callback (token theft?)
          → Registration endpoint (account enumeration?)
          → Mobile API login (same protections?)
          → SSO integration (misconfigured trust?)

HARDENED: Main web application (WAF protected)
LATERAL:  → Subdomain services (same WAF?)
          → WebSocket endpoints (WAF can't inspect?)
          → GraphQL endpoint (different input parsing?)
          → File upload endpoint (binary = WAF blind?)
          → Health check / status endpoints (no auth?)

HARDENED: API v3 (auth, rate limiting, input validation)
LATERAL:  → API v1 (still accessible? same controls?)
          → Internal API (exposed via SSRF?)
          → Partner API (different auth model?)
          → Webhook receivers (validate sender?)
          → API documentation (exposes internal structure?)
```

## Phase 4: Prioritized Attack Plan

Synthesize everything into an ordered list of what to attack.

### 4.1 — Scoring

For each blind spot or lateral vector identified, score:

```
priority = (likelihood_undefended × potential_impact × exploitability)

WHERE:
  likelihood_undefended:
    3 = no visible defense, no indirect protection
    2 = partial defense or uncertain coverage
    1 = likely defended but worth checking

  potential_impact:
    3 = data breach, account takeover, RCE
    2 = information disclosure, privilege escalation
    1 = low-severity issue, informational

  exploitability:
    3 = known technique, tools available, easy to test
    2 = requires some research or custom approach
    1 = theoretical, complex exploitation chain
```

### 4.2 — Attack Order

Sort by priority score descending. Present as:

```
KAMBO DEFENSE MODEL REPORT
============================
Target: {target}
Defense Profile: {profile from 2.1}

WHAT THEY DEFENDED (skip these first):
  1. {defense} → protects against {threat}
  2. ...

WHAT THEY MISSED (attack these):
  #1 [Score: 27] {blind_spot}
     Why they missed it: {cognitive bias or assumption}
     Attack vector: {specific technique}
     Tools: {kambo tools to use}

  #2 [Score: 18] {blind_spot}
     ...

ASSUMPTION GAPS:
  - "{assumption}" → Test with: {tool + technique}
  - ...

LATERAL VECTORS:
  - {hardened_surface} → pivot to: {lateral_target}
  - ...

RECOMMENDED HUNT ORDER:
  1. {first_target} — highest ROI
  2. {second_target} — quick win
  3. {third_target} — deeper investigation
```

## Phase 5: Log and Learn

After executing the attack plan, log what the defense model predicted correctly
and where it was wrong:

```
FOR EACH prediction:
  IF blind_spot was real → log as validated insight
  IF blind_spot was actually defended → log as model error
    → WHY was the model wrong? Update bias mappings.
```

Use `report_finding` with source="defense-model" to tag findings discovered
through this approach. This feeds `/kambo-refine` with data on how well the
defense modeling performed.

## Integration with Other Skills

| Flow | Integration |
|------|-------------|
| `/kambo-hunt` → Phase 1 done → `/kambo-think-like-defense` | Use recon data to model defenses before attacking |
| `/kambo-think-like-defense` → attack plan → `/kambo-hunt` Phase 3 | Feed prioritized vectors back into the hunting pipeline |
| Finding discovered → `/kambo-confidence` | Validate findings from lateral vectors with extra care |
| `/kambo-kingrecon` | Cross-reference one-liners with identified blind spots |
| Post-hunt → `/kambo-refine` | Defense model accuracy feeds the improvement cycle |

## Anti-Patterns

- **Skipping Phase 2**: jumping straight to "what's missing" without understanding the defender's logic produces generic lists, not targeted insights.
- **Assuming no defense = easy win**: absence of visible defense doesn't mean absence of defense — it could mean you missed it. Verify.
- **Over-theorizing**: this skill informs where to look, not what you'll find. Spend 15-20 minutes on the model, then go test. Don't spend hours imagining scenarios.
- **Ignoring strong defenses**: sometimes the defense has a flaw in implementation. "They have a WAF" doesn't mean the WAF is configured correctly.
- **Tunnel vision on one blind spot**: map the full negative space before committing time to a single vector. The best entry point might not be the first one you notice.
