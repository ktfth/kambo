---
name: kambo-js-hunt
description: Extract and analyze JavaScript bundles for hardcoded secrets, API endpoints, internal routes, source maps, and hidden functionality. One of the highest-ROI activities in modern bug bounty — JS files leak what the server hides. Use when hunting on any web target, after recon, when looking for quick wins, or when the user says "check the JS", "find secrets in JS", "JS analysis", "client-side secrets", "source maps", "hidden endpoints".
triggers:
  - js hunt
  - javascript analysis
  - client-side secrets
  - source maps
  - hidden endpoints
  - js secrets
  - check the JS
  - extract endpoints from JS
---

# Kambo JS Hunt — Client-Side Intelligence Extraction

JavaScript files are the most underrated attack surface in bug bounty.

Developers bundle their entire application logic into JS files served to every visitor.
These files contain API endpoints the UI never calls, admin routes behind feature flags,
hardcoded tokens for staging environments, internal service URLs, and debug comments
that reveal architecture. The server hides nothing that the client already knows.

## When to Use

- After recon identifies a web target (especially SPAs: React, Angular, Vue, Next.js)
- When standard scanning returns little (the interesting stuff is in the JS)
- When looking for quick wins before deep vulnerability analysis
- When a target uses a CDN/WAF that blocks active scanning (JS analysis is passive)
- After `recon_tech_stack` identifies a JavaScript framework

## Phase 1: JS File Discovery

Gather all JavaScript files from the target. Run in parallel:

```
scan_directories    → use wordlist focused on JS paths:
                      /static/js/, /assets/js/, /build/, /dist/,
                      /bundle.js, /app.js, /main.js, /vendor.js,
                      /chunk-*.js, /runtime.js, /_next/static/

scan_api_endpoints  → discover API docs that reference JS SDK files

recon_tech_stack    → identify framework (React=webpack bundles,
                      Next.js=_next/static, Vue=dist/js, Angular=main.js)
```

### 1.1 — Source Map Detection

Source maps (`.js.map`) are the holy grail — they contain the original source code:

```
FOR EACH js_file discovered:
  Check: {js_file}.map
  Check: sourceMappingURL comment inside the JS file
  Check: X-SourceMap HTTP header in response

  IF source_map_found:
    → This is a CRITICAL finding by itself (information disclosure)
    → Log with report_finding(severity="high", title="Source Map Exposed")
    → The source map contains the ENTIRE original codebase
    → Extract and analyze the original source for all subsequent phases
```

### 1.2 — JS File Inventory

Build an inventory of all JS files found:

```
CLASSIFY each file:
  - vendor/library (React, lodash, etc.) → SKIP analysis
  - application code (app.js, main.js, custom chunks) → ANALYZE
  - webpack runtime → CHECK for environment variables
  - service worker → CHECK for cached API routes and auth tokens
```

## Phase 2: Secret Extraction

Search every application JS file for hardcoded secrets.

### 2.1 — High-Value Patterns

These patterns frequently yield valid credentials:

| Pattern | Regex | Severity |
|---------|-------|----------|
| AWS Keys | `AKIA[0-9A-Z]{16}` | CRITICAL |
| API Keys (generic) | `['"](api[_-]?key|apikey|api[_-]?secret)['"]\\s*[:=]\\s*['"][a-zA-Z0-9_\\-]{16,}['"]` | HIGH |
| JWT Tokens | `eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*` | HIGH |
| Private Keys | `-----BEGIN (RSA\|EC\|DSA\|OPENSSH) PRIV KEY-----` | CRITICAL |
| OAuth Secrets | `client[_-]?secret['"]\\s*[:=]\\s*['"][a-zA-Z0-9_\\-]{16,}['"]` | HIGH |
| Firebase Config | `apiKey.*\\.firebaseio\\.com` | MEDIUM |
| Stripe Keys | `(sk|pk)_(test|live)_[a-zA-Z0-9]{24,}` | HIGH (sk=CRITICAL) |
| Google API Keys | `AIza[0-9A-Za-z_-]{35}` | MEDIUM |
| Slack Tokens | `xox[bpras]-[a-zA-Z0-9-]+` | HIGH |
| GitHub Tokens | `gh[ps]_[a-zA-Z0-9]{36}` | HIGH |
| SendGrid | `SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}` | HIGH |
| Twilio | `SK[a-f0-9]{32}` | HIGH |

### 2.2 — Environment Variable Leaks

Webpack/Vite/Next.js bundle `process.env` or `import.meta.env` values:

```
Search for:
  process.env.REACT_APP_*
  process.env.NEXT_PUBLIC_*
  import.meta.env.VITE_*
  __NEXT_DATA__
  window.__ENV__
  window.__CONFIG__
  globalThis.*_API_KEY

These often contain:
  - API base URLs (internal services!)
  - Feature flag endpoints
  - Analytics keys (can be abused for data injection)
  - Sentry DSN (reveals internal project structure)
  - Debug mode flags
```

### 2.3 — Validation

Not every string that looks like a key IS a key. Validate:

```
FOR EACH potential_secret:
  1. Is it a placeholder? ("YOUR_API_KEY_HERE", "xxx", "test123") → SKIP
  2. Is it a public key? (Stripe pk_*, Firebase apiKey) → LOW severity
  3. Is it a private/secret key? → HIGH/CRITICAL
  4. Can you verify it? Try:
     - cloud_secret_scan with the target URL
     - Manual curl with the key against the expected API
  5. Is it expired/revoked? Old bundles may have rotated keys

  IF verified_active:
    → report_finding with evidence of active key
    → bounty_estimate_value (exposed credentials = HIGH payout)
```

## Phase 3: Endpoint Extraction

JS files contain the complete API surface — including endpoints the UI doesn't expose.

### 3.1 — URL Pattern Extraction

```
Search for:
  Absolute URLs:    https?://[a-zA-Z0-9._-]+/[a-zA-Z0-9/_-]+
  Relative paths:   ['"](/api/[a-zA-Z0-9/_-]+)['"]
  Template literals: `/api/${...}/...`
  Fetch/axios calls: fetch(*, axios.get(*, axios.post(*
  GraphQL endpoints: /graphql, /gql, /query

CLASSIFY found endpoints:
  PUBLIC:    matches known UI-accessible routes → lower priority
  HIDDEN:    not referenced in visible UI → HIGH priority
  INTERNAL:  points to internal domains/IPs → CRITICAL
  ADMIN:     contains /admin/, /manage/, /dashboard/ → HIGH
  DEBUG:     contains /debug/, /test/, /dev/ → HIGH
  DEPRECATED: v1/v2 when current is v3+ → MEDIUM
```

### 3.2 — Hidden Functionality Discovery

Look for code paths behind feature flags or conditional logic:

```
Search for:
  if (featureFlag.*) { ... }
  if (isAdmin) { ... }
  if (isDev || isStaging) { ... }
  if (process.env.NODE_ENV !== 'production') { ... }
  enableDebugMode, debugPanel, adminOverride

  These reveal:
  - Admin-only endpoints that exist but aren't linked in the UI
  - Debug endpoints that should be disabled in production
  - Feature-flagged functionality that might bypass auth checks
  - Staging/dev URLs that might still be accessible
```

### 3.3 — Route Mapping

For SPA frameworks, extract the full route table:

```
React Router:   <Route path="..." component={...} />
                Routes array with path/element
Vue Router:     routes: [{ path: '...', component: ... }]
Angular:        { path: '...', component: ... }
Next.js:        pages/ directory structure in source maps

BUILD a complete route map:
  /public/route → accessible without auth
  /admin/route → should require auth (test if it does!)
  /api/internal/route → should not be directly accessible
  /debug/route → should not exist in production
```

## Phase 4: Architecture Intelligence

The JS code reveals how the application works internally.

### 4.1 — Auth Flow Analysis

```
Search for:
  Authorization header construction
  Token storage (localStorage, sessionStorage, cookies)
  Token refresh logic (reveals refresh endpoint)
  Role checking logic (reveals role structure)
  Permission checks (reveals permission model)

  This feeds directly into:
  - vuln_jwt (if JWT is used)
  - api_test_bola (if role-based access)
  - api_test_bfla (if function-level auth)
  - exploit_auth_bypass (if auth logic is client-side)
```

### 4.2 — Error Handling Leaks

```
Search for:
  catch blocks with error.message exposure
  console.log/console.error in production code
  Sentry/Bugsnag/Rollbar configuration
  Custom error pages with stack traces
  Error response parsing (reveals server error format)
```

### 4.3 — Third-Party Service Discovery

```
Search for:
  SDK initializations (Stripe, Firebase, Algolia, Auth0, etc.)
  API base URLs for backend services
  WebSocket connection URLs
  CDN origins
  Microservice endpoints

  Each third-party integration is a potential lateral vector
  for /kambo-think-like-defense
```

## Phase 5: Synthesis & Reporting

### 5.1 — Findings Classification

```
KAMBO JS HUNT REPORT
======================
Target: {target}
JS Files Analyzed: {count}
Source Maps Found: {count}

CRITICAL FINDINGS:
  [C1] Exposed Source Map at {url}
  [C2] Active AWS Key: AKIA... at {file}:{line}

HIGH FINDINGS:
  [H1] Hidden Admin API: /api/admin/users (no auth check in JS)
  [H2] Internal Service URL: https://internal.example.com/api/...
  [H3] Debug endpoint active: /api/debug/config

ENDPOINTS DISCOVERED:
  Total: {count} | Hidden: {count} | Internal: {count}
  
  New endpoints for vuln testing:
    POST /api/v1/admin/bulk-delete  → test BFLA
    GET  /api/internal/user/{id}    → test BOLA/IDOR
    PUT  /api/debug/config          → test auth bypass

SECRETS FOUND:
  Verified active: {count}
  Likely expired: {count}
  Public keys (low risk): {count}

ARCHITECTURE INTEL:
  Auth: {JWT|session|OAuth} via {mechanism}
  Roles: {list of roles discovered}
  Services: {list of backend services found}
```

### 5.2 — Feed Into Pipeline

```
FOR EACH hidden_endpoint:
  → pipeline_ingest as discovered asset
  → queue for vuln_idor, api_test_bola, api_test_bfla

FOR EACH active_secret:
  → report_finding immediately
  → bounty_estimate_value

FOR EACH internal_url:
  → queue for vuln_ssrf testing
  → feed into /kambo-think-like-defense as assumption gap
```

## Integration with Other Skills

| Flow | Integration |
|------|-------------|
| `/kambo-hunt` Phase 2 → `/kambo-js-hunt` | Run JS analysis during scanning phase |
| `/kambo-js-hunt` → `/kambo-hunt` Phase 3 | Feed discovered endpoints into vuln analysis |
| `/kambo-js-hunt` → `/kambo-think-like-defense` | Architecture intel reveals defensive assumptions |
| `/kambo-js-hunt` → `/kambo-chain` | Auth flow analysis enables multi-step exploits |
| `/kambo-js-hunt` → `/kambo-confidence` | Validate secrets before reporting |

## Anti-Patterns

- **Ignoring vendor files**: don't analyze React/jQuery/lodash — focus on application code only.
- **Reporting public keys as critical**: Stripe `pk_*` and Firebase `apiKey` are designed to be public. Check if it's actually a secret.
- **Not verifying secrets**: a hex string in a JS file might be a CSS color, a hash, or junk. Verify before reporting.
- **Skipping source maps**: if `.map` files exist, they override everything — analyze the original source, not the minified bundle.
- **One-and-done**: JS files change with every deployment. Re-run JS hunt periodically or after `recon_diff` detects changes.

## Persist Learnings

After completing this workflow, persist insights for future sessions:

1. Save operational patterns discovered during this session
2. Record which techniques/tools produced the best results
3. Note target-specific behaviors that affected outcomes
4. Feed findings into the calibration pipeline via `/kambo-calibrate`

Learnings are stored at `~/.kambo/learnings.jsonl` and loaded automatically in future sessions.
