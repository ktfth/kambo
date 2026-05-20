"""API Security Assessment workflow prompt — quantified with evidence-based decisions."""

API_ASSESSMENT_PROMPT = """You are conducting an API security assessment following OWASP API Security Top 10 (2023).

## Scope
Target API: {target}
Context: {context}

## Methodology — Evidence-Driven

### Phase 1: Discovery (15 min)
1. `scan_api_endpoints` — find Swagger/OpenAPI specs, enumerate endpoints
   - **IF swagger specs found**: download and analyze for hidden endpoints
   - Note `total_endpoints` for coverage tracking
2. `recon_tech_stack` — identify API framework and version
3. Document all endpoints, methods, and authentication mechanisms

**Checkpoint**: How many endpoints discovered? This is your denominator for coverage.

### Phase 2: Authentication Testing (API2)
1. `api_test_auth` — check for unauthenticated access
   - Check `evidence.signals` — 200 with error body is NOT a finding
   - Multiple endpoints tested, not just /api/users
2. `vuln_jwt` — analyze JWT tokens
   - **IF weak_secret cracked (confidence=CONFIRMED)**: this is P1, report immediately
   - **IF none algorithm accepted**: token forgery possible
3. Test token lifecycle (expiry, logout invalidation, refresh)

### Phase 3: Authorization Testing (API1, API3, API5)
Each tool captures baseline responses for comparison. Trust the evidence chain.

1. `api_test_bola` — horizontal privilege escalation
   - Requires TWO valid tokens (user_a and user_b)
   - **Check evidence**: identical responses = false positive (generic page)
   - **Real BOLA**: different user data returned with wrong token
2. `api_test_bfla` — vertical privilege escalation
   - Gets unauthenticated baseline first
   - **Check evidence**: "soft denial" (200 with error body) is NOT vulnerable
   - **Real BFLA**: admin data indicators in response (users, settings, logs)
3. `api_test_bopla` — mass assignment
   - **Real mass assignment**: injected field value reflected in response
   - Field present but value ignored = NOT vulnerable

### Phase 4: Input & Business Logic (API4, API6)
1. `vuln_sqli` — SQL/NoSQL injection
   - **IF confidence=CONFIRMED**: use `exploit_sqli` action=dbs for proof
2. `api_test_resource` — rate limiting
   - No 429 after 20 requests = no rate limiting (medium finding)
   - **IF rate limited + bypass works**: escalate to high
3. `scan_parameters` — discover hidden parameters
4. Test business logic flaws (race conditions, flow bypass)

### Phase 5: Configuration (API7, API8, API9, API10)
1. `api_test_misconfig` — checks CORS, headers, error handling, methods
   - CORS: only report if `credentials_allowed` in evidence
   - Missing headers: LOW severity (informational)
   - Verbose errors: MEDIUM severity
2. `vuln_ssrf` — SSRF via URL parameters
   - Check evidence for actual content retrieval, not just status codes
3. Check for deprecated API versions (API9)
4. Test third-party API consumption safety (API10)

**Checkpoint**: Run `report_metrics` — review confidence distribution.

### Phase 6: Report
1. Run `report_metrics` — final quality check
2. `report_finding` for each vulnerability with `confidence` field
3. `report_cvss` to calculate severity
4. `report_export` with template=api_assessment, min_confidence=firm
5. `report_confirm_finding` to mark verified findings

## OWASP API Top 10 Coverage Tracker

After testing, update this checklist with findings:

| # | Vulnerability | Tool | Status | Confidence |
|---|--------------|------|--------|------------|
| API1 | BOLA | api_test_bola | [ ] Tested | |
| API2 | Broken Auth | api_test_auth, vuln_jwt | [ ] Tested | |
| API3 | BOPLA | api_test_bopla | [ ] Tested | |
| API4 | Resource Consumption | api_test_resource | [ ] Tested | |
| API5 | BFLA | api_test_bfla | [ ] Tested | |
| API6 | Business Flows | manual | [ ] Tested | |
| API7 | SSRF | vuln_ssrf | [ ] Tested | |
| API8 | Misconfiguration | api_test_misconfig | [ ] Tested | |
| API9 | Inventory | manual | [ ] Tested | |
| API10 | Unsafe Consumption | manual | [ ] Tested | |

**Coverage target**: 10/10 categories tested. Report untested categories as "Not Assessed".
"""


def get_api_assessment_prompt(target: str, context: str = "pentest") -> str:
    return API_ASSESSMENT_PROMPT.format(target=target, context=context)
