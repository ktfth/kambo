"""API Security Assessment workflow prompt."""

API_ASSESSMENT_PROMPT = """You are conducting an API security assessment following OWASP API Security Top 10 (2023).

## Scope
Target API: {target}
Context: {context}

## Methodology

### Phase 1: Discovery (15 min)
1. `scan_api_endpoints` — find Swagger/OpenAPI specs, enumerate endpoints
2. `recon_tech_stack` — identify API framework and version
3. Document all endpoints, methods, and authentication mechanisms

### Phase 2: Authentication Testing (API2)
1. `api_test_auth` — check for unauthenticated access
2. `vuln_jwt` — analyze JWT tokens (weak secrets, algorithm confusion)
3. Test token lifecycle (expiry, logout invalidation, refresh)

### Phase 3: Authorization Testing (API1, API3, API5)
1. `api_test_bola` — horizontal privilege escalation (user A → user B data)
2. `api_test_bfla` — vertical privilege escalation (user → admin functions)
3. `api_test_bopla` — mass assignment (inject role/admin/balance fields)

### Phase 4: Input & Business Logic (API4, API6)
1. `vuln_sqli` — SQL/NoSQL injection in API parameters
2. `api_test_resource` — rate limiting and resource exhaustion
3. `scan_parameters` — discover hidden parameters
4. Test business logic flaws (race conditions, flow bypass)

### Phase 5: Configuration (API7, API8, API9, API10)
1. `api_test_misconfig` — CORS, headers, error handling, methods
2. `vuln_ssrf` — SSRF via URL parameters (API7)
3. Check for deprecated API versions (API9)
4. Test third-party API consumption safety (API10)

### Phase 6: Report
1. `report_finding` for each vulnerability found
2. `report_cvss` to calculate severity
3. `report_export` with api_assessment template

## OWASP API Top 10 Checklist
- [ ] API1: BOLA — Can user access other users' objects?
- [ ] API2: Broken Auth — Can endpoints be accessed without auth?
- [ ] API3: BOPLA — Can hidden properties be modified?
- [ ] API4: Resource — Is rate limiting enforced?
- [ ] API5: BFLA — Can regular user access admin functions?
- [ ] API6: Business Flows — Can automated abuse occur?
- [ ] API7: SSRF — Do URL parameters allow internal access?
- [ ] API8: Misconfiguration — Are security headers present?
- [ ] API9: Inventory — Are old API versions exposed?
- [ ] API10: Unsafe Consumption — Are third-party APIs trusted blindly?
"""


def get_api_assessment_prompt(target: str, context: str = "pentest") -> str:
    return API_ASSESSMENT_PROMPT.format(target=target, context=context)
