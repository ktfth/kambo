"""Vector playbooks — the concrete next experiment that advances a vector.

This is *knowledge*, not data: a static catalog mapping ``(attack vector,
stance) -> the next probe to run``. It is what turns the notes board's
``next_action`` from a generic stance label ("probe this vector") into a guided,
vector-specific step ("swap the object id to a neighbor, diff the response"),
making the path to viabilizing a vector explicit.

Keyed by the string values of ``AttackVector`` / ``VectorStance`` so this module
has **no import dependency** on ``notes.py`` (no cycle). Only the early/active
stances carry vector-specific guidance; ``confirmed`` / ``ruled_out`` fall back
to the generic hints in ``notes.py``.

Actions describe *non-destructive, proof-oriented* steps (benign canaries, OOB
callbacks, read-only confirmations) consistent with bug-bounty rules of
engagement — never destructive payloads.
"""

from __future__ import annotations

# vector value -> stance value -> concrete next experiment
PLAYBOOKS: dict[str, dict[str, str]] = {
    "idor": {
        "untested": "enumerate object ids (numeric ±1, UUIDs leaked in other responses); diff body/length/status across identities",
        "suspected": "replay the request with a second account's session against the first account's object id — confirm cross-tenant read",
        "probing": "escalate to a state-changing method (PUT/PATCH/DELETE) on another owner's object; capture before/after to prove impact",
    },
    "bola": {
        "untested": "call the object endpoint with a valid token but another user's object id; compare 200 vs 403",
        "suspected": "iterate ids across tenants via the API; confirm returned data belongs to a different principal",
        "probing": "chain to a write/delete method on the foreign object to maximize severity",
    },
    "access_control": {
        "untested": "force-browse privileged/admin routes (from JS, sitemap, guessing) with a low-priv session",
        "suspected": "replay a privileged action with the admin role/cookie stripped — does the server enforce authz or only hide UI?",
        "probing": "perform the privileged action end-to-end as low-priv and verify the side effect persisted",
    },
    "auth": {
        "untested": "map the flow (login, reset, MFA, session); test user enumeration and lockout strength",
        "suspected": "try session fixation, missing logout invalidation, or password-reset token reuse",
        "probing": "take over a test account via the weakness (reset poisoning / MFA bypass) and prove access",
    },
    "jwt": {
        "untested": "decode the token; inspect alg, exp, signature presence, and sensitive claims",
        "suspected": "try alg:none, HS/RS confusion (sign with the public key as HMAC secret), or crack a weak HMAC secret",
        "probing": "forge a token elevating a claim (role/sub) and use it against a protected resource",
    },
    "sqli": {
        "untested": "inject a single quote / arithmetic into each param; watch for errors, type juggling, boolean diffs",
        "suspected": "confirm with boolean (1 AND 1=1 vs 1=2) and time-based (SLEEP) payloads; rule out WAF echo",
        "probing": "extract a benign datum (version(), current_user) via UNION/blind to prove read access — no destructive payloads",
    },
    "xss": {
        "untested": "inject a unique canary into each sink (reflected, stored, DOM); grep response/DOM for it unencoded",
        "suspected": "break out of the context (attribute/script/HTML) with a minimal payload; confirm the parser executes it",
        "probing": "fire a harmless proof (alert/console with a unique token, or a controlled OOB beacon) in a real browser",
    },
    "ssrf": {
        "untested": "point any URL/host param at a collaborator/OOB host; watch for inbound DNS/HTTP",
        "suspected": "OOB fired — pivot to internal targets (169.254.169.254, localhost, internal ranges)",
        "probing": "read cloud metadata / an internal service response and exfil a benign internal datum to prove impact",
    },
    "ssti": {
        "untested": "inject ${7*7} / {{7*7}} / #{7*7} into each param; look for 49 in the response",
        "suspected": "fingerprint the engine with orthogonal payloads ({{7*'7'}} → 7777777 for Jinja2)",
        "probing": "escalate to a benign read (config/env var); avoid RCE payloads unless the program allows it",
    },
    "rce": {
        "untested": "find injection surfaces (command params, file processors, deserializers); inject a benign OOB ping",
        "suspected": "confirm execution via OOB callback (DNS/HTTP) with a unique token — no destructive commands",
        "probing": "prove with a read-only command (id / whoami / hostname) captured in output or OOB",
    },
    "lfi": {
        "untested": "traverse with ../ and encoded variants on file/path params; request a known file (/etc/passwd, web.config)",
        "suspected": "confirm file read; test wrappers (php://filter) and log-poisoning paths",
        "probing": "read a sensitive in-scope file (source/config) to prove disclosure; stop short of RCE unless allowed",
    },
    "xxe": {
        "untested": "submit XML with a benign external entity pointing at an OOB host; watch for callback",
        "suspected": "OOB fired — escalate to file read via parameter entities (OOB exfil)",
        "probing": "exfiltrate a benign local file over OOB to prove read; avoid internal port scans unless allowed",
    },
    "open_redirect": {
        "untested": "set redirect/return/next params to an external host; follow the 3xx Location",
        "suspected": "bypass naive filters (//evil, https:evil, @evil, whitelisted-prefix.evil)",
        "probing": "chain into a higher-impact flow (OAuth code/token theft, SSRF) to lift severity above informational",
    },
    "csrf": {
        "untested": "check state-changing requests for anti-CSRF tokens, SameSite cookies, and origin checks",
        "suspected": "replay the request without the token or from a foreign origin; see if it still succeeds",
        "probing": "build a minimal cross-origin PoC that performs the action as the victim",
    },
    "cors": {
        "untested": "send Origin: evil.example; inspect ACAO/ACAC reflection on authenticated endpoints",
        "suspected": "confirm reflected origin + credentials:true on a sensitive endpoint (not a public CDN/static asset)",
        "probing": "PoC reading the authenticated response cross-origin to prove data theft",
    },
    "business_logic": {
        "untested": "map the workflow/state machine; list invariants (price, quantity, ownership, sequence) that could break",
        "suspected": "replay steps out of order / skip a step / tamper a server-trusted value (price, role, status)",
        "probing": "complete the abuse end-to-end (negative quantity, coupon stacking) and quantify the loss",
    },
    "race": {
        "untested": "identify a state-changing endpoint with a check-then-act window (balance, coupon, vote)",
        "suspected": "fire N concurrent identical requests (single-packet / last-byte sync); watch for over-redemption",
        "probing": "demonstrate the doubled effect (double spend / multi-redeem) with before/after state",
    },
    "graphql": {
        "untested": "probe introspection (__schema); if open, dump types, queries, and mutations",
        "suspected": "test field-level authz, query batching, and aliased duplication for authz / rate-limit bypass",
        "probing": "exploit a sensitive query/mutation or a nested-query DoS PoC within scope",
    },
    "subdomain_takeover": {
        "untested": "resolve CNAMEs to dangling third-party hosts (S3, GitHub Pages, Heroku); match fingerprints",
        "suspected": "fingerprint matched — verify the backing resource is unclaimed and claimable",
        "probing": "claim it and serve a benign proof page on the subdomain to confirm takeover",
    },
    "secrets": {
        "untested": "grep JS bundles / source maps / responses for keys, tokens, and internal URLs",
        "suspected": "classify the candidate secret (provider, scope) without using it destructively",
        "probing": "validate it with a single read-only call (e.g. token introspection) to prove it is live",
    },
    "info_disclosure": {
        "untested": "check error pages, debug endpoints, headers, and .git/.env/backup files for leaks",
        "suspected": "assess the leaked data's sensitivity and whether it enables another vector",
        "probing": "show concrete impact (creds, PII, internal architecture) — tie it to an exploit path if possible",
    },
    "misconfig": {
        "untested": "check security headers, default creds, exposed admin panels, directory listing, verbose errors",
        "suspected": "verify the misconfig is exploitable, not cosmetic (e.g. actuator/console reachable and functional)",
        "probing": "demonstrate the concrete consequence (data access, action) rather than reporting the header alone",
    },
    "deserialization": {
        "untested": "spot serialized blobs (java / php / .net / pickle) in params or cookies; identify the format",
        "suspected": "send a benign OOB gadget (DNS callback) to confirm the sink deserializes attacker input",
        "probing": "prove with a read-only / OOB gadget chain; avoid RCE payloads unless the program permits",
    },
    "prototype_pollution": {
        "untested": "inject __proto__[x]=y via JSON / query / params; check if Object.prototype gains x",
        "suspected": "find a gadget that reads the polluted property (template engine, config merge)",
        "probing": "chain pollution + gadget into a concrete impact (XSS, auth bypass, DoS) PoC",
    },
}


def playbook_action(vector: str, stance: str) -> str | None:
    """The vector-specific next experiment for a ``(vector, stance)``, or
    ``None`` when no playbook covers it (caller falls back to the generic hint)."""
    return PLAYBOOKS.get(vector, {}).get(stance)
