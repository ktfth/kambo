# Dia 15 — Workflow: Bug Bounty do Zero ao Report

## LinkedIn

```
📋 Do alvo ao relatório em um workflow contínuo — como o Kambo organiza um bug bounty completo

Vou mostrar o fluxo completo de uma sessão real com o Kambo:

─────────────────────────────────
ETAPA 1: Configurar o escopo
─────────────────────────────────

set_scope(
  targets: ["example.com", "*.example.com"],
  context: "bug_bounty",
  platform: "hackerone",
  exclusions: ["staging.example.com"]
)

Tudo que sair desse escopo gera ScopeViolationError. Proteção total.

─────────────────────────────────
ETAPA 2: Reconhecimento
─────────────────────────────────

→ recon_subdomains encontra 47 subdomínios
→ recon_certs revela api-internal.example.com (não listado no programa)
→ recon_asn descobre 3 blocos IP da empresa
→ recon_waf detecta Cloudflare no domínio principal

─────────────────────────────────
ETAPA 3: Scanning inteligente
─────────────────────────────────

→ scan_vulns (Nuclei) encontra CVE-2024-XXXX no serviço de email
→ scan_api_endpoints descobre /api/v2/admin/users
→ scan_parameters encontra ?debug=true retornando stack traces

─────────────────────────────────
ETAPA 4: Análise de vulnerabilidades
─────────────────────────────────

→ vuln_idor confirma BOLA em /api/v2/users/{id} — troca de ID expõe dados
→ vuln_cors confirma misconfiguration com credentials
→ Evidence chain BOLA: 0.9 → CONFIRMED ✅

─────────────────────────────────
ETAPA 5: Relatório
─────────────────────────────────

→ report_cvss calcula CVSS 3.1: 8.1 HIGH
→ report_bounty_template gera template formatado para HackerOne
→ report_export salva Markdown + JSON

Total do workflow: menos de 2 horas para um relatório P2 completo.

🔗 github.com/ktfth/kambo

#BugBounty #PenetrationTesting #CyberSecurity #HackerOne #Bugcrowd #EthicalHacking #AI #ClaudeAI #MCP #OpenSource
```
