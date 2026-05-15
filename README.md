# Kambo — Pentest & Bug Bounty MCP Server

MCP Server em Python que orquestra ferramentas de segurança ofensiva dentro de um container Kali Linux. Compatível com Windows, macOS e Linux via Docker.

## Requisitos

- Python 3.11+
- Docker Desktop (Windows/macOS) ou Docker Engine (Linux)

## Setup

```bash
# 1. Build o container Kali
docker compose build

# 2. Instale o servidor
pip install -e .

# 3. (Opcional) Inicie o container
docker compose up -d
```

## Uso com Claude Code

Adicione ao `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "kambo": {
      "command": "kambo",
      "args": []
    }
  }
}
```

## Uso Direto (stdio)

```bash
kambo
```

## Ferramentas Disponíveis

### Scope Management
- `set_scope` — Configurar escopo do engagement

### Phase 1: Reconnaissance
- `recon_subdomains` — Enumeração de subdomínios
- `recon_dns` — Enumeração DNS (AXFR, brute, records)
- `recon_ports_fast` — Discovery rápido de portas
- `recon_tech_stack` — Fingerprint de tecnologias
- `recon_waf` — Detecção de WAF/CDN
- `recon_certs` — Certificate Transparency
- `recon_asn` — ASN e blocos IP

### Phase 2: Scanning
- `scan_ports_full` — Port scan completo (nmap)
- `scan_services` — Detecção de serviços/versões
- `scan_directories` — Fuzzing de diretórios web
- `scan_api_endpoints` — Descoberta de endpoints API
- `scan_vulns` — Scanner Nuclei
- `scan_vhosts` — Virtual host discovery
- `scan_parameters` — Parâmetros ocultos (Arjun)
- `scan_tls` — Análise SSL/TLS

### Phase 3: Vulnerability Analysis
- `vuln_sqli` — SQL Injection
- `vuln_xss` — Cross-Site Scripting
- `vuln_ssrf` — Server-Side Request Forgery
- `vuln_jwt` — JWT weaknesses
- `vuln_cors` — CORS misconfiguration
- `vuln_idor` — IDOR/BOLA testing
- `vuln_subdomain_takeover` — Subdomain takeover

### Phase 4: Exploitation
- `exploit_sqli` — SQLi exploitation
- `exploit_password_spray` — Password spray
- `exploit_ssrf` — SSRF to internal

### Phase 5: Post-Exploitation
- `post_privesc_linux` — Linux privesc enum
- `post_ad_enum` — AD enumeration
- `post_kerberoast` — Kerberoasting
- `post_lateral_move` — Lateral movement

### API Security (OWASP Top 10)
- `api_test_bola` — Broken Object Level Authorization
- `api_test_bfla` — Broken Function Level Authorization
- `api_test_misconfig` — Security Misconfiguration

### Cloud Security
- `cloud_imds_test` — SSRF to cloud metadata
- `cloud_storage_enum` — Public storage enum
- `cloud_secret_scan` — Exposed secrets

### Reporting
- `report_finding` — Criar finding
- `report_cvss` — Calcular CVSS 3.1
- `report_export` — Exportar relatório
- `report_bounty_template` — Template bug bounty

## Workflows (Prompts)

- `full_pentest` — PTES completo (Fases 1-6)
- `bug_bounty_web` — Bug bounty otimizado
- `api_assessment` — OWASP API Top 10

## Testes

```bash
pip install -e ".[dev]"
pytest
```
