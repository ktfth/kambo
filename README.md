# Kambo — Pentest & Bug Bounty MCP Server

> **[English](#english)** | **[Portugues](#portugues)**

---

<a id="english"></a>

## English

Kambo is an MCP (Model Context Protocol) server written in Python that orchestrates offensive security tools inside a Kali Linux Docker container. It enables AI assistants like Claude Code to conduct authorized penetration tests, bug bounty hunts, and API security assessments through a structured, methodology-driven interface.

### How It Works

```
Claude Code ←→ MCP (stdio) ←→ Kambo Server ←→ Docker API ←→ Kali Linux Container
                                     ↓
                              SQLite (findings, logs)
```

1. Claude Code connects to Kambo via the MCP stdio protocol.
2. Kambo validates each request against the configured engagement scope.
3. Commands execute inside a Kali Linux container that ships 30+ security tools pre-installed.
4. Results are parsed, stored in SQLite, and returned as structured JSON.

### Requirements

- Python 3.11+
- Docker Desktop (Windows/macOS) or Docker Engine (Linux)

### Installation

```bash
# 1. Clone the repository
git clone <repo-url> && cd kambo

# 2. Build the Kali container
docker compose build

# 3. Install the server (editable mode)
pip install -e .

# 4. (Optional) Start the container in advance
docker compose up -d
```

### Configuration with Claude Code

Add to your Claude Code MCP settings (`~/.claude/settings.json` or `.mcp.json`):

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

Or with explicit environment variables:

```json
{
  "mcpServers": {
    "kambo": {
      "command": "python",
      "args": ["-m", "kambo.server"],
      "env": {
        "KAMBO_CONTAINER_NAME": "kambo-kali",
        "KAMBO_OUTPUT_DIR": "./output",
        "KAMBO_WORDLISTS_DIR": "./wordlists",
        "KAMBO_DEFAULT_CONTEXT": "pentest"
      }
    }
  }
}
```

### Direct Usage (stdio)

```bash
kambo
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KAMBO_CONTAINER_NAME` | `kambo-kali` | Docker container name |
| `KAMBO_DOCKER_TIMEOUT` | `300` | Command execution timeout (seconds) |
| `KAMBO_OUTPUT_DIR` | `./output` | Directory for scan outputs and SQLite DB |
| `KAMBO_WORDLISTS_DIR` | `./wordlists` | Directory for wordlists |
| `KAMBO_DB_PATH` | `./output/kambo.db` | SQLite database path |
| `KAMBO_DEFAULT_CONTEXT` | `pentest` | Default engagement context (`pentest`, `bug_bounty`, `ctf`) |
| `KAMBO_RECON_RATE_LIMIT` | `10` | Recon requests per second |
| `KAMBO_EXPLOIT_RATE_LIMIT` | `5` | Exploit requests per second |
| `KAMBO_MAX_CONCURRENT_TOOLS` | `5` | Maximum parallel tool executions |

### Scope Management

Before running any tool, you **must** configure the engagement scope. Every tool validates targets against the scope — out-of-scope targets raise `ScopeViolationError`.

```
set_scope(
  targets: ["example.com", "*.example.com", "10.0.0.0/24"],
  context: "pentest",               # pentest | bug_bounty | ctf
  exclusions: ["prod.example.com"], # out-of-scope targets
  engagement_id: "ENG-2025-001",
  platform: "hackerone"             # for bug bounty
)
```

Scope supports:
- Exact domain matching (`example.com`)
- Wildcard subdomains (`*.example.com`)
- CIDR notation (`10.0.0.0/24`)
- URL extraction (validates domain from full URLs)
- Per-target and global exclusions

### Available Tools

#### Phase 1: Reconnaissance

| Tool | Description |
|------|-------------|
| `recon_subdomains` | Enumerate subdomains via crt.sh, subfinder, amass, dnsenum |
| `recon_dns` | DNS enumeration (zone transfer, records, brute force) |
| `recon_ports_fast` | Quick port discovery on common ports |
| `recon_tech_stack` | Technology fingerprinting (whatweb, httpx) |
| `recon_waf` | WAF/CDN detection (wafw00f) |
| `recon_certs` | Certificate Transparency log queries |
| `recon_asn` | ASN and IP block enumeration |

#### Phase 2: Scanning

| Tool | Description |
|------|-------------|
| `scan_ports_full` | Full TCP port scan (nmap) |
| `scan_services` | Service/version detection |
| `scan_directories` | Web directory fuzzing (ffuf) |
| `scan_api_endpoints` | API endpoint discovery (Swagger, fuzzing) |
| `scan_vulns` | Vulnerability scanning (Nuclei) |
| `scan_vhosts` | Virtual host discovery via Host header |
| `scan_parameters` | Hidden parameter discovery (Arjun) |
| `scan_tls` | SSL/TLS configuration analysis |

#### Phase 3: Vulnerability Analysis

| Tool | Description |
|------|-------------|
| `vuln_sqli` | SQL Injection detection (sqlmap) |
| `vuln_xss` | Cross-Site Scripting reflection detection |
| `vuln_ssrf` | Server-Side Request Forgery testing |
| `vuln_jwt` | JWT token weakness analysis |
| `vuln_cors` | CORS misconfiguration testing |
| `vuln_idor` | IDOR/BOLA testing via ID enumeration |
| `vuln_subdomain_takeover` | Subdomain takeover via dangling CNAME |

#### Phase 4: Exploitation

| Tool | Description |
|------|-------------|
| `exploit_sqli` | SQL Injection exploitation (extract data) |
| `exploit_password_spray` | Password spraying (SSH, SMB, FTP, RDP) |
| `exploit_ssrf` | SSRF exploitation for internal access |

#### Phase 5: Post-Exploitation

| Tool | Description |
|------|-------------|
| `post_privesc_linux` | Linux privilege escalation enumeration |
| `post_ad_enum` | Active Directory enumeration (BloodHound) |
| `post_kerberoast` | Kerberoasting — extract service ticket hashes |
| `post_lateral_move` | Lateral movement (PtH, WMI, PSExec) |

#### API Security (OWASP API Top 10)

| Tool | Description |
|------|-------------|
| `api_test_bola` | Broken Object Level Authorization (API1:2023) |
| `api_test_bfla` | Broken Function Level Authorization (API5:2023) |
| `api_test_misconfig` | Security Misconfiguration (API8:2023) |

#### Cloud Security

| Tool | Description |
|------|-------------|
| `cloud_imds_test` | SSRF to cloud metadata (AWS/Azure/GCP) |
| `cloud_storage_enum` | Public storage enumeration (S3/Blob/GCS) |
| `cloud_secret_scan` | Exposed secrets scanning |

#### Reporting

| Tool | Description |
|------|-------------|
| `report_finding` | Create and store a security finding |
| `report_cvss` | Calculate CVSS 3.1 score |
| `report_export` | Export report (Markdown or JSON) |
| `report_bounty_template` | Generate bug bounty submission template |

#### Utilities

| Tool | Description |
|------|-------------|
| `container_status` | Check Kali container health |
| `set_scope` | Configure engagement scope |

### MCP Resources

| URI | Description |
|-----|-------------|
| `scope://targets` | Current authorized targets and rules |
| `findings://current` | Vulnerabilities discovered in this session |
| `session://log` | Complete log of all actions |

### Workflow Prompts

Kambo includes pre-built workflow prompts that guide Claude through complete assessment methodologies:

#### `full_pentest` — PTES Complete

Follows the Penetration Testing Execution Standard across all 6 phases: Reconnaissance, Scanning, Vulnerability Analysis, Exploitation, Post-Exploitation, and Reporting.

```
Use prompt: full_pentest
  target: "example.com"
  engagement_id: "ENG-2025-001"
```

#### `bug_bounty_web` — Speed + Impact

Optimized for bug bounty programs. Focuses on high-payout vulnerabilities (P1/P2) first, then generates platform-ready submission reports.

```
Use prompt: bug_bounty_web
  target: "example.com"
  platform: "hackerone"
```

#### `api_assessment` — OWASP API Top 10

Structured API security assessment covering BOLA, BFLA, misconfigurations, and more.

```
Use prompt: api_assessment
  target: "https://api.example.com"
```

### Kali Container Tools

The Docker container is based on `kalilinux/kali-rolling` and includes:

**Network & Scanning:** nmap, masscan, ffuf, gobuster, dirb, nikto, nuclei
**Exploitation:** sqlmap, hydra, crackmapexec, impacket-scripts, responder
**Reconnaissance:** subfinder, amass, whatweb, wafw00f, dnsrecon, dnsenum, fierce, theharvester, httpx
**Crypto & Web:** testssl.sh, sslyze, wpscan, jwt_tool
**Post-Exploitation:** bloodhound, pwntools, evil-winrm
**Secrets:** trufflehog
**Wordlists:** SecLists, rockyou.txt

### Project Structure

```
kambo/
├── src/kambo/
│   ├── server.py          # MCP server entry point
│   ├── config.py          # Environment-based configuration
│   ├── models.py          # Domain models (Finding, ToolResult, Scope)
│   ├── scope.py           # Scope validation engine
│   ├── database.py        # SQLite persistence
│   ├── docker_runner.py   # Docker container integration
│   ├── tools/             # Tool implementations by phase
│   │   ├── recon.py       # Phase 1: Reconnaissance
│   │   ├── scanning.py    # Phase 2: Scanning
│   │   ├── vulns.py       # Phase 3: Vulnerability Analysis
│   │   ├── exploit.py     # Phase 4: Exploitation
│   │   ├── post_exploit.py# Phase 5: Post-Exploitation
│   │   ├── reporting.py   # Reporting & CVSS
│   │   ├── api_security.py# OWASP API Top 10
│   │   ├── cloud.py       # Cloud security
│   │   ├── containers.py  # Container management
│   │   └── ad.py          # Active Directory
│   ├── parsers/           # Output parsers (nmap, nuclei, ffuf, subfinder)
│   ├── prompts/           # Workflow prompt templates
│   └── resources/         # MCP resource handlers
├── kali/
│   ├── Dockerfile         # Kali Linux container definition
│   └── scripts/           # Container utility scripts
├── wordlists/             # Custom wordlists
├── output/                # Scan results and SQLite database
├── tests/                 # Test suite
├── docker-compose.yml     # Container orchestration
└── pyproject.toml         # Python project metadata
```

### Running Tests

```bash
pip install -e ".[dev]"
pytest
```

### Security Notice

This tool is intended **exclusively** for authorized security testing: penetration testing engagements with written authorization, bug bounty programs within their defined scope, CTF competitions, and educational/research purposes. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

### License

MIT

---

<a id="portugues"></a>

## Portugues

Kambo e um servidor MCP (Model Context Protocol) escrito em Python que orquestra ferramentas de seguranca ofensiva dentro de um container Docker com Kali Linux. Ele permite que assistentes de IA como o Claude Code conduzam testes de penetracao autorizados, bug bounty e avaliacoes de seguranca de APIs atraves de uma interface estruturada e orientada por metodologia.

### Como Funciona

```
Claude Code ←→ MCP (stdio) ←→ Kambo Server ←→ Docker API ←→ Container Kali Linux
                                     ↓
                              SQLite (findings, logs)
```

1. O Claude Code conecta-se ao Kambo via protocolo MCP stdio.
2. O Kambo valida cada requisicao contra o escopo de engajamento configurado.
3. Os comandos sao executados dentro de um container Kali Linux com 30+ ferramentas pre-instaladas.
4. Os resultados sao parseados, armazenados em SQLite e retornados como JSON estruturado.

### Requisitos

- Python 3.11+
- Docker Desktop (Windows/macOS) ou Docker Engine (Linux)

### Instalacao

```bash
# 1. Clone o repositorio
git clone <repo-url> && cd kambo

# 2. Build do container Kali
docker compose build

# 3. Instale o servidor (modo editavel)
pip install -e .

# 4. (Opcional) Inicie o container antecipadamente
docker compose up -d
```

### Configuracao com Claude Code

Adicione a configuracao MCP do Claude Code (`~/.claude/settings.json` ou `.mcp.json`):

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

Ou com variaveis de ambiente explicitas:

```json
{
  "mcpServers": {
    "kambo": {
      "command": "python",
      "args": ["-m", "kambo.server"],
      "env": {
        "KAMBO_CONTAINER_NAME": "kambo-kali",
        "KAMBO_OUTPUT_DIR": "./output",
        "KAMBO_WORDLISTS_DIR": "./wordlists",
        "KAMBO_DEFAULT_CONTEXT": "pentest"
      }
    }
  }
}
```

### Uso Direto (stdio)

```bash
kambo
```

### Variaveis de Ambiente

| Variavel | Padrao | Descricao |
|----------|--------|-----------|
| `KAMBO_CONTAINER_NAME` | `kambo-kali` | Nome do container Docker |
| `KAMBO_DOCKER_TIMEOUT` | `300` | Timeout de execucao de comandos (segundos) |
| `KAMBO_OUTPUT_DIR` | `./output` | Diretorio para saidas de scan e banco SQLite |
| `KAMBO_WORDLISTS_DIR` | `./wordlists` | Diretorio de wordlists |
| `KAMBO_DB_PATH` | `./output/kambo.db` | Caminho do banco SQLite |
| `KAMBO_DEFAULT_CONTEXT` | `pentest` | Contexto padrao (`pentest`, `bug_bounty`, `ctf`) |
| `KAMBO_RECON_RATE_LIMIT` | `10` | Requisicoes de recon por segundo |
| `KAMBO_EXPLOIT_RATE_LIMIT` | `5` | Requisicoes de exploit por segundo |
| `KAMBO_MAX_CONCURRENT_TOOLS` | `5` | Maximo de execucoes paralelas de ferramentas |

### Gerenciamento de Escopo

Antes de executar qualquer ferramenta, voce **deve** configurar o escopo do engajamento. Toda ferramenta valida os alvos contra o escopo — alvos fora do escopo geram `ScopeViolationError`.

```
set_scope(
  targets: ["example.com", "*.example.com", "10.0.0.0/24"],
  context: "pentest",               # pentest | bug_bounty | ctf
  exclusions: ["prod.example.com"], # alvos fora do escopo
  engagement_id: "ENG-2025-001",
  platform: "hackerone"             # para bug bounty
)
```

O escopo suporta:
- Match exato de dominio (`example.com`)
- Subdominio wildcard (`*.example.com`)
- Notacao CIDR (`10.0.0.0/24`)
- Extracao de URL (valida dominio de URLs completas)
- Exclusoes por alvo e globais

### Ferramentas Disponiveis

#### Fase 1: Reconhecimento

| Ferramenta | Descricao |
|------------|-----------|
| `recon_subdomains` | Enumeracao de subdominios via crt.sh, subfinder, amass, dnsenum |
| `recon_dns` | Enumeracao DNS (transferencia de zona, registros, forca bruta) |
| `recon_ports_fast` | Descoberta rapida de portas comuns |
| `recon_tech_stack` | Fingerprint de tecnologias (whatweb, httpx) |
| `recon_waf` | Deteccao de WAF/CDN (wafw00f) |
| `recon_certs` | Consulta de logs Certificate Transparency |
| `recon_asn` | Enumeracao de ASN e blocos IP |

#### Fase 2: Scanning

| Ferramenta | Descricao |
|------------|-----------|
| `scan_ports_full` | Port scan TCP completo (nmap) |
| `scan_services` | Deteccao de servicos/versoes |
| `scan_directories` | Fuzzing de diretorios web (ffuf) |
| `scan_api_endpoints` | Descoberta de endpoints API (Swagger, fuzzing) |
| `scan_vulns` | Scanner de vulnerabilidades (Nuclei) |
| `scan_vhosts` | Descoberta de virtual hosts via header Host |
| `scan_parameters` | Descoberta de parametros ocultos (Arjun) |
| `scan_tls` | Analise de configuracao SSL/TLS |

#### Fase 3: Analise de Vulnerabilidades

| Ferramenta | Descricao |
|------------|-----------|
| `vuln_sqli` | Deteccao de SQL Injection (sqlmap) |
| `vuln_xss` | Deteccao de Cross-Site Scripting |
| `vuln_ssrf` | Teste de Server-Side Request Forgery |
| `vuln_jwt` | Analise de fraquezas em tokens JWT |
| `vuln_cors` | Teste de misconfiguracao CORS |
| `vuln_idor` | Teste IDOR/BOLA via enumeracao de IDs |
| `vuln_subdomain_takeover` | Subdomain takeover via CNAME pendente |

#### Fase 4: Exploracao

| Ferramenta | Descricao |
|------------|-----------|
| `exploit_sqli` | Exploracao de SQL Injection (extracao de dados) |
| `exploit_password_spray` | Password spray (SSH, SMB, FTP, RDP) |
| `exploit_ssrf` | Exploracao SSRF para acesso interno |

#### Fase 5: Pos-Exploracao

| Ferramenta | Descricao |
|------------|-----------|
| `post_privesc_linux` | Enumeracao de escalacao de privilegios Linux |
| `post_ad_enum` | Enumeracao de Active Directory (BloodHound) |
| `post_kerberoast` | Kerberoasting — extracao de hashes de tickets |
| `post_lateral_move` | Movimentacao lateral (PtH, WMI, PSExec) |

#### Seguranca de API (OWASP API Top 10)

| Ferramenta | Descricao |
|------------|-----------|
| `api_test_bola` | Broken Object Level Authorization (API1:2023) |
| `api_test_bfla` | Broken Function Level Authorization (API5:2023) |
| `api_test_misconfig` | Security Misconfiguration (API8:2023) |

#### Seguranca Cloud

| Ferramenta | Descricao |
|------------|-----------|
| `cloud_imds_test` | SSRF para metadata cloud (AWS/Azure/GCP) |
| `cloud_storage_enum` | Enumeracao de storage publico (S3/Blob/GCS) |
| `cloud_secret_scan` | Scan de secrets expostos |

#### Relatorios

| Ferramenta | Descricao |
|------------|-----------|
| `report_finding` | Criar e armazenar um finding de seguranca |
| `report_cvss` | Calcular score CVSS 3.1 |
| `report_export` | Exportar relatorio (Markdown ou JSON) |
| `report_bounty_template` | Gerar template de submissao bug bounty |

#### Utilitarios

| Ferramenta | Descricao |
|------------|-----------|
| `container_status` | Verificar saude do container Kali |
| `set_scope` | Configurar escopo do engajamento |

### Recursos MCP

| URI | Descricao |
|-----|-----------|
| `scope://targets` | Alvos autorizados e regras atuais |
| `findings://current` | Vulnerabilidades descobertas nesta sessao |
| `session://log` | Log completo de todas as acoes |

### Prompts de Workflow

O Kambo inclui prompts de workflow pre-configurados que guiam o Claude atraves de metodologias completas de avaliacao:

#### `full_pentest` — PTES Completo

Segue o Penetration Testing Execution Standard em todas as 6 fases: Reconhecimento, Scanning, Analise de Vulnerabilidades, Exploracao, Pos-Exploracao e Relatorio.

```
Use prompt: full_pentest
  target: "example.com"
  engagement_id: "ENG-2025-001"
```

#### `bug_bounty_web` — Velocidade + Impacto

Otimizado para programas de bug bounty. Foca primeiro em vulnerabilidades de alto pagamento (P1/P2), depois gera relatorios prontos para submissao na plataforma.

```
Use prompt: bug_bounty_web
  target: "example.com"
  platform: "hackerone"
```

#### `api_assessment` — OWASP API Top 10

Avaliacao de seguranca de API estruturada cobrindo BOLA, BFLA, misconfiguracoes e mais.

```
Use prompt: api_assessment
  target: "https://api.example.com"
```

### Ferramentas do Container Kali

O container Docker e baseado em `kalilinux/kali-rolling` e inclui:

**Rede & Scanning:** nmap, masscan, ffuf, gobuster, dirb, nikto, nuclei
**Exploracao:** sqlmap, hydra, crackmapexec, impacket-scripts, responder
**Reconhecimento:** subfinder, amass, whatweb, wafw00f, dnsrecon, dnsenum, fierce, theharvester, httpx
**Crypto & Web:** testssl.sh, sslyze, wpscan, jwt_tool
**Pos-Exploracao:** bloodhound, pwntools, evil-winrm
**Secrets:** trufflehog
**Wordlists:** SecLists, rockyou.txt

### Estrutura do Projeto

```
kambo/
├── src/kambo/
│   ├── server.py          # Entry point do servidor MCP
│   ├── config.py          # Configuracao baseada em variaveis de ambiente
│   ├── models.py          # Modelos de dominio (Finding, ToolResult, Scope)
│   ├── scope.py           # Motor de validacao de escopo
│   ├── database.py        # Persistencia SQLite
│   ├── docker_runner.py   # Integracao com container Docker
│   ├── tools/             # Implementacao de ferramentas por fase
│   │   ├── recon.py       # Fase 1: Reconhecimento
│   │   ├── scanning.py    # Fase 2: Scanning
│   │   ├── vulns.py       # Fase 3: Analise de Vulnerabilidades
│   │   ├── exploit.py     # Fase 4: Exploracao
│   │   ├── post_exploit.py# Fase 5: Pos-Exploracao
│   │   ├── reporting.py   # Relatorios & CVSS
│   │   ├── api_security.py# OWASP API Top 10
│   │   ├── cloud.py       # Seguranca cloud
│   │   ├── containers.py  # Gerenciamento de containers
│   │   └── ad.py          # Active Directory
│   ├── parsers/           # Parsers de saida (nmap, nuclei, ffuf, subfinder)
│   ├── prompts/           # Templates de prompts de workflow
│   └── resources/         # Handlers de recursos MCP
├── kali/
│   ├── Dockerfile         # Definicao do container Kali Linux
│   └── scripts/           # Scripts utilitarios do container
├── wordlists/             # Wordlists customizadas
├── output/                # Resultados de scan e banco SQLite
├── tests/                 # Suite de testes
├── docker-compose.yml     # Orquestracao de containers
└── pyproject.toml         # Metadados do projeto Python
```

### Executando Testes

```bash
pip install -e ".[dev]"
pytest
```

### Aviso de Seguranca

Esta ferramenta e destinada **exclusivamente** para testes de seguranca autorizados: engajamentos de pentest com autorizacao por escrito, programas de bug bounty dentro do escopo definido, competicoes CTF e propositos educacionais/pesquisa. Acesso nao autorizado a sistemas computacionais e ilegal. Sempre obtenha autorizacao adequada antes de testar.

### Licenca

MIT
