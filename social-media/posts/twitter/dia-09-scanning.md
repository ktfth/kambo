# Dia 09 — Fase 2: Scanning

## Twitter / X

```
Fase 2 do Kambo: Scanning 🔬

scan_ports_full    → nmap TCP completo
scan_services      → detecção de versões
scan_directories   → ffuf (fuzzing de diretórios)
scan_api_endpoints → Swagger + fuzzing de APIs
scan_vulns         → Nuclei (templates CISA KEV)
scan_vhosts        → virtual hosts via Host header
scan_parameters    → Arjun (parâmetros ocultos)
scan_tls           → testssl.sh

Da superfície à vulnerabilidade. 🎯

#bugbounty #nuclei #nmap #ffuf #cybersecurity
```

---

## Thread

```
🧵 Por que o Nuclei é a ferramenta mais valiosa do scanning?

Mais de 9.000 templates CVE + misconfigs + exposures.
O Kambo roda com os templates CISA KEV (Known Exploited Vulnerabilities) primeiro — máximo impacto.
```

```
scan_parameters com Arjun é ouro para bug bounty.

Parâmetros ocultos = superfície de ataque extra.
Encontrar `?debug=true` ou `?admin=1` antes de todo mundo é a diferença entre P1 e duplicata.
```

```
scan_vhosts via Host header manipulation:

→ Descobre apps internas atrás do mesmo IP
→ Revela ambientes de staging
→ Encontra APIs sem autenticação

Muitos hunters pulam essa etapa. Não seja um deles. 👀

#pentest #scanning #infosec #ethicalhacking #redteam
```
