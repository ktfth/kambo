# Dia 04 — Arquitetura interna

## Twitter / X

```
Como o Kambo funciona por dentro? 🔬

Claude Code ←→ MCP stdio ←→ Kambo Server ←→ Docker API ←→ Kali Linux
                                    ↓
                             SQLite (findings + logs)

Cada tool call passa por:
1. Validação de escopo
2. Execução no container
3. Parse estruturado do output
4. Retorno como JSON

🔗 github.com/ktfth/kambo

#pentest #docker #python #MCP #infosec
```

---

## Thread técnico

```
🧵 1/ O Kambo tem 5 camadas:

→ server.py — entry point MCP
→ scope.py — validação de alvos (CIDR, wildcard, exact)
→ docker_runner.py — executa comandos no container Kali
→ parsers/ — converte saída bruta em JSON estruturado
→ database.py — persiste findings em SQLite
```

```
2/ Os parsers são a parte mais importante.

nmap XML → PortScanResult
nuclei output → VulnFinding
ffuf JSON → DirectoryResult
subfinder output → SubdomainList

Sem parse, você tem texto. Com parse, você tem inteligência.
```

```
3/ O modelo de confiança:

Cada finding acumula sinais ponderados.
Se a soma passar do threshold → CONFIRMED.
Múltiplos sinais convergentes → FIRM.
Sinal único → TENTATIVE.

Isso é o que separa sinal de ruído. 🎯

#kalilinux #cybersecurity #ethicalhacking #redteam
```
