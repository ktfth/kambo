# Dia 05 — Instalação em 4 comandos

## Twitter / X

```
Instalar o Kambo leva menos de 5 minutos:

git clone github.com/ktfth/kambo
docker compose build
pip install -e .
# adicione ao .mcp.json e abra o Claude Code

Pronto. Você tem um pentester IA com Kali Linux à disposição. 🐸

🔗 github.com/ktfth/kambo

#bugbounty #kalilinux #docker #claudeai #cybersecurity
```

---

## Thread de instalação detalhada

```
🧵 Guia completo de instalação do Kambo:

Requisitos:
• Python 3.11+
• Docker (Desktop ou Engine)
• Claude Code instalado
```

```
1/ Clone e build do container Kali:

git clone https://github.com/ktfth/kambo
cd kambo
docker compose build

(O build inclui nmap, nuclei, sqlmap, subfinder e mais 25 ferramentas)
```

```
2/ Instale o servidor:

pip install -e .

3/ Configure o Claude Code (.mcp.json):

{
  "mcpServers": {
    "kambo": { "command": "kambo" }
  }
}
```

```
4/ Primeira sessão:

"configure o escopo para example.com no contexto bug_bounty"

E deixa o Claude trabalhar. 🚀

#pentest #ethicalhacking #infosec #opensource #python
```
