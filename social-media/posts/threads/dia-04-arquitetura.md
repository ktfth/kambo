# Dia 04 — Arquitetura do Kambo

```
🏗️ Arquitetura do Kambo por dentro:

Claude Code ←→ MCP ←→ Kambo Server ←→ Docker Kali

• Python 3.14 + async/await
• Pydantic models com frozen=True
• SQLite para métricas por ferramenta
• 200+ testes passando

Todos os comandos rodam isolados no container.
Nenhuma ferramenta opera fora do escopo configurado.

🔗 github.com/ktfth/kambo

#python #docker #security #opensource
```
