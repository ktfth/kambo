# Dia 16 — Scope Management

## Twitter / X

```
A regra de ouro do bug bounty: nunca saia do escopo.

O Kambo torna isso impossível de violar acidentalmente.

set_scope(
  targets: ["*.example.com"],
  exclusions: ["prod.example.com"]
)

Qualquer tool call fora desse escopo → ScopeViolationError imediato.

Proteção automática. Auditoria completa. 🛡️

🔗 github.com/ktfth/kambo

#bugbounty #cybersecurity #ethicalhacking #infosec
```

---

## Thread

```
🧵 O scope engine do Kambo suporta:

✅ Domínio exato: "example.com"
✅ Wildcard: "*.example.com"  
✅ CIDR: "10.0.0.0/24"
✅ URL completa (extrai e valida o domínio)
✅ Exclusões por alvo e globais
```

```
Por que isso é crítico?

Em 2024, vários hunters foram banidos de plataformas por testar fora do escopo "por acidente".

Com o Kambo, o Claude simplesmente não consegue executar ferramentas em targets não autorizados. O erro acontece antes do comando.
```

```
Bonus: o log de auditoria em SQLite registra:
• Cada ferramenta executada
• O target testado
• O timestamp
• O resultado

Se alguém questionar o que você fez: você tem evidência de compliance total.

#pentest #bugbounty #hackerone #bugcrowd #redteam
```
