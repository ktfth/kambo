# Dia 17 — CVSS Score Automático

## Twitter / X

```
report_cvss() — calcula CVSS 3.1 automaticamente.

Você passa:
• Attack Vector (Network/Adjacent/Local/Physical)
• Complexity (Low/High)
• Privileges Required
• User Interaction
• Scope, CIA impact

O Kambo retorna:
• Score numérico (0.0 - 10.0)
• Severidade (Critical/High/Medium/Low)
• Vector string completa

Sem planilhas. Sem calculadora online. ✅

🔗 github.com/ktfth/kambo

#bugbounty #cvss #cybersecurity #infosec
```

---

## Thread

```
🧵 Por que o CVSS score importa tanto?

HackerOne e Bugcrowd pagam baseado em severidade.
Sem CVSS documentado → risco de downgrade do bounty.

P1 (Critical 9.0+) → $5k-$50k+
P2 (High 7.0-8.9) → $1k-$10k
P3 (Medium 4.0-6.9) → $200-$2k
P4 (Low) → $50-$500

O score certo = o pagamento certo.
```

```
Dica: o Kambo gera o vector string CVSS automaticamente.

CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

Cole direto no seu report. O triager sabe que você fez o trabalho correto.

Isso aumenta a confiança e acelera o processo de pagamento. 💰

#bugbounty #hackerone #bugcrowd #pentest #ethicalhacking
```
