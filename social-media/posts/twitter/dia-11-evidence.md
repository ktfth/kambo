# Dia 11 — Evidence Chains

## Twitter / X

```
O que separa um bom relatório de bug bounty de um ótimo?

Evidências.

O Kambo usa Evidence Chains — sinais ponderados que acumulam confiança:

✅ CONFIRMED → threshold superado, exploração validada
🔶 FIRM → múltiplos sinais convergentes
🔵 TENTATIVE → sinal único, precisa verificação

Você nunca entrega um "possível" sem saber exatamente o porquê.

#bugbounty #cybersecurity #infosec #vulnresearch
```

---

## Thread

```
🧵 Como funciona um evidence chain na prática?

Exemplo: detecção de CORS misconfiguration

Sinal 1: Origin: evil.com refletido no Access-Control-Allow-Origin → +0.5
Sinal 2: Access-Control-Allow-Credentials: true presente → +0.3
Sinal 3: Resposta contém dados sensíveis → +0.2

Total: 1.0 → CONFIRMED ✅
```

```
Por que isso importa para bug bounty?

Plataformas como HackerOne e Bugcrowd rejeitam reports sem evidência clara.

Com evidence chains, você chega com:
• Prova de conceito
• Reprodução passo a passo
• Impacto quantificado

Taxa de aceitação muito maior. 💰
```

```
O model de confiança é configurável.

Você pode calibrar os thresholds via /kambo-calibrate baseado no seu histórico de reports aceitos/rejeitados.

O sistema aprende com você.

🔗 github.com/ktfth/kambo

#pentest #ethicalhacking #redteam #MCP #claudeai
```
