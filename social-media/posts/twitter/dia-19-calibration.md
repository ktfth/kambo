# Dia 19 — Calibração automática

## Twitter / X

```
O Kambo detecta quando suas predições de confiança estão erradas.

E se auto-corrige.

Se você reporta CONFIRMED mas a plataforma rejeita → drift detectado.
/kambo-calibrate ajusta os weights baseado no histórico real.

A taxa de aceitação dos seus reports melhora ao longo do tempo. 📈

🔗 github.com/ktfth/kambo

#bugbounty #ai #cybersecurity #infosec #MCP
```

---

## Thread

```
🧵 Como funciona a calibração na prática:

1. Você faz hunting com o Kambo
2. Submete os reports para HackerOne/Bugcrowd
3. Registra o feedback (aceito/rejeitado/downgrade)
4. Roda /kambo-calibrate
5. Os thresholds de confiança são ajustados

Na próxima sessão, menos falsos positivos.
```

```
O learnings store (~/.kambo/learnings.jsonl) persiste:

• "CORS + credentials sem dados sensíveis = TENTATIVE, não FIRM"
• "JWT alg:none sempre CONFIRMED se o server aceita"
• "Nuclei template X: 60% FP rate atrás de WAF"

São regras que você não precisa mais lembrar. A IA já sabe.
```

```
Isso é o que separa uma ferramenta estática de um sistema inteligente.

Cada sessão é um ponto de dado.
Dados acumulam em padrões.
Padrões viram calibração.
Calibração vira resultados melhores.

É um flywheel de qualidade. 🔄

#pentest #ethicalhacking #ai #claudeai #redteam
```
