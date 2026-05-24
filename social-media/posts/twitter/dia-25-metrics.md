# Dia 25 — Métricas por sessão

## Twitter / X

```
Você sabe quais ferramentas de pentest realmente funcionam pra você?

O Kambo rastreia por sessão:
• Precisão por ferramenta
• Taxa de falso positivo
• Tempo médio de execução
• Findings confirmados vs. descartados

Dados objetivos. Sem achismo. 📊

🔗 github.com/ktfth/kambo

#bugbounty #cybersecurity #metrics #pentest #infosec
```

---

## Thread

```
🧵 Por que métricas de ferramenta importam para bug hunters?

Você já percebeu que:
• Nuclei gera 50 findings dos quais 40 são FP?
• subfinder acha 30 subs mas amass acha 100?
• sqlmap demora 20min mas só confirma 10% dos casos?

Sem dados, você não sabe otimizar.
```

```
O Kambo coleta automaticamente:

per_tool_metrics {
  tool: "nuclei",
  total_runs: 47,
  avg_precision: 0.62,
  false_positive_rate: 0.38,
  avg_execution_time: 145s
}

Depois de 10 sessões, você sabe exatamente onde investir tempo.
```

```
O Pattern Analyzer classifica:

🏆 Elite: precision > 0.8, FP < 0.15
✅ Reliable: precision > 0.6
⚠️ Noisy: FP > 0.4 (ajuste os templates)
🔴 Broken: error_rate > 0.3 (precisa de fix)

Isso é gestão de qualidade aplicada a segurança ofensiva. 📈

#pentest #bugbounty #ai #cybersecurity #ethicalhacking
```
