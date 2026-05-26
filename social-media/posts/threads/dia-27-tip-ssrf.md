# Dia 27 — Dica: SSRF via IMDS

```
💡 Dica: SSRF via IMDS (AWS)

Quando encontrar SSRF, tente:
http://169.254.169.254/latest/meta-data/

Em AWS, isso vaza:
• Credenciais IAM temporárias
• Instance ID, AMI, região
• User-data (pode conter secrets)

Um SSRF em AWS pode escalar para comprometimento total da conta.

O Kambo testa isso automaticamente na fase de cloud.

🔗 github.com/ktfth/kambo

#ssrf #aws #bugbounty #cloud #imds
```
