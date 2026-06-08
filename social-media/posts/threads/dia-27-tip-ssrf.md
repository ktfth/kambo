# Dia 27 — Dica Técnica: SSRF para IMDS Cloud

## Threads (≤500 chars)

```
💡 Dica técnica: SSRF → IMDS cloud

Payload para testar AWS IMDS:
http://169.254.169.254/latest/meta-data/

Se o servidor fizer a request, você tem SSRF confirmado.
Próximo passo: extrair IAM credentials.

O Kambo detecta e valida isso com evidence chain CONFIRMED. 🎯

🔗 github.com/ktfth/kambo

#ssrf #bugbounty #aws #cloud #pentest #tip
```
