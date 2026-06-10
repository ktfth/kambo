# Dia 27 — Dica técnica: SSRF para IMDS cloud

## Threads (≤ 500 caracteres)

```
🔍 Dica técnica: SSRF → acesso ao IMDS cloud.

Payload clássico para testar SSRF em AWS:
http://169.254.169.254/latest/meta-data/iam/security-credentials/

App busca URLs sem validação → credenciais da instância expostas.

O Kambo automatiza esse check em todos os parâmetros suspeitos.

🔗 github.com/ktfth/kambo

#SSRF #AWS #cloud #bugbounty #tip
```
