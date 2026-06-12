# Dia 27 — Dica técnica: SSRF para IMDS

```
💡 Dica: SSRF → IMDS cloud = bounty crítico

Se encontrar SSRF, teste imediatamente:

AWS:
http://169.254.169.254/latest/meta-data/iam/security-credentials/

Azure:
http://169.254.169.254/metadata/identity/oauth2/token

GCP:
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/

Credenciais temporárias expostas = Critical severity.

O Kambo testa esses endpoints automaticamente ao detectar SSRF.

🔗 github.com/ktfth/kambo

#bugbounty #SSRF #cloudsecurity #pentest #tip
```
