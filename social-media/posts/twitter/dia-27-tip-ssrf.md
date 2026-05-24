# Dia 27 — Dica técnica: SSRF para IMDS cloud

## Twitter / X

```
💡 Dica técnica: SSRF → IMDS = P1 garantido

Se você encontrar um SSRF, tente:
http://169.254.169.254/latest/meta-data/iam/security-credentials/

Em AWS, isso retorna credenciais IAM temporárias.

O Kambo testa isso automaticamente com cloud_imds_test():
• AWS: 169.254.169.254
• Azure: 169.254.169.254/metadata
• GCP: metadata.google.internal

🔗 github.com/ktfth/kambo

#ssrf #bugbounty #aws #cloud #cybersecurity
```

---

## Thread

```
🧵 Por que SSRF → Cloud Metadata é tão crítico?

AWS IMDS v1 (sem IMDSv2):
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/[role-name]

Retorna:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2025-..."
}

Isso é acesso total à conta AWS. CVSS 10.0.
```

```
Como o Kambo detecta isso:

1. vuln_ssrf confirma que o servidor faz requests para URLs arbitrárias
2. cloud_imds_test tenta os endpoints de metadata
3. Se a resposta contém "AccessKeyId" → CONFIRMED ✅
4. Evidence chain score: 1.0

O triager do HackerOne recebe a evidência exata, sem ambiguidade.
```

```
Proteção (para devs):

• AWS IMDSv2 obrigatório (requer token de sessão)
• Validar e sanitizar URLs antes de fazer requests server-side
• Network egress filtering no container

Saber atacar também ensina a defender. 🛡️

#ssrf #aws #bugbounty #cloud #cybersecurity #imds
```
