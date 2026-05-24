# Dia 13 — Cloud Security

## Twitter / X

```
Cloud misconfiguration = dinheiro fácil em bug bounty. 💸

O Kambo tem 3 cloud security tools:

☁️ cloud_imds_test   → SSRF para metadata AWS/Azure/GCP (credentials, IAM roles)
🪣 cloud_storage_enum → S3/Blob/GCS públicos (dados expostos?)
🔑 cloud_secret_scan  → TruffleHog em repositórios/respostas HTTP

Um único S3 público pode valer $5.000+.

🔗 github.com/ktfth/kambo

#bugbounty #aws #cloud #ssrf #cybersecurity
```

---

## Thread

```
🧵 Por que SSRF → IMDS é tão impactante?

AWS IMDS (http://169.254.169.254) retorna:
• Credenciais temporárias IAM
• Token de sessão AWS
• ID da conta e região
• User data (pode ter secrets hardcoded)

Um SSRF para esse endpoint = acesso à conta AWS. Bounty P1 garantido.
```

```
cloud_storage_enum faz o quê?

1. Gera variações do nome da empresa (company-dev, company-prod, company-backup...)
2. Testa S3, Azure Blob, GCS
3. Verifica se os buckets existem E se são públicos
4. Lista arquivos se acessível

Já encontrei arquivos .env com DATABASE_URL em bucket público. 👀
```

```
TruffleHog + Kambo:

Varre respostas HTTP, JS bundles e repositórios públicos em busca de:
• AWS keys
• GitHub tokens  
• Stripe/Twilio secrets
• Senhas hardcoded

Tudo com validação de entropia + regex especializado.

#cloud #aws #azure #gcp #infosec #ethicalhacking
```
