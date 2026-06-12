# Dia 28 — Dica técnica: Subdomain Takeover

```
💡 Dica: Subdomain Takeover via CNAME

Passo a passo:

1. subfinder → lista subdomínios
2. dnsx → resolve CNAMEs
3. Verifica se o destino do CNAME existe

Se CNAME aponta para:
→ *.github.io (repositório deletado)
→ *.s3.amazonaws.com (bucket removido)
→ *.azurewebsites.net (app deletado)

E o serviço aceita qualquer hostname = Takeover! 🚩

Kambo detecta isso automaticamente na fase de recon.

🔗 github.com/ktfth/kambo

#bugbounty #subdomaintakeover #recon #pentest
```
