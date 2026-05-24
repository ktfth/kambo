# Dia 28 — Dica técnica: Subdomain Takeover

## Twitter / X

```
💡 Subdomain takeover = P1 com baixo esforço

O padrão:
1. app.example.com → CNAME → old-app.azurewebsites.net
2. old-app.azurewebsites.net foi deletado
3. Você registra old-app.azurewebsites.net
4. Você controla app.example.com

O Kambo detecta com vuln_subdomain_takeover() — verifica todos os CNAMEs da recon.

🔗 github.com/ktfth/kambo

#bugbounty #subdomain #takeover #cybersecurity
```

---

## Thread

```
🧵 Quais serviços são vulneráveis a subdomain takeover?

Os mais comuns:
• Azure (azurewebsites.net, cloudapp.azure.com)
• Heroku (herokuapp.com)
• GitHub Pages (github.io)  
• Fastly, Shopify, Zendesk
• AWS S3 (bucket deletado com CNAME)

O Kambo tem fingerprints de 20+ serviços.
```

```
O flow do Kambo:

1. recon_subdomains encontra 100+ subdomínios
2. recon_dns mapeia todos os CNAMEs
3. vuln_subdomain_takeover verifica cada CNAME:
   → O domínio destino existe?
   → O serviço retorna "unclaimed"?
   → É possível registrar?

4. Finding com CONFIRMED → relatório gerado
```

```
Impacto real de um subdomain takeover:

✅ Hospedar phishing no domínio da empresa
✅ Roubar cookies de sessão via XSS no subdomínio
✅ Bypass de CSP (mesmo domínio = confiável)
✅ Emails "legítimos" do domínio comprometido

P1-P2 em praticamente qualquer programa. 💰

#bugbounty #subdomain #takeover #xss #phishing #cybersecurity
```
