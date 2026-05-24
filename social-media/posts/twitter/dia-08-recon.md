# Dia 08 — Fase 1: Reconhecimento

## Twitter / X

```
Fase 1 do Kambo: Reconhecimento 🔍

7 ferramentas, 1 comando:

recon_subdomains  → crt.sh + subfinder + amass + dnsenum
recon_dns         → zone transfer + brute force
recon_ports_fast  → portas comuns
recon_tech_stack  → whatweb + httpx
recon_waf         → wafw00f (detecta Cloudflare, Akamai...)
recon_certs       → Certificate Transparency logs
recon_asn         → blocos IP da organização

Tudo isso antes de disparar 1 payload.

#bugbounty #recon #infosec #subfinder #ethicalhacking
```

---

## Thread detalhado

```
🧵 Por que o recon é a fase mais importante?

80% dos bounties P1 vêm de ativos esquecidos:
• subdomínios abandonados
• staging servers expostos
• APIs internas sem autenticação
• storage buckets públicos

O Kambo mapeia tudo antes de atacar.
```

```
recon_certs é subestimado demais.

Certificate Transparency logs revelam:
✅ Subdomínios internos
✅ Ambientes de staging/dev
✅ Serviços de terceiros vinculados
✅ Histórico de infraestrutura

Tudo público. Tudo válido para bug bounty.
```

```
recon_asn + recon_ports_fast = mapa completo da superfície de ataque.

Se a empresa tem 5 ASNs, você provavelmente encontra:
- servidores de email expostos
- VPNs legadas
- portas incomuns em produção

Oportunidades que 90% dos hunters ignoram. 🎯

#pentest #bugbounty #cybersecurity #kalilinux #OSINT
```
