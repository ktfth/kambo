# Dia 26 — Template de Relatório HackerOne/Bugcrowd

## LinkedIn

```
📄 Um bom relatório vale tanto quanto a vulnerabilidade em si

Bug hunters experientes sabem: a qualidade do report define o bounty. Um P1 mal documentado pode ser downgradeado para P2 ou até rejeitado.

O Kambo gera templates prontos para HackerOne e Bugcrowd com report_bounty_template().

O que está incluído no template:

━━━━━━━━━━━━━━━━━━━
TÍTULO
━━━━━━━━━━━━━━━━━━━
[TIPO DE VULN] em [ENDPOINT] permite [IMPACTO]
Ex: "IDOR em /api/v2/users/{id} permite acesso a dados de qualquer usuário autenticado"

━━━━━━━━━━━━━━━━━━━
SUMÁRIO EXECUTIVO
━━━━━━━━━━━━━━━━━━━
Uma vulnerabilidade do tipo [X] foi identificada em [URL]. Um atacante autenticado com privilege [Y] consegue [IMPACTO CONCRETO].

━━━━━━━━━━━━━━━━━━━
SEVERIDADE E CVSS
━━━━━━━━━━━━━━━━━━━
• Severidade: HIGH (CVSS 3.1: 8.1)
• Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N

━━━━━━━━━━━━━━━━━━━
PASSOS DE REPRODUÇÃO
━━━━━━━━━━━━━━━━━━━
1. Autentique como User A
2. Faça GET /api/v2/users/1337
3. Observe dados do User B na resposta
[Evidence chain screenshot incluído]

━━━━━━━━━━━━━━━━━━━
IMPACTO
━━━━━━━━━━━━━━━━━━━
• Exposição de PII de todos os usuários
• Violação de GDPR/LGPD (dados pessoais)
• Estimativa de usuários afetados: [N]

━━━━━━━━━━━━━━━━━━━
RECOMENDAÇÃO
━━━━━━━━━━━━━━━━━━━
Validar no lado do servidor que o ID solicitado pertence ao usuário autenticado.

━━━━━━━━━━━━━━━━━━━

Tudo isso gerado automaticamente pelo Kambo com base nos findings da sessão.

🔗 github.com/ktfth/kambo

#BugBounty #HackerOne #Bugcrowd #CyberSecurity #PenetrationTesting #VulnerabilityResearch #EthicalHacking #IDOR #ReportWriting
```
