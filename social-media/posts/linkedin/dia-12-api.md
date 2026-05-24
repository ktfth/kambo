# Dia 12 — Segurança de API: OWASP API Top 10

## LinkedIn

```
🔌 APIs são o maior vetor de ataque de 2025 — o Kambo cobre o OWASP API Top 10

Mais de 80% das aplicações modernas expõem APIs. E a maioria delas tem pelo menos uma falha de autorização.

O Kambo tem 3 analyzers especializados em API Security:

1️⃣ api_test_bola — Broken Object Level Authorization (API1:2023)
→ Testa se você consegue acessar recursos de outros usuários trocando IDs
→ Enumera IDs sequenciais, UUIDs e hashes
→ Verifica se a resposta muda com diferentes tokens de autenticação

2️⃣ api_test_bfla — Broken Function Level Authorization (API5:2023)
→ Testa se endpoints admin/internos são acessíveis por usuários regulares
→ Verifica métodos HTTP não documentados (PUT, DELETE em endpoints GET-only)
→ Testa path traversal em rotas de API

3️⃣ api_test_misconfig — Security Misconfiguration (API8:2023)
→ Headers de segurança ausentes
→ CORS permissivo
→ Rate limiting ausente
→ Swagger/OpenAPI exposto em produção
→ Stack traces em respostas de erro

📊 Por que BOLA é o #1 há 4 anos consecutivos?

Porque implementar autorização por objeto é trabalhoso, e muitos devs assumem que "se o usuário está logado, pode acessar". O resultado são APIs que retornam dados de qualquer usuário se você mudar o ID na URL.

O Kambo detecta isso em segundos.

🔗 github.com/ktfth/kambo

#APISecurity #OWASP #BugBounty #CyberSecurity #BOLA #BFLA #PenetrationTesting #WebSecurity #EthicalHacking
```
