---
name: kambo-social
description: Gera o post do dia do Kambo e publica no Threads via Chrome. Determina o dia do ciclo de 30 dias, extrai o texto do arquivo correspondente e usa o browser MCP para abrir threads.net e publicar automaticamente.
triggers:
  - social
  - publicar post
  - postar hoje
  - threads
  - divulgar kambo
  - post do dia
---

# Kambo Social — Publicação Diária no Threads

Gera e publica o post diário do Kambo no Threads usando o Chrome.

## Passo 1 — Determinar o dia do ciclo

Leia o arquivo de controle do ciclo:

```
Read: social-media/.start-date
```

Se o arquivo **não existir**, crie-o com a data de hoje (`YYYY-MM-DD`) e use `dia = 1`.

Se existir, calcule:
```
dia = ((hoje - start_date).days % 30) + 1
```

Informe: `📅 Hoje é o dia X/30 do ciclo (início: DATA)`

## Passo 2 — Carregar o post do dia

Use este mapeamento para encontrar o arquivo:

| Dia | Arquivo |
|-----|---------|
| 1 | `social-media/posts/twitter/dia-01-lancamento.md` |
| 2 | `social-media/posts/twitter/dia-02-problema.md` |
| 3 | `social-media/posts/linkedin/dia-03-solucao.md` |
| 4 | `social-media/posts/twitter/dia-04-arquitetura.md` |
| 5 | `social-media/posts/twitter/dia-05-instalacao.md` |
| 6 | `social-media/posts/linkedin/dia-06-claudecode.md` |
| 7 | `social-media/posts/twitter/dia-07-recap1.md` |
| 8 | `social-media/posts/twitter/dia-08-recon.md` |
| 9 | `social-media/posts/twitter/dia-09-scanning.md` |
| 10 | `social-media/posts/linkedin/dia-10-vulns.md` |
| 11 | `social-media/posts/twitter/dia-11-evidence.md` |
| 12 | `social-media/posts/linkedin/dia-12-api.md` |
| 13 | `social-media/posts/twitter/dia-13-cloud.md` |
| 14 | `social-media/posts/instagram/dia-14-recap2.md` |
| 15 | `social-media/posts/linkedin/dia-15-workflow.md` |
| 16 | `social-media/posts/twitter/dia-16-scope.md` |
| 17 | `social-media/posts/twitter/dia-17-cvss.md` |
| 18 | `social-media/posts/linkedin/dia-18-selfimprove.md` |
| 19 | `social-media/posts/twitter/dia-19-calibration.md` |
| 20 | `social-media/posts/twitter/dia-20-postexploit.md` |
| 21 | `social-media/posts/instagram/dia-21-recap3.md` |
| 22 | `social-media/posts/linkedin/dia-22-contribuir.md` |
| 23 | `social-media/posts/twitter/dia-23-tools.md` |
| 24 | `social-media/posts/twitter/dia-24-ctf.md` |
| 25 | `social-media/posts/twitter/dia-25-metrics.md` |
| 26 | `social-media/posts/linkedin/dia-26-report.md` |
| 27 | `social-media/posts/twitter/dia-27-tip-ssrf.md` |
| 28 | `social-media/posts/twitter/dia-28-tip-takeover.md` |
| 29 | `social-media/posts/linkedin/dia-29-roadmap.md` |
| 30 | `social-media/posts/twitter/dia-30-cta.md` |

Leia o arquivo com `Read`. Extraia o conteúdo do **primeiro bloco de código** (entre os primeiros ` ``` ` e ` ``` `). Esse é o texto pronto para publicar.

Mostre o texto extraído e o número de caracteres:
```
📝 Post do dia X (Plataforma):
─────────────────────────────
[TEXTO]
─────────────────────────────
📊 N caracteres (limite Threads: 500)
```

Se o texto tiver mais de 500 caracteres, **trunce antes de publicar** e avise o usuário.

## Passo 3 — Publicar no Threads via Chrome

Use as ferramentas do browser MCP (`playwright_*` ou `browser_*` conforme disponível).

### 3a. Navegar para o Threads

```
browser_navigate(url="https://www.threads.net")
```

Aguarde o carregamento completo. Tire um screenshot para confirmar o estado.

### 3b. Verificar login

Se a URL contiver `/login` ou `/signup`, pare e informe:
```
❌ Chrome não está logado no Threads.
   Abra o Chrome, acesse threads.net, faça login e rode /kambo-social novamente.
```

### 3c. Abrir o composer

Clique no botão de novo post. Tente os seletores nesta ordem até encontrar um visível:
1. `a[href="/compose"]`
2. `[aria-label="New thread"]`
3. `[aria-label="Novo thread"]`
4. Qualquer `div[role="button"]` ou `a` com texto "New" ou "Novo"

Se nenhum funcionar, tente navegar diretamente para `https://www.threads.net/compose`.

### 3d. Escrever o texto

Localize o campo de texto (`[contenteditable="true"]` ou `div[role="textbox"]`).

Injete o texto via JavaScript para preservar emojis e quebras de linha:
```javascript
const el = document.querySelector('[contenteditable="true"]') 
        || document.querySelector('div[role="textbox"]');
el.focus();
document.execCommand('insertText', false, TEXTO_DO_POST);
```

Tire um screenshot para confirmar que o texto apareceu corretamente.

### 3e. Publicar

Clique no botão de publicar:
- `button` com texto "Post", "Publicar", "Post thread" ou "Publicar thread"
- `[aria-label="Post"]` ou `[aria-label="Publicar"]`

Aguarde 2 segundos e tire um screenshot final de confirmação.

## Passo 4 — Registrar no log

Acrescente uma linha ao arquivo `social-media/post-log.jsonl`:

```json
{"timestamp": "YYYY-MM-DDTHH:MM:SS", "day": N, "file": "CAMINHO", "chars": N, "status": "published"}
```

## Passo 5 — Relatório final

```
✅ Post publicado com sucesso!
📅 Dia N/30
📝 Arquivo: social-media/posts/...
📊 N caracteres
🔗 https://www.threads.net

Próximo post: dia N+1 — [tema do próximo dia conforme o calendário]
```

---

## Notas de operação

- **Se o Chrome não abrir automaticamente**: o MCP Playwright abre seu próprio Chrome. Certifique-se de que `@playwright/mcp` está configurado no `.mcp.json` do projeto.
- **Se a interface do Threads mudou**: tire um screenshot com `browser_screenshot`, descreva o que vê e tente identificar o botão de composição visualmente.
- **Se o post já foi feito hoje**: verifique o `post-log.jsonl` antes de publicar para evitar duplicatas.
- **Para forçar um dia específico**: o operador pode dizer `"publica o dia 5"` e a skill usa esse número diretamente.
