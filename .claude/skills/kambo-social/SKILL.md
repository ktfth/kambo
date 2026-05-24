---
name: kambo-social
description: Gera o post do dia do Kambo e publica no Threads usando o Chrome nativo do Claude Code (--chrome). Determina o dia do ciclo de 30 dias, extrai o texto do arquivo correspondente e controla o browser para abrir threads.net e publicar.
triggers:
  - social
  - publicar post
  - postar hoje
  - threads
  - divulgar kambo
  - post do dia
  - publica hoje
---

# Kambo Social — Publicação Diária no Threads

Usa o Chrome integrado ao Claude Code para publicar o post do dia no Threads.

## Passo 1 — Determinar o dia do ciclo

Leia o arquivo de controle:

```
Read: social-media/.start-date
```

- **Não existe** → crie-o com a data de hoje (`YYYY-MM-DD`) e use `dia = 1`.
- **Existe** → calcule: `dia = ((hoje - start_date).days % 30) + 1`

Informe: `📅 Hoje é o dia N/30 do ciclo (início: DATA)`

Verifique também se já houve publicação hoje em `social-media/post-log.jsonl`.
Se a última entrada tiver o timestamp de hoje, pergunte ao usuário se quer publicar novamente antes de continuar.

## Passo 2 — Carregar e exibir o post

Mapeamento dia → arquivo (relativo à raiz do projeto):

```
1  → social-media/posts/twitter/dia-01-lancamento.md
2  → social-media/posts/twitter/dia-02-problema.md
3  → social-media/posts/linkedin/dia-03-solucao.md
4  → social-media/posts/twitter/dia-04-arquitetura.md
5  → social-media/posts/twitter/dia-05-instalacao.md
6  → social-media/posts/linkedin/dia-06-claudecode.md
7  → social-media/posts/twitter/dia-07-recap1.md
8  → social-media/posts/twitter/dia-08-recon.md
9  → social-media/posts/twitter/dia-09-scanning.md
10 → social-media/posts/linkedin/dia-10-vulns.md
11 → social-media/posts/twitter/dia-11-evidence.md
12 → social-media/posts/linkedin/dia-12-api.md
13 → social-media/posts/twitter/dia-13-cloud.md
14 → social-media/posts/instagram/dia-14-recap2.md
15 → social-media/posts/linkedin/dia-15-workflow.md
16 → social-media/posts/twitter/dia-16-scope.md
17 → social-media/posts/twitter/dia-17-cvss.md
18 → social-media/posts/linkedin/dia-18-selfimprove.md
19 → social-media/posts/twitter/dia-19-calibration.md
20 → social-media/posts/twitter/dia-20-postexploit.md
21 → social-media/posts/instagram/dia-21-recap3.md
22 → social-media/posts/linkedin/dia-22-contribuir.md
23 → social-media/posts/twitter/dia-23-tools.md
24 → social-media/posts/twitter/dia-24-ctf.md
25 → social-media/posts/twitter/dia-25-metrics.md
26 → social-media/posts/linkedin/dia-26-report.md
27 → social-media/posts/twitter/dia-27-tip-ssrf.md
28 → social-media/posts/twitter/dia-28-tip-takeover.md
29 → social-media/posts/linkedin/dia-29-roadmap.md
30 → social-media/posts/twitter/dia-30-cta.md
```

Leia o arquivo. Extraia o conteúdo do **primeiro bloco de código** (entre o primeiro par de ` ``` `). Esse é o texto pronto para publicar.

Exiba para o usuário:
```
📝 Post do dia N:
──────────────────────────────────────
[TEXTO EXTRAÍDO]
──────────────────────────────────────
📊 X caracteres  (Threads suporta até 500)
```

Se tiver mais de 500 caracteres, avise e trunce em 497 + `...`.

## Passo 3 — Publicar no Threads via Chrome

Use as ferramentas de browser nativas do Claude Code.

### 3a. Abrir o Threads

Navegue para `https://www.threads.net` e aguarde o carregamento.

Tire um screenshot para ver o estado atual da página.

### 3b. Verificar login

Se a URL contiver `/login` ou `/signup`, ou a página mostrar formulário de login, **pare** e informe:

```
❌ Chrome não está logado no Threads.
   Faça login manualmente em threads.net e rode /kambo-social novamente.
```

### 3c. Abrir o composer de novo post

Procure e clique no elemento de criação de post. Ordem de tentativa:

1. Link ou botão com `href="/compose"`
2. Elemento com `aria-label` contendo "New thread" ou "Novo thread"
3. Ícone de lápis / compose na barra de navegação
4. Qualquer botão proeminente com texto "New", "Novo", "Post" ou "Thread"

Se nenhum funcionar com clique, navegue diretamente para `https://www.threads.net/compose`.

Tire screenshot após abrir o composer para confirmar.

### 3d. Inserir o texto

Localize o campo de entrada (contenteditable ou textarea). Clique nele para focar.

Injete o texto preservando emojis e quebras de linha com JavaScript:

```javascript
const field =
  document.querySelector('[contenteditable="true"]') ||
  document.querySelector('div[role="textbox"]') ||
  document.querySelector('textarea');
if (field) {
  field.focus();
  document.execCommand('insertText', false, `TEXTO_DO_POST`);
}
```

Tire screenshot para confirmar que o texto apareceu corretamente no campo.

### 3e. Publicar

Localize e clique no botão de publicação:

- Texto "Post", "Publicar", "Post thread" ou "Publicar thread"
- `aria-label` "Post" ou "Publicar"
- Botão primário/destacado visível no composer

Aguarde 2–3 segundos e tire um screenshot final para confirmar que o post foi publicado (o composer deve fechar ou mostrar confirmação).

## Passo 4 — Registrar no log

Acrescente uma linha ao `social-media/post-log.jsonl`:

```json
{"timestamp": "YYYY-MM-DDTHH:MM:SS", "day": N, "file": "CAMINHO_RELATIVO", "chars": N, "status": "published"}
```

## Passo 5 — Resumo final

```
✅ Publicado no Threads!
📅 Dia N/30 | DATA HORA
📝 social-media/posts/...
📊 N caracteres

Próximo post: amanhã, dia N+1 → [tema do próximo dia]
```

---

## Comportamento para dia específico

Se o operador disser `"publica o dia 5"` ou `"post do dia 12"`, use esse número diretamente sem calcular pelo ciclo.

## Requisito

Este skill requer que o Claude Code seja iniciado com suporte ao Chrome:

```
claude --chrome
```

As ferramentas de browser ficam disponíveis automaticamente nesse modo.
