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

Leia o mapa centralizado de posts:

```
Read: social-media/posts-map.json
```

Este arquivo contém `{ "1": "caminho/relativo.md", ..., "30": "..." }`.
Use a chave correspondente ao dia calculado no Passo 1 para obter o caminho do arquivo.

Leia o arquivo em `social-media/posts/<caminho>`. Extraia o conteúdo do **primeiro bloco de código** (entre o primeiro par de ` ``` `). Esse é o texto pronto para publicar.

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
