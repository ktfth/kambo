# ⏰ Kambo — Post automático às 18h no Threads

> Configura uma vez, publica todos os dias.  
> Repositório: `https://github.com/ktfth/kambo`

---

## O que já existe (pronto para usar)

| Item | Status |
|------|--------|
| 30 posts escritos (Twitter, LinkedIn, Instagram) | ✅ |
| `poster.py` — publica o post do dia | ✅ |
| `threads_client.py` — integração com Threads API + Chrome | ✅ |
| GitHub Actions — publica às 18h sem computador ligado | ✅ |
| Agendamento local via cron (Linux/macOS) | ✅ |
| Agendamento local via Task Scheduler (Windows) | ✅ |

---

## 🚀 Opção 1 — GitHub Actions (recomendado)

Publica automaticamente às 18h todo dia, direto do GitHub.  
**Não precisa do computador ligado.**

### Passo 1 — Obter o token do Threads

1. Acesse [developers.facebook.com](https://developers.facebook.com)
2. Crie um app → adicione o produto **Threads API**
3. Configure permissões: `threads_basic` + `threads_content_publish`
4. Gere um **Long-lived Access Token** (válido 60 dias, renovável)
5. Obtenha seu User ID:
   ```bash
   curl "https://graph.threads.net/v1.0/me?access_token=SEU_TOKEN"
   # Retorna: {"id": "123456789", "name": "..."}
   ```

### Passo 2 — Adicionar segredos no GitHub

No repositório `ktfth/kambo`:

```
Settings → Secrets and variables → Actions → New repository secret
```

| Nome | Valor |
|------|-------|
| `THREADS_USER_ID` | ID do seu usuário Threads (ex: `123456789`) |
| `THREADS_ACCESS_TOKEN` | Token longo do Threads (`EAAxxxx...`) |

E uma **variável** (não segredo):

```
Settings → Secrets and variables → Actions → Variables → New repository variable
```

| Nome | Valor |
|------|-------|
| `KAMBO_START_DATE` | Data de início do ciclo (ex: `2026-05-25`) |

### Passo 3 — Ativar o workflow

O arquivo `.github/workflows/social-poster.yml` já está no repositório.

Para ativar:
1. Vá em **Actions** no GitHub
2. Clique em **📣 Kambo — Post Diário às 18h**
3. Clique em **Enable workflow**

A partir daí: todo dia às **21h UTC (= 18h BRT)** o GitHub publica automaticamente.

### Passo 4 — Testar antes do horário agendado

Na aba **Actions → Kambo Post Diário → Run workflow**:

- **day**: deixe vazio (usa o ciclo automático) ou coloque um número (1–30)
- **dry_run**: marque `true` para ver o post SEM publicar

---

## 💻 Opção 2 — Computador local (cron / Task Scheduler)

Se preferir rodar na sua máquina:

### Linux / macOS

```bash
# Instalar dependências
cd kambo/social-media
pip install -r requirements-social.txt
playwright install chrome

# Configurar
cp .env.example .env
# Edite o .env (modo browser não precisa de API key)

# Agendar às 18h
python poster.py schedule install

# Verificar
python poster.py schedule status
crontab -l
```

### Windows

```powershell
# No PowerShell como Administrador:
cd kambo\social-media
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup-windows.ps1
```

O script instala tudo e cria a task no Agendador de Tarefas automaticamente.

---

## 📋 Comandos úteis

```bash
# Ver o post de hoje (sem publicar)
python social-media/poster.py today --dry-run

# Ver um dia específico
python social-media/poster.py day 5 --dry-run

# Ver todos os 30 posts
bash social-media/preview-all.sh

# Ver a semana 1 (dias 1–7)
bash social-media/preview-all.sh 1 7

# Publicar manualmente hoje
python social-media/poster.py today

# Ver status do agendamento
python social-media/poster.py schedule status

# Listar todos os posts com status
python social-media/poster.py list
```

---

## 📅 Calendário de conteúdo (30 dias)

| Semana | Tema | Plataforma |
|--------|------|------------|
| 1 (dias 1–7) | Apresentação, problema, solução, arquitetura | Twitter + LinkedIn |
| 2 (dias 8–14) | Fases do pentest: recon, scan, vulns, API, cloud | Twitter + Instagram |
| 3 (dias 15–21) | Workflows reais, scope, CVSS, métricas | LinkedIn + Twitter |
| 4 (dias 22–30) | Comunidade, dicas técnicas, roadmap, CTA final | Todas |

O ciclo se repete automaticamente a cada 30 dias. 🔁

---

## 🔄 Renovar o token Threads (a cada 60 dias)

O Long-lived Token expira em 60 dias. Para renovar:

```bash
curl -X GET \
  "https://graph.threads.net/refresh_access_token?grant_type=th_refresh_token&access_token=SEU_TOKEN_ATUAL"
```

Depois atualize o secret `THREADS_ACCESS_TOKEN` no GitHub.

> **Dica**: crie um lembrete no calendário para renovar a cada 55 dias.

---

## 📝 Log de publicações

Cada publicação é registrada em `social-media/post-log.jsonl`:

```json
{"timestamp": "2026-05-25T18:00:01", "day": 1, "platform": "🐦 Twitter / X", "result": {"success": true}}
```

Ver as últimas publicações:
```bash
python social-media/poster.py schedule status
```

---

## ❓ Troubleshooting

| Problema | Solução |
|---------|---------|
| `Nenhum bloco de código encontrado` | O arquivo .md não tem bloco ` ``` ` — verifique o post |
| `Token expirado` | Renove o access token (veja seção acima) |
| `THREADS_USER_ID não definido` | Adicione o secret no GitHub ou no .env |
| Post com mais de 500 chars | O `threads_client.py` trunca automaticamente |
| Workflow não roda | Verifique se o Actions está ativado no repositório |
