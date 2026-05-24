# 📣 Kambo — Kit de Divulgação nas Redes Sociais

Kit completo de conteúdo para publicação **automática** no Threads todos os dias às **18h**.
Funciona em **Windows, macOS e Linux**.

---

## 📁 Estrutura

```
social-media/
├── README.md                ← Este arquivo
├── calendar-30days.md       ← Calendário de 30 dias com temas
├── hashtags.md              ← Banco de hashtags por plataforma
│
├── poster.py                ← 🆕 Poster automático cross-platform (Python)
├── threads_client.py        ← 🆕 Cliente Threads: API oficial + Chrome/Playwright
├── requirements-social.txt  ← 🆕 Dependências Python
├── .env.example             ← 🆕 Template de configuração
│
├── setup-windows.ps1        ← 🆕 Setup automático para Windows
├── windows-task.xml         ← 🆕 Task Scheduler XML (import manual)
├── schedule.sh              ← Script bash (Linux/macOS, cron)
│
└── posts/
    ├── twitter/             ← Posts curtos (até 280 chars / Threads 500)
    ├── linkedin/            ← Posts profissionais (mais longos)
    └── instagram/           ← Captions + sugestão de arte visual
```

---

## 🚀 Setup Rápido

### 🪟 Windows (recomendado)

```powershell
# 1. Abra o PowerShell como Administrador

# 2. Permita a execução do script
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 3. Execute o setup (instala deps, Chrome, Task Scheduler)
cd kambo\social-media
.\setup-windows.ps1
```

O setup vai:
- ✅ Verificar Python 3.11+ e Chrome
- ✅ Instalar dependências (`playwright`, `httpx`, etc.)
- ✅ Instalar o driver Chrome do Playwright
- ✅ Criar o `.env` com o caminho do seu perfil Chrome
- ✅ Perguntar se quer agendar às 18h no Task Scheduler

### 🐧 Linux / 🍎 macOS

```bash
# 1. Instale as dependências
cd kambo/social-media
pip install -r requirements-social.txt
playwright install chrome

# 2. Configure o .env
cp .env.example .env
# Edite o .env com seu editor preferido

# 3. Agende às 18h (cron)
python poster.py schedule install
```

---

## ⚙️ Configuração do `.env`

```bash
cp social-media/.env.example social-media/.env
```

| Variável | Descrição | Padrão |
|----------|-----------|--------|
| `POSTER_MODE` | `browser` (Chrome) ou `api` (Threads API) | `browser` |
| `CHROME_PROFILE_DIR` | Pasta do perfil Chrome (auto-detectada no setup Windows) | auto |
| `CHROME_PROFILE_NAME` | Nome do perfil | `Default` |
| `CHROME_HEADLESS` | Abrir Chrome visível (`False`) ou oculto (`True`) | `False` |
| `THREADS_USER_ID` | ID do usuário Threads (modo `api`) | — |
| `THREADS_ACCESS_TOKEN` | Token de acesso Threads (modo `api`) | — |
| `KAMBO_START_DATE` | Data de início do ciclo (`YYYY-MM-DD`) | auto |

---

## 🖥️ Modos de Publicação

### Modo `browser` (padrão, mais fácil)

Abre o Chrome com seu perfil já logado no Threads e publica via automação.  
**Não precisa de API key.** Basta estar logado no Threads no Chrome.

```bash
# Configurar
POSTER_MODE=browser
CHROME_PROFILE_DIR=C:\Users\seu_usuario\AppData\Local\Google\Chrome\User Data
```

### Modo `api` (avançado)

Usa a API Graph oficial do Threads (Meta).  
Precisa de um app no Meta for Developers com permissão `threads_basic` e `threads_content_publish`.

```bash
# Obtenha em: https://developers.facebook.com/docs/threads/get-started
POSTER_MODE=api
THREADS_USER_ID=123456789
THREADS_ACCESS_TOKEN=EAAxxxxxxx...
```

---

## 📋 Comandos do Poster

```bash
# Ver o post de hoje (sem publicar)
python social-media/poster.py today --dry-run

# Publicar o post de hoje
python social-media/poster.py today

# Publicar um dia específico
python social-media/poster.py day 5

# Listar todos os posts disponíveis
python social-media/poster.py list

# Configurar .env interativamente
python social-media/poster.py setup

# Gerenciar agendamento
python social-media/poster.py schedule install    # Instala (18h diário)
python social-media/poster.py schedule uninstall  # Remove
python social-media/poster.py schedule status     # Verifica
```

### Windows — comandos equivalentes via script PowerShell

```powershell
# Na pasta social-media\
python poster.py today --dry-run
python poster.py today
python poster.py schedule status
```

---

## ⏰ Agendamento às 18h

### Windows — Task Scheduler
```powershell
python poster.py schedule install
# → Cria a task "KamboSocialPoster" no Agendador de Tarefas
# → Executa todo dia às 18h00
# → Usa o Python e o Chrome do seu perfil atual
```

Para ver no GUI: Abra **Agendador de Tarefas** → Biblioteca → `KamboSocialPoster`

### Linux / macOS — cron
```bash
python poster.py schedule install
# → Adiciona: 0 18 * * * python /caminho/poster.py today
crontab -l  # verificar
```

---

## 🌐 Como o Chrome é usado

O `threads_client.py` usa **Playwright** para automatizar o Chrome:

1. Abre o Chrome com o **perfil que você já usa** (já logado no Threads)
2. Navega para `threads.net`
3. Clica no botão de novo post
4. Digita o texto do post via JavaScript (preserva emojis)
5. Clica em "Publicar"
6. Tira um screenshot de confirmação

> **Primeira execução**: rode com `CHROME_HEADLESS=False` (padrão) para ver o Chrome abrir e confirmar que está funcionando.  
> **Produção**: mude para `CHROME_HEADLESS=True` para rodar em segundo plano.

---

## 📅 Conteúdo — 30 dias

| Semana | Foco | Plataforma |
|--------|------|------------|
| 1 | Apresentação e o problema que resolve | Twitter + LinkedIn |
| 2 | Cada fase do pentest em destaque | Twitter + LinkedIn |
| 3 | Workflows reais, scope, CVSS, métricas | LinkedIn + Twitter |
| 4 | Comunidade, dicas técnicas, roadmap, CTA | Todas |

O ciclo se repete automaticamente a cada 30 dias.

---

## 🔐 Obter Token da API Threads (modo `api`)

1. Acesse [developers.facebook.com](https://developers.facebook.com) e crie um app
2. Adicione o produto **Threads API**
3. Configure as permissões: `threads_basic`, `threads_content_publish`
4. Gere um **Long-lived Access Token** (válido por 60 dias, renovável)
5. Obtenha seu **User ID** via `GET https://graph.threads.net/v1.0/me`
6. Adicione ao `.env`:
   ```
   THREADS_USER_ID=seu_id
   THREADS_ACCESS_TOKEN=seu_token
   ```

---

## 🧪 Teste sem publicar

```bash
# Vê o post do dia no terminal sem abrir o Chrome ou chamar a API
python social-media/poster.py today --dry-run
```

---

## 📝 Log de Publicações

Cada publicação é registrada em `post-log.jsonl`:

```json
{"timestamp": "2026-05-24T18:00:01", "day": 1, "platform": "🐦 Twitter / X", "result": {"success": true, "mode": "browser"}}
```

Ver últimas publicações:
```bash
python social-media/poster.py schedule status
```
