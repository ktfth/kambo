# 📣 Kambo — Kit de Divulgação nas Redes Sociais

Kit completo de conteúdo para publicação diária às **18h**.

## 📁 Estrutura

```
social-media/
├── README.md               ← Este arquivo
├── calendar-30days.md      ← Calendário de 30 dias com temas
├── hashtags.md             ← Banco de hashtags por plataforma
├── schedule.sh             ← Script para agendar via cron (18h diário)
└── posts/
    ├── twitter/            ← Posts curtos (até 280 caracteres)
    ├── linkedin/           ← Posts profissionais (mais longos)
    └── instagram/          ← Captions + sugestão de arte visual
```

## 🚀 Configurar agendamento automático às 18h

```bash
# Tornar o script executável
chmod +x social-media/schedule.sh

# Instalar o cron job (vai imprimir o post do dia às 18h)
./social-media/schedule.sh install

# Ver o cron job instalado
crontab -l

# Remover o agendamento
./social-media/schedule.sh uninstall
```

## 📅 Fluxo diário recomendado

1. Às **17h50** → consulte `calendar-30days.md` para o tema do dia
2. Abra o post correspondente em `posts/twitter/`, `posts/linkedin/` ou `posts/instagram/`
3. Copie, personalize se quiser, e publique às **18h00**
4. Adicione a URL do repositório no post: `https://github.com/ktfth/kambo`

## 🎯 Estratégia de conteúdo

| Semana | Foco |
|--------|------|
| 1 | Apresentação do projeto e problema que resolve |
| 2 | Funcionalidades em destaque (cada fase do pentest) |
| 3 | Casos de uso reais e workflows |
| 4 | Comunidade, contribuição e próximos passos |

Repita o ciclo mensalmente com variações nos posts.
