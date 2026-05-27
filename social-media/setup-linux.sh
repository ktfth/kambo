#!/usr/bin/env bash
# =============================================================================
# Kambo Social Media Poster — Setup Linux / macOS
# Execute:
#   chmod +x setup-linux.sh && ./setup-linux.sh
# =============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🐸 Kambo Social Media Poster — Setup Linux/macOS           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─────────────────────────────────────────────────
# 1. Python 3.11+
# ─────────────────────────────────────────────────
echo "🔍 Verificando Python..."

PYTHON_CMD=""
for cmd in python3.13 python3.12 python3.11 python3 python; do
  if command -v "$cmd" &>/dev/null; then
    ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
    major=${ver%%.*}
    minor=${ver##*.}
    if [[ "$major" -ge 3 && "$minor" -ge 11 ]]; then
      PYTHON_CMD="$cmd"
      echo "✅ Python $ver encontrado ($cmd)"
      break
    fi
  fi
done

if [[ -z "$PYTHON_CMD" ]]; then
  echo "❌ Python 3.11+ não encontrado."
  echo "   Ubuntu/Debian: sudo apt install python3.11"
  echo "   macOS:         brew install python@3.11"
  exit 1
fi

# ─────────────────────────────────────────────────
# 2. Dependências Python
# ─────────────────────────────────────────────────
echo ""
echo "📦 Instalando dependências Python..."

"$PYTHON_CMD" -m pip install --quiet --upgrade pip
"$PYTHON_CMD" -m pip install --quiet -r "$SCRIPT_DIR/requirements-social.txt"
echo "✅ Dependências instaladas"

# ─────────────────────────────────────────────────
# 3. Playwright Chrome
# ─────────────────────────────────────────────────
echo ""
echo "🌐 Instalando Chrome via Playwright..."

if "$PYTHON_CMD" -m playwright install chrome --quiet 2>/dev/null; then
  echo "✅ Chrome (Playwright) instalado"
else
  echo "⚠️  Playwright install falhou — tente manualmente:"
  echo "   $PYTHON_CMD -m playwright install chrome"
fi

# ─────────────────────────────────────────────────
# 4. Criar .env
# ─────────────────────────────────────────────────
echo ""
echo "⚙️  Configurando .env..."

if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
  cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"

  # Detecta perfil Chrome
  if [[ "$OSTYPE" == "darwin"* ]]; then
    CHROME_DIR="$HOME/Library/Application Support/Google/Chrome"
  else
    CHROME_DIR="$HOME/.config/google-chrome"
  fi

  sed -i.bak "s|CHROME_PROFILE_DIR=|CHROME_PROFILE_DIR=$CHROME_DIR|" "$SCRIPT_DIR/.env"
  rm -f "$SCRIPT_DIR/.env.bak"

  echo "✅ .env criado com CHROME_PROFILE_DIR=$CHROME_DIR"
  echo "   Edite $SCRIPT_DIR/.env se precisar ajustar"
else
  echo "ℹ️  .env já existe — mantido sem alterações"
fi

# ─────────────────────────────────────────────────
# 5. Agendamento
# ─────────────────────────────────────────────────
echo ""
echo "📅 Como agendar o post diário às 18h?"
echo "   1. systemd timer  (recomendado — retry automático, logs via journald)"
echo "   2. cron           (simples, funciona em qualquer Linux/macOS)"
echo "   3. Pular          (configurar depois)"
echo ""
read -rp "Opção (1/2/3) [1]: " SCHED_CHOICE
SCHED_CHOICE="${SCHED_CHOICE:-1}"

if [[ "$SCHED_CHOICE" == "1" ]]; then
  # ── systemd ─────────────────────────────────
  PYTHON_ABS="$(command -v "$PYTHON_CMD")"
  POSTER_ABS="$SCRIPT_DIR/poster.py"
  UNIT_DIR="$HOME/.config/systemd/user"
  mkdir -p "$UNIT_DIR"

  cat > "$UNIT_DIR/kambo-social.service" <<EOF
[Unit]
Description=Kambo Social Media Poster — post do dia
After=network-online.target

[Service]
Type=oneshot
ExecStart=$PYTHON_ABS $POSTER_ABS today
WorkingDirectory=$SCRIPT_DIR
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
EOF

  cat > "$UNIT_DIR/kambo-social.timer" <<EOF
[Unit]
Description=Kambo Social — dispara às 18h todo dia
Requires=kambo-social.service

[Timer]
OnCalendar=*-*-* 18:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

  if command -v systemctl &>/dev/null && systemctl --user daemon-reload 2>/dev/null; then
    systemctl --user enable --now kambo-social.timer
    echo "✅ systemd timer ativo: kambo-social.timer"
    echo "   Logs:    journalctl --user -u kambo-social.service -f"
    echo "   Status:  systemctl --user status kambo-social.timer"
    echo "   Parar:   systemctl --user disable --now kambo-social.timer"
  else
    echo "✅ Arquivos systemd criados em $UNIT_DIR"
    echo "   Para ativar manualmente:"
    echo "   systemctl --user daemon-reload"
    echo "   systemctl --user enable --now kambo-social.timer"
  fi

elif [[ "$SCHED_CHOICE" == "2" ]]; then
  # ── cron ────────────────────────────────────
  "$PYTHON_CMD" "$SCRIPT_DIR/poster.py" schedule install
  echo "✅ Cron job instalado"

else
  echo "ℹ️  Agendamento pulado."
  echo "   Para agendar depois:"
  echo "   $PYTHON_CMD $SCRIPT_DIR/poster.py schedule install"
fi

# ─────────────────────────────────────────────────
# 6. Teste dry-run
# ─────────────────────────────────────────────────
echo ""
echo "🔍 Rodando dry-run do post de hoje..."
echo ""
"$PYTHON_CMD" "$SCRIPT_DIR/poster.py" today --dry-run

# ─────────────────────────────────────────────────
# 7. Resumo
# ─────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ Setup concluído!                                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Próximos passos:"
echo "  1. Abra o Threads em seu Chrome e faça login"
echo "  2. Execute um teste real:"
echo "     $PYTHON_CMD $SCRIPT_DIR/poster.py today"
echo ""
echo "Outros comandos:"
echo "  $PYTHON_CMD $SCRIPT_DIR/poster.py list              # Ver todos os 30 posts"
echo "  $PYTHON_CMD $SCRIPT_DIR/poster.py day 5             # Post do dia 5"
echo "  $PYTHON_CMD $SCRIPT_DIR/poster.py schedule status   # Status do agendamento"
echo ""
