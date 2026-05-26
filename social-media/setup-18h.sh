#!/usr/bin/env bash
# =============================================================================
# Kambo — Setup do agendamento diário às 18h
#
# Suporta:
#   • systemd user timer (Linux — recomendado)
#   • crontab (Linux / macOS / WSL2 — fallback)
#
# Uso:
#   bash setup-18h.sh install    # Instala o agendamento
#   bash setup-18h.sh uninstall  # Remove o agendamento
#   bash setup-18h.sh status     # Mostra o status
#   bash setup-18h.sh test       # Exibe o post de hoje imediatamente
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOTIFY_SCRIPT="$SCRIPT_DIR/notify-18h.sh"
KAMBO_DIR="$(dirname "$SCRIPT_DIR")"

SERVICE_NAME="kambo-social"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"

# ─────────────────────────────────────────────────
show_help() {
  cat <<EOF

🐸 Kambo — Setup de publicação diária às 18h

Uso: bash $(basename "$0") [COMANDO]

Comandos:
  install     Instala o agendamento (systemd ou cron)
  uninstall   Remove o agendamento
  status      Mostra o status atual
  test        Exibe o post de hoje no terminal agora
  help        Esta mensagem

Exemplos:
  bash setup-18h.sh install    # Ativa postagem às 18h
  bash setup-18h.sh status     # Verifica se está ativo
  bash setup-18h.sh test       # Testa sem esperar as 18h

EOF
}

# ─────────────────────────────────────────────────
# systemd user timer (Linux recomendado)
# ─────────────────────────────────────────────────
install_systemd() {
  mkdir -p "$SYSTEMD_USER_DIR"

  # .service
  cat > "$SYSTEMD_USER_DIR/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Kambo — Post diário no Threads às 18h
After=network.target

[Service]
Type=oneshot
WorkingDirectory=$KAMBO_DIR
ExecStart=/usr/bin/env bash $NOTIFY_SCRIPT
StandardOutput=journal
StandardError=journal
EOF

  # .timer
  cat > "$SYSTEMD_USER_DIR/${SERVICE_NAME}.timer" <<EOF
[Unit]
Description=Kambo — Executa todo dia às 18h
Requires=${SERVICE_NAME}.service

[Timer]
OnCalendar=*-*-* 18:00:00
Persistent=true
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF

  systemctl --user daemon-reload
  systemctl --user enable --now "${SERVICE_NAME}.timer"

  echo ""
  echo "✅ systemd timer instalado com sucesso!"
  echo ""
  echo "📅 Executa todo dia às 18h00"
  echo "📋 Service: ${SERVICE_NAME}.service"
  echo "⏰ Timer:   ${SERVICE_NAME}.timer"
  echo ""
  echo "Comandos úteis:"
  echo "  systemctl --user status ${SERVICE_NAME}.timer"
  echo "  systemctl --user list-timers"
  echo "  journalctl --user -u ${SERVICE_NAME}.service -f"
  echo ""
}

# ─────────────────────────────────────────────────
# cron (fallback para macOS / WSL2 sem systemd)
# ─────────────────────────────────────────────────
install_cron() {
  local log_file="$SCRIPT_DIR/post-log-cron.txt"
  local cron_cmd="0 18 * * * bash $NOTIFY_SCRIPT >> $log_file 2>&1 # KamboSocial18h"

  if crontab -l 2>/dev/null | grep -q "# KamboSocial18h"; then
    echo "⚠️  Cron job do Kambo já está instalado."
    echo "   Use 'bash setup-18h.sh status' para verificar."
    return 0
  fi

  (crontab -l 2>/dev/null || true; echo "$cron_cmd") | crontab -

  echo ""
  echo "✅ Cron job instalado com sucesso!"
  echo ""
  echo "📅 Executa todo dia às 18h00"
  echo "📁 Log: $log_file"
  echo ""
  echo "Para verificar: crontab -l"
  echo "Para remover:   bash setup-18h.sh uninstall"
  echo ""
}

install_schedule() {
  chmod +x "$NOTIFY_SCRIPT"

  echo ""
  echo "🐸 Instalando agendamento diário às 18h..."
  echo ""

  # Tenta systemd primeiro (Linux com systemd)
  if command -v systemctl &>/dev/null && systemctl --user status &>/dev/null 2>&1; then
    echo "🔧 Usando systemd user timer (recomendado)..."
    install_systemd
  elif command -v crontab &>/dev/null; then
    echo "🔧 Usando crontab (fallback)..."
    install_cron
  else
    echo "❌ Nenhum método de agendamento disponível."
    echo ""
    echo "Opções manuais:"
    echo "  • Adicione ao seu ~/.bashrc: alias kambo-post='bash $NOTIFY_SCRIPT'"
    echo "  • Execute manualmente: bash $NOTIFY_SCRIPT"
    echo "  • Use Task Scheduler (Windows) com o arquivo windows-task.xml"
    exit 1
  fi

  echo "📝 Post de hoje para teste:"
  echo "   bash setup-18h.sh test"
}

uninstall_schedule() {
  local removed=0

  # Remove systemd timer
  if command -v systemctl &>/dev/null; then
    if systemctl --user is-enabled "${SERVICE_NAME}.timer" &>/dev/null 2>&1; then
      systemctl --user disable --now "${SERVICE_NAME}.timer" 2>/dev/null || true
      rm -f "$SYSTEMD_USER_DIR/${SERVICE_NAME}.service" \
            "$SYSTEMD_USER_DIR/${SERVICE_NAME}.timer"
      systemctl --user daemon-reload 2>/dev/null || true
      echo "✅ systemd timer removido."
      removed=1
    fi
  fi

  # Remove cron
  if command -v crontab &>/dev/null; then
    if crontab -l 2>/dev/null | grep -q "# KamboSocial18h"; then
      crontab -l 2>/dev/null | grep -v "# KamboSocial18h" | crontab -
      echo "✅ Cron job removido."
      removed=1
    fi
  fi

  if (( removed == 0 )); then
    echo "ℹ️  Nenhum agendamento Kambo encontrado."
  fi
}

show_status() {
  echo ""
  echo "📊 Status do Kambo Social Scheduler"
  echo "════════════════════════════════════"

  # systemd
  if command -v systemctl &>/dev/null && systemctl --user is-active "${SERVICE_NAME}.timer" &>/dev/null 2>&1; then
    echo ""
    echo "⏰ systemd Timer: 🟢 ATIVO"
    systemctl --user list-timers "${SERVICE_NAME}.timer" --no-pager 2>/dev/null || true
  elif command -v crontab &>/dev/null && crontab -l 2>/dev/null | grep -q "# KamboSocial18h"; then
    echo ""
    echo "⏰ Cron Job: 🟢 ATIVO"
    crontab -l 2>/dev/null | grep "# KamboSocial18h"
  else
    echo ""
    echo "⏰ Agendamento: 🔴 INATIVO"
    echo "   Execute 'bash setup-18h.sh install' para ativar"
  fi

  echo ""
  echo "📁 Data de início do ciclo:"
  if [[ -f "$SCRIPT_DIR/.start-date" ]]; then
    local start today diff day
    start=$(cat "$SCRIPT_DIR/.start-date")
    today=$(date +%Y-%m-%d)
    diff=$(python3 -c "from datetime import date; print((date.fromisoformat('$today') - date.fromisoformat('$start')).days)")
    day=$(( (diff % 30) + 1 ))
    echo "   Início: $start"
    echo "   Hoje é o dia $day/30 do ciclo"
  else
    echo "   Ciclo não iniciado (será criado no primeiro post)"
  fi

  echo ""
  echo "📝 Últimas 5 entradas no log:"
  if [[ -f "$SCRIPT_DIR/post-log.jsonl" ]]; then
    tail -5 "$SCRIPT_DIR/post-log.jsonl" | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line.strip())
        print(f\"  {d['timestamp']} | Dia {d['day']:02d} | {d['status']} | {d['file']}\")
    except: pass
"
  else
    echo "   Nenhum post registrado ainda"
  fi
  echo ""
}

# ─────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────
case "${1:-help}" in
  install)    install_schedule ;;
  uninstall)  uninstall_schedule ;;
  status)     show_status ;;
  test)       bash "$NOTIFY_SCRIPT" ;;
  help|--help|-h) show_help ;;
  *)
    echo "❌ Comando desconhecido: ${1}"
    show_help
    exit 1
    ;;
esac
