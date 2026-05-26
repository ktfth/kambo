#!/usr/bin/env bash
# =============================================================================
# Kambo — Notificação diária às 18h
# Exibe o post do dia no terminal e envia notificação desktop (notify-send)
#
# Uso direto:    bash notify-18h.sh
# Via schedule:  bash schedule.sh today
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTS_DIR="$SCRIPT_DIR/posts"
POSTS_MAP="$SCRIPT_DIR/posts-map.json"
LOG_FILE="$SCRIPT_DIR/post-log.jsonl"

# ─────────────────────────────────────────────────
# Calcula o dia do ciclo (1-30)
# ─────────────────────────────────────────────────
get_day_number() {
  if [[ ! -f "$SCRIPT_DIR/.start-date" ]]; then
    date +%Y-%m-%d > "$SCRIPT_DIR/.start-date"
  fi

  local start_date today diff
  start_date=$(cat "$SCRIPT_DIR/.start-date")
  today=$(date +%Y-%m-%d)
  diff=$(python3 -c "
from datetime import date
print((date.fromisoformat('$today') - date.fromisoformat('$start_date')).days)
")
  echo $(( (diff % 30) + 1 ))
}

# ─────────────────────────────────────────────────
# Extrai o texto do primeiro bloco de código
# ─────────────────────────────────────────────────
extract_post_text() {
  local file="$1"
  python3 - "$file" <<'PYEOF'
import sys, re

with open(sys.argv[1]) as f:
    content = f.read()

# Extrai o primeiro bloco de código entre ```
match = re.search(r'```\n(.*?)```', content, re.DOTALL)
if match:
    print(match.group(1).strip())
else:
    print(content.strip())
PYEOF
}

# ─────────────────────────────────────────────────
# Envia notificação desktop se disponível
# ─────────────────────────────────────────────────
send_desktop_notification() {
  local day="$1"
  local preview="$2"
  local short_preview="${preview:0:100}..."

  # notify-send (Linux com libnotify)
  if command -v notify-send &>/dev/null; then
    notify-send \
      --urgency=normal \
      --expire-time=10000 \
      --icon=dialog-information \
      "🐸 Kambo — Post do Dia $day/30" \
      "$short_preview"
    return 0
  fi

  # osascript (macOS)
  if command -v osascript &>/dev/null; then
    osascript -e "display notification \"$short_preview\" with title \"🐸 Kambo — Post do Dia $day/30\""
    return 0
  fi

  # Windows (PowerShell)
  if command -v powershell.exe &>/dev/null; then
    powershell.exe -Command "
      Add-Type -AssemblyName System.Windows.Forms
      \$notify = New-Object System.Windows.Forms.NotifyIcon
      \$notify.Icon = [System.Drawing.SystemIcons]::Information
      \$notify.BalloonTipTitle = '🐸 Kambo — Post do Dia $day/30'
      \$notify.BalloonTipText = '$short_preview'
      \$notify.Visible = \$true
      \$notify.ShowBalloonTip(5000)
    "
    return 0
  fi

  echo "ℹ️  notify-send/osascript não disponível — notificação apenas no terminal."
}

# ─────────────────────────────────────────────────
# Registra no log JSONL
# ─────────────────────────────────────────────────
log_notification() {
  local day="$1"
  local file="$2"
  local chars="$3"

  echo "{\"timestamp\": \"$(date -Iseconds)\", \"day\": $day, \"file\": \"$file\", \"chars\": $chars, \"status\": \"notified\"}" \
    >> "$LOG_FILE"
}

# ─────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────
main() {
  if ! command -v python3 &>/dev/null; then
    echo "❌ python3 é necessário." >&2
    exit 1
  fi

  local day
  day=$(get_day_number)

  # Obtém o caminho do post
  local post_rel
  post_rel=$(python3 -c "
import json, sys
with open('$POSTS_MAP') as f:
    m = json.load(f)
print(m.get('$day', ''))
")

  if [[ -z "$post_rel" ]]; then
    echo "❌ Dia $day não encontrado em posts-map.json." >&2
    exit 1
  fi

  local full_path="$POSTS_DIR/$post_rel"
  if [[ ! -f "$full_path" ]]; then
    echo "❌ Arquivo não encontrado: $full_path" >&2
    exit 1
  fi

  # Extrai o texto do post
  local post_text
  post_text=$(extract_post_text "$full_path")
  local chars=${#post_text}

  # Trunca se necessário (Threads: 500 chars)
  if (( chars > 500 )); then
    post_text="${post_text:0:497}..."
    chars=500
  fi

  # Exibe no terminal
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  printf "║  🐸 KAMBO — Post do Dia %02d/30 | %s       ║\n" "$day" "$(date '+%d/%m/%Y %H:%M')"
  echo "╠══════════════════════════════════════════════════════════════╣"
  echo "║  📱 THREADS — Pronto para publicar                          ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  echo "$post_text"
  echo ""
  echo "─────────────────────────────────────────────────────────────────"
  printf "📊 %d caracteres (Threads suporta até 500)\n" "$chars"
  echo "📁 $post_rel"
  echo ""
  echo "🚀 Para publicar automaticamente:"
  echo "   claude --chrome"
  echo "   → /kambo-social"
  echo "─────────────────────────────────────────────────────────────────"

  # Notificação desktop
  send_desktop_notification "$day" "$post_text"

  # Log
  log_notification "$day" "$post_rel" "$chars"
}

main "$@"
