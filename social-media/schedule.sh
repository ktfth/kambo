#!/usr/bin/env bash
# =============================================================================
# Kambo Social Media Scheduler
# Exibe o post do dia às 18h00 no terminal (stdout / notificação)
#
# Requer: python3 (para leitura do posts-map.json e cálculo de datas)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTS_DIR="$SCRIPT_DIR/posts"
POSTS_MAP="$SCRIPT_DIR/posts-map.json"
LOG_FILE="$SCRIPT_DIR/post-log.txt"
REPO_URL="https://github.com/ktfth/kambo"

# ─────────────────────────────────────────────────
# Pré-requisito: python3
# ─────────────────────────────────────────────────
require_python3() {
  if ! command -v python3 &>/dev/null; then
    echo "❌ python3 é necessário mas não foi encontrado." >&2
    echo "   Instale o Python 3.11+ e tente novamente." >&2
    exit 1
  fi
}

# ─────────────────────────────────────────────────
# Lê o arquivo de post para um dado dia (1-30)
# usando o posts-map.json como fonte única
# ─────────────────────────────────────────────────
get_post_file() {
  local day_num="$1"
  python3 - "$day_num" "$POSTS_MAP" <<'PYEOF'
import json, sys
day = int(sys.argv[1])
with open(sys.argv[2]) as f:
    m = json.load(f)
print(m.get(str(day), ""))
PYEOF
}

# ─────────────────────────────────────────────────
# Funções auxiliares
# ─────────────────────────────────────────────────

show_help() {
  cat <<EOF
Kambo Social Media Scheduler
Uso: $0 [COMANDO]

Comandos:
  today       Mostra o post do dia (baseado em dias desde o início)
  day N       Mostra o post do dia N (1-30)
  list        Lista todos os posts disponíveis
  install     Instala o cron job para executar às 18h00 diariamente
  uninstall   Remove o cron job
  status      Mostra o status do cron job
  help        Exibe esta ajuda

Exemplos:
  $0 today          # Post de hoje
  $0 day 5          # Post do dia 5
  $0 install        # Agenda às 18h todo dia
EOF
}

get_day_number() {
  require_python3

  local start_date="${KAMBO_START_DATE:-}"

  if [[ -f "$SCRIPT_DIR/.start-date" ]]; then
    start_date=$(cat "$SCRIPT_DIR/.start-date")
  elif [[ -z "$start_date" ]]; then
    start_date=$(date +%Y-%m-%d)
    echo "$start_date" > "$SCRIPT_DIR/.start-date"
  fi

  local today
  today=$(date +%Y-%m-%d)

  # python3 é portável em Linux e macOS (sem GNU date -d)
  local diff
  diff=$(python3 -c "
from datetime import date
print((date.fromisoformat('$today') - date.fromisoformat('$start_date')).days)
")

  printf "%02d" "$(( (diff % 30) + 1 ))"
}

show_post() {
  require_python3

  local day_num
  day_num=$(printf "%02d" "$1")

  local post_file
  post_file=$(get_post_file "$((10#$day_num))")

  if [[ -z "$post_file" ]]; then
    echo "❌ Dia $day_num não encontrado em $POSTS_MAP."
    exit 1
  fi

  local full_path="$POSTS_DIR/$post_file"
  if [[ ! -f "$full_path" ]]; then
    echo "❌ Arquivo não encontrado: $full_path"
    exit 1
  fi

  local platform
  if [[ "$post_file" == twitter/* ]];    then platform="🐦 TWITTER / X"
  elif [[ "$post_file" == linkedin/* ]]; then platform="💼 LINKEDIN"
  elif [[ "$post_file" == instagram/* ]];then platform="📸 INSTAGRAM"
  elif [[ "$post_file" == threads/* ]];  then platform="🧵 THREADS"
  else platform="📣 SOCIAL MEDIA"
  fi

  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  🐸 KAMBO — Post do Dia $day_num de 30 | $(date '+%d/%m/%Y %H:%M')       ║"
  echo "║  $platform"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  cat "$full_path"
  echo ""
  echo "─────────────────────────────────────────────────────────────"
  echo "🔗 Repositório: $REPO_URL"
  echo "📁 Arquivo: social-media/$post_file"
  echo "─────────────────────────────────────────────────────────────"

  echo "$(date '+%Y-%m-%d %H:%M:%S') | Dia $day_num | $platform | $post_file" >> "$LOG_FILE"
}

list_posts() {
  require_python3

  echo ""
  echo "📅 Posts disponíveis (30 dias):"
  echo ""

  python3 - "$POSTS_DIR" "$POSTS_MAP" <<'PYEOF'
import json, sys
from pathlib import Path

posts_dir = Path(sys.argv[1])
with open(sys.argv[2]) as f:
    post_map = json.load(f)

for day in range(1, 31):
    path = post_map.get(str(day), "N/A")
    status = "✅" if (posts_dir / path).exists() else "❌"
    if "twitter"   in path: icon = "🐦"
    elif "linkedin"  in path: icon = "💼"
    elif "instagram" in path: icon = "📸"
    elif "threads"   in path: icon = "🧵"
    else: icon = "❓"
    print(f"  Dia {day:02d}: {status} {icon} {path}")
PYEOF

  echo ""
}

install_cron() {
  local cron_cmd="0 18 * * * cd $SCRIPT_DIR && bash $SCRIPT_DIR/schedule.sh today >> $LOG_FILE 2>&1"

  if crontab -l 2>/dev/null | grep -q "# KamboSocialPoster"; then
    echo "⚠️  Cron job do Kambo já está instalado."
    echo "Use '$0 status' para verificar."
    return 0
  fi

  (crontab -l 2>/dev/null || true; echo "# KamboSocialPoster"; echo "$cron_cmd") | crontab -

  echo "✅ Cron job instalado com sucesso!"
  echo ""
  echo "📅 Agendamento: todo dia às 18h00"
  echo "📁 Log: $LOG_FILE"
  echo ""
  echo "Para verificar: crontab -l"
  echo "Para remover: $0 uninstall"
}

uninstall_cron() {
  if ! crontab -l 2>/dev/null | grep -q "# KamboSocialPoster"; then
    echo "ℹ️  Nenhum cron job do Kambo encontrado."
    return 0
  fi

  # Remove o marcador '# KamboSocialPoster' e a linha imediatamente seguinte
  crontab -l 2>/dev/null | awk '
    /# KamboSocialPoster/ { skip=1; next }
    skip { skip=0; next }
    { print }
  ' | crontab -

  echo "✅ Cron job removido com sucesso."
}

show_status() {
  echo ""
  echo "📊 Status do Kambo Social Scheduler"
  echo "────────────────────────────────────"

  if crontab -l 2>/dev/null | grep -q "# KamboSocialPoster"; then
    echo "🟢 Cron job: ATIVO (18h00 diário)"
  else
    echo "🔴 Cron job: INATIVO"
    echo "   Execute '$0 install' para ativar"
  fi

  echo ""
  echo "📁 Data de início do ciclo:"
  if [[ -f "$SCRIPT_DIR/.start-date" ]]; then
    echo "   $(cat "$SCRIPT_DIR/.start-date")"
  else
    echo "   Não iniciado ainda"
  fi

  echo ""
  echo "📅 Dia atual do ciclo: $(get_day_number)/30"

  echo ""
  echo "📝 Últimas 5 publicações:"
  if [[ -f "$LOG_FILE" ]]; then
    tail -5 "$LOG_FILE" | while read -r line; do
      echo "   $line"
    done
  else
    echo "   Nenhuma publicação registrada ainda"
  fi
  echo ""
}

# ─────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────
case "${1:-help}" in
  today)
    day=$(get_day_number)
    show_post "$((10#$day))"
    ;;
  day)
    if [[ -z "${2:-}" ]] || ! [[ "${2}" =~ ^[0-9]+$ ]] || (( "${2}" < 1 || "${2}" > 30 )); then
      echo "❌ Uso: $0 day N  (onde N é um número de 1 a 30)"
      exit 1
    fi
    show_post "${2}"
    ;;
  list)      list_posts ;;
  install)   install_cron ;;
  uninstall) uninstall_cron ;;
  status)    show_status ;;
  help|--help|-h) show_help ;;
  *)
    echo "❌ Comando desconhecido: ${1}"
    show_help
    exit 1
    ;;
esac
