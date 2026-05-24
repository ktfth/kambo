#!/usr/bin/env bash
# =============================================================================
# Kambo Social Media Scheduler
# Exibe o post do dia às 18h00 no terminal (stdout / notificação)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTS_DIR="$SCRIPT_DIR/posts"
CALENDAR="$SCRIPT_DIR/calendar-30days.md"
LOG_FILE="$SCRIPT_DIR/post-log.txt"
REPO_URL="https://github.com/ktfth/kambo"

# ─────────────────────────────────────────────────
# Mapeamento dia → arquivo de post
# ─────────────────────────────────────────────────
declare -A POST_MAP=(
  [01]="twitter/dia-01-lancamento.md"
  [02]="twitter/dia-02-problema.md"
  [03]="linkedin/dia-03-solucao.md"
  [04]="twitter/dia-04-arquitetura.md"
  [05]="twitter/dia-05-instalacao.md"
  [06]="linkedin/dia-06-claudecode.md"
  [07]="twitter/dia-07-recap1.md"
  [08]="twitter/dia-08-recon.md"
  [09]="twitter/dia-09-scanning.md"
  [10]="linkedin/dia-10-vulns.md"
  [11]="twitter/dia-11-evidence.md"
  [12]="linkedin/dia-12-api.md"
  [13]="twitter/dia-13-cloud.md"
  [14]="instagram/dia-14-recap2.md"
  [15]="linkedin/dia-15-workflow.md"
  [16]="twitter/dia-16-scope.md"
  [17]="twitter/dia-17-cvss.md"
  [18]="linkedin/dia-18-selfimprove.md"
  [19]="twitter/dia-19-calibration.md"
  [20]="twitter/dia-20-postexploit.md"
  [21]="instagram/dia-21-recap3.md"
  [22]="linkedin/dia-22-contribuir.md"
  [23]="twitter/dia-23-tools.md"
  [24]="twitter/dia-24-ctf.md"
  [25]="twitter/dia-25-metrics.md"
  [26]="linkedin/dia-26-report.md"
  [27]="twitter/dia-27-tip-ssrf.md"
  [28]="twitter/dia-28-tip-takeover.md"
  [29]="linkedin/dia-29-roadmap.md"
  [30]="twitter/dia-30-cta.md"
)

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
  # Calcula o dia do ciclo (1-30) baseado na data atual
  # Você pode definir uma data de início alterando START_DATE
  START_DATE="${KAMBO_START_DATE:-$(date +%Y-%m-%d)}"

  # Se o arquivo .start-date existir, usa como referência
  if [[ -f "$SCRIPT_DIR/.start-date" ]]; then
    START_DATE=$(cat "$SCRIPT_DIR/.start-date")
  else
    # Primeira execução: salva a data de início
    echo "$START_DATE" > "$SCRIPT_DIR/.start-date"
  fi

  TODAY=$(date +%Y-%m-%d)

  # Calcula diferença em dias
  if command -v python3 &>/dev/null; then
    DIFF=$(python3 -c "from datetime import date; print((date.fromisoformat('$TODAY') - date.fromisoformat('$START_DATE')).days)")
  else
    # Fallback: usa date aritmética do sistema
    DIFF=$(( ($(date -d "$TODAY" +%s) - $(date -d "$START_DATE" +%s)) / 86400 ))
  fi

  # Ciclo de 30 dias (0-indexed → 1-indexed, loop)
  DAY_NUM=$(( (DIFF % 30) + 1 ))
  printf "%02d" "$DAY_NUM"
}

show_post() {
  local day_num
  day_num=$(printf "%02d" "$1")

  local post_file="${POST_MAP[$day_num]:-}"

  if [[ -z "$post_file" ]]; then
    echo "❌ Dia $day_num não encontrado no mapa de posts."
    exit 1
  fi

  local full_path="$POSTS_DIR/$post_file"

  if [[ ! -f "$full_path" ]]; then
    echo "❌ Arquivo não encontrado: $full_path"
    exit 1
  fi

  # Detecta a plataforma pelo caminho
  local platform
  if [[ "$post_file" == twitter/* ]]; then
    platform="🐦 TWITTER / X"
  elif [[ "$post_file" == linkedin/* ]]; then
    platform="💼 LINKEDIN"
  elif [[ "$post_file" == instagram/* ]]; then
    platform="📸 INSTAGRAM"
  else
    platform="📣 SOCIAL MEDIA"
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

  # Registra no log
  echo "$(date '+%Y-%m-%d %H:%M:%S') | Dia $day_num | $platform | $post_file" >> "$LOG_FILE"
}

list_posts() {
  echo ""
  echo "📅 Posts disponíveis (30 dias):"
  echo ""
  for i in $(seq 1 30); do
    day_num=$(printf "%02d" "$i")
    post_file="${POST_MAP[$day_num]:-N/A}"

    if [[ "$post_file" == twitter/* ]]; then
      icon="🐦"
    elif [[ "$post_file" == linkedin/* ]]; then
      icon="💼"
    elif [[ "$post_file" == instagram/* ]]; then
      icon="📸"
    else
      icon="❓"
    fi

    # Verifica se o arquivo existe
    if [[ -f "$POSTS_DIR/$post_file" ]]; then
      status="✅"
    else
      status="❌"
    fi

    echo "  Dia $day_num: $status $icon $post_file"
  done
  echo ""
}

install_cron() {
  local cron_cmd="0 18 * * * cd $SCRIPT_DIR && bash $SCRIPT_DIR/schedule.sh today >> $LOG_FILE 2>&1"

  # Verifica se já existe
  if crontab -l 2>/dev/null | grep -q "kambo.*schedule.sh"; then
    echo "⚠️  Cron job do Kambo já está instalado."
    echo "Use '$0 status' para verificar."
    return 0
  fi

  # Adiciona ao crontab
  (crontab -l 2>/dev/null || true; echo "$cron_cmd") | crontab -

  echo "✅ Cron job instalado com sucesso!"
  echo ""
  echo "📅 Agendamento: todo dia às 18h00"
  echo "📁 Log: $LOG_FILE"
  echo ""
  echo "Para verificar: crontab -l"
  echo "Para remover: $0 uninstall"
}

uninstall_cron() {
  if ! crontab -l 2>/dev/null | grep -q "kambo.*schedule.sh"; then
    echo "ℹ️  Nenhum cron job do Kambo encontrado."
    return 0
  fi

  crontab -l 2>/dev/null | grep -v "kambo.*schedule.sh" | crontab -
  echo "✅ Cron job removido com sucesso."
}

show_status() {
  echo ""
  echo "📊 Status do Kambo Social Scheduler"
  echo "────────────────────────────────────"

  if crontab -l 2>/dev/null | grep -q "kambo.*schedule.sh"; then
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
  list)
    list_posts
    ;;
  install)
    install_cron
    ;;
  uninstall)
    uninstall_cron
    ;;
  status)
    show_status
    ;;
  help|--help|-h)
    show_help
    ;;
  *)
    echo "❌ Comando desconhecido: ${1}"
    show_help
    exit 1
    ;;
esac
