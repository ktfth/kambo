#!/usr/bin/env bash
# preview-all.sh — Visualiza todos os 30 posts sem publicar nada
#
# Uso:
#   bash social-media/preview-all.sh          # todos os dias
#   bash social-media/preview-all.sh 1 7      # dias 1 a 7
#   bash social-media/preview-all.sh today    # somente hoje

set -euo pipefail
cd "$(dirname "$0")"

START=${1:-1}
END=${2:-30}

if [ "${START}" = "today" ]; then
  python poster.py today --dry-run
  exit 0
fi

for day in $(seq "$START" "$END"); do
  python poster.py day "$day" --dry-run
  echo ""
done

echo "✅ Preview completo: dias ${START}–${END}"
