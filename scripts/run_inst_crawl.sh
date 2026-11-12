#!/usr/bin/env bash
# 기관 자료실 정기 수집 래퍼 (스케줄러용) — inst_crawl/README.md
#   scripts/run_inst_crawl.sh                 # 분기 정기 실행
#   scripts/run_inst_crawl.sh --only 한국장애인개발원
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"
LOCKFILE="$PROJECT_DIR/.run_inst_crawl.lock"
exec 9>"$LOCKFILE"
if ! flock -n 9; then echo "[$(date '+%F %T')] already running, skip" >&2; exit 0; fi
[ -f "$PROJECT_DIR/.venv/bin/activate" ] && . "$PROJECT_DIR/.venv/bin/activate"
if [ -f "$PROJECT_DIR/.env" ]; then set -a; . <(grep -E '^INST_[A-Z_]+=' "$PROJECT_DIR/.env"); set +a; fi
echo "[$(date '+%F %T')] run_inst_crawl start"
python -m inst_crawl.runner "$@"
rc=$?
echo "[$(date '+%F %T')] run_inst_crawl end exit=$rc"
exit $rc
