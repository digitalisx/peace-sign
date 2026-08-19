#!/usr/bin/env bash
# SOAR 실습 랩 설치 스크립트
#   ./setup.sh          설치 또는 재설치 (기존 데이터 유지)
#   ./setup.sh --clean   n8n 계정·실행이력까지 전부 지우고 새로 설치
set -euo pipefail
cd "$(dirname "$0")"

WF_IDS=(soarLab1Triage01 soarLab2Block001 soarLab3Approve1 soarLab4Rollbk01)
CLEAN=0
[ "${1:-}" = "--clean" ] && CLEAN=1

say() { printf '\n\033[1m▶ %s\033[0m\n' "$*"; }

# ── 1. Docker 확인 ────────────────────────────────────────────────
say "Docker 확인"
if ! command -v docker >/dev/null; then
  echo "Docker 가 설치되어 있지 않다. https://www.docker.com/products/docker-desktop 에서 설치할 것."
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "  Docker 데몬이 꺼져 있다. Docker Desktop 을 실행한다..."
  open -a Docker 2>/dev/null || true
  for i in $(seq 1 90); do
    docker info >/dev/null 2>&1 && break
    sleep 1
  done
  docker info >/dev/null 2>&1 || { echo "  Docker 데몬을 시작하지 못했다. 수동으로 실행 후 다시 시도할 것."; exit 1; }
fi
echo "  OK — $(docker --version)"

# ── 2. 초기화 (선택) ──────────────────────────────────────────────
if [ "$CLEAN" = "1" ]; then
  say "기존 환경 삭제"
  docker compose down -v 2>/dev/null || true
  rm -rf n8n-data
  echo "  삭제 완료"
fi

# ── 3. 컨테이너 기동 ──────────────────────────────────────────────
say "컨테이너 빌드·기동 (처음이면 이미지 내려받느라 몇 분 걸린다)"
docker compose up -d --build

# ── 4. n8n 대기 ───────────────────────────────────────────────────
say "n8n 기동 대기"
for i in $(seq 1 90); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:5678/ 2>/dev/null || true)
  [ "$code" = "200" ] && { echo "  준비됨 (${i}s)"; break; }
  sleep 2
done
[ "$code" = "200" ] || { echo "  n8n 이 응답하지 않는다. docker compose logs n8n 확인할 것."; exit 1; }

# ── 5. 워크플로 import ────────────────────────────────────────────
say "실습 워크플로 4종 import"
docker exec soar-n8n n8n import:workflow --separate --input=/workflows 2>&1 | grep -v "Custom API" | tail -1

say "워크플로 활성화"
for id in "${WF_IDS[@]}"; do
  docker exec soar-n8n n8n publish:workflow --id="$id" >/dev/null 2>&1 && echo "  $id"
done

# ── 6. 재시작 (활성화 반영에 필요) ─────────────────────────────────
say "n8n 재시작 — 웹훅 등록 반영"
docker compose restart n8n >/dev/null 2>&1
for i in $(seq 1 90); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:5678/ 2>/dev/null || true)
  [ "$code" = "200" ] && break
  sleep 2
done
sleep 5

# ── 7. 동작 확인 ──────────────────────────────────────────────────
say "동작 확인"
curl -s -o /dev/null -w '  n8n        : HTTP %{http_code}\n' http://localhost:5678/
curl -s -o /dev/null -w '  lab-target : HTTP %{http_code}\n' http://localhost:8080/
resp=$(curl -sS -X POST http://localhost:5678/webhook/lab1-alert \
  -H 'Content-Type: application/json' \
  -d '{"rule":"setup check","severity":"low","src_ip":"8.8.8.8","host":"-","user":"-"}' 2>&1 || true)
if echo "$resp" | grep -q '"ok":true'; then
  echo "  플레이북    : 정상 (Lab 1 경보 처리 성공)"
else
  echo "  플레이북    : 실패 — $resp"
  exit 1
fi
curl -s http://localhost:8080/api/reset >/dev/null

cat <<'DONE'

────────────────────────────────────────────────────────────
 설치 완료

 n8n         http://localhost:5678   최초 1회 계정 생성 (로컬 전용, 아무 값이나)
 대상 시스템  http://localhost:8080   차단·케이스·알림 대시보드

 첫 실습
   ./scripts/send-alert.sh lab1 malicious
   ./scripts/lab-ctl.sh trace

 전체 진행 안내는 README.md 참고
────────────────────────────────────────────────────────────
DONE
