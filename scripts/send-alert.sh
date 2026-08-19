#!/usr/bin/env bash
# SIEM 경보 발생기 — n8n 웹훅으로 가짜 경보를 쏜다.
#   사용법: ./send-alert.sh <lab1|lab2|lab3> <malicious|scanner|benign|internal|custom> [IP]
#
#   TEST=1 을 붙이면 테스트 URL(/webhook-test/)로 보낸다.
#   이때는 n8n 화면에서 'Execute workflow' 를 먼저 눌러 대기 상태로 만들어야 하며,
#   캔버스에서 노드별 데이터 흐름이 실시간으로 보인다.
#     예) TEST=1 ./send-alert.sh lab1 malicious
set -euo pipefail

LAB="${1:-lab1}"
CASE="${2:-malicious}"
N8N="${N8N_URL:-http://localhost:5678}"
if [ "${TEST:-0}" = "1" ]; then
  URL="$N8N/webhook-test/${LAB}-alert"   # 캔버스에서 흐름이 보인다 (Execute workflow 선행 필요)
else
  URL="$N8N/webhook/${LAB}-alert"        # 프로덕션 — 결과는 Executions 목록에만 남는다
fi

case "$CASE" in
  malicious)  # 평판 95 · 실제 차단 대상
    IP="45.155.205.233"; RULE="SSH brute force (다중 실패 후 성공)"; SEV="high"
    HOST="web-prod-01"; USER="deploy" ;;
  scanner)    # 평판 91 · 사내 취약점 스캐너 → 오탐 시연용
    IP="203.0.113.77";  RULE="Port scan detected (1024 ports/60s)"; SEV="high"
    HOST="dmz-gw";      USER="-" ;;
  benign)     # 평판 0 · 정상 종결
    IP="8.8.8.8";       RULE="Outbound DNS anomaly"; SEV="medium"
    HOST="office-nb-12"; USER="dhkim" ;;
  internal)   # 내부 대역 경보
    IP="192.168.10.55"; RULE="Lateral movement suspected (SMB)"; SEV="critical"
    HOST="fin-srv-02";  USER="svc_backup" ;;
  custom)
    IP="${3:?custom 은 IP 인자가 필요하다}"; RULE="Manual test alert"; SEV="high"
    HOST="lab-host";    USER="tester" ;;
  *) echo "unknown case: $CASE"; exit 1 ;;
esac

BODY=$(cat <<JSON
{"alert_id":"ALERT-$(date +%s)","rule":"$RULE","severity":"$SEV",
 "src_ip":"$IP","host":"$HOST","user":"$USER","sensor":"lab-siem"}
JSON
)

echo "→ POST $URL"
echo "  $IP · $SEV · $RULE"
curl -sS -X POST "$URL" -H 'Content-Type: application/json' -d "$BODY" -w '\n[HTTP %{http_code}]\n'
echo "  대시보드 확인: http://localhost:8080"
if [ "${TEST:-0}" != "1" ]; then
  echo "  실행 내역   : http://localhost:5678 → 좌측 Executions"
fi
