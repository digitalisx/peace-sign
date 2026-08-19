#!/usr/bin/env bash
# 실습 환경 제어 유틸
set -euo pipefail
T="${LAB_TARGET:-http://localhost:8080}"
case "${1:-help}" in
  reset)     curl -sS "$T/api/reset" | head -3 ;;
  blocklist) curl -sS "$T/api/blocklist" ;;
  cases)     curl -sS "$T/api/cases" ;;
  audit)     curl -sS "$T/api/audit" ;;
  unblock)   curl -sS -X DELETE "$T/api/block/${2:?IP 필요}" ;;
  trace)     python3 "$(dirname "$0")/trace.py" "${2:-1}" ;;
  chaos)     curl -sS -X POST "$T/api/chaos" -H 'Content-Type: application/json' \
               -d "{\"mode\":\"${2:-none}\",\"target\":\"${3:-all}\"}" ;;
  *) cat <<'H'
사용법:
  ./lab-ctl.sh reset                 실습 상태 초기화(차단·케이스·알림 전부 삭제)
  ./lab-ctl.sh blocklist             현재 차단 목록
  ./lab-ctl.sh cases                 케이스 목록
  ./lab-ctl.sh audit                 감사 로그
  ./lab-ctl.sh unblock <IP>          수동 차단 해제
  ./lab-ctl.sh trace [N]             최근 N번째 실행의 노드별 로그 출력 (기본 1 = 마지막)
  ./lab-ctl.sh chaos 500 block       차단 API 가 500 을 반환하도록 장애 주입
  ./lab-ctl.sh chaos slow all        모든 API 8초 지연
  ./lab-ctl.sh chaos timeout block   차단 API 무응답(타임아웃 시연)
  ./lab-ctl.sh chaos none            장애 해제
H
;;
esac
