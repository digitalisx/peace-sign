# SOAR 실습 랩 (n8n 기반)

n8n을 SOAR 엔진으로 쓰고, 별도의 목(mock) 대상 시스템에 실제로 조치를 반영하며
**수집 → 보강 → 판정 → 조치 → 기록 → 롤백** 전 과정을 손으로 만들어보는 실습 환경.

외부 API·계정·라이선스가 전혀 필요 없다. (평판 조회·방화벽·Slack·케이스 관리 모두 목업)

---

## 구성

| 서비스 | 주소 | 역할 |
|---|---|---|
| n8n | http://localhost:5678 | SOAR 엔진 — 플레이북 작성·실행 |
| Lab Target | http://localhost:8080 | 대상 시스템 — 차단 목록·케이스·알림·감사 로그 대시보드 |

Lab Target이 제공하는 API (n8n 컨테이너에서는 `http://lab-target:8080` 으로 접근)

```
GET    /api/reputation/<ip>   평판 조회        (AbuseIPDB/VirusTotal 대역)
POST   /api/block             차단 실행        (방화벽/EDR 대역, 멱등)
DELETE /api/block/<ip>        차단 해제        (롤백)
GET    /api/blocklist         차단 목록
POST   /api/cases             케이스 생성      (케이스 관리 대역)
PATCH  /api/cases/<id>        케이스 갱신
POST   /api/notify            알림 발송        (Slack/Discord 대역)
POST   /api/chaos             장애 주입        (커넥터 장애 시연)
GET    /api/reset             실습 상태 초기화
```

## 설치

### 사전 요구사항

- **Docker Desktop** (macOS / Windows / Linux) — 이것 하나뿐이다
  https://www.docker.com/products/docker-desktop
- 여유 디스크 약 2GB, 포트 **5678**·**8080** 이 비어 있을 것
- 인터넷 연결 (최초 1회 이미지 내려받기)

Python·Node·n8n 을 따로 설치할 필요 없다. 전부 컨테이너 안에서 돈다.

### 한 번에 설치

```bash
cd ~/soar-lab
./setup.sh
```

`setup.sh` 가 하는 일 — Docker 확인 및 자동 실행 → 이미지 빌드·기동 → n8n 대기 →
워크플로 4종 import → 활성화 → 재시작 → 경보 한 발 쏴서 동작 확인.
처음이면 이미지 내려받느라 3~5분 걸린다.

완전히 새로 시작하려면 (n8n 계정·실행 이력까지 삭제):

```bash
./setup.sh --clean
```

### 설치 후 첫 화면

1. http://localhost:5678 접속 → **최초 1회 계정 생성** (로컬 전용, 아무 값이나 입력)
2. 좌측 목록에 **Lab 1~4 워크플로가 이미 들어와 있고 전부 활성 상태**다
3. http://localhost:8080 을 옆 화면에 띄워둔다 (2초마다 자동 새로고침 — 시연용)

### 수강생에게 배포하기

`n8n-data/` 는 계정·실행 이력이 든 로컬 상태라 배포에 포함하지 않는다 (`.gitignore` 처리됨).

```bash
# 배포용 압축
cd ~ && tar czf soar-lab.tar.gz \
  --exclude='soar-lab/n8n-data' \
  --exclude='soar-lab/ai-soc/.venv' \
  soar-lab

# 수강생 쪽
tar xzf soar-lab.tar.gz && cd soar-lab && ./setup.sh
```

필요한 파일은 이게 전부다.

```
soar-lab/
├── setup.sh                 설치 스크립트
├── docker-compose.yml       n8n + lab-target
├── lab-target/              대상 시스템 목업 (표준 라이브러리만)
├── workflows/               플레이북 4종 (import 대상)
├── scripts/                 경보 발생기 · 제어 유틸 · 로그 뷰어
└── README.md
```

### 수동 설치 (setup.sh 없이)

```bash
docker compose up -d --build
# n8n 이 뜰 때까지 대기 후
docker exec soar-n8n n8n import:workflow --separate --input=/workflows
for id in soarLab1Triage01 soarLab2Block001 soarLab3Approve1 soarLab4Rollbk01; do
  docker exec soar-n8n n8n publish:workflow --id=$id
done
docker compose restart n8n      # 활성화 반영에 재시작이 필요하다
```

### 문제가 생기면

| 증상 | 원인 · 해결 |
|---|---|
| `port is already allocated` | 5678/8080 을 다른 프로세스가 쓰는 중. `lsof -i :5678` 로 확인 |
| 웹훅이 404 | 워크플로가 비활성. `publish:workflow` 후 **재시작**했는지 확인 |
| n8n 목록이 비어 있음 | 계정 생성 전이면 안 보인다. 계정 만든 뒤 새로고침 |
| `lab-target 에 접속할 수 없다` | `docker compose ps` 로 상태 확인, `docker compose logs lab-target` |
| 전부 꼬였을 때 | `./setup.sh --clean` |

## 중지·재시작

```bash
docker compose stop      # 중지 (데이터 유지)
docker compose start     # 재시작
docker compose down      # 컨테이너 제거 (n8n 데이터는 n8n-data/ 에 남음)
docker compose down -v   # 전부 삭제
```

## 경보 발생시키기

```bash
./scripts/send-alert.sh <lab1|lab2|lab3> <malicious|scanner|benign|internal>
```

### 프로덕션 URL vs 테스트 URL — 처음 반드시 헷갈리는 지점

n8n은 실행 경로가 두 개고, **캔버스가 움직이는 쪽은 테스트 URL 하나뿐이다.**

| | URL | 캔버스 | 확인 방법 |
|---|---|---|---|
| 프로덕션 | `/webhook/lab1-alert` | 움직이지 않음 | 좌측 **Executions** 목록 |
| 테스트 | `/webhook-test/lab1-alert` | 노드별 데이터 흐름이 보임 | 캔버스에서 바로 |

```bash
./scripts/send-alert.sh lab1 malicious          # 프로덕션 (기본)
TEST=1 ./scripts/send-alert.sh lab1 malicious   # 테스트 — 캔버스에서 흐름 관찰
```

테스트 모드는 화면에서 **Execute workflow** 를 누른 뒤 **1회만** 수신한다. 다음 경보를 보내려면 다시 눌러야 한다.

> 수업 진행 순서 — ① 테스트 모드로 한 발 보내 노드별 데이터 변화를 짚고
> ② 프로덕션 모드로 여러 발 보내 "경보는 사람이 버튼을 눌러서 들어오지 않는다"를 보여준 뒤
> ③ Executions 목록에 쌓인 실행 이력을 그대로 '지표·리포팅' 설명 재료로 쓴다

| 프리셋 | 출발지 IP | 평판 | 위험도 | 의도 |
|---|---|---|---|---|
| `malicious` | 45.155.205.233 | 95 | 94 | 정상적인 자동 차단 대상 |
| `scanner`   | 203.0.113.77   | 91 | 91 | **사내 취약점 스캐너** — 오탐 사고 재현용 |
| `benign`    | 8.8.8.8        | 0  | 15 | 자동 종결 |
| `internal`  | 192.168.10.55  | 0  | 35 | 내부 대역 경보 |

## 실습 제어

```bash
./scripts/lab-ctl.sh reset               # 차단·케이스·알림 전부 초기화
./scripts/lab-ctl.sh blocklist           # 차단 목록 조회
./scripts/lab-ctl.sh cases               # 케이스 목록
./scripts/lab-ctl.sh audit               # 감사 로그
./scripts/lab-ctl.sh unblock <IP>        # 수동 차단 해제
./scripts/lab-ctl.sh chaos 500 block     # 차단 API 가 500 을 반환 (커넥터 장애)
./scripts/lab-ctl.sh chaos slow all      # 모든 API 8초 지연
./scripts/lab-ctl.sh chaos timeout block # 차단 API 무응답
./scripts/lab-ctl.sh chaos none          # 장애 해제
```

---

# 로그 보기

모든 Code 노드에 로그 헬퍼 `L(...)` 이 들어 있고, HTTP 호출 뒤에는 **로그 전용 노드**가 붙어 있다
(`전송 결과 로그` · `차단 결과 로그` · `승인 응답 로그` · `롤백 결과 로그`).
데이터는 그대로 통과시키고 내용만 기록하므로 흐름에는 영향이 없다.

기록은 두 곳에서 보인다.

**① 노드 출력 패널의 `_log` 필드 — 모든 실행에서 남는다 (권장)**

노드 클릭 → 출력 패널 → **JSON** 탭 → `_log` 배열.
프로덕션 실행에도 남으므로 **Executions** 목록에서 지난 실행을 열어도 그대로 보인다.

```
▼ 위험도 산정
   경보  : SSH brute force · web-prod-01/deploy · severity=high → 가중치 55
   평판  : score=95 country=RU asn=AS49505 cats=[bruteforce,c2] internal=false
   계산  : round(95 × 0.7 + 55 × 0.5) = 94
   판정  : block  (임계값 80, 위험도 94)
▼ 차단 결과 로그
   방화벽 응답: {"ok":true,"idempotent":false,...}
   → 새로 차단했다
   !! 되돌리기 어려운 구간을 지났다. 오탐이면 Lab 4 롤백이 필요하다
```

`_log` 는 노드를 지나며 **누적**된다. 마지막 노드의 `_log` 를 펼치면 그 경보가 어떤 판단을 거쳐
어떤 조치까지 갔는지 한 줄로 읽힌다 — 케이스 관리에서 말하는 "판단 근거 기록"이 이것이다.

**② Code 노드의 `Logs` 탭 — 편집 화면에서 직접 실행할 때만**

`console.log` 출력은 실행 데이터에 저장되지 않는다. 화면에서 **Execute workflow** 로 실행할 때만
해당 Code 노드 출력 패널의 **Logs** 탭에 실시간으로 찍힌다.

```bash
# 화면에서 Execute workflow 를 누른 뒤
TEST=1 ./scripts/send-alert.sh lab1 malicious
```

> 정리 — 수업 중 실시간으로 보여줄 때는 ②(테스트 실행 + Logs 탭),
> 지나간 실행을 되짚을 때는 ①(Executions + `_log` 필드).

**③ 같은 내용을 터미널에서 보기**

```bash
./scripts/lab-ctl.sh trace          # 마지막 실행의 노드별 로그를 순서대로 출력
```

---

# 랩 진행 시나리오

## Lab 1 — 경보 트리아지 (수집 → 보강 → 판정 → 알림)

```
경보 수신(Webhook) → 경보 파싱(정규화) → 평판 조회(TI) → 위험도 산정 → 알림
```

```bash
./scripts/send-alert.sh lab1 malicious
./scripts/send-alert.sh lab1 benign
```

**짚을 것**
- 경보 파싱 노드 = SIEM마다 다른 필드를 공통 스키마로 맞추는 단계. 이게 없으면 뒤 노드가 전부 깨진다
- 위험도 산정 노드에서 `$('경보 파싱').first().json` 으로 앞 데이터를 참조 —
  HTTP 노드를 지나면 `$json` 이 응답으로 갈아끼워진다는 것이 n8n 실습의 첫 번째 벽
- 아직 아무것도 차단하지 않는다. **조회형 액션은 되돌릴 것이 없어 전면 자동화해도 안전하다**

## Lab 2 — 자동 차단과 오탐 (플레이북 · 자동화 · 예외 처리)

```
… → 위험도 산정 → [예외 목록 확인] → IF(차단 대상?) ─┬─ 차단 실행 → 케이스(blocked)
                                                     └─ 케이스(false_positive / held)
```

**2-1. 정상 차단**
```bash
./scripts/lab-ctl.sh reset
./scripts/send-alert.sh lab2 malicious
```
대시보드에 차단 1건 + CASE-0001(blocked) 생성 확인.

**2-2. 오탐 사고 재현 — 이 랩의 핵심**
```bash
./scripts/send-alert.sh lab2 scanner
```
사내 취약점 스캐너(203.0.113.77)가 외부 TI에 `scanner`로 등재돼 있어 평판 91 →
**위험도 91로 자동 차단된다.** 실제였다면 사내 스캔 업무가 그 순간 죽는다.

여기서 질문을 던진다 — *"경보도 맞고 평판도 맞는데 왜 사고가 났나?"*
→ 답: 플레이북에 **우리 환경에 대한 지식(예외 목록)** 이 없었다.

**2-3. 예외 목록 켜기**
n8n에서 Lab 2 워크플로를 열고 회색 처리된 **`예외 목록 확인`** 노드를 우클릭 → Activate.
(코드 안 `ALLOWLIST` 배열에 203.0.113.77 이 이미 들어 있다)

```bash
./scripts/lab-ctl.sh reset
./scripts/send-alert.sh lab2 scanner     # → held (사람 검토 대기)
./scripts/send-alert.sh lab2 malicious   # → blocked (정상 차단은 그대로)
```

**짚을 것**
- 오탐도 케이스로 기록한다. 조용히 지우면 같은 오탐이 영원히 반복된다
- 차단 API는 멱등이다. 같은 IP를 두 번 차단해도 상태가 같다 (`hits` 만 증가) —
  대량 경보에서 재시도가 안전하려면 대상 쪽이 멱등이어야 한다

**2-4. 커넥터 장애 (선택)**
```bash
./scripts/lab-ctl.sh chaos 500 block
./scripts/send-alert.sh lab2 malicious
```
차단 노드가 500을 받아 실행이 실패한다. n8n 좌측 **Executions** 에 빨간 실패 기록만 남고
케이스는 만들어지지 않는다 → *"플레이북 실패는 조용히 지나간다. 그래서 실패율을 지표로 봐야 한다."*
```bash
./scripts/lab-ctl.sh chaos none
```

## Lab 3 — 승인 게이트 (Human-in-the-Loop)

```
… → IF(차단 대상?) → 승인 요청 알림(승인/거부 링크) → Wait(웹훅 · 10분 타임아웃)
      → IF(승인?) ─┬─ 차단 실행 → 케이스(approved)
                   └─ 케이스(denied / timeout)
```

```bash
./scripts/lab-ctl.sh reset
./scripts/send-alert.sh lab3 malicious
```
대시보드 **알림** 카드에 `승인 — 차단 실행` / `거부 — 오탐 종결` 버튼이 뜬다.
누르면 대기 중이던 실행이 그 지점부터 재개된다.

- **승인** 클릭 → 차단 실행 + CASE(approved, approver 기록)
- **거부** 클릭 → 차단 없이 CASE(denied)
- **아무것도 안 누르고 10분 대기** → CASE(timeout) — *무응답의 기본 동작은 "차단하지 않음"* 으로 설계돼 있다

**짚을 것**
- 승인 링크는 `$execution.resumeUrl` — n8n이 실행별로 발급하는 재개 URL이다
- 기본 동작(타임아웃 시 진행 / 대기)을 정하지 않은 승인 게이트는 사고 대응을 멈춰 세운다
- 승인이 늘수록 자동화 효과는 줄어든다 → 반복 승인되는 액션은 자동 실행으로 승격하는 게 튜닝

## Lab 4 — 롤백

```bash
curl -X POST http://localhost:5678/webhook/lab-unblock \
  -H 'Content-Type: application/json' \
  -d '{"ip":"203.0.113.77","reason":"오탐 확인 — 사내 스캐너"}'
```

**짚을 것**
- 파급이 큰 액션에는 되돌리는 경로를 **함께** 만든다. 롤백 없는 자동 차단은 자동 장애다
- 차단 목록에 없는 IP를 해제해도 200을 준다 (멱등) — 롤백이 재시도돼도 안전해야 한다

---

# 구성요소 ↔ 실습 매핑

| SOAR 구성요소 | 실습에서 대응하는 것 |
|---|---|
| 오케스트레이션 | HTTP Request 노드로 목 방화벽·TI·케이스 API 연동 |
| 커넥터 | 각 API의 URL·메서드·바디를 감싼 노드들 |
| 플레이북 | 워크플로 캔버스 전체 |
| 자동화 | 평판 조회·차단 실행 노드의 무인 실행 |
| 승인 게이트 | Lab 3 의 알림 + Wait 노드 |
| 케이스 관리 | `/api/cases` 기록과 대시보드 케이스 카드 |
| 대응 | 차단 실행 / 차단 해제 |
| 협업 | `/api/notify` (Slack 대역) |
| 지표·리포팅 | n8n Executions 목록 + 대시보드 건수 |
| 플레이북 튜닝 | Lab 2-3 의 예외 목록 추가 |

# 이 실습으로 배울 수 없는 것 (마무리에 반드시 언급)

- **경보가 깨끗하다** — 필드 누락·스키마 불일치·중복 경보·초당 수백 건의 폭주가 없다
- **대상이 항상 200을 준다** — chaos 로 흉내는 내지만 부분 실패·권한 부족·설정 반영 지연은 없다
- **규모가 없다** — 큐잉·동시 실행 제한·실행 이력 보존 비용은 이 규모에서 드러나지 않는다
- **n8n에는 케이스 관리·RBAC·감사 추적·플레이북 버전 관리가 없다** —
  이번에 `/api/cases` 로 직접 만든 것이 상용 SOAR에서는 제품 기능으로 들어 있다

→ 마지막 10분은 상용 SOAR(XSOAR·Tines·Sentinel) 화면을 보여주고
"여러분이 손으로 만든 것 / 만들지 못한 것"으로 대조하면 실습이 강의로 닫힌다.

# 정리

```bash
docker compose down          # 중지
docker compose down -v       # 데이터까지 삭제
```

# 주의

- n8n Community 버전에는 RBAC·감사 로그가 없다. **실제 인프라 자격증명을 넣지 말 것**
- 실습 환경은 인증이 없으므로 로컬/격리 네트워크에서만 사용한다
- API 키를 쓰도록 확장할 경우 노드에 하드코딩하지 말고 n8n Credentials에 저장한다 (시크릿 관리)
