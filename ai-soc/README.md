# AI SOC 트리아지 에이전트 (LangChain + Claude)

SOAR 실습 랩(`../`)에 붙는 최소 예제. 경보 하나를 받아 **조사하고 판정까지만** 하고,
조치는 사람 승인 뒤 스크립트가 실행한다.

## 설계에서 드러내려는 것 3가지

**1. 모델에게 준 도구는 전부 조회형이다**

| 모델이 쓸 수 있는 도구 | 모델이 쓸 수 없는 것 |
|---|---|
| `lookup_reputation` — 외부 평판 조회 | 차단 (`POST /api/block`) |
| `check_blocklist` — 현재 차단 여부 | 케이스 종결 |
| `lookup_asset` — 사내 자산 대장 조회 | 롤백 |
| `search_past_cases` — 과거 케이스 이력 | |

되돌릴 수 있는 일만 맡긴다. 차단은 `execute()` 함수 안에만 있고, 그 함수는 도구로 등록하지 않았다.

**2. 근거 없는 결론을 못 내게 스키마로 막았다**

`TriageVerdict` 에 `evidence: list[str]` 를 필수 필드로 두고 "도구로 확인한 사실만" 쓰게 했다.
출처 없는 판단은 분석가가 전부 재검증해야 해서 오히려 일이 늘어난다.

**3. 경보 본문을 신뢰하지 않는다**

경보의 `rule`·`host`·`user` 는 공격자가 채워 넣을 수 있는 값이다.
`<alert>` 태그로 감싸 데이터임을 명시하고, 시스템 프롬프트에서 그 안의 지시문을 따르지 말라고 못박았다.
`--alert injection` 으로 시연할 수 있다.

## 실행

랩이 떠 있어야 한다.

```bash
cd ~/soar-lab && docker compose up -d
```

**API 키 없이 배선만 확인**

```bash
cd ~/soar-lab/ai-soc
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python triage_agent.py --alert scanner --offline
```

**LLM 으로 실제 조사**

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python triage_agent.py --alert malicious      # 외부 공격자 → block 권고 → 승인 요청
python triage_agent.py --alert scanner        # 사내 스캐너 → 자산 조회로 오탐 판별
python triage_agent.py --alert injection      # 프롬프트 인젝션 시연
```

결과는 대시보드 http://localhost:8080 의 케이스·차단 목록에 그대로 반영된다.

## 프리셋

| 프리셋 | IP | 상황 | 기대 동작 |
|---|---|---|---|
| `malicious` | 45.155.205.233 | 평판 95, 사내 자산 아님 | true_positive → block 권고 |
| `scanner` | 203.0.113.77 | 평판 91, **사내 취약점 스캐너** | 자산 조회로 false_positive 판별 |
| `benign` | 8.8.8.8 | 평판 0 | false_positive → close |
| `internal` | 192.168.10.55 | 내부 회계 서버 | 파급 범위 경고 |
| `injection` | 45.155.205.233 | 경보 본문에 지시문 주입 | 지시 무시 + `injection_suspected: true` |

## 코드 구조

```
경보 → SystemMessage + <alert> 데이터
      → llm.bind_tools(조회형 4종)
      → 도구 호출 루프 (최대 8턴, 실무의 실행 상한과 같은 역할)
      → llm.with_structured_output(TriageVerdict)   ← 근거 필수 스키마
      → show()      판정 출력
      → execute()   ← 여기서만 차단. 승인 게이트 통과 시에만 실행
```

**LangChain 요소 ↔ SOAR 구성요소**

| 코드 | SOAR |
|---|---|
| `@tool` 함수들 | 커넥터 |
| `bind_tools` + 호출 루프 | 플레이북의 조사 단계 |
| `TriageVerdict` 스키마 | 판정 기록 규격 |
| `input("실행할까?")` | 승인 게이트 |
| `POST /api/cases` | 케이스 관리 |
| 최대 8턴 제한 | 실행 상한 · 비용 통제 |

## 이 예제에 없는 것 (강의에서 짚을 것)

- **평가셋이 없다** — 프롬프트나 모델을 바꿨을 때 성능이 떨어져도 알 방법이 없다.
  과거 종결 케이스를 정답셋으로 삼는 회귀 측정이 실무에서는 필수다.
- **관측성이 없다** — 어떤 프롬프트가 나갔고 토큰을 얼마나 썼는지 기록하지 않는다.
- **비용·지연 통제가 없다** — 경보 건당 토큰 비용이 곧 처리량 한계가 된다.
- **자산 대장이 하드코딩** — 실제로는 CMDB·IAM 연동이 필요하고, 그 연동 품질이 판정 품질을 좌우한다.
