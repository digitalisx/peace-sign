#!/usr/bin/env python3
"""n8n 실행 이력에서 노드별 로그(_log)를 꺼내 순서대로 출력한다.
   사용법: ./lab-ctl.sh trace [N]      N=1 이면 마지막 실행"""
import sqlite3, os, json, sys

N = int(sys.argv[1]) if len(sys.argv) > 1 else 1
db = os.path.expanduser("~/soar-lab/n8n-data/database.sqlite")
if not os.path.exists(db):
    sys.exit("n8n 데이터베이스를 찾을 수 없다: " + db)

c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
rows = c.execute("""select ed.executionId, ed.data, e.status, e.startedAt, w.name
                    from execution_data ed
                    join execution_entity e on e.id = ed.executionId
                    left join workflow_entity w on w.id = e.workflowId
                    order by ed.executionId desc limit ?""", (N,)).fetchall()
if not rows:
    sys.exit("실행 이력이 없다. 경보를 한 번 보내볼 것: ./scripts/send-alert.sh lab1 malicious")

eid, raw, status, started, wfname = rows[-1]

def unflatten(text):                       # n8n 은 flatted 포맷으로 저장한다
    arr, seen = json.loads(text), {}
    def resolve(v): return revive(int(v)) if isinstance(v, str) else v
    def revive(i):
        if i in seen: return seen[i]
        v = arr[i]
        if isinstance(v, dict):
            o = {}; seen[i] = o
            for k, val in v.items(): o[k] = resolve(val)
            return o
        if isinstance(v, list):
            o = []; seen[i] = o
            for val in v: o.append(resolve(val))
            return o
        seen[i] = v; return v
    return revive(0)

data = unflatten(raw)
run  = data["resultData"]["runData"]

print(f"실행 #{eid} · {wfname} · {status} · {started}")
print("─" * 78)
prev = []
for name, runs in run.items():
    try:
        j = runs[0]["data"]["main"][0][0]["json"]
    except Exception:
        print(f"▼ {name}  (출력 없음)"); continue
    ms = runs[0].get("executionTime", 0)
    logs = j.get("_log") if isinstance(j, dict) else None
    print(f"▼ {name}  [{ms}ms]")
    if not logs:
        print("     (로그 없음)"); continue
    fresh = [l for l in logs if l not in prev]      # 누적분은 새로 생긴 줄만 보여준다
    for l in (fresh or logs[-1:]):
        print("     " + (l if len(l) < 160 else l[:157] + "..."))
    prev = logs
