#!/usr/bin/env python3
"""
SOAR Lab Target — n8n 플레이북이 실제로 '조치'를 반영할 대상 시스템(목업).

제공 기능
  - 평판 조회 API   : 외부 TI 서비스(AbuseIPDB/VirusTotal) 대역
  - 차단 API        : 방화벽/EDR 대역 (차단 · 롤백 · 목록)
  - 케이스 API      : 케이스 관리 대역
  - 알림 API        : Slack/Discord 대역
  - 카오스 API      : 커넥터 장애(500 · 타임아웃 · 지연) 주입
  - 대시보드        : http://localhost:8080  (2초 자동 새로고침, 시연용)

외부 네트워크 의존이 전혀 없다. 표준 라이브러리만 사용.
"""
import hashlib
import ipaddress
import json
import threading
import time
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

KST = timezone(timedelta(hours=9))
LOCK = threading.Lock()

STATE = {
    "blocklist": {},        # ip -> {ip, reason, actor, blocked_at, hits}
    "cases": [],            # 케이스 관리 대역
    "notifications": [],    # 알림 대역
    "audit": [],            # 감사 로그(누가 무엇을 왜)
    "chaos": {"mode": "none", "target": "all"},
    "seq": {"case": 0},
}

# 실습용 고정 평판 — 재현 가능한 시연을 위해 하드코딩
FIXED_REPUTATION = {
    "45.155.205.233": {"score": 95, "country": "RU", "asn": "AS49505", "cats": ["bruteforce", "c2"]},
    "185.220.101.34": {"score": 88, "country": "DE", "asn": "AS205100", "cats": ["tor-exit", "scanner"]},
    "103.75.190.11":  {"score": 82, "country": "VN", "asn": "AS135905", "cats": ["malware-host"]},
    # 오탐 시연용 — 회사 소유 취약점 스캐너인데 외부 TI에는 '스캐너'로 등재돼 평판이 나쁘다
    "203.0.113.77":   {"score": 91, "country": "KR", "asn": "AS9318", "cats": ["scanner", "probe"]},
    "8.8.8.8":        {"score": 0,  "country": "US", "asn": "AS15169", "cats": []},
    "1.1.1.1":        {"score": 0,  "country": "AU", "asn": "AS13335", "cats": []},
}

ALLOWLIST_NOTE = "internal / RFC1918"


def now():
    return datetime.now(KST).isoformat(timespec="seconds")


def is_internal(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def reputation(ip):
    # 고정 샘플이 우선한다. 203.0.113.0/24 는 문서용 대역이라 파이썬이 private 로 보지만,
    # 실습에서는 '회사 소유 공인 IP' 역할이므로 여기서 먼저 처리한다.
    if ip in FIXED_REPUTATION:
        f = FIXED_REPUTATION[ip]
        return {"ip": ip, "score": f["score"], "country": f["country"], "asn": f["asn"],
                "categories": f["cats"], "internal": False, "note": "fixed sample"}
    if is_internal(ip):
        return {"ip": ip, "score": 0, "country": "-", "asn": "-",
                "categories": [], "internal": True, "note": ALLOWLIST_NOTE}
    # 그 외에는 IP 해시로 결정적 점수 생성(같은 IP는 항상 같은 점수)
    h = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
    score = h % 101
    cats = ["scanner"] if score > 60 else []
    return {"ip": ip, "score": score, "country": ["US", "CN", "NL", "BR", "IN"][h % 5],
            "asn": f"AS{10000 + h % 50000}", "categories": cats,
            "internal": False, "note": "derived"}


def audit(action, detail):
    STATE["audit"].insert(0, {"at": now(), "action": action, "detail": detail})
    del STATE["audit"][200:]


def apply_chaos(target):
    """커넥터 장애 주입. (mode, target) 이 맞으면 예외/지연 발생."""
    c = STATE["chaos"]
    if c["mode"] == "none":
        return None
    if c["target"] not in ("all", target):
        return None
    if c["mode"] == "500":
        return ("error", 500, {"error": "upstream device unavailable (chaos)"})
    if c["mode"] == "timeout":
        time.sleep(120)
        return None
    if c["mode"] == "slow":
        time.sleep(8)
        return None
    return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"[{now()}] {self.address_string()} {fmt % args}", flush=True)

    # ---------- helpers ----------
    def send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html, status=200):
        body = html.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode() or "{}")
        except json.JSONDecodeError:
            return {}

    # ---------- routes ----------
    def do_GET(self):
        u = urlparse(self.path)
        p, q = u.path.rstrip("/") or "/", parse_qs(u.query)

        if p == "/":
            return self.send_html(dashboard())
        if p == "/health":
            return self.send_json({"ok": True, "at": now()})
        if p.startswith("/api/reputation/"):
            ip = p.rsplit("/", 1)[-1]
            ch = apply_chaos("reputation")
            if ch:
                return self.send_json(ch[2], ch[1])
            return self.send_json(reputation(ip))
        if p == "/api/blocklist":
            with LOCK:
                return self.send_json({"count": len(STATE["blocklist"]),
                                       "items": list(STATE["blocklist"].values())})
        if p == "/api/cases":
            with LOCK:
                return self.send_json({"count": len(STATE["cases"]), "items": STATE["cases"]})
        if p == "/api/notifications":
            with LOCK:
                return self.send_json({"items": STATE["notifications"][:50]})
        if p == "/api/audit":
            with LOCK:
                return self.send_json({"items": STATE["audit"][:100]})
        if p == "/api/state":
            with LOCK:
                return self.send_json({"chaos": STATE["chaos"],
                                       "blocked": len(STATE["blocklist"]),
                                       "cases": len(STATE["cases"])})
        if p == "/api/reset":
            with LOCK:
                STATE["blocklist"].clear()
                STATE["cases"].clear()
                STATE["notifications"].clear()
                STATE["audit"].clear()
                STATE["seq"]["case"] = 0
                STATE["chaos"] = {"mode": "none", "target": "all"}
            return self.send_json({"ok": True, "msg": "lab state reset"})
        return self.send_json({"error": "not found", "path": p}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        p = u.path.rstrip("/") or "/"
        data = self.read_json()

        if p == "/api/block":
            ch = apply_chaos("block")
            if ch:
                return self.send_json(ch[2], ch[1])
            ip = str(data.get("ip", "")).strip()
            if not ip:
                return self.send_json({"error": "ip required"}, 400)
            with LOCK:
                exist = STATE["blocklist"].get(ip)
                if exist:                       # 멱등성: 두 번 차단해도 상태 동일
                    exist["hits"] += 1
                    audit("block(dup)", f"{ip} — 이미 차단됨, hits={exist['hits']}")
                    return self.send_json({"ok": True, "idempotent": True, "entry": exist})
                entry = {"ip": ip, "reason": data.get("reason", "-"),
                         "actor": data.get("actor", "n8n-playbook"),
                         "case_id": data.get("case_id"), "blocked_at": now(), "hits": 1}
                STATE["blocklist"][ip] = entry
                audit("block", f"{ip} — {entry['reason']} (by {entry['actor']})")
                if is_internal(ip):
                    audit("!! WARNING", f"{ip} 는 내부 대역이다 — 서비스 영향 가능")
            return self.send_json({"ok": True, "idempotent": False, "entry": entry}, 201)

        if p == "/api/cases":
            with LOCK:
                STATE["seq"]["case"] += 1
                cid = f"CASE-{STATE['seq']['case']:04d}"
                case = {
                    "id": cid, "created_at": now(), "updated_at": now(),
                    "alert": data.get("alert", "-"), "src_ip": data.get("src_ip", "-"),
                    "host": data.get("host", "-"), "user": data.get("user", "-"),
                    "risk_score": data.get("risk_score"), "verdict": data.get("verdict", "open"),
                    "action": data.get("action", "-"), "rationale": data.get("rationale", "-"),
                    "approver": data.get("approver"), "playbook": data.get("playbook", "-"),
                }
                STATE["cases"].insert(0, case)
                audit("case", f"{cid} 생성 — {case['verdict']} / {case['action']}")
            return self.send_json(case, 201)

        if p == "/api/notify":
            item = {"at": now(), "level": data.get("level", "info"),
                    "title": data.get("title", "(제목 없음)"),
                    "text": data.get("text", ""), "links": data.get("links", [])}
            with LOCK:
                STATE["notifications"].insert(0, item)
                del STATE["notifications"][100:]
                audit("notify", f"[{item['level']}] {item['title']}")
            return self.send_json({"ok": True, "delivered": item})

        if p == "/api/chaos":
            mode = data.get("mode", "none")
            if mode not in ("none", "500", "timeout", "slow"):
                return self.send_json({"error": "mode must be none|500|timeout|slow"}, 400)
            with LOCK:
                STATE["chaos"] = {"mode": mode, "target": data.get("target", "all")}
                audit("chaos", f"mode={mode} target={STATE['chaos']['target']}")
            return self.send_json({"ok": True, "chaos": STATE["chaos"]})

        return self.send_json({"error": "not found", "path": p}, 404)

    def do_PATCH(self):
        p = urlparse(self.path).path.rstrip("/")
        data = self.read_json()
        if p.startswith("/api/cases/"):
            cid = p.rsplit("/", 1)[-1]
            with LOCK:
                for c in STATE["cases"]:
                    if c["id"] == cid:
                        c.update({k: v for k, v in data.items() if k != "id"})
                        c["updated_at"] = now()
                        audit("case-update", f"{cid} — {data}")
                        return self.send_json(c)
            return self.send_json({"error": "case not found", "id": cid}, 404)
        return self.send_json({"error": "not found"}, 404)

    def do_DELETE(self):
        p = urlparse(self.path).path.rstrip("/")
        if p.startswith("/api/block/"):
            ip = p.rsplit("/", 1)[-1]
            with LOCK:
                entry = STATE["blocklist"].pop(ip, None)
            if entry:
                audit("unblock", f"{ip} — 롤백 완료")
                return self.send_json({"ok": True, "removed": entry})
            audit("unblock(miss)", f"{ip} — 차단 목록에 없음")
            return self.send_json({"ok": True, "removed": None, "note": "not in blocklist"})
        return self.send_json({"error": "not found"}, 404)


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def dashboard():
    with LOCK:
        bl = list(STATE["blocklist"].values())
        cases = STATE["cases"][:15]
        notis = STATE["notifications"][:12]
        audits = STATE["audit"][:20]
        chaos = dict(STATE["chaos"])

    def rows_block():
        if not bl:
            return "<tr><td colspan=5 class=empty>차단된 항목 없음</td></tr>"
        out = []
        for b in bl:
            warn = " class=warn" if is_internal(b["ip"]) else ""
            tag = " <span class=badge-red>내부대역</span>" if is_internal(b["ip"]) else ""
            out.append(f"<tr{warn}><td class=mono>{esc(b['ip'])}{tag}</td><td>{esc(b['reason'])}</td>"
                       f"<td>{esc(b['actor'])}</td><td class=mono>{esc(b.get('case_id') or '-')}</td>"
                       f"<td class=dim>{esc(b['blocked_at'][11:])}</td></tr>")
        return "".join(out)

    def rows_case():
        if not cases:
            return "<tr><td colspan=6 class=empty>케이스 없음</td></tr>"
        out = []
        for c in cases:
            v = c["verdict"]
            cls = {"blocked": "badge-red", "false_positive": "badge-gray",
                   "held": "badge-amber", "approved": "badge-red",
                   "denied": "badge-gray", "timeout": "badge-amber"}.get(v, "badge-blue")
            out.append(f"<tr><td class=mono>{esc(c['id'])}</td><td>{esc(c['alert'])}</td>"
                       f"<td class=mono>{esc(c['src_ip'])}</td><td class=mono>{esc(c['risk_score'])}</td>"
                       f"<td><span class={cls}>{esc(v)}</span></td><td class=dim>{esc(c['action'])}</td></tr>")
        return "".join(out)

    def list_noti():
        if not notis:
            return "<div class=empty>알림 없음</div>"
        out = []
        for n in notis:
            links = "".join(f"<a href='{esc(l['url'])}' target=_blank>{esc(l['label'])}</a>"
                            for l in n.get("links", []) if isinstance(l, dict))
            lv = {"critical": "badge-red", "warn": "badge-amber"}.get(n["level"], "badge-blue")
            out.append(f"<div class=noti><div><span class={lv}>{esc(n['level'])}</span> "
                       f"<b>{esc(n['title'])}</b> <span class=dim>{esc(n['at'][11:])}</span></div>"
                       f"<div class=notitext>{esc(n['text'])}</div><div class=links>{links}</div></div>")
        return "".join(out)

    def list_audit():
        if not audits:
            return "<div class=empty>기록 없음</div>"
        return "".join(f"<div class=aud><span class=dim>{esc(a['at'][11:])}</span> "
                       f"<b>{esc(a['action'])}</b> {esc(a['detail'])}</div>" for a in audits)

    chaos_txt = ("정상" if chaos["mode"] == "none"
                 else f"장애 주입 중 — mode={chaos['mode']}, target={chaos['target']}")
    chaos_cls = "ok" if chaos["mode"] == "none" else "bad"

    return f"""<!doctype html><html lang=ko><head><meta charset=utf-8>
<meta http-equiv=refresh content=2><title>SOAR Lab Target</title>
<style>
 :root{{--bg:#0f1117;--card:#171a23;--line:#262b38;--fg:#e6e9ef;--dim:#8a92a6}}
 *{{box-sizing:border-box}}
 body{{margin:0;padding:24px;background:var(--bg);color:var(--fg);
   font:14px/1.55 -apple-system,BlinkMacSystemFont,'Apple SD Gothic Neo',sans-serif}}
 h1{{margin:0 0 4px;font-size:19px}} h2{{margin:0 0 12px;font-size:14px;color:var(--dim);
   font-weight:600;letter-spacing:.04em;text-transform:uppercase}}
 .sub{{color:var(--dim);margin-bottom:18px;font-size:13px}}
 .grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
 .card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;overflow-x:auto}}
 .span2{{grid-column:1/-1}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 th{{text-align:left;color:var(--dim);font-weight:500;padding:6px 8px;border-bottom:1px solid var(--line)}}
 td{{padding:7px 8px;border-bottom:1px solid #1d2230}}
 tr.warn td{{background:#2a1417}}
 .mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}
 .dim{{color:var(--dim)}} .empty{{color:var(--dim);padding:14px 8px;text-align:center}}
 .badge-red{{background:#3a1620;color:#ff8f9e;padding:2px 7px;border-radius:5px;font-size:12px}}
 .badge-amber{{background:#3a2c12;color:#f2c14e;padding:2px 7px;border-radius:5px;font-size:12px}}
 .badge-gray{{background:#232838;color:#9aa3b8;padding:2px 7px;border-radius:5px;font-size:12px}}
 .badge-blue{{background:#12263a;color:#6fb3ff;padding:2px 7px;border-radius:5px;font-size:12px}}
 .noti{{border-bottom:1px solid #1d2230;padding:9px 0}} .notitext{{color:var(--dim);font-size:13px}}
 .links a{{display:inline-block;margin:6px 8px 0 0;padding:4px 10px;background:#1c2233;
   border:1px solid var(--line);border-radius:6px;color:#6fb3ff;text-decoration:none;font-size:12px}}
 .aud{{padding:4px 0;font-size:12.5px;border-bottom:1px solid #1a1f2c}}
 .status{{display:inline-block;padding:3px 10px;border-radius:6px;font-size:12px}}
 .ok{{background:#12301f;color:#5fd39a}} .bad{{background:#3a1620;color:#ff8f9e}}
</style></head><body>
<h1>SOAR Lab Target <span class="status {chaos_cls}">{esc(chaos_txt)}</span></h1>
<div class=sub>n8n 플레이북이 조치를 반영하는 대상 시스템 · 2초마다 자동 새로고침 · 차단 {len(bl)}건 / 케이스 {len(STATE['cases'])}건</div>
<div class=grid>
  <div class=card><h2>차단 목록 (방화벽 대역)</h2><table>
    <tr><th>IP</th><th>사유</th><th>실행 주체</th><th>케이스</th><th>시각</th></tr>{rows_block()}</table></div>
  <div class=card><h2>케이스 (케이스 관리 대역)</h2><table>
    <tr><th>ID</th><th>경보</th><th>출발지</th><th>점수</th><th>판정</th><th>조치</th></tr>{rows_case()}</table></div>
  <div class=card><h2>알림 (Slack 대역)</h2>{list_noti()}</div>
  <div class=card><h2>감사 로그</h2>{list_audit()}</div>
</div></body></html>"""


if __name__ == "__main__":
    print("SOAR Lab Target listening on :8080", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
