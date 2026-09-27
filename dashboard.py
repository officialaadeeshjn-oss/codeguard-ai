from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
AUDIT = ROOT / "data" / "codeguard_audit.jsonl"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/audit":
            events = []
            if AUDIT.exists():
                for line in AUDIT.read_text(encoding="utf-8").splitlines()[-50:]:
                    try:
                        events.append(json.loads(line))
                    except:
                        pass
            body = json.dumps(events).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
            return

        html = """<!DOCTYPE html>
<html>
<head>
<title>CodeGuard AI</title>
<style>
body{font-family:Arial;background:#0b1020;color:#eee;margin:0}
header{padding:24px 40px;background:#111936;border-bottom:1px solid #29345c}
h1{margin:0} .sub{color:#9da9c9;margin-top:6px}
main{padding:30px 40px;max-width:1200px;margin:auto}
.cards{display:flex;gap:16px;flex-wrap:wrap}
.card{background:#151d38;padding:20px;border-radius:12px;min-width:180px}
.number{font-size:30px;font-weight:bold;margin-top:8px}
.block{color:#ff6b6b}.allow{color:#61e294}
section{margin-top:28px;background:#151d38;padding:22px;border-radius:12px}
.event{padding:14px;border-bottom:1px solid #29345c}
.badge{font-weight:bold;padding:5px 9px;border-radius:6px}
</style>
</head>
<body>
<header><h1>??? CodeGuard AI</h1><div class="sub">Understand ? Predict ? Govern ? Prove ? Execute ? Verify ? Audit</div></header>
<main>
<div class="cards">
<div class="card">Total Events<div id="total" class="number">0</div></div>
<div class="card">Blocked<div id="blocked" class="number block">0</div></div>
<div class="card">Allowed<div id="allowed" class="number allow">0</div></div>
</div>
<section><h2>Decision Center</h2><div id="events">Loading...</div></section>
<section><h2>Trust & Audit</h2><p>Every tool action is evaluated against CodeGuard policies and recorded as a structured audit event.</p></section>
</main>
<script>
async function load(){
 const r=await fetch('/api/audit'); const data=await r.json();
 document.getElementById('total').textContent=data.length;
 document.getElementById('blocked').textContent=data.filter(x=>x.decision==='BLOCK').length;
 document.getElementById('allowed').textContent=data.filter(x=>x.decision==='ALLOW').length;
 document.getElementById('events').innerHTML=data.reverse().map(x=>
 '<div class="event"><span class="badge '+(x.decision==='BLOCK'?'block':'allow')+'">'+x.decision+
 '</span> &nbsp; '+(x.tool||'unknown')+'<br><small>Policy: '+((x.policy_ids||[]).join(', ')||'None')+
 '<br>'+((x.reasons||[]).join('; ')||'No policy violation')+'</small></div>'
 ).join('') || 'No audit events yet.';
}
load(); setInterval(load,3000);
</script>
</body></html>"""
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type","text/html")
        self.end_headers()
        self.wfile.write(body)

HTTPServer(("127.0.0.1",8000),Handler).serve_forever()
