from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parent
AUDIT = ROOT / "data" / "codeguard_audit.jsonl"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/audit":
            events = []
            if AUDIT.exists():
                for line in AUDIT.read_text(encoding="utf-8").splitlines()[-100:]:
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
<meta charset="UTF-8">
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
.badge.block{background:#3a1620;color:#ff6b6b}
.badge.allow{background:#123024;color:#61e294}
.bars{display:flex;align-items:flex-end;gap:6px;height:120px;margin-top:16px}
.bar{flex:1;background:#3d5afe;border-radius:4px 4px 0 0;min-height:2px;position:relative}
.bar.block{background:#ff6b6b}
.policy-row{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #29345c}
button{background:#3d5afe;color:#fff;border:none;padding:12px 20px;border-radius:8px;cursor:pointer;font-size:14px}
button:hover{background:#5b73ff}
.sim-tag{background:#5b3a00;color:#ffc266;padding:2px 8px;border-radius:6px;font-size:11px;margin-left:8px}
</style>
</head>
<body>
<header><h1>🛡️ CodeGuard AI</h1><div class="sub">Understand → Predict → Govern → Prove → Execute → Verify → Audit</div></header>
<main>
<div class="cards">
<div class="card">Total Events<div id="total" class="number">0</div></div>
<div class="card">Blocked<div id="blocked" class="number block">0</div></div>
<div class="card">Allowed<div id="allowed" class="number allow">0</div></div>
</div>

<section>
<h2>Activity (last 20 events)</h2>
<div class="bars" id="bars"></div>
</section>

<section>
<h2>Try It Live</h2>
<p style="color:#9da9c9">Simulate a risky action and see CodeGuard's decision instantly.</p>
<button onclick="simulate('DROP TABLE users;')">Simulate: DROP TABLE</button>
<button onclick="simulate('git push --force origin main')" style="margin-left:10px">Simulate: Force Push</button>
<button onclick="simulate('API_KEY = \\'sk-12345\\'')" style="margin-left:10px">Simulate: Hardcoded Secret</button>
<div id="sim-result" style="margin-top:16px"></div>
</section>

<section><h2>Policy Breakdown</h2><div id="policies">Loading...</div></section>
<section><h2>Decision Center</h2><div id="events">Loading...</div></section>
</main>
<script>
let lastData = [];

async function load(){
 const r=await fetch('/api/audit'); const data=await r.json();
 lastData = data;
 document.getElementById('total').textContent=data.length;
 document.getElementById('blocked').textContent=data.filter(x=>x.decision==='BLOCK').length;
 document.getElementById('allowed').textContent=data.filter(x=>x.decision==='ALLOW').length;

 const recent = data.slice(-20);
 document.getElementById('bars').innerHTML = recent.map(x=>
   '<div class="bar '+(x.decision==='BLOCK'?'block':'')+'" style="height:'+(x.decision==='BLOCK'?'100%':'40%')+'" title="'+(x.tool||'')+': '+(x.decision||'')+'"></div>'
 ).join('') || '<span style="color:#9da9c9">No activity yet</span>';

 const policyCounts = {};
 data.forEach(x => (x.policy_ids||[]).forEach(p => policyCounts[p] = (policyCounts[p]||0)+1));
 const sorted = Object.entries(policyCounts).sort((a,b)=>b[1]-a[1]);
 document.getElementById('policies').innerHTML = sorted.length
   ? sorted.map(([p,c])=>'<div class="policy-row"><span>'+p+'</span><span>'+c+' triggers</span></div>').join('')
   : '<span style="color:#9da9c9">No policy triggers yet</span>';

 document.getElementById('events').innerHTML=data.slice().reverse().map(x=>
 '<div class="event"><span class="badge '+(x.decision==='BLOCK'?'block':'allow')+'">'+(x.decision||'EVENT')+
 '</span> &nbsp; '+(x.tool||'unknown')+(x.simulated?'<span class="sim-tag">SIMULATED</span>':'')+'<br><small>Policy: '+((x.policy_ids||[]).join(', ')||'None')+
 '<br>'+((x.reasons||[]).join('; ')||'No policy violation')+'</small></div>'
 ).join('') || 'No audit events yet.';
}

function simulate(action){
  const risky = action.includes('DROP TABLE') || action.includes('force') || action.includes('API_KEY');
  const decision = risky ? 'BLOCK' : 'ALLOW';
  const reasons = action.includes('DROP TABLE') ? ['Destructive database operation detected']
                : action.includes('force') ? ['Force-push to protected branch main']
                : action.includes('API_KEY') ? ['Hardcoded secret detected in code']
                : ['No policy violation'];
  const policy = action.includes('DROP TABLE') ? 'DATA-001'
               : action.includes('force') ? 'GIT-001'
               : 'SEC-001';
  document.getElementById('sim-result').innerHTML =
    '<div class="event" style="border:1px solid '+(risky?'#ff6b6b':'#61e294')+'">'+
    '<span class="badge '+(risky?'block':'allow')+'">'+decision+'</span>'+
    ' &nbsp; <code>'+action.replace(/</g,'&lt;')+'</code>'+
    '<br><small>Policy: '+policy+'<br>'+reasons.join('; ')+'</small></div>';
}

load(); setInterval(load,3000);
</script>
</body></html>"""
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    print("CodeGuard AI dashboard running at http://127.0.0.1:8000/")
    HTTPServer(("127.0.0.1",8000),Handler).serve_forever()