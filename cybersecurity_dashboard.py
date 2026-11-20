#!/usr/bin/env python3
"""Read-only local CybersecurityAgent coverage dashboard (Python standard library only).

Usage:
  python cybersecurity_dashboard.py --report remediation/control-validation/coverage-report-v1.json
Optional: --history-dir remediation/control-validation --port 8765 --no-browser
No validators, test runners, or project files are modified.
"""
import argparse
import json
import threading
import webbrowser
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

MAX_BYTES = 10_000_000
MAX_HISTORY = 100

HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CybersecurityAgent · Control Coverage</title>
<style>
:root{font-family:Inter,Segoe UI,Arial,sans-serif;color:#e7edf8;background:#0b1220;font-size:14px}
*{box-sizing:border-box}body{margin:0}header{background:#111d30;border-bottom:1px solid #2c3b52;padding:21px max(20px,calc((100vw - 1280px)/2))}
.brand{display:flex;align-items:center;gap:12px}.logo{background:#2044ad;padding:11px;border-radius:12px;font-weight:800;letter-spacing:1px}.muted{color:#99a8c1}
h1{font-size:21px;margin:0}h2{font-size:16px;margin:0 0 15px}main{max-width:1320px;margin:auto;padding:26px 20px 60px}
.stats{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:13px;margin-bottom:20px}
.card,.panel{background:#131f32;border:1px solid #293a51;border-radius:13px;padding:19px}
.card .num{font-size:31px;font-weight:750;margin:11px 0 3px}.card .label{color:#aab8ce;font-size:12px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px}.panel{min-width:0}
.progress{height:13px;background:#2a3549;border-radius:8px;overflow:hidden;margin:14px 0 9px}
.fill{height:100%;background:#47c9a4}.barrow{display:grid;grid-template-columns:minmax(100px,150px) 1fr 72px;align-items:center;gap:12px;margin:13px 0}
.track{height:10px;background:#29374c;border-radius:8px;overflow:hidden}.pass{height:100%;background:#47c9a4}
.small{font-size:12px}.controls{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:15px}
input,select,button{background:#0b1628;border:1px solid #344761;border-radius:8px;color:#edf3ff;padding:10px;font:inherit}
input{flex:2;min-width:180px}select{flex:1;min-width:145px}button{cursor:pointer}
table{width:100%;border-collapse:collapse;text-align:left}th,td{padding:11px 9px;border-bottom:1px solid #2a394e}th{color:#aab8ce;font-size:12px;position:sticky;top:0;background:#131f32}
.scroll{overflow:auto;max-height:550px}.pill{display:inline-block;padding:5px 8px;border-radius:7px;font-size:11px;font-weight:650;background:#303d53;color:#c4d0e2}
.pill.good{background:#164b44;color:#a0f0d9}.pill.bad{background:#57332f;color:#ffbeb3}
footer{color:#9daac0;margin-top:20px;font-size:12px}.error{background:#5b252c;padding:16px;border-radius:8px;margin-bottom:15px}
@media(max-width:900px){.stats{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}}
</style></head><body>
<header><div class="brand"><div class="logo">CA</div><div><h1>CybersecurityAgent <span class="muted">/ Control Coverage</span></h1>
<div class="muted small">Read-only threat-model validation intelligence · local dashboard</div></div></div></header>
<main><div id="error"></div><section class="stats" id="stats"></section>
<div class="grid"><section class="panel"><h2>Validation progress</h2><div id="progress"></div></section>
<section class="panel"><h2>STRIDE coverage</h2><div id="stride"></div></section>
<section class="panel"><h2>Security domains</h2><div id="domains"></div></section>
<section class="panel"><h2>Validation history</h2><div id="history"></div></section></div>
<section class="panel"><h2>Test specification inventory</h2>
<div class="controls"><input id="search" type="search" placeholder="Search test ID, scenario, domain, STRIDE…">
<select id="status"><option value="">All statuses</option></select>
<select id="domain"><option value="">All domains</option></select>
<select id="stridefilter"><option value="">All STRIDE categories</option></select>
<button id="export">Export filtered CSV</button></div>
<div class="muted small" id="count"></div><div class="scroll"><table><thead><tr>
<th>Test ID</th><th>Scenario</th><th>Domain</th><th>STRIDE</th><th>Status</th><th>Pytest cases</th><th>Control effectiveness</th>
</tr></thead><tbody id="tbody"></tbody></table></div></section>
<footer id="foot"></footer></main>
<script>
const $=id=>document.getElementById(id);
const el=(tag,cls,txt)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(txt!==undefined)n.textContent=String(txt);return n};
let data,rows=[];
function add(parent,tag,cls,txt){let n=el(tag,cls,txt);parent.appendChild(n);return n}
function metric(name,value){let c=add($('stats'),'div','card');add(c,'div','label',name);add(c,'div','num',value)}
function category(target,key){let dest=$(target);dest.replaceChildren();let groups={};
 for(let r of rows){let k=String(r[key]||'Unspecified');(groups[k]??=[]).push(r)}
 let entries=Object.entries(groups).sort((a,b)=>b[1].length-a[1].length);
 if(!entries.length){add(dest,'p','muted','No data');return}
 for(let [name,items] of entries){let pass=items.filter(x=>x.status==='LOCAL_PASSED_REVIEW_REQUIRED').length;
 let line=add(dest,'div','barrow');add(line,'div','small',name);let track=add(line,'div','track');
 let fill=add(track,'div','pass');fill.style.width=(100*pass/items.length)+'%';
 add(line,'div','small muted',pass+' / '+items.length)}
}
function fillOptions(id,field){let s=$(id);for(let v of [...new Set(rows.map(r=>String(r[field]||'Unspecified')))].sort()){
 let o=add(s,'option','',v);o.value=v}}
function filtered(){let q=$('search').value.trim().toLowerCase();
 return rows.filter(r=>(!$('status').value||r.status===$('status').value)&&
 (!$('domain').value||String(r.domain||'Unspecified')===$('domain').value)&&
 (!$('stridefilter').value||String(r.stride||'Unspecified')===$('stridefilter').value)&&
 (!q||[r.test_id,r.scenario_id,r.domain,r.stride,r.status].some(x=>String(x||'').toLowerCase().includes(q))))}
const fields=['test_id','scenario_id','domain','stride','status','observed_pytest_cases','control_effectiveness'];
function renderTable(){let items=filtered(),body=$('tbody');body.replaceChildren();
 $('count').textContent=items.length+' of '+rows.length+' specifications shown';
 for(let r of items){let tr=add(body,'tr');for(let f of fields){
 let td=add(tr,'td');if(f==='status'){let state=String(r[f]||'');
 add(td,'span','pill '+(state==='LOCAL_PASSED_REVIEW_REQUIRED'?'good':state==='NOT_EXECUTED'?'':'bad'),state.replaceAll('_',' '))}
 else td.textContent=String(r[f]??'')}}}
function csvCell(v){let s=String(v??'');if(/^[\s]*[=+\-@]/.test(s))s="'"+s;return '"'+s.replaceAll('"','""')+'"'}
function exportCsv(){let lines=[fields.join(','),...filtered().map(r=>fields.map(f=>csvCell(r[f])).join(','))];
 let blob=new Blob([lines.join('\r\n')],{type:'text/csv;charset=utf-8'}),u=URL.createObjectURL(blob),a=el('a');a.href=u;a.download='cybersecurityagent-filtered-coverage.csv';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)}
async function init(){try{let res=await fetch('/api/data',{cache:'no-store'});if(!res.ok)throw Error('HTTP '+res.status);
 data=await res.json();rows=data.current.tests;let s=data.current.summary;
 metric('Threat scenarios',s.proposed_scenarios);metric('Security requirements',s.proposed_requirements);
 metric('Test specifications',s.proposed_test_specifications);metric('Locally passed specs',s.locally_passed_test_specifications);
 metric('Verified controls',s.verified_security_controls);
 let rate=rows.length?100*rows.filter(r=>r.status==='LOCAL_PASSED_REVIEW_REQUIRED').length/rows.length:0;
 add($('progress'),'div','','Local test-specification coverage: '+rate.toFixed(1)+'%');
 let track=add($('progress'),'div','progress');let fill=add(track,'div','fill');fill.style.width=rate+'%';
 add($('progress'),'div','muted small',s.locally_passed_test_specifications+' locally passed · '+s.not_executed+' not executed · '+s.local_failed_or_inconclusive+' failed/inconclusive');
 add($('progress'),'p','muted small','Passing local tests do not establish verified control effectiveness.');
 category('stride','stride');category('domains','domain');
 let h=$('history');if(!data.history.length)add(h,'p','muted','No historical reports found.');
 for(let item of data.history){let line=add(h,'div','barrow');add(line,'div','small',item.generated_at_utc||'Unknown date');
 let t=add(line,'div','track');let f=add(t,'div','pass');f.style.width=(item.proposed_test_specifications?100*item.locally_passed_test_specifications/item.proposed_test_specifications:0)+'%';
 add(line,'div','small muted',item.locally_passed_test_specifications+' / '+item.proposed_test_specifications)}
 for(let f of ['status','domain','stride'])fillOptions(f==='stride'?'stridefilter':f,f);
 for(let id of ['search','status','domain','stridefilter'])$(id).addEventListener('input',renderTable);
 $('export').addEventListener('click',exportCsv);renderTable();
 $('foot').textContent='Report generated: '+(s.generated_at_utc||'unknown')+' · '+(s.caveat||'');
 }catch(e){add($('error'),'div','error','Unable to load report: '+e.message)}}
init();
</script></body></html>"""

def read_report(path):
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"Report too large: {path}")
    with path.open(encoding="utf-8-sig") as f:
        report = json.load(f)
    if not isinstance(report, dict) or not isinstance(report.get("summary"), dict) or not isinstance(report.get("tests"), list):
        raise ValueError(f"Invalid coverage report: {path}")
    if report["summary"].get("artifact_type") != "threat_control_coverage_summary":
        raise ValueError(f"Unexpected report type: {path}")
    return report

def load_payload(report_path, history_dir):
    current = read_report(report_path)
    history = []
    if history_dir is not None:
        for path in history_dir.glob("coverage-report*.json"):
            try:
                item = read_report(path)["summary"]
                history.append({k: item.get(k) for k in (
                    "generated_at_utc", "proposed_test_specifications",
                    "locally_passed_test_specifications")})
            except (OSError, ValueError, json.JSONDecodeError):
                continue
    else:
        item = current["summary"]
        history.append({k: item.get(k) for k in (
            "generated_at_utc", "proposed_test_specifications",
            "locally_passed_test_specifications")})
    history.sort(key=lambda x: str(x.get("generated_at_utc") or ""))
    return {"current": current, "history": history[-MAX_HISTORY:]}

def serve(report_path, history_dir, host, port, open_browser):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            route = urlsplit(self.path).path
            if route == "/":
                raw, kind = HTML.encode("utf-8"), "text/html; charset=utf-8"
            elif route == "/api/data":
                try:
                    raw = json.dumps(load_payload(report_path, history_dir), ensure_ascii=False).encode("utf-8")
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    self.send_error(500, str(exc))
                    return
                kind = "application/json; charset=utf-8"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(raw)
        def log_message(self, format, *args):
            pass
    server = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{server.server_port}/"
    print(f"CybersecurityAgent dashboard: {url}", flush=True)
    print(f"Reading report: {report_path}", flush=True)
    if open_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--history-dir", type=Path)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    report = args.report.resolve(strict=True)
    history = args.history_dir.resolve(strict=True) if args.history_dir else None
    read_report(report)
    if history is not None and not history.is_dir():
        parser.error("--history-dir must be a directory")
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    serve(report, history, "127.0.0.1", args.port, not args.no_browser)

if __name__ == "__main__":
    main()
