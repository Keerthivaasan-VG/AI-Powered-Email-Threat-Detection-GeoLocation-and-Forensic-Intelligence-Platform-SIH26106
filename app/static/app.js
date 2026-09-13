let inv=null, file=null, current="summary";
const $=s=>document.querySelector(s), result=$("#result"), err=$("#error");
$("#file").addEventListener("change",e=>select(e.target.files[0]));
$("#drop").addEventListener("dragover",e=>e.preventDefault());
$("#drop").addEventListener("drop",e=>{e.preventDefault();select(e.dataTransfer.files[0])});
function select(f){file=f;if(!f)return;if(!f.name.toLowerCase().endsWith(".eml"))return showError("Only .eml files are accepted.");if(f.size>10*1024*1024)return showError("The selected file exceeds the 10 MB upload limit.");err.hidden=true;$("#selected").hidden=false;$("#selected").textContent=`Selected: ${f.name} (${Math.ceil(f.size/1024)} KB)`;$("#analyze").disabled=false}
$("#analyze").onclick=async()=>{if(!file)return;$("#analyze").disabled=true;$("#analyze").textContent="Analyzing…";err.hidden=true;try{let fd=new FormData();fd.append("file",file);let r=await fetch("/api/investigations",{method:"POST",body:fd});let d=await r.json();if(!r.ok)throw Error(d.detail||d.error||"Analysis failed");inv=d;render()}catch(e){showError(e.message)}finally{$("#analyze").disabled=false;$("#analyze").textContent="Analyze Email"}};
document.querySelectorAll(".nav").forEach(b=>b.onclick=()=>{current=b.dataset.tab;document.querySelectorAll(".nav").forEach(x=>x.classList.remove("active"));b.classList.add("active");if(inv)render()});
async function health(){try{let r=await fetch("/health");let d=await r.json();$("#health").textContent="● System operational";$("#health").className="ok"}catch{$("#health").textContent="● Backend unavailable";$("#health").className="warn"}}health();
function esc(x){return String(x??"Not available").replace(/[&<>"]/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[m]))}
function card(title,body){return `<section class="card"><h2>${title}</h2>${body}</section>`}
function kv(obj){return `<table class="table"><tbody>${Object.entries(obj||{}).map(([k,v])=>`<tr><th>${esc(k)}</th><td>${typeof v==="object"?`<pre>${esc(JSON.stringify(v,null,2))}</pre>`:esc(v)}</td></tr>`).join("")}</tbody></table>`}
function render(){let e=inv.email,a=inv.assessment;let body="";
if(current==="summary")body=card("Investigation Summary",`<div class="grid"><div class="metric"><label>Investigation</label><strong class="mono">${esc(inv.investigationId)}</strong></div><div class="metric"><label>Status</label><strong>${esc(inv.status)}</strong></div><div class="metric"><label>Classification</label><strong>${esc(a.classification)}</strong></div><div class="metric"><label>Risk</label><strong>${esc(a.riskScore??"Cannot reliably determine")}</strong></div></div><p>${esc(a.reason)}</p><button class="primary" onclick="generateReport()">Generate PDF Report</button>`);
else if(current==="headers")body=card("Email Headers",kv(inv.headers)+`<h3>Raw headers</h3><pre>${esc(inv.headers.raw)}</pre>`);
else if(current==="auth")body=card("Authentication",kv(inv.authentication));
else if(current==="routing")body=card("Routing",kv(inv.routing));
else if(current==="indicators")body=card("Indicators",kv(inv.indicators));
else if(current==="intel")body=card("Threat Intelligence",kv(inv.intelligence));
else if(current==="threat")body=card("Threat Analysis",`<div class="grid"><div class="metric"><label>Classification</label><strong>${esc(a.classification)}</strong></div><div class="metric"><label>Confidence</label><strong>${esc(a.confidence)}</strong></div><div class="metric"><label>Risk Band</label><strong>${esc(a.riskBand)}</strong></div><div class="metric"><label>Findings</label><strong>${inv.findings.length}</strong></div></div>${inv.findings.map(f=>`<div class="finding"><b>${esc(f.name)}</b><p>${esc(f.finding)}</p><span class="badge">${esc(f.severity)}</span> <span class="badge">${esc(f.points)} points</span></div>`).join("")}`);
else if(current==="report")body=card("Forensic Report",inv.report?.reportId?`<p>Report generated: ${esc(inv.report.reportId)}</p><a href="/api/reports/${encodeURIComponent(inv.report.reportId)}.pdf" target="_blank">Open PDF report</a>`:`<p>No report generated yet.</p><button class="primary" onclick="generateReport()">Generate PDF Report</button>`);
else if(current==="qa")fetch("/api/qa/readiness").then(r=>r.json()).then(d=>result.innerHTML=card("QA / Readiness",kv(d))).catch(e=>showError(e.message));
else body=card("Email Information",kv(e));
result.innerHTML=body}
async function generateReport(){let r=await fetch(`/api/investigations/${encodeURIComponent(inv.investigationId)}/report`,{method:"POST"});let d=await r.json();if(!r.ok)showError(d.detail||"Report generation failed");else{inv.report=d;current="report";render()}}
function showError(m){err.textContent=m;err.hidden=false}
