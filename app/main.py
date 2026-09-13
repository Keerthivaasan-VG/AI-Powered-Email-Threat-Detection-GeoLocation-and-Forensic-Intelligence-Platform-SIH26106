import json,hashlib,os,sqlite3
from pathlib import Path
from datetime import datetime,timezone
from fastapi import FastAPI,UploadFile,File,Form,HTTPException,Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from .modules.email_parser import parse_eml
from .modules.authentication import analyze as auth_analyze
from .modules.routing import analyze as route_analyze
from .modules.indicators import analyze as indicator_analyze
from .modules.intelligence import analyze as intel_analyze
from .modules.threat_analysis import analyze as threat_analyze
from .modules.security import hashes,verify,validate_filename
from .modules.report import generate as generate_report

ROOT=Path(__file__).resolve().parents[1]; DATA=ROOT/"data"; ACQ=DATA/"acquisitions"; REPORTS=DATA/"reports"
DB=DATA/"forensics.db"; ACQ.mkdir(parents=True,exist_ok=True);REPORTS.mkdir(parents=True,exist_ok=True)
app=FastAPI(title="Email Forensics — Integrated Platform",version="1.0.0")
app.mount("/static",StaticFiles(directory=ROOT/"app/static"),name="static")

def db():
    c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;return c
def init():
    c=db();c.execute("""CREATE TABLE IF NOT EXISTS investigations(id TEXT PRIMARY KEY, filename TEXT, sha256 TEXT, created_at TEXT, status TEXT, case_id TEXT, json TEXT, idempotency TEXT UNIQUE)""");c.execute("""CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT, timestamp TEXT, actor TEXT, action TEXT, status TEXT)""");c.commit();c.close()
init()
def now():return datetime.now(timezone.utc).isoformat()
def save(inv, idem=None):
    c=db();c.execute("INSERT OR REPLACE INTO investigations(id,filename,sha256,created_at,status,case_id,json,idempotency) VALUES(?,?,?,?,?,?,?,?)",
                     (inv["investigationId"],inv["source"]["filename"],inv["source"]["sha256"],inv["createdAt"],inv["status"],inv.get("caseId"),json.dumps(inv),idem));c.commit();c.close()
def get(iid):
    c=db();r=c.execute("SELECT json FROM investigations WHERE id=?",(iid,)).fetchone();c.close();return json.loads(r["json"]) if r else None
def audit(iid,action,status="SUCCESS",actor="SYSTEM"):
    c=db();c.execute("INSERT INTO audit(investigation_id,timestamp,actor,action,status) VALUES(?,?,?,?,?)",(iid,now(),actor,action,status));c.commit();c.close()

MODULES=["emailInformation","headers","authentication","routing","indicators","intelligence","threatAnalysis","report"]
@app.get("/health")
def health(): return {"status":"ok","application":"Email Forensics","version":"1.0.0"}
@app.get("/api/qa/readiness")
def readiness():
    return {"status":"READY_WITH_LIMITATIONS","checks":{
        "database":True,"evidenceStorage":True,"frontend":True,"reporting":True,
        "authentication":"NOT_CONFIGURED","externalThreatIntel":"CONFIGURED" if os.getenv("THREAT_INTEL_ENABLED","false").lower()=="true" else "NOT_CONFIGURED",
        "mlModel":"CONFIGURED" if (ROOT/"models/email_threat_classifier.joblib").exists() else "MODEL_UNAVAILABLE"}}
@app.post("/api/investigations")
async def create(request:Request,file:UploadFile=File(...),caseId:str|None=Form(None)):
    content=await file.read(); name=file.filename or ""
    try:validate_filename(name)
    except ValueError as e:raise HTTPException(400,str(e))
    if len(content)>10*1024*1024:raise HTTPException(413,"The selected file exceeds the 10 MB upload limit.")
    digest=hashlib.sha256(content).hexdigest(); idem=request.headers.get("X-Idempotency-Key")
    if idem:
        c=db();r=c.execute("SELECT json,sha256 FROM investigations WHERE idempotency=?",(idem,)).fetchone();c.close()
        if r:
            if r["sha256"]!=digest:raise HTTPException(409,"X-Idempotency-Key was already used for different content.")
            return json.loads(r["json"])
    iid=f"INV-{datetime.now(timezone.utc).year}-{digest[:8].upper()}"
    parsed=parse_eml(content,name); h=parsed["headers"]; email=parsed["email"]
    auth=auth_analyze(h); routing=route_analyze(h); indicators=indicator_analyze(parsed); intel=intel_analyze(indicators)
    threat=threat_analyze({"email":email,"headers":h,"authentication":auth,"routing":routing,"indicators":indicators,"intelligence":intel})
    inv={"investigationId":iid,"status":"COMPLETED","createdAt":now(),"caseId":caseId,
         "source":{"filename":name,"fileType":"eml",**hashes(content)},
         "modules":{m:{"status":"SUCCESS","completedAt":now(),"provider":"in_process"} for m in MODULES},
         "email":email,"headers":h,"authentication":auth,"routing":routing,"indicators":indicators,"intelligence":intel,
         "assessment":threat["assessment"],"findings":threat["findings"],"evidence":threat["evidence"],
         "recommendations":threat["recommendations"],"ruleResults":threat["ruleResults"],"scoreContributions":threat["scoreContributions"],
         "processingTimeline":[],"auditLog":threat["auditLog"],"security":{"evidenceHash":digest,"sha256":digest,"sha512":hashes(content)["sha512"],"hashAlgorithm":"SHA-256","chainOfCustody":"ACQUIRED"}}
    ACQ.joinpath(iid+".eml").write_bytes(content)
    save(inv,idem);audit(iid,"Investigation created");return inv
@app.get("/api/investigations")
def list_investigations(q:str|None=None):
    c=db();rows=c.execute("SELECT id,filename,sha256,created_at,status,case_id FROM investigations ORDER BY created_at DESC").fetchall();c.close()
    out=[dict(r) for r in rows]
    return [x for x in out if not q or q.lower() in x["id"].lower() or q.lower() in x["filename"].lower()]
@app.get("/api/investigations/{iid}")
def investigation(iid:str):
    x=get(iid)
    if not x:raise HTTPException(404,"Investigation not found")
    return x
@app.get("/api/investigations/{iid}/status")
def status(iid:str):
    x=investigation(iid);return {"investigationId":iid,"overallStatus":x["status"],"modules":{k:v["status"] for k,v in x["modules"].items()}}
@app.get("/api/investigations/{iid}/evidence")
def evidence(iid:str):return investigation(iid).get("evidence",[])
@app.get("/api/investigations/{iid}/audit")
def audit_log(iid:str):
    c=db();rows=c.execute("SELECT timestamp,actor,action,status FROM audit WHERE investigation_id=? ORDER BY id",(iid,)).fetchall();c.close();return [dict(r) for r in rows]
@app.post("/api/investigations/{iid}/verify")
async def verify_evidence(iid:str,file:UploadFile=File(...)):
    inv=investigation(iid);content=await file.read();return verify(content,inv["source"]["sha256"])
@app.post("/api/investigations/{iid}/report")
def report(iid:str):
    inv=investigation(iid);r=generate_report(inv,REPORTS);inv["report"]=r;save(inv);audit(iid,"Forensic report generated");return r
@app.get("/api/reports/{rid}.pdf")
def pdf(rid:str):
    p=REPORTS/(rid+".pdf")
    if not p.exists():raise HTTPException(404,"Report not found")
    return FileResponse(p,media_type="application/pdf",filename=p.name)
@app.get("/api/ml/status")
def ml_status():
    p=ROOT/"models/email_threat_classifier.joblib";return {"status":"CONFIGURED" if p.exists() else "MODEL_UNAVAILABLE","modelPath":str(p)}
@app.post("/api/ml/classify")
def ml_classify(payload:dict):
    p=ROOT/"models/email_threat_classifier.joblib"
    if not p.exists():return {"status":"MODEL_UNAVAILABLE","classification":None,"probability":None,"limitations":["No validated trained model is configured."]}
    import joblib
    subj=(payload.get("email") or {}).get("subject","");body=payload.get("body","")
    if not (subj.strip() or body.strip()):return {"status":"INSUFFICIENT_INPUT","limitations":["Subject and body are both empty."]}
    model=joblib.load(p);text=f"{subj}\n{body}".strip();probs=model.predict_proba([text])[0];classes=list(model.classes_);d={str(c):float(v) for c,v in zip(classes,probs)};c=max(d,key=d.get)
    return {"status":"SUCCESS","classification":c,"probability":d[c],"probabilities":d,"limitations":["Probabilistic prediction; final forensic assessment remains authoritative."]}
@app.get("/",include_in_schema=False)
def root():return FileResponse(ROOT/"app/static/index.html")
