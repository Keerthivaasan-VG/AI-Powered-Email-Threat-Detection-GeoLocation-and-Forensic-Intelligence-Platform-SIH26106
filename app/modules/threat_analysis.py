from datetime import datetime,timezone
def now(): return datetime.now(timezone.utc).isoformat()
def evidence(payload):
    out=[]; n=1
    def add(cat,typ,val,src,field=None):
        nonlocal n
        out.append({"id":f"EV-{n:03d}","category":cat,"type":typ,"field":field or typ.lower(),"value":val,"source":src,"origin":"supplied","verified":True});n+=1
    auth=payload.get("authentication",{})
    for f in ("spf","dkim","dmarc"):
        v=auth.get(f,{}); v=v.get("status") if isinstance(v,dict) else v
        if v and v!="NOT_AVAILABLE": add("authentication",f.upper(),v,"Authentication-Results",f)
    inds=payload.get("indicators",{})
    for o in inds.get("observations",[]):
        reason=o.get("reason","").lower()
        typ="url_uses_ip" if "ip address" in reason else "punycode_hostname" if "punycode" in reason else "non_standard_url_port" if "non-standard port" in reason else "from_replyto_domain_mismatch" if "reply-to" in reason else "structural_observation"
        add("url" if typ.startswith(("url_","punycode")) else "email",typ,True,o.get("source","indicators"))
    for a in inds.get("attachments",[]):
        if a.get("category")=="EXECUTABLE": add("attachment","executable_attachment",True,"indicators")
        if a.get("category")=="SCRIPT": add("attachment","script_attachment",True,"indicators")
        for o in a.get("observations",[]):
            if "multiple file" in o.get("reason","").lower(): add("attachment","double_extension",True,"indicators")
    intel=payload.get("intelligence",{})
    for coll,typ in [("urls","malicious_url"),("domains","malicious_domain"),("ips","malicious_ip"),("blacklists","blacklist")]:
        vals=intel.get(coll,[])
        if isinstance(vals,list):
            for x in vals:
                if isinstance(x,dict) and str(x.get("verdict","")).upper() in {"MALICIOUS","BLACKLISTED"} and x.get("verified"):
                    add("intelligence",typ,x.get("value",True),x.get("source","threat-intelligence"))
    return out
RULES=[
("AUTH-001","SPF Failure","spf","FAIL",10,"MEDIUM"),("AUTH-002","DKIM Failure","dkim","FAIL",10,"MEDIUM"),("AUTH-003","DMARC Failure","dmarc","FAIL",15,"HIGH"),
]
def analyze(payload):
    ev=evidence(payload); findings=[]; contrib=[]
    def match(typ,val=None):
        return next((e for e in ev if e["type"]==typ and (val is None or str(e["value"]).upper()==val)),None)
    for rid,name,field,val,pts,sev in RULES:
        e=match(field.upper(),val)
        if e: findings.append({"ruleId":rid,"name":name,"status":"TRIGGERED","severity":sev,"confidence":"HIGH","evidenceIds":[e["id"]],"points":pts,"finding":f"{name} observed."});contrib.append({"ruleId":rid,"evidenceId":e["id"],"points":pts})
    extra=[("AUTH-004","From/Reply-To Domain Mismatch","from_replyto_domain_mismatch",10,"MEDIUM"),("URL-001","URL Uses IP Address","url_uses_ip",10,"LOW"),
           ("URL-002","Punycode Hostname","punycode_hostname",5,"LOW"),("URL-003","Non-standard URL Port","non_standard_url_port",5,"LOW"),
           ("ATTACH-001","Executable Attachment","executable_attachment",15,"HIGH"),("ATTACH-002","Script Attachment","script_attachment",15,"HIGH"),("ATTACH-003","Double Extension","double_extension",10,"MEDIUM")]
    for rid,name,typ,pts,sev in extra:
        e=match(typ)
        if e: findings.append({"ruleId":rid,"name":name,"status":"TRIGGERED","severity":sev,"confidence":"HIGH","evidenceIds":[e["id"]],"points":pts,"finding":f"{name} observed."});contrib.append({"ruleId":rid,"evidenceId":e["id"],"points":pts})
    risk=min(100,sum(x["points"] for x in contrib))
    if not findings: assessment={"classification":"INSUFFICIENT_EVIDENCE","riskScore":None,"riskBand":None,"confidence":"LOW","reason":"Available evidence is insufficient to support a reliable threat classification."}
    else:
        cls="SUSPICIOUS"
        if any(f["ruleId"] in {"ATTACH-001","ATTACH-002"} for f in findings): cls="MALWARE_DELIVERY"
        band="LOW" if risk<20 else "GUARDED" if risk<40 else "MEDIUM" if risk<60 else "HIGH" if risk<80 else "CRITICAL"
        assessment={"classification":cls,"riskScore":risk,"riskBand":band,"confidence":"MEDIUM","reason":"Assessment is based only on supplied structured evidence."}
    rec=[{"id":f"REC-{i+1:03d}","text":f["finding"],"evidenceIds":f["evidenceIds"]} for i,f in enumerate(findings)]
    return {"assessment":assessment,"findings":findings,"evidence":ev,"recommendations":rec,
            "ruleResults":[{"ruleId":f["ruleId"],"status":"TRIGGERED"} for f in findings],
            "scoreContributions":contrib,"analysisMetadata":{"rulesEvaluated":len(RULES)+len(extra),"rulesTriggered":len(findings),"analyzedAt":now()},
            "auditLog":{"analysisId":"AN-"+datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"),"timestamp":now(),"evidenceUsed":[e["id"] for e in ev]}}
