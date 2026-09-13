import hashlib,json,os
from datetime import datetime,timezone
from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
def generate(inv, report_dir):
    rid=f"REP-{inv['investigationId']}"
    data={k:inv.get(k,{}) for k in ["source","email","headers","authentication","routing","indicators","intelligence","assessment","findings","evidence","recommendations"]}
    data["reportMetadata"]={"reportId":rid,"investigationId":inv["investigationId"],"generatedAt":datetime.now(timezone.utc).isoformat(),"status":"GENERATED"}
    p=Path(report_dir);p.mkdir(parents=True,exist_ok=True);pdf=p/(rid+".pdf")
    styles=getSampleStyleSheet(); story=[Paragraph("EMAIL FORENSICS — FORENSIC REPORT",styles["Title"]),Paragraph(inv["investigationId"],styles["Normal"]),Spacer(1,12)]
    a=inv.get("assessment",{}); story.append(Paragraph(f"Classification: {a.get('classification','NOT AVAILABLE')} | Risk: {a.get('riskScore','NOT AVAILABLE')} | Confidence: {a.get('confidence','NOT AVAILABLE')}",styles["Heading2"]))
    story.append(Spacer(1,8))
    rows=[["Field","Value"],["Source file",inv["source"]["filename"]],["SHA-256",inv["source"]["sha256"]],["From",inv.get("email",{}).get("from") or "NOT AVAILABLE"],["Subject",inv.get("email",{}).get("subject") or "NOT AVAILABLE"],["Findings",str(len(inv.get("findings",[])))],["Evidence",str(len(inv.get("evidence",[])))]]
    t=Table(rows,colWidths=[55*mm,125*mm]);t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.5,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("VALIGN",(0,0),(-1,-1),"TOP")]))
    story.append(t);story.append(Spacer(1,12));story.append(Paragraph("Executive summary",styles["Heading2"]))
    story.append(Paragraph(a.get("reason","No assessment available."),styles["BodyText"]))
    SimpleDocTemplate(str(pdf),pagesize=A4).build(story)
    sha=hashlib.sha256(pdf.read_bytes()).hexdigest();data["reportMetadata"]["sha256"]=sha
    (p/(rid+".json")).write_text(json.dumps(data,indent=2,default=str),encoding="utf8")
    return {"reportId":rid,"status":"GENERATED","sha256":sha,"pdfPath":str(pdf)}
