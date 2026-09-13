import re,ipaddress,hashlib
from urllib.parse import urlparse
EMAIL_RE=re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",re.I)
URL_RE=re.compile(r"\bhttps?://[^\s<>'\"`]+",re.I)
def classify_ip(ip):
    try:
        x=ipaddress.ip_address(ip)
        if x.is_private:return "PRIVATE"
        if x.is_loopback:return "LOOPBACK"
        if x.is_link_local:return "LINK-LOCAL"
        if x.is_multicast:return "MULTICAST"
        if x.is_reserved:return "RESERVED"
        return "PUBLIC"
    except:return "UNKNOWN"
def analyze(parsed):
    headers=parsed["headers"]["all"]; text=parsed.get("body",""); html=parsed.get("html","")
    src=f"{text}\n{re.sub('<[^>]+>',' ',html)}\n"+" \n".join(f"{h['name']}: {h['value']}" for h in headers)
    urls=[]; domains=[]; ips=[]; emails=[]; observations=[]
    seen=set()
    for u in URL_RE.findall(src):
        u=u.rstrip("),.;!?")
        if u in seen:continue
        seen.add(u)
        try:p=urlparse(u); host=p.hostname or ""
        except:continue
        rec={"original":u,"normalized":u,"scheme":p.scheme,"host":host.lower(),"port":p.port,"path":p.path,"source":"Email content","observations":[]}
        try:is_ip=bool(ipaddress.ip_address(host))
        except:is_ip=False
        if is_ip: rec["observations"].append({"indicator":u,"reason":"URL uses an IP address as host.","source":"Indicators"})
        if host.startswith("xn--") or any(x.startswith("xn--") for x in host.split(".")): rec["observations"].append({"indicator":host,"reason":"Punycode hostname detected.","source":"Indicators"})
        if p.port and not ((p.scheme=="http" and p.port==80) or (p.scheme=="https" and p.port==443)): rec["observations"].append({"indicator":u,"reason":"URL uses a non-standard port.","source":"Indicators"})
        urls.append(rec); observations.extend(rec["observations"])
        if not is_ip and host and host not in {d["domain"] for d in domains}: domains.append({"domain":host.lower(),"sources":["Email content"],"occurrences":1})
    for e in EMAIL_RE.findall(src):
        el=e.lower()
        if not any(x["email"]==el for x in emails): emails.append({"email":el,"domain":el.split("@")[-1],"source":"Email content"})
    for ip in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])",src):
        if classify_ip(ip)!="UNKNOWN" and not any(x["ip"]==ip for x in ips): ips.append({"ip":ip,"classification":classify_ip(ip),"source":"Email content"})
    # Explicit From/Reply-To mismatch evidence
    f=next((x["value"] for x in headers if x["name"].lower()=="from"),"")
    r=next((x["value"] for x in headers if x["name"].lower()=="reply-to"),"")
    fe=EMAIL_RE.findall(f); re_=EMAIL_RE.findall(r)
    if fe and re_ and fe[0].split("@")[-1].lower()!=re_[0].split("@")[-1].lower():
        observations.append({"indicator":f"{fe[0]} -> {re_[0]}","reason":"From and Reply-To domains differ.","source":"Email headers"})
    atts=[]
    for a in parsed.get("attachments",[]):
        fn=a["filename"].lower()
        cat="EXECUTABLE" if fn.endswith((".exe",".dll")) else "SCRIPT" if fn.endswith((".bat",".cmd",".ps1",".js",".vbs",".jar",".scr")) else "ARCHIVE" if fn.endswith((".zip",".rar",".7z",".tar",".gz")) else "OTHER"
        ao=[]
        if cat in {"EXECUTABLE","SCRIPT"}: ao.append({"indicator":a["filename"],"reason":"Executable or script file type detected.","source":"Attachment metadata"})
        if re.search(r"\.[a-z0-9]{1,8}\.[a-z0-9]{1,8}$",fn): ao.append({"indicator":a["filename"],"reason":"Multiple file extensions detected.","source":"Attachment metadata"})
        a=dict(a);a["category"]=cat;a["observations"]=ao;atts.append(a);observations.extend(ao)
    return {"summary":{"total":len(urls)+len(domains)+len(ips)+len(emails)+len(atts),"urls":len(urls),"domains":len(domains),"ips":len(ips),"emails":len(emails),"attachments":len(atts),"observations":len(observations)},
            "urls":urls,"domains":domains,"ips":ips,"emailAddresses":emails,"attachments":atts,"observations":observations}
