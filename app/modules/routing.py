import ipaddress,re
def classify(ip):
    try:
        x=ipaddress.ip_address(ip)
        if x.is_private:return "PRIVATE"
        if x.is_loopback:return "LOOPBACK"
        if x.is_link_local:return "LINK-LOCAL"
        if x.is_multicast:return "MULTICAST"
        if x.is_reserved:return "RESERVED"
        return "PUBLIC"
    except:return "UNKNOWN"
def ips(text):
    return [m.group(0) for m in re.finditer(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])",text)]
def parse_received(value,index):
    s=re.sub(r"\r?\n[ \t]+"," ",str(value)).strip()
    sem=s.rfind(";"); route=s[:sem] if sem>=0 else s; ts=s[sem+1:].strip() if sem>=0 else None
    fm=re.search(r"\bfrom\s+(.+?)(?=\s+by\s+|\s+with\s+|\s+id\s+|\s+for\s+|$)",route,re.I)
    bm=re.search(r"\bby\s+(.+?)(?=\s+with\s+|\s+id\s+|\s+for\s+|$)",route,re.I)
    wm=re.search(r"\bwith\s+([^\s;]+)",route,re.I)
    fseg=fm.group(1).strip() if fm else None
    fhost=re.sub(r"\s*\[[^\]]+\]","",fseg).strip() if fseg else None
    found=[x for x in ips(route) if classify(x) in {"PUBLIC","PRIVATE","RESERVED","LOOPBACK","LINK-LOCAL"}]
    fip=None
    if fseg:
        m=re.search(r"\[\s*([0-9.]+)\s*\]",fseg)
        if m and classify(m.group(1))!="UNKNOWN": fip=m.group(1)
    if not fip and found:fip=found[0]
    missing=[]
    for label,val in [("from host",fhost),("from IP",fip),("by host",bm.group(1).strip() if bm else None),("protocol",wm.group(1) if wm else None),("timestamp",ts)]:
        if not val: missing.append(label)
    return {"index":index+1,"raw":f"Received: {s}","fromHost":fhost,"fromIp":fip,"byHost":bm.group(1).strip() if bm else None,
            "protocol":wm.group(1) if wm else None,"timestamp":ts,"parseStatus":"COMPLETE" if not missing else ("PARTIAL" if fm or bm or found or ts else "UNPARSED"),
            "parseReason":f"Unable to extract: {', '.join(missing)}." if missing else None,
            "ips":[{"ip":x,"classification":classify(x)} for x in found]}
def analyze(headers):
    rows=[parse_received(h["value"],i) for i,h in enumerate(headers.get("all",[])) if h["name"].lower()=="received"]
    allips=[{"ip":x["ip"],"classification":x["classification"],"headerIndex":r["index"]} for r in rows for x in r["ips"]]
    public=[x for x in allips if x["classification"]=="PUBLIC"]; candidate=None
    for r in reversed(rows):
        p=[x for x in r["ips"] if x["classification"]=="PUBLIC"]
        if p: candidate={"ip":p[0]["ip"],"headerIndex":r["index"],"classification":"PUBLIC","basis":"Earliest observable external IP"};break
    return {"receivedHeaderCount":len(rows),"parsedHeaderCount":sum(r["parseStatus"]!="UNPARSED" for r in rows),
            "ipCount":len(allips),"publicIpCount":len(public),"received":rows,"ips":allips,
            "candidateOrigin":candidate,"warnings":[{"type":"PARSING","headerIndex":r["index"],"message":f"Received #{r['index']} could not be fully parsed."} for r in rows if r["parseStatus"]!="COMPLETE"],
            "status":"Routing Evidence Available" if rows else "No Routing Evidence"}
