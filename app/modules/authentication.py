import re
def result_from_auth(value):
    s=str(value or "").upper()
    for field in ("SPF","DKIM","DMARC"):
        m=re.search(rf"\b{field}\s*=\s*(PASS|FAIL|SOFTFAIL|NEUTRAL|NONE|TEMPERROR|PERMERROR)",s)
        if m:return m.group(1)
    return None
def analyze(headers):
    allh=headers.get("all",[])
    auth_headers=[h["value"] for h in allh if h["name"].lower() in {"authentication-results","received-spf"}]
    out={}
    for field in ("spf","dkim","dmarc"):
        vals=[]
        for v in auth_headers:
            m=re.search(rf"\b{field}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)",v,re.I)
            if m: vals.append(m.group(1).upper())
        if not vals:
            # DKIM-Signature presence means signing exists, but is not verification.
            if field=="dkim" and any(h["name"].lower()=="dkim-signature" for h in allh):
                out[field]={"status":"PRESENT","verified":False}
            else: out[field]={"status":"NOT_AVAILABLE","verified":False}
        else: out[field]={"status":vals[0],"verified":True,"observations":vals}
    return {"spf":out["spf"],"dkim":out["dkim"],"dmarc":out["dmarc"],"source":"Authentication-Results / supplied headers"}
