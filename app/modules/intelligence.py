import os, socket, ipaddress
def analyze(indicators):
    if os.getenv("THREAT_INTEL_ENABLED","false").lower()!="true":
        return {"status":"NOT_CONFIGURED","ips":[],"domains":[],"urls":[],"dns":[],"reputation":[],"blacklists":[],"sources":[],"reason":"External threat-intelligence providers are disabled; enable THREAT_INTEL_ENABLED and configure provider credentials."}
    domains=indicators.get("domains",[])[:100]; dns=[]
    for d in domains:
        name=d.get("domain") if isinstance(d,dict) else str(d)
        try:
            addrs=sorted({x[4][0] for x in socket.getaddrinfo(name,80,type=socket.SOCK_STREAM)})
            dns.append({"domain":name,"addresses":addrs,"status":"SUCCESS","source":"system DNS"})
        except Exception as e:dns.append({"domain":name,"status":"SOURCE_ERROR","error":str(e),"source":"system DNS"})
    return {"status":"SUCCESS","ips":[],"domains":[],"urls":[],"dns":dns,"reputation":[],"blacklists":[],"sources":["system DNS"]}
