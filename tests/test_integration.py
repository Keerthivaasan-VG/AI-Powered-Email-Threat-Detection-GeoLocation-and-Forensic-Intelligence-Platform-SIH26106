import io,os
from fastapi.testclient import TestClient
from app.main import app,DB,ACQ,REPORTS
client=TestClient(app)
EML=open(os.path.join(os.path.dirname(__file__),"sample.eml"),"rb").read()
def test_health_and_readiness():
    assert client.get("/health").status_code==200
    r=client.get("/api/qa/readiness");assert r.status_code==200;assert "status" in r.json()
def test_full_investigation_pipeline():
    r=client.post("/api/investigations",files={"file":("sample.eml",EML,"message/rfc822")})
    assert r.status_code==200
    d=r.json()
    assert d["status"]=="COMPLETED"
    assert all(x["status"]=="SUCCESS" for x in d["modules"].values())
    assert d["assessment"]["riskScore"] is not None
    assert len(d["headers"]["all"])>0
    assert d["routing"]["receivedHeaderCount"]==1
    assert d["indicators"]["summary"]["urls"]>=1
    assert d["security"]["sha256"]
    iid=d["investigationId"]
    assert client.get(f"/api/investigations/{iid}").status_code==200
    assert client.get(f"/api/investigations/{iid}/evidence").status_code==200
    assert client.get(f"/api/investigations/{iid}/audit").status_code==200
    rr=client.post(f"/api/investigations/{iid}/report");assert rr.status_code==200
    rid=rr.json()["reportId"];assert client.get(f"/api/reports/{rid}.pdf").status_code==200
def test_oversize_rejected():
    r=client.post("/api/investigations",files={"file":("big.eml",b"A"*(10*1024*1024+1),"message/rfc822")})
    assert r.status_code==413

def test_bad_extension():
    r=client.post("/api/investigations",files={"file":("bad.txt",b"hello","text/plain")})
    assert r.status_code==400
def test_idempotency():
    h={"X-Idempotency-Key":"qa-key-1"}
    a=client.post("/api/investigations",headers=h,files={"file":("idempotent.eml",EML,"message/rfc822")})
    b=client.post("/api/investigations",headers=h,files={"file":("idempotent.eml",EML,"message/rfc822")})
    assert a.status_code==200 and b.status_code==200 and a.json()["investigationId"]==b.json()["investigationId"]
def test_hash_verification():
    r=client.post("/api/investigations",files={"file":("verify.eml",EML,"message/rfc822")})
    iid=r.json()["investigationId"]
    v=client.post(f"/api/investigations/{iid}/verify",files={"file":("verify.eml",EML,"message/rfc822")})
    assert v.status_code==200 and v.json()["verified"] is True

def test_ml_explicit_state():
    r=client.get("/api/ml/status");assert r.status_code==200
    if r.json()["status"]=="MODEL_UNAVAILABLE":
        x=client.post("/api/ml/classify",json={"email":{"subject":"test"},"body":"hello"}).json()
        assert x["status"]=="MODEL_UNAVAILABLE"
