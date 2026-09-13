import hashlib, os, re
def validate_filename(name):
    if not name or not name.lower().endswith(".eml"): raise ValueError("Only .eml files are accepted.")
    if "/" in name or "\\" in name or ".." in name: raise ValueError("Unsafe filename.")
def hashes(content): return {"sha256":hashlib.sha256(content).hexdigest(),"sha512":hashlib.sha512(content).hexdigest(),"size":len(content)}
def verify(content, expected_sha256):
    actual=hashlib.sha256(content).hexdigest()
    return {"verified":actual.lower()==str(expected_sha256).lower(),"expected":expected_sha256,"actual":actual}
