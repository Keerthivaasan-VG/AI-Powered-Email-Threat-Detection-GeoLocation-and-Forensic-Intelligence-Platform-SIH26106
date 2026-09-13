# Final Test Report

Date: 2026-09-13

## Verification commands

```text
python -m pytest -q
node --check app/static/app.js
python -m py_compile app/main.py app/modules/*.py
uvicorn app.main:app --host 127.0.0.1 --port 8765
curl /health
curl /api/qa/readiness
```

## Results

- Python integration tests: **7 passed, 0 failed, 0 skipped**
- Frontend JavaScript syntax check: **passed**
- Python compile check: **passed**
- Live `/health`: **passed**
- Live `/api/qa/readiness`: **passed**
- Full EML pipeline test: **passed**
- PDF generation and retrieval test: **passed**
- SHA-256 integrity verification test: **passed**
- 10 MB upload boundary test: **passed**
- invalid extension test: **passed**
- idempotency test: **passed**
- ML unavailable-state test: **passed**

## Required validation

Modules integrated: **14 / 14 logical capabilities**

Supplied ZIP archives inspected: **13 / 14 requested archives**

Tests:
**7 passed**
**0 failed**
**0 skipped**

Integration status:

**READY_WITH_LIMITATIONS**

## Known issues

1. A fourteenth ZIP archive was not uploaded, so archive-level inspection is 13/14.
2. Authentication/authorization is not a production identity provider; the deployment must add one.
3. External threat intelligence is disabled by default and requires explicit deployment configuration.
4. No validated production ML model is bundled. The supplied ten-row sample has one example per class and is not sufficient for reliable stratified training.
5. SQLite/local evidence storage is a prototype default; production should use managed persistence and controlled object storage.
6. Production TLS, rate limiting, WORM audit storage, malware sandboxing, and centralized observability remain deployment responsibilities.

No claim of full production readiness is made.
