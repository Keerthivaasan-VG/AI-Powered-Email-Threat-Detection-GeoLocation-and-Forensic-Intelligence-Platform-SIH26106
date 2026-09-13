# API Inventory

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | service health |
| GET | `/api/qa/readiness` | readiness/configuration state |
| POST | `/api/investigations` | full EML investigation |
| GET | `/api/investigations` | list/search |
| GET | `/api/investigations/{id}` | full investigation |
| GET | `/api/investigations/{id}/status` | module statuses |
| GET | `/api/investigations/{id}/evidence` | evidence lineage |
| GET | `/api/investigations/{id}/audit` | audit events |
| POST | `/api/investigations/{id}/verify` | acquisition integrity verification |
| POST | `/api/investigations/{id}/report` | generate report |
| GET | `/api/reports/{reportId}.pdf` | retrieve PDF |
| GET | `/api/ml/status` | ML model state |
| POST | `/api/ml/classify` | optional ML prediction |
