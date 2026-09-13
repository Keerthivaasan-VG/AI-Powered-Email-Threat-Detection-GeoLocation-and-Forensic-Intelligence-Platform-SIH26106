# Architecture

Browser → FastAPI unified API → in-process module pipeline → SQLite + acquisition storage.

Pipeline:
`.eml` → Email Information → Headers → Authentication + Routing → Indicators → Threat Intelligence → Threat Analysis → Report.

Cross-cutting:
- Security hashes acquisition bytes before analysis.
- Audit events record investigation lifecycle.
- ML is assistive and never overwrites the forensic assessment.
- QA/readiness reports configuration state.
