# Email Forensics — Final Integrated Platform

Unified desktop-first email-forensics application integrating the supplied module implementations into one FastAPI backend and one frontend.

## Integrated capabilities

1. Email information / RFC-aware `.eml` parsing
2. Header extraction and raw-header inspection
3. SPF/DKIM/DMARC result parsing from supplied authentication headers
4. Received-header routing reconstruction
5. Indicator extraction: URLs, domains, IPs, addresses, attachments and structural observations
6. Threat intelligence adapter boundary with safe explicit provider states; optional DNS when enabled
7. Threat analysis and evidence correlation with deterministic risk scoring
8. Forensic PDF report generation
9. Unified investigation persistence and API
10. Dashboard frontend
11. Evidence SHA-256/SHA-512 integrity and verification
12. Chain-of-custody/audit records
13. ML/NLP classification endpoint with validated-model contract
14. QA/readiness endpoint and release documentation

## Important source inventory note

The upload set contained **13 ZIP archives**, not 14. Two archives represent overlapping integration/dashboard lineage, and no separate standalone archive for the missing module was supplied. The final system therefore reports **13/14 supplied archives integrated** while implementing the missing authentication capability from the available header evidence rather than pretending a fourteenth archive was inspected.

## Requirements

Python 3.10+ recommended. Python 3.13 was used for local verification.

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/`.

API documentation: `http://127.0.0.1:8000/docs`.

## Unified API

- `POST /api/investigations` — upload and run the full pipeline
- `GET /api/investigations`
- `GET /api/investigations/{id}`
- `GET /api/investigations/{id}/status`
- `GET /api/investigations/{id}/evidence`
- `GET /api/investigations/{id}/audit`
- `POST /api/investigations/{id}/verify` — verify supplied bytes against acquisition SHA-256
- `POST /api/investigations/{id}/report`
- `GET /api/reports/{reportId}.pdf`
- `GET /api/ml/status`
- `POST /api/ml/classify`
- `GET /api/qa/readiness`
- `GET /health`

## Security boundaries

- `.eml` only; 10 MB maximum
- uploaded filenames are validated and never used as storage paths
- URLs are parsed as text and never opened by the analysis pipeline
- attachments are never executed
- provider credentials are not accepted from email content
- evidence hashes are calculated from the actual acquisition bytes
- reports are projections of stored investigation data
- external threat intelligence is disabled by default
- ML does not replace the deterministic forensic assessment

## ML model

The supplied ML module contains a training pipeline but its bundled sample dataset has one example per class, which is insufficient for a meaningful stratified train/validation/test model. No fake trained model is bundled.

To deploy a real model, provide a reviewed labeled dataset with repeated examples per class, train and evaluate it using the supplied training design, then place the validated artifact at `models/email_threat_classifier.joblib` with matching metadata. Git LFS or external object storage is recommended for models larger than ordinary Git limits. For a small validated joblib, normal Git may be acceptable; never commit secrets or unreviewed serialized models.

## Testing

```bash
pytest -q
```

The final report must be based on the actual command output; no pre-generated report is treated as proof.

## Deployment

See `docs/deployment/deployment.md`, `docs/deployment/troubleshooting.md`, and `docs/architecture/architecture.md`.

## Known limitations

- No separate fourthteenth ZIP was supplied, so archive-level integration is 13/14.
- Real external threat-intelligence providers are not enabled by default and require deployment configuration.
- Real authentication/authorization is not implemented; protect the service behind an identity-aware reverse proxy before production use.
- The bundled ML sample is not suitable for a reliable trained classifier; ML reports `MODEL_UNAVAILABLE` until a validated model is installed.
- SQLite and local evidence storage are prototype defaults; production should use access-controlled persistent storage and append-only/WORM audit infrastructure.
