# Troubleshooting

### `ModuleNotFoundError`
Activate `.venv` and run `pip install -r requirements.txt`.

### Upload rejected
The file must end in `.eml` and be <= 10 MB.

### ML says MODEL_UNAVAILABLE
This is intentional until a validated model artifact is installed. Do not substitute an arbitrary `.joblib`.

### Threat intelligence says NOT_CONFIGURED
Set `THREAT_INTEL_ENABLED=true` and configure the deployment's approved provider credentials if external providers are implemented.

### PDF report fails
Check that `reportlab` is installed and `data/reports/` is writable.

### Production authentication
The final prototype does not include an identity provider. Use an authenticated reverse proxy/API gateway before exposing it outside a trusted environment.
