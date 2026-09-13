# Deployment

## Local / Windows

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

For production, place the application behind HTTPS and an authenticated reverse proxy.

## Storage

Use a persistent disk for `data/`. Replace SQLite/local acquisition storage with a managed database and controlled object storage for production.

## Environment

Copy `.env.example` to `.env`. Never commit `.env`.

## ML

For a large model, use Git LFS or external object storage rather than ordinary Git. External storage is preferable for multi-hundred-MB models and production model versioning.
