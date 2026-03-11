# FTP Server + Web Portal

This project starts a local FTP server and a web UI with a login page. The web UI lists uploaded files, shows modified dates, and supports filtering and search.

## Quick start

1. Install dependencies

```powershell
pip install -r requirements.txt
```

2. Run the app

```powershell
python app.py
```

4. Open the web UI

- http://localhost:5000

From the web UI you can upload a file from your computer and optionally add a description.
If you run locally over HTTP and have login issues, keep `SECURE_COOKIES_AUTO = True` (default).

## Production (Gunicorn)

Run with Gunicorn:

```powershell
gunicorn app:app
```

For hosting behind a reverse proxy (recommended), set `TRUST_PROXY = True` in `app.py`.

## Security settings (recommended for hosting)

Edit `app.py` and `pass.py`:

- `WEB_SECRET` in `app.py` set to a long random value.
- `WEB_PASS_HASH` in `pass.py` set to a strong hash (use `python pass.py`).
- `SECURE_COOKIES_AUTO = True` in `app.py` (keeps cookies secure on HTTPS).
- `TRUST_PROXY = True` in `app.py` when behind Nginx/Traefik/etc.
- `MAX_UPLOAD_MB` in `app.py` to cap upload size.
- `START_FTP = False` in `app.py` unless you explicitly need FTP.

If you want FTP in production, run it as a separate process, or use a single Gunicorn worker to avoid port conflicts.

## Configuration (hardcoded)

All config is hardcoded in `app.py` and `pass.py` (no environment variables):

- `UPLOAD_DIR`, `WEB_HOST`, `WEB_PORT`, `FTP_HOST`, `FTP_PORT`
- `WEB_SECRET`, `START_FTP`, `MAX_UPLOAD_MB`, `SECURE_COOKIES_AUTO`, `TRUST_PROXY`
- `SESSION_MINUTES`, `LOGIN_MAX_ATTEMPTS`, `LOGIN_WINDOW_SECONDS`
- `WEB_USER`, `WEB_PASS_HASH`, `PBKDF2_ITERATIONS`

## Notes

- FTP is not encrypted. Use it only on trusted networks or behind a VPN.
- Change the default credentials before exposing the server.

## Generating a new password hash

```powershell
python pass.py
```

Copy the output into `WEB_PASS_HASH` in `pass.py`.
