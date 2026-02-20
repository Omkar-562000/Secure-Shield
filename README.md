# SecureShield

SecureShield is a one-time secure sharing web app for safely sending credentials and sensitive content.
It is designed for day-to-day operational sharing (API keys, temporary passwords, photos, and videos).

## Core Features

- Client-side encryption with Web Crypto (AES-GCM)
- Server stores ciphertext only (no plaintext storage)
- Login, signup, forgot-password, and reset-password pages
- One-time or limited-view retrieval
- Mandatory 6-digit access code per share
- Auto-expiration (30 min to 7 days configurable in UI)
- Manual revoke support via delete token
- Basic rate limiting and security headers (CSP, no-sniff, no-store)
- Clean and responsive UI for desktop/mobile

## How It Works

1. Authenticated user logs in and creates a share (text/photo/video).
2. Browser encrypts content with a random AES key.
3. Ciphertext is sent to server and stored in the database (SQLite local, PostgreSQL in production).
4. Share link is generated as:
   `/secret/<id>#k=<decryption-key>`
5. A 6-digit access code is generated for that share.
6. Recipient opens link, enters code, browser decrypts locally, and content is consumed per view policy.

The key in URL fragment (`#...`) is not sent to the server in HTTP requests.

## Project Structure

- `app.py` Flask app with HTML routes + JSON API
- `templates/` UI templates
- `static/js/create.js` client-side encryption + create flow
- `static/js/reveal.js` fetch + client-side decryption flow
- `static/css/app.css` visual system and responsive styling
- `.env.example` environment variable template
- `data/secureshield.db` local SQLite database (auto-created when `DATABASE_URL` is not set)

## Local Development

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

For local password reset testing, keep `MAIL_MODE=console` and check terminal logs for the 6-digit reset code.

## API Endpoints

- `POST /api/secrets`
- `GET /api/secrets/<secret_id>`
- `DELETE /api/secrets/<secret_id>?token=<delete_token>`
- `GET /healthz`

## Production Setup (Render + Vercel)

### 1. Database (Render PostgreSQL)

- Create a Render PostgreSQL instance.
- Copy its external database URL.
- Set `DATABASE_URL` in Render web service env vars.
- Use psycopg format:
  `postgresql+psycopg://...`

### 2. Render Backend Deployment

- Create Render Web Service from this repo.
- Build command:
  `pip install -r requirements.txt`
- Start command:
  `gunicorn -w 2 -b 0.0.0.0:$PORT app:app`
- Set env vars:
  - `SECRET_KEY` (required)
  - `SESSION_COOKIE_SECURE=true`
  - `DATABASE_URL` (Render Postgres URL)
  - `MAIL_MODE=smtp`
  - `MAIL_FROM`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_USE_TLS=true`

### 3. Vercel Frontend Strategy

Use Vercel for your portfolio site/landing page, and link the app hosted on Render.
If you later split frontend/backend, Vercel can host frontend and call Render API.

### 4. SMTP Requirement

Forgot-password is production-ready with SMTP.
Use a mail provider (Gmail App Password, Brevo, SendGrid SMTP, etc.) and set SMTP env vars on Render.

## Security Caveat

This MVP improves sharing safety significantly versus plain text channels, but for high-compliance environments you should add:

- strict CSRF strategy and origin policy hardening
- stronger rate limits with Redis-backed counters
- abuse detection, audit events, and secret scanning controls
- external KMS-backed server-side controls and key rotation policies
