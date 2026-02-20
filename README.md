# SecureShield

SecureShield now uses:
- React (Vite) for the frontend
- Python (Flask + SQLAlchemy) for the backend API

It provides encrypted one-time/limited-view sharing for text, images, and videos.

## Architecture

- `app.py`: Flask backend API, sessions, DB models, secret lifecycle
- `frontend/`: React SPA (auth + create + reveal flows)
- `data/secureshield.db`: local SQLite DB (when `DATABASE_URL` is not set)

## Backend API

Auth:
- `GET /api/auth/me`
- `POST /api/auth/signup`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`

Secrets:
- `POST /api/secrets`
- `GET /api/secrets/<secret_id>?code=<6-digit-code>`
- `DELETE /api/secrets/<secret_id>?token=<delete_token>`

Health:
- `GET /healthz`

## Local Development

### 1. Start Python backend

```powershell
cd SecureShield
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Backend runs at `http://127.0.0.1:5000`.

### 2. Start React frontend

```powershell
cd SecureShield\frontend
npm install
npm run dev
```

Frontend runs at `http://127.0.0.1:5173` and proxies `/api` to backend.

## Production Build

Build frontend:

```powershell
cd SecureShield\frontend
npm install
npm run build
```

This generates `frontend/dist`. Flask serves this build automatically for non-API routes.

## Environment Variables

See `.env.example`.

Important:
- `SECRET_KEY`
- `SESSION_COOKIE_SECURE`
- `DATABASE_URL` (optional locally, required in production Postgres setups)
- SMTP variables when using `MAIL_MODE=smtp`

## Notes

- Client-side AES-GCM encryption is done in React before upload.
- Backend stores ciphertext only.
- Decryption key stays in the URL fragment (`#k=...`) and is not sent to the server.
