# SecureShield

Project is now split cleanly:
- `frontend/` -> React (Vite) SPA
- `backend/` -> Flask API + DB + auth/session

## Folder Layout

- `frontend/`
  - `src/` React app
  - `vite.config.js` frontend dev server + API proxy
- `backend/`
  - `app.py` Flask API
  - `requirements.txt`
  - `.env` / `.env.example`
  - `data/secureshield.db` local SQLite
  - `Procfile`, `render.yaml`

Removed as unwanted legacy frontend:
- `templates/`
- `static/`

## Run Locally

1. Start backend:

```powershell
cd e:\SecureShield\SecureShield
python -m venv backend\.venv
backend\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
python -m backend.app
```

Backend: `http://127.0.0.1:5000`

2. Start frontend (new terminal):

```powershell
cd e:\SecureShield\SecureShield\frontend
npm install
npm run dev
```

Frontend: `http://127.0.0.1:5173`

## Notes

- Backend loads env from `backend/.env`.
- Flask serves built SPA from `frontend/dist` in production.
- Current backend DB engine is SQLAlchemy (`DATABASE_URL`), not MongoDB yet.
