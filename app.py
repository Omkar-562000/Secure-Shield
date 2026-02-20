from __future__ import annotations

import hashlib
import os
import smtplib
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps
from pathlib import Path
from secrets import randbelow, token_urlsafe
from typing import Deque

from dotenv import load_dotenv
from flask import Flask, g, jsonify, request, send_from_directory, session
from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, scoped_session, sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SQLITE_PATH = DATA_DIR / "secureshield.db"

MIN_EXPIRY_MINUTES = 5
MAX_EXPIRY_MINUTES = 7 * 24 * 60
MAX_CIPHERTEXT_SIZE = 25_000_000
MAX_VIEWS_CAP = 5
MAX_UPLOAD_BYTES = 12 * 1024 * 1024


def utc_now() -> datetime:
    return datetime.utcnow()


def get_database_url() -> str:
    raw = os.getenv("DATABASE_URL", "").strip()
    if raw:
        if raw.startswith("postgres://"):
            return raw.replace("postgres://", "postgresql+psycopg://", 1)
        if raw.startswith("postgresql://") and "+psycopg" not in raw:
            return raw.replace("postgresql://", "postgresql+psycopg://", 1)
        return raw

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{SQLITE_PATH.as_posix()}"


DATABASE_URL = get_database_url()
IS_SQLITE = DATABASE_URL.startswith("sqlite:")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if IS_SQLITE else {},
    pool_pre_ping=True,
)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class PasswordResetCode(Base):
    __tablename__ = "password_reset_codes"

    email: Mapped[str] = mapped_column(String(255), primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    code_salt: Mapped[str] = mapped_column(String(120), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class Secret(Base):
    __tablename__ = "secrets"
    __table_args__ = (
        Index("idx_secrets_expires_at", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    owner_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    content_kind: Mapped[str] = mapped_column(String(20), nullable=False, default="text")
    mime_type: Mapped[str] = mapped_column(String(120), nullable=False, default="text/plain")
    filename: Mapped[str] = mapped_column(String(180), nullable=False, default="")
    code_salt: Mapped[str] = mapped_column(String(120), nullable=False)
    code_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    remaining_views: Mapped[int] = mapped_column(Integer, nullable=False)
    delete_token: Mapped[str] = mapped_column(String(255), nullable=False)


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", token_urlsafe(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"

rate_limit_lock = threading.Lock()
rate_limit_cache: dict[str, Deque[float]] = defaultdict(deque)
FRONTEND_DIST_DIR = BASE_DIR / "frontend" / "dist"


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def cleanup_expired() -> None:
    now = utc_now()
    db = SessionLocal()
    try:
        db.query(Secret).filter(Secret.expires_at <= now).delete(synchronize_session=False)
        db.query(PasswordResetCode).filter(PasswordResetCode.expires_at <= now).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_rate_limited(key: str, limit: int, window_seconds: int = 60) -> bool:
    now = datetime.now().timestamp()
    with rate_limit_lock:
        entries = rate_limit_cache[key]
        while entries and now - entries[0] > window_seconds:
            entries.popleft()
        if len(entries) >= limit:
            return True
        entries.append(now)
        return False


def parse_int(value: object, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def make_code_hash(code: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{code}".encode("utf-8")).hexdigest()


def generate_six_digit_code() -> str:
    return f"{randbelow(1_000_000):06d}"


def logged_in_user_id() -> int | None:
    value = session.get("user_id")
    if isinstance(value, int):
        return value
    return None


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not logged_in_user_id():
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required."}), 401
            return jsonify({"error": "Authentication required."}), 401
        return view_func(*args, **kwargs)

    return wrapped


def secret_not_available_message() -> tuple[dict[str, str], int]:
    return {"error": "Content is unavailable (expired, viewed, or not found)."}, 404


def user_to_dict(user: User) -> dict[str, str | int]:
    return {"id": user.id, "name": user.name, "email": user.email}


def send_reset_email(recipient_email: str, code: str) -> tuple[bool, str | None]:
    mode = os.getenv("MAIL_MODE", "console").strip().lower()
    sender = os.getenv("MAIL_FROM", "noreply@secureshield.app")

    if mode == "console":
        print(f"[SecureShield] Password reset code for {recipient_email}: {code}")
        return True, None

    if mode != "smtp":
        return False, "MAIL_MODE must be either 'console' or 'smtp'."

    host = os.getenv("SMTP_HOST", "").strip()
    port = parse_int(os.getenv("SMTP_PORT", "587"), 587)
    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "").strip()
    use_tls = os.getenv("SMTP_USE_TLS", "true").strip().lower() == "true"

    if not host or not username or not password:
        return False, "SMTP config missing. Set SMTP_HOST/SMTP_USERNAME/SMTP_PASSWORD."

    msg = EmailMessage()
    msg["Subject"] = "SecureShield Password Reset Code"
    msg["From"] = sender
    msg["To"] = recipient_email
    msg.set_content(
        "Use the following code to reset your SecureShield password:\n\n"
        f"{code}\n\n"
        "This code expires in 10 minutes."
    )

    try:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            if use_tls:
                smtp.starttls()
            smtp.login(username, password)
            smtp.send_message(msg)
        return True, None
    except Exception as exc:  # pragma: no cover
        return False, str(exc)


@app.before_request
def load_user() -> None:
    user_id = logged_in_user_id()
    g.user = None
    if not user_id:
        return
    db = SessionLocal()
    try:
        row = db.get(User, user_id)
        if row:
            g.user = {"id": row.id, "name": row.name, "email": row.email}
    finally:
        db.close()


@app.teardown_appcontext
def shutdown_session(_exception=None):
    SessionLocal.remove()


@app.context_processor
def inject_user():
    return {"current_user": g.get("user")}


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "media-src 'self' blob:; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    return response


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "time_utc": utc_now().isoformat()})


@app.get("/api/auth/me")
def me():
    user_id = logged_in_user_id()
    if not user_id:
        return jsonify({"authenticated": False, "user": None})

    db = SessionLocal()
    try:
        user = db.get(User, user_id)
        if not user:
            session.clear()
            return jsonify({"authenticated": False, "user": None})
        return jsonify({"authenticated": True, "user": user_to_dict(user)})
    finally:
        db.close()


@app.post("/api/auth/signup")
def signup():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "").strip()
    email = str(payload.get("email") or "").strip().lower()
    password = str(payload.get("password") or "")

    if len(name) < 2:
        return jsonify({"error": "Name is too short."}), 400
    if "@" not in email or "." not in email:
        return jsonify({"error": "Enter a valid email address."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    db = SessionLocal()
    try:
        existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if existing:
            return jsonify({"error": "Email already registered."}), 409

        user = User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password),
            created_at=utc_now(),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        session["user_id"] = user.id
        return jsonify({"message": "Account created.", "user": user_to_dict(user)}), 201
    finally:
        db.close()


@app.post("/api/auth/login")
def login():
    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email") or "").strip().lower()
    password = str(payload.get("password") or "")

    db = SessionLocal()
    try:
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    finally:
        db.close()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials."}), 401

    session["user_id"] = user.id
    return jsonify({"message": "Logged in.", "user": user_to_dict(user)})


@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"logged_out": True})


@app.post("/api/auth/forgot-password")
def forgot_password():
    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email") or "").strip().lower()

    if "@" not in email or "." not in email:
        return jsonify({"error": "Enter a valid email address."}), 400

    db = SessionLocal()
    try:
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if not user:
            return jsonify({"error": "No account found for this email."}), 404

        code = generate_six_digit_code()
        salt = token_urlsafe(8)
        code_hash = make_code_hash(code, salt)
        expires_at = utc_now() + timedelta(minutes=10)

        existing = db.get(PasswordResetCode, email)
        if existing:
            existing.code_hash = code_hash
            existing.code_salt = salt
            existing.expires_at = expires_at
        else:
            db.add(
                PasswordResetCode(
                    email=email,
                    code_hash=code_hash,
                    code_salt=salt,
                    expires_at=expires_at,
                )
            )
        db.commit()
    finally:
        db.close()

    sent, error_message = send_reset_email(email, code)
    show_code = os.getenv("MAIL_MODE", "console").strip().lower() == "console"
    if not sent:
        return jsonify({"error": f"Failed to send reset code: {error_message}"}), 500
    return jsonify(
        {
            "message": "Reset code sent. Check your email inbox.",
            "email": email,
            "reset_code": code if show_code else None,
        }
    )


@app.post("/api/auth/reset-password")
def reset_password():
    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email") or "").strip().lower()
    code = str(payload.get("code") or "").strip()
    new_password = str(payload.get("new_password") or "")

    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters."}), 400
    if len(code) != 6 or not code.isdigit():
        return jsonify({"error": "Code must be a 6-digit value."}), 400

    db = SessionLocal()
    try:
        reset_row = db.get(PasswordResetCode, email)
        if not reset_row or reset_row.expires_at <= utc_now():
            return jsonify({"error": "Reset code is invalid or expired."}), 400

        expected_hash = make_code_hash(code, reset_row.code_salt)
        if expected_hash != reset_row.code_hash:
            return jsonify({"error": "Reset code is invalid."}), 400

        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if not user:
            return jsonify({"error": "No account found for this email."}), 404

        user.password_hash = generate_password_hash(new_password)
        db.delete(reset_row)
        db.commit()
    finally:
        db.close()

    return jsonify({"message": "Password reset successful. Please log in."})


@app.post("/api/secrets")
def create_secret():
    cleanup_expired()
    if is_rate_limited(f"create:{client_ip()}", limit=25):
        return jsonify({"error": "Rate limit exceeded. Try again soon."}), 429

    user_id = logged_in_user_id()
    if not user_id:
        return jsonify({"error": "Authentication required."}), 401

    payload = request.get_json(silent=True) or {}
    ciphertext = payload.get("ciphertext", "")
    expires_minutes = parse_int(payload.get("expires_minutes"), 60)
    max_views = parse_int(payload.get("max_views"), 1)
    content_kind = (payload.get("content_kind") or "text").strip().lower()
    mime_type = (payload.get("mime_type") or "").strip().lower()
    filename = (payload.get("filename") or "").strip()
    file_size = parse_int(payload.get("file_size"), 0)

    if not isinstance(ciphertext, str) or not ciphertext.strip():
        return jsonify({"error": "ciphertext is required"}), 400
    if len(ciphertext) > MAX_CIPHERTEXT_SIZE:
        return jsonify({"error": "ciphertext is too large"}), 400
    if expires_minutes < MIN_EXPIRY_MINUTES or expires_minutes > MAX_EXPIRY_MINUTES:
        return jsonify({"error": f"expires_minutes must be {MIN_EXPIRY_MINUTES}-{MAX_EXPIRY_MINUTES}"}), 400
    if max_views < 1 or max_views > MAX_VIEWS_CAP:
        return jsonify({"error": f"max_views must be 1-{MAX_VIEWS_CAP}"}), 400
    if content_kind not in {"text", "file"}:
        return jsonify({"error": "content_kind must be text or file"}), 400
    if content_kind == "file":
        if file_size <= 0 or file_size > MAX_UPLOAD_BYTES:
            return jsonify({"error": f"file_size must be 1-{MAX_UPLOAD_BYTES} bytes"}), 400
        if not (mime_type.startswith("image/") or mime_type.startswith("video/")):
            return jsonify({"error": "Only image and video files are supported."}), 400
        if len(filename) > 180:
            return jsonify({"error": "filename is too long"}), 400
    else:
        mime_type = "text/plain"
        filename = ""

    secret_id = token_urlsafe(12)
    delete_token = token_urlsafe(24)
    access_code = generate_six_digit_code()
    code_salt = token_urlsafe(8)
    code_hash = make_code_hash(access_code, code_salt)
    created_at = utc_now()
    expires_at = created_at + timedelta(minutes=expires_minutes)

    db = SessionLocal()
    try:
        db.add(
            Secret(
                id=secret_id,
                owner_user_id=user_id,
                ciphertext=ciphertext,
                content_kind=content_kind,
                mime_type=mime_type,
                filename=filename,
                code_salt=code_salt,
                code_hash=code_hash,
                created_at=created_at,
                expires_at=expires_at,
                remaining_views=max_views,
                delete_token=delete_token,
            )
        )
        db.commit()
    finally:
        db.close()

    return jsonify(
        {
            "secret_id": secret_id,
            "expires_at": expires_at.isoformat(),
            "max_views": max_views,
            "access_code": access_code,
            "delete_url": f"/api/secrets/{secret_id}?token={delete_token}",
        }
    )


@app.get("/api/secrets/<secret_id>")
def reveal_secret(secret_id: str):
    cleanup_expired()
    if is_rate_limited(f"reveal:{client_ip()}", limit=80):
        return jsonify({"error": "Rate limit exceeded. Try again soon."}), 429

    code = (request.args.get("code") or "").strip()
    if len(code) != 6 or not code.isdigit():
        return jsonify({"error": "A valid 6-digit code is required."}), 400

    db = SessionLocal()
    try:
        secret = db.get(Secret, secret_id)
        if not secret:
            body, code_value = secret_not_available_message()
            return jsonify(body), code_value

        if secret.expires_at <= utc_now() or secret.remaining_views <= 0:
            db.delete(secret)
            db.commit()
            body, code_value = secret_not_available_message()
            return jsonify(body), code_value

        expected = make_code_hash(code, secret.code_salt)
        if expected != secret.code_hash:
            return jsonify({"error": "Incorrect access code."}), 403

        secret.remaining_views -= 1
        remaining_after = max(secret.remaining_views, 0)
        payload = {
            "ciphertext": secret.ciphertext,
            "content_kind": secret.content_kind,
            "mime_type": secret.mime_type,
            "filename": secret.filename,
            "expires_at": secret.expires_at.isoformat(),
            "remaining_views": remaining_after,
        }
        if secret.remaining_views <= 0:
            db.delete(secret)
        db.commit()
    finally:
        db.close()

    return jsonify(payload)


@app.delete("/api/secrets/<secret_id>")
def delete_secret(secret_id: str):
    token = request.args.get("token", "")
    if not token:
        return jsonify({"error": "token is required"}), 400

    db = SessionLocal()
    try:
        secret = db.get(Secret, secret_id)
        if not secret:
            body, code = secret_not_available_message()
            return jsonify(body), code
        if token != secret.delete_token:
            return jsonify({"error": "Invalid token"}), 403
        db.delete(secret)
        db.commit()
    finally:
        db.close()

    return jsonify({"deleted": True})


@app.errorhandler(404)
def not_found(_):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    if FRONTEND_DIST_DIR.exists():
        return send_from_directory(FRONTEND_DIST_DIR, "index.html"), 200
    return jsonify({"error": "Not found", "hint": "Build frontend/dist or run React dev server."}), 404


@app.errorhandler(500)
def internal_error(_):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal server error"}), 500
    return jsonify({"error": "Internal server error"}), 500


@app.get("/", defaults={"path": ""})
@app.get("/<path:path>")
def serve_spa(path: str):
    if path.startswith("api/"):
        return jsonify({"error": "Not found"}), 404

    if FRONTEND_DIST_DIR.exists():
        candidate = FRONTEND_DIST_DIR / path
        if path and candidate.is_file():
            return send_from_directory(FRONTEND_DIST_DIR, path)
        return send_from_directory(FRONTEND_DIST_DIR, "index.html")

    return jsonify(
        {
            "message": "SecureShield backend is running.",
            "next_step": "Start the React frontend (frontend/) or build it into frontend/dist.",
            "api_base": "/api",
        }
    )


init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
