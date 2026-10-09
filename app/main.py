"""Secure FastAPI starter: JWT auth, RBAC, lockout, rate limiting, security headers, IDOR-safe notes."""
from __future__ import annotations

import sqlite3
import time

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import db, security
from .config import Settings
from .ratelimit import RateLimiter
from .schemas import LoginIn, NoteIn, RegisterIn

bearer = HTTPBearer(auto_error=False)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or Settings()
    db.init_db(cfg.db_path)
    # Docs are disabled outside dev to reduce attack surface; the CSP above also blocks Swagger assets.
    app = FastAPI(title="Secure FastAPI Starter", docs_url=None, redoc_url=None, openapi_url=None)
    login_limit = RateLimiter(cfg.login_rate_limit, cfg.rate_window_seconds)
    register_limit = RateLimiter(cfg.register_rate_limit, cfg.rate_window_seconds)

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers[k] = v
        return response

    @app.exception_handler(Exception)
    async def hide_internal_errors(request: Request, exc: Exception):
        # Never leak stack traces or SQL errors to clients
        return JSONResponse({"detail": "Internal server error"}, status_code=500)

    # ----------------------------- auth dependencies --------------------------
    def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
        if not creds:
            raise HTTPException(401, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})
        try:
            claims = security.decode_token(creds.credentials, cfg.secret_key, cfg.issuer)
        except jwt.PyJWTError:
            raise HTTPException(401, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
        with db.get_conn(cfg.db_path) as conn:
            row = conn.execute("SELECT id, username, role FROM users WHERE id = ?",
                               (int(claims["sub"]),)).fetchone()
        if not row:
            raise HTTPException(401, "Invalid or expired token")
        # Role comes from the DB, not the token, so demotions take effect immediately.
        return dict(row)

    def require_admin(user: dict = Depends(current_user)) -> dict:
        if user["role"] != "admin":
            raise HTTPException(403, "Admin privileges required")
        return user

    # ----------------------------- routes -------------------------------------
    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/auth/register", status_code=201, dependencies=[Depends(register_limit)])
    def register(body: RegisterIn, request: Request):
        pw_hash = security.hash_password(body.password)
        try:
            with db.get_conn(cfg.db_path) as conn:
                conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                             (body.username, pw_hash))
                db.audit(conn, "register", body.username, request.client.host if request.client else None)
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Username unavailable")
        return {"message": "registered"}  # role is always 'user'; no mass-assignment of role

    @app.post("/auth/login", dependencies=[Depends(login_limit)])
    def login(body: LoginIn, request: Request):
        ip = request.client.host if request.client else None
        generic = HTTPException(401, "Invalid username or password")  # same message for every failure
        with db.get_conn(cfg.db_path) as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (body.username,)).fetchone()
            now = time.time()
            if row and row["locked_until"] > now:
                db.audit(conn, "login_locked", body.username, ip)
                conn.commit()
                raise HTTPException(423, "Account temporarily locked. Try again later.")
            ok = security.verify_password(body.password, row["password_hash"] if row else None)
            if not ok:
                if row:
                    attempts = row["failed_attempts"] + 1
                    locked = now + cfg.lockout_minutes * 60 if attempts >= cfg.max_failed_logins else 0
                    conn.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                                 (0 if locked else attempts, locked, row["id"]))
                db.audit(conn, "login_failed", body.username, ip)
                conn.commit()
                raise generic
            conn.execute("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?", (row["id"],))
            db.audit(conn, "login_success", body.username, ip)
        token = security.create_token(row["id"], row["role"], cfg.secret_key, cfg.issuer, cfg.token_minutes)
        return {"access_token": token, "token_type": "bearer",  # nosec B105
                "expires_in": cfg.token_minutes * 60}

    @app.get("/users/me")
    def me(user: dict = Depends(current_user)):
        return user

    @app.get("/admin/users")
    def list_users(_: dict = Depends(require_admin)):
        with db.get_conn(cfg.db_path) as conn:
            rows = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    @app.get("/admin/audit")
    def audit_log(_: dict = Depends(require_admin)):
        with db.get_conn(cfg.db_path) as conn:
            rows = conn.execute("SELECT ts, event, username, ip FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
        return [dict(r) for r in rows]

    # Notes: every query is scoped to owner_id, which prevents IDOR / broken object-level authorization.
    @app.post("/notes", status_code=201)
    def create_note(body: NoteIn, user: dict = Depends(current_user)):
        with db.get_conn(cfg.db_path) as conn:
            cur = conn.execute("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
                               (user["id"], body.title, body.body))
        return {"id": cur.lastrowid, "title": body.title}

    @app.get("/notes")
    def list_notes(user: dict = Depends(current_user)):
        with db.get_conn(cfg.db_path) as conn:
            rows = conn.execute("SELECT id, title, created_at FROM notes WHERE owner_id = ? ORDER BY id",
                                (user["id"],)).fetchall()
        return [dict(r) for r in rows]

    @app.get("/notes/{note_id}")
    def get_note(note_id: int, user: dict = Depends(current_user)):
        with db.get_conn(cfg.db_path) as conn:
            row = conn.execute("SELECT id, title, body, created_at FROM notes WHERE id = ? AND owner_id = ?",
                               (note_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "Note not found")  # 404 (not 403) so IDs of others' notes are not revealed
        return dict(row)

    @app.delete("/notes/{note_id}", status_code=204)
    def delete_note(note_id: int, user: dict = Depends(current_user)):
        with db.get_conn(cfg.db_path) as conn:
            cur = conn.execute("DELETE FROM notes WHERE id = ? AND owner_id = ?", (note_id, user["id"]))
        if cur.rowcount == 0:
            raise HTTPException(404, "Note not found")

    return app
