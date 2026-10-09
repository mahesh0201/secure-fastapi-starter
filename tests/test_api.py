import sqlite3
import time

import jwt
import pytest

from app import security
from tests.conftest import PASSWORD, register_and_login


# ---------------- registration / validation ----------------
@pytest.mark.parametrize("pw", ["short1A", "alllowercase1234", "NoDigitsHereAtAll", "A1" * 40])
def test_weak_or_oversized_password_rejected(client, pw):
    r = client.post("/auth/register", json={"username": "bob", "password": pw})
    assert r.status_code == 422


def test_bad_username_rejected(client):
    r = client.post("/auth/register", json={"username": "bob; DROP TABLE users", "password": PASSWORD})
    assert r.status_code == 422


def test_mass_assignment_of_role_rejected(client):
    r = client.post("/auth/register", json={"username": "eve", "password": PASSWORD, "role": "admin"})
    assert r.status_code == 422


def test_duplicate_username_conflict(client):
    register_and_login(client)
    r = client.post("/auth/register", json={"username": "ALICE", "password": PASSWORD})
    assert r.status_code == 409


def test_password_stored_as_bcrypt_hash(client, settings):
    register_and_login(client)
    stored = sqlite3.connect(settings.db_path).execute("SELECT password_hash FROM users").fetchone()[0]
    assert stored.startswith("$2") and PASSWORD not in stored


# ---------------- authentication ----------------
def test_login_wrong_password_and_unknown_user_same_message(client):
    register_and_login(client)
    a = client.post("/auth/login", json={"username": "alice", "password": "WrongPassword123"})
    b = client.post("/auth/login", json={"username": "nobody", "password": "WrongPassword123"})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_sql_injection_in_login_fails(client):
    register_and_login(client)
    r = client.post("/auth/login", json={"username": "alice' OR '1'='1", "password": "x"})
    assert r.status_code == 401


def test_account_lockout_after_repeated_failures(client):
    register_and_login(client)
    for _ in range(5):
        client.post("/auth/login", json={"username": "alice", "password": "WrongPassword123"})
    r = client.post("/auth/login", json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 423  # even the correct password is refused while locked


def test_login_rate_limit(settings):
    from fastapi.testclient import TestClient
    from app.main import create_app
    c = TestClient(create_app(settings))
    codes = [c.post("/auth/login", json={"username": "x", "password": "y"}).status_code
             for _ in range(settings.login_rate_limit + 2)]
    assert codes[-1] == 429


# ---------------- tokens ----------------
def test_requires_token(client):
    assert client.get("/users/me").status_code == 401


def test_tampered_token_rejected(client):
    h = register_and_login(client)
    bad = {"Authorization": h["Authorization"][:-3] + "abc"}
    assert client.get("/users/me", headers=bad).status_code == 401


def test_alg_none_token_rejected(client, settings):
    forged = jwt.encode({"sub": "1", "iss": settings.issuer, "iat": 1, "exp": 9999999999}, key=None, algorithm="none")
    assert client.get("/users/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_expired_token_rejected(client, settings):
    register_and_login(client)
    old = security.create_token(1, "user", settings.secret_key, settings.issuer, minutes=-1)
    assert client.get("/users/me", headers={"Authorization": f"Bearer {old}"}).status_code == 401


def test_wrong_issuer_rejected(client, settings):
    register_and_login(client)
    t = security.create_token(1, "user", settings.secret_key, "someone-else", minutes=5)
    assert client.get("/users/me", headers={"Authorization": f"Bearer {t}"}).status_code == 401


# ---------------- authorization ----------------
def test_user_cannot_access_admin_routes(client):
    h = register_and_login(client)
    assert client.get("/admin/users", headers=h).status_code == 403


def test_admin_can_list_users(client, settings):
    h = register_and_login(client)
    sqlite3.connect(settings.db_path).execute("UPDATE users SET role='admin'").connection.commit()
    r = client.get("/admin/users", headers=h)
    assert r.status_code == 200 and r.json()[0]["username"] == "alice"
    assert "password_hash" not in r.text


def test_idor_user_cannot_read_or_delete_others_notes(client):
    alice = register_and_login(client, "alice")
    bob = register_and_login(client, "bobby")
    nid = client.post("/notes", json={"title": "secret", "body": "alice only"}, headers=alice).json()["id"]
    assert client.get(f"/notes/{nid}", headers=alice).status_code == 200
    assert client.get(f"/notes/{nid}", headers=bob).status_code == 404
    assert client.delete(f"/notes/{nid}", headers=bob).status_code == 404
    assert client.get("/notes", headers=bob).json() == []


def test_sql_metacharacters_stored_literally(client):
    h = register_and_login(client)
    title = "x'); DROP TABLE notes;--"
    nid = client.post("/notes", json={"title": title, "body": "b"}, headers=h).json()["id"]
    assert client.get(f"/notes/{nid}", headers=h).json()["title"] == title


# ---------------- hardening ----------------
def test_security_headers_present(client):
    r = client.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]


def test_audit_log_records_failed_login(client, settings):
    h = register_and_login(client)
    client.post("/auth/login", json={"username": "alice", "password": "WrongPassword123"})
    sqlite3.connect(settings.db_path).execute("UPDATE users SET role='admin'").connection.commit()
    events = [e["event"] for e in client.get("/admin/audit", headers=h).json()]
    assert "login_failed" in events and "login_success" in events


def test_production_requires_secret_key(monkeypatch):
    from app.config import Settings
    monkeypatch.setenv("ENV", "production")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        Settings(db_path=":memory:")
