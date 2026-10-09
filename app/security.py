"""Password hashing and JWT helpers."""
from __future__ import annotations

import time
import uuid

import bcrypt
import jwt

ALGORITHM = "HS256"
# bcrypt silently truncates input at 72 bytes, so we cap length at validation time.
# A pre-computed hash lets us do equal work when the user does not exist (timing-safe login).
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt(rounds=12))


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: str | None) -> bool:
    target = hashed.encode() if hashed else _DUMMY_HASH
    ok = bcrypt.checkpw(password.encode(), target)
    return ok and hashed is not None


def create_token(user_id: int, role: str, secret: str, issuer: str, minutes: int) -> str:
    now = int(time.time())
    claims = {"sub": str(user_id), "role": role, "iss": issuer, "iat": now,
              "exp": now + minutes * 60, "jti": uuid.uuid4().hex}
    return jwt.encode(claims, secret, algorithm=ALGORITHM)


def decode_token(token: str, secret: str, issuer: str) -> dict:
    """Raises jwt.PyJWTError on any problem. Algorithm is pinned (prevents alg=none / confusion)."""
    return jwt.decode(token, secret, algorithms=[ALGORITHM], issuer=issuer,
                      options={"require": ["exp", "iat", "sub", "iss"]})
