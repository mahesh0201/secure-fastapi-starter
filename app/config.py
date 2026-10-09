"""Configuration from environment variables. Secrets are never hard-coded."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


@dataclass
class Settings:
    db_path: str = field(default_factory=lambda: os.getenv("DB_PATH", "secure.db"))
    secret_key: str = field(default_factory=lambda: os.getenv("SECRET_KEY", ""))
    token_minutes: int = int(os.getenv("TOKEN_MINUTES", "15"))
    issuer: str = "secure-fastapi-starter"
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    login_rate_limit: int = 10      # requests per window per IP
    register_rate_limit: int = 5
    rate_window_seconds: int = 60

    def __post_init__(self):
        if not self.secret_key:
            if os.getenv("ENV", "dev") == "production":
                raise RuntimeError("SECRET_KEY must be set in production")
            # Dev only: random per-process key (tokens become invalid on restart)
            self.secret_key = secrets.token_urlsafe(48)
        if len(self.secret_key) < 32:
            raise RuntimeError("SECRET_KEY must be at least 32 characters")
