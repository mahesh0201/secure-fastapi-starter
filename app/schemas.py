"""Input validation with Pydantic: strict types, length limits, allow-listed characters."""
from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)  # reject unknown fields


class RegisterIn(_Strict):
    username: str
    password: str = Field(max_length=72)  # bcrypt limit

    @field_validator("username")
    @classmethod
    def valid_username(cls, v: str) -> str:
        if not USERNAME_RE.match(v):
            raise ValueError("username must be 3-32 chars: letters, digits, _ . -")
        return v

    @field_validator("password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        problems = []
        if len(v) < 12:
            problems.append("at least 12 characters")
        if not re.search(r"[a-z]", v) or not re.search(r"[A-Z]", v):
            problems.append("upper and lower case letters")
        if not re.search(r"\d", v):
            problems.append("a digit")
        if problems:
            raise ValueError("password needs " + ", ".join(problems))
        return v


class LoginIn(_Strict):
    username: str = Field(max_length=64)
    password: str = Field(max_length=72)


class NoteIn(_Strict):
    title: str = Field(min_length=1, max_length=100)
    body: str = Field(min_length=1, max_length=5000)
