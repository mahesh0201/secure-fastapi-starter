# Secure FastAPI Starter

A small REST API that demonstrates **secure-by-default backend design** with FastAPI: authentication,
authorization, input validation, brute-force protection, safe error handling and an automated security
test suite. Every control is covered by a test and mapped to STRIDE and the OWASP Top 10
(see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)).

## Security features

- **Authentication:** bcrypt password hashing (cost 12), JWT access tokens (HS256 pinned, `exp`/`iss`/`sub` required, 15-minute lifetime)
- **Brute-force defence:** per-IP rate limiting + account lockout (5 failures -> 15 minutes) + audit log
- **Authorization:** role-based access control (`user` / `admin`); role is read from the database on each request
- **Broken object-level authorization (IDOR) protection:** notes are always queried with `owner_id`
- **Injection defence:** parameterised SQL only; strict Pydantic validation (`extra="forbid"` stops mass assignment)
- **No user enumeration:** identical error and similar timing for unknown user vs wrong password
- **Hardening:** security headers on every response, internal errors hidden, OpenAPI docs disabled, non-root Docker image
- **DevSecOps CI:** pytest + Bandit (SAST) + pip-audit (dependency scan) on every push

## Endpoints

| Method | Path | Access |
|--------|------|--------|
| POST | `/auth/register` | public (rate limited) |
| POST | `/auth/login` | public (rate limited, lockout) |
| GET | `/users/me` | authenticated |
| POST/GET | `/notes` | authenticated (own notes only) |
| GET/DELETE | `/notes/{id}` | owner only |
| GET | `/admin/users`, `/admin/audit` | admin only |
| GET | `/health` | public |

## Run locally

```bash
git clone https://github.com/<your-username>/secure-fastapi-starter.git
cd secure-fastapi-starter
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
uvicorn app.main:create_app --factory --reload
```

Try it (new terminal):

```bash
curl -X POST localhost:8000/auth/register -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"Str0ngPassword!23"}'

TOKEN=$(curl -s -X POST localhost:8000/auth/login -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"Str0ngPassword!23"}' | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -X POST localhost:8000/notes -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"title":"hello","body":"my first note"}'
curl localhost:8000/notes -H "Authorization: Bearer $TOKEN"
```

Make a user an admin (server-side only, never over HTTP): `python scripts/create_admin.py alice`

## Run the tests and scanners

```bash
pytest -q                 # 24 tests: auth, lockout, JWT attacks, IDOR, SQLi, headers, RBAC
bandit -r app             # static analysis
pip-audit -r requirements.txt
```

## Docker

```bash
docker build -t secure-fastapi-starter .
docker run -p 8000:8000 -e ENV=production \
  -e SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')" \
  -v appdata:/data -e DB_PATH=/data/secure.db secure-fastapi-starter
```

In production the app **refuses to start** without `SECRET_KEY`.

## Project layout

```
app/main.py        app factory, routes, middleware, auth dependencies
app/security.py    bcrypt + JWT helpers
app/schemas.py     input validation models
app/ratelimit.py   sliding-window rate limiter
app/db.py          SQLite schema + parameterised access, audit log
tests/             security-focused pytest suite
docs/THREAT_MODEL.md   STRIDE table, OWASP mapping, known limitations
```

## Limitations

This is a learning project. See the "Known limitations" section of the threat model (single-node rate limiting,
no refresh tokens/MFA, TLS expected at a reverse proxy).

## License

MIT
