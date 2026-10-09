# Threat Model (STRIDE) and OWASP mapping

**Assets:** user credentials, JWT access tokens, users' private notes, audit log.
**Trust boundary:** the internet-facing HTTP API.

| STRIDE | Threat | Mitigation in this project | Test |
|--------|--------|----------------------------|------|
| **S**poofing | Stolen/forged tokens | HS256 pinned (no `alg=none`), signature + `exp` + `iss` required, 15-minute lifetime | `test_alg_none_token_rejected`, `test_tampered_token_rejected`, `test_expired_token_rejected` |
| **S**poofing | Credential stuffing / brute force | bcrypt (cost 12), account lockout after 5 failures, per-IP rate limit | `test_account_lockout...`, `test_login_rate_limit` |
| **S**poofing | Username enumeration | Same error for unknown user and wrong password; dummy hash keeps timing similar | `test_login_wrong_password_and_unknown_user_same_message` |
| **T**ampering | SQL injection | 100% parameterised queries; strict input validation | `test_sql_injection_in_login_fails`, `test_sql_metacharacters_stored_literally` |
| **T**ampering | Mass assignment (`role: admin`) | Pydantic `extra="forbid"`; role never read from input | `test_mass_assignment_of_role_rejected` |
| **R**epudiation | Deny failed/successful logins | `audit_log` table (register, login success/fail/locked) | `test_audit_log_records_failed_login` |
| **I**nformation disclosure | IDOR on `/notes/{id}` | Every query scoped by `owner_id`; 404 instead of 403 | `test_idor_...` |
| **I**nformation disclosure | Stack traces / hash leaks | Global exception handler; responses never include `password_hash` | `test_admin_can_list_users` |
| **D**enial of service | Request floods, huge payloads | Rate limiting, field length limits (bcrypt 72-byte cap) | `test_weak_or_oversized_password_rejected` |
| **E**levation of privilege | User calls admin endpoints | `require_admin` dependency; role read from DB each request (demotion is immediate) | `test_user_cannot_access_admin_routes` |

## OWASP Top 10 (2021) mapping

| Category | Where addressed |
|----------|-----------------|
| A01 Broken Access Control | RBAC dependency, owner-scoped queries |
| A02 Cryptographic Failures | bcrypt hashing, secrets from environment, SECRET_KEY length check |
| A03 Injection | Parameterised SQL, Pydantic validation |
| A04 Insecure Design | Lockout, rate limiting, short-lived tokens |
| A05 Security Misconfiguration | Security headers, docs disabled, non-root Docker user |
| A06 Vulnerable Components | `pip-audit` in CI |
| A07 Identification and Authentication Failures | Password policy, lockout, generic errors |
| A09 Security Logging and Monitoring Failures | Audit log |

## Known limitations (be honest in interviews)

- Rate limiter and lockout counters are per-process / SQLite: use Redis and a real database for multi-instance deployments.
- No refresh tokens, token revocation list or MFA.
- No HTTPS here: terminate TLS at a reverse proxy (nginx, Caddy, cloud load balancer) and set HSTS there.
- `request.client.host` is the proxy IP when behind a proxy; configure trusted proxy headers properly.
- HS256 uses one shared secret; use asymmetric keys (RS256/EdDSA) if multiple services verify tokens.
