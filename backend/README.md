# backend/

The ASKQ FastAPI service. Phase 3 adds the foundation: configuration, the two
database connections, Argon2id passwords, JWT authentication, and role-based
access control with a data-scope model. SQL generation, Claude, CAIR and the
query pipeline are later phases.

```
app/
├── main.py            create_app(settings, database): CORS, error handlers, routers
├── config.py          Settings (Pydantic Settings, reads C:\ASKQ\.env)
├── clock.py           the only wall-clock read (naive UTC, like TIMESTAMP(3))
├── errors.py          uniform {"error": {...}} responses; no internals leak
├── api/
│   ├── health.py      GET /health, GET /health/db
│   ├── router.py      /api/v1
│   └── auth.py        POST /api/v1/auth/login, GET /api/v1/auth/me
├── auth/
│   ├── password.py    Argon2id hash / verify / upgrade, timing equaliser, policy
│   ├── tokens.py      TokenService: issue + strict validation of JWTs
│   ├── service.py     AuthService: login, token -> UserContext
│   ├── schemas.py     request/response models
│   └── dependencies.py get_current_user, require_authenticated_user
├── rbac/
│   ├── roles.py       Role (ADMIN, HOD, TEACHER, STUDENT; ids pinned by Phase 2)
│   ├── permissions.py the role -> permission table
│   ├── scope.py       Scope, UserContext, resolve_scope
│   └── dependencies.py require_roles, require_permission, require_admin/hod/teacher/student
├── db/
│   ├── engine.py      build_app_engine (askq_app), build_reader_engine (askq_reader)
│   ├── session.py     Database container; get_app_session, get_reader_connection
│   ├── models/        users, roles, departments, app_user_credentials, security_audit_log
│   └── repositories/  users, credentials, audit
└── cli/set_password.py  provision a user's password (run by hand)
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | Liveness. Never touches the database. |
| GET | `/health/db` | none | `SELECT 1` through each account. `200 {"status":"ok","checks":{"app":"ok","reader":"ok"}}`, or `503` with `"unavailable"` per failed check. No host, user, version or error text. |
| POST | `/api/v1/auth/login` | none | `{"username","password"}` → `{"access_token","token_type":"bearer","expires_in","user":{id,username,role,permissions}}` |
| GET | `/api/v1/auth/me` | Bearer | `{id, username, role, permissions}` for the caller, re-read from the database |
| GET | `/docs`, `/openapi.json` | none | Interactive docs (disabled when `APP_ENV=production`) |

## Configuration

`app/config.py` reads the root `.env`. Variable names are shared with
`database/setup_db.ps1` and must not be renamed.

| Variable | Default | Notes |
|---|---|---|
| `APP_ENV` | `development` | `development`, `test` or `production` |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated `scheme://host[:port]`; `*` is rejected |
| `DB_HOST`, `DB_PORT` | `127.0.0.1`, `3306` | The accounts exist only `@127.0.0.1` |
| `DB_UNIVERSITY_NAME`, `DB_SYSTEM_NAME` | `askq_university`, `askq_system` | |
| `DB_READER_USER` / `DB_READER_PASSWORD` | `askq_reader` / none | Must differ from the app account |
| `DB_APP_USER` / `DB_APP_PASSWORD` | `askq_app` / none | |
| `JWT_SECRET` | none | ≥ 32 characters; no fallback |
| `JWT_ALGORITHM` | `HS256` | `HS256`, `HS384` or `HS512` only |
| `JWT_EXPIRE_MINUTES` | `60` | 1–1440 |
| `DB_POOL_SIZE`, `DB_MAX_OVERFLOW` | `5`, `5` | Per engine; sum ≤ 20 (each account's `MAX_USER_CONNECTIONS`) |
| `DB_POOL_RECYCLE_SECONDS`, `DB_CONNECT_TIMEOUT_SECONDS` | `1800`, `5` | |

Secrets are `SecretStr`: masked in `repr`, logs and validation errors. A secret
that is unset or still has its `.env.example` placeholder (`change-me…`) counts
as **not configured**. In development the feature needing it answers `503`
(for example login without `JWT_SECRET`), rather than running with a weak
default. With `APP_ENV=production` the app refuses to start unless all three
secrets and `CORS_ORIGINS` are set.

## Database connections: two accounts, never merged

| | App connection | Reader connection |
|---|---|---|
| Account | `askq_app@127.0.0.1` | `askq_reader@127.0.0.1` |
| Default database | `askq_system` | `askq_university` |
| Used for | login lookups (`users`, `roles`, `departments`), credentials, audit log, later history/CAIR | executing validated, user-scoped SELECTs (Phase 5+) |
| API | `get_app_session` → ORM `Session` | `get_reader_connection` → plain `Connection` |
| Session init | `time_zone = '+00:00'` | `time_zone = '+00:00'`, `transaction_read_only = ON` |

The separation is structural. The ORM sessionmaker is bound only to the app
engine, and the reader hands out plain connections whose MySQL session is
read-only, on top of its SELECT-only grants. Neither account can do the
other's job: the reader has no access to `askq_system`, `users` or `roles`,
and the app account cannot read organisational tables such as `students` or
`teachers`. `tests/integration` proves this against MySQL.

Both engines use `pool_pre_ping`, `pool_recycle`, utf8mb4, a connect timeout
and `hide_parameters=True`, so bound values never appear in error messages.
Engines are created lazily (the app starts without a database) and disposed
on shutdown. Root is never used by the application.

## Authentication

**Passwords.** Argon2id through pwdlib with argon2-cffi defaults (t=3,
m=64 MiB, p=4, 16-byte salt). Only the PHC hash is stored, in
`askq_system.app_user_credentials`. Hashes with outdated parameters are
upgraded transparently at the next successful login.

**Login flow** (`AuthService.login`):

1. Look up the user by username (lowercased; usernames are lowercase in the schema).
2. Run **exactly one** Argon2 verification: against the stored hash, or against
   a dummy hash if the user or credential doesn't exist. Timing doesn't reveal which.
3. Reject if there's no user, no credential, a wrong password, an inactive
   account, an active lock (`locked_until`), or role links that don't fit the
   role (fail closed).
4. Resolve role and scope **from the database**.
5. Record the outcome. A failure increments `failed_login_attempts` (wrong
   password only). A success resets it and sets `last_login_at`. Each attempt
   writes a `LOGIN_FAILED` or `LOGIN_SUCCEEDED` row to `security_audit_log` with
   the reason, but never the attempted username or password.
6. Issue the JWT.

Every failure returns the same `401 {"error":{"code":"unauthenticated","message":"Invalid username or password."}}`.
The request model forbids extra fields, so a client-supplied `role` or `scope` is a `422`.

**JWT.** HMAC (`JWT_ALGORITHM`), with claims `sub` (user id), `role`, `iat`,
`exp`, `jti` and `iss="askq-backend"` only. There's no personal data in the
token. Decoding pins the algorithm list (so `none` and algorithm switching are
rejected), and requires every claim, a matching issuer, an unexpired `exp`, a
numeric `sub` and a known role.

**Every authenticated request** (`get_current_user`):

1. Verifies the token.
2. Re-reads the user and credential.
3. Rejects the token if any of these hold:
   - the user is missing or inactive;
   - the account is locked;
   - the token was issued before the last password change (tokens are revoked by a password change);
   - the database role differs from the token's role claim.
4. Rebuilds the `UserContext` from the database.

A missing or invalid token gets `401` with `WWW-Authenticate: Bearer`.

## RBAC

- **Roles** (`rbac/roles.py`): ADMIN=1, HOD=2, TEACHER=3, STUDENT=4, exactly as
  pinned by `roles.ck_roles_id_code`. A `roles` row that doesn't match its pinned id is treated as no role.
- **Permissions** (`rbac/permissions.py`) cover features, in one table. Every
  role has `ASK_QUESTIONS` and `VIEW_OWN_HISTORY`. ADMIN additionally has
  `VIEW_ALL_HISTORY`, `VIEW_SECURITY_AUDIT`, `MANAGE_USERS` and `RUN_EVALUATIONS`.
- **Scope** (`rbac/scope.py`) covers rows, resolved from the user's links:

  | Role | Scope | From |
  |---|---|---|
  | ADMIN | `ORGANIZATION` | no teacher/student link |
  | HOD | `DEPARTMENT` (+ own `teacher_id`) | `departments.head_teacher_id = users.teacher_id` |
  | TEACHER | `TEACHER` | `users.teacher_id` |
  | STUDENT | `STUDENT` | `users.student_id` |

  Links that don't fit the role (for example a HOD who heads no department) give no scope, and login fails.
- **Guards** (`rbac/dependencies.py`): `require_roles(*roles)` (exact match),
  `require_admin`, `require_hod`, `require_teacher`, `require_student`,
  `require_permission(p)`. Use them as `Depends(...)`: unauthenticated gives
  `401`, and a wrong role or missing permission gives `403`. Endpoints never compare role strings.
- **`UserContext` is immutable** and is built only by the server, per request.
  Later phases (row-scope rewriting, CAIR, conversations) must take it from the
  request dependency. **Conversation context, model output, request
  parameters, headers or token claims never override role or scope.**

## Errors

All errors share one shape: `{"error": {"code": "...", "message": "..."}}`.

- Validation errors (`422`) list field locations and messages only. They never
  echo the input, which could be a password.
- Database and configuration failures return a generic `503`.
- Anything unexpected returns a generic `500` with an `error_id`. The same id is
  logged server-side with the traceback. No SQL, connection strings or stack
  traces reach the client.

## CORS

Origins come from `CORS_ORIGINS` as an explicit list, and `*` is rejected at
startup. Tokens are sent in the `Authorization` header, not cookies, so
`allow_credentials` is off. Only `GET`/`POST` and the
`Authorization`/`Content-Type` headers are allowed.

## Development

```powershell
cd C:\ASKQ\backend
.\.venv\Scripts\python -m uvicorn app.main:app --reload     # http://127.0.0.1:8000/docs

# Give an existing user a password (hidden prompt, typed twice; never echoed or logged)
.\.venv\Scripts\python -m app.cli.set_password admin

.\.venv\Scripts\python -m pytest                 # unit tests: no .env, no MySQL (SQLite stand-in)
.\.venv\Scripts\python -m pytest --mysql         # + integration tests against the local MySQL
.\.venv\Scripts\python -m ruff check ..
.\.venv\Scripts\python -m ruff format --check ..
```

`app_user_credentials` starts empty, so nobody can log in until
`set_password` has been run for them. The integration tests don't need it:
they insert credentials inside a transaction that is always rolled back, so
`askq_system` stays empty.

## Security notes and future hardening

- **Rate limiting and automatic lockout are not implemented yet.** Failed
  attempts are counted and `locked_until` is honoured, but nothing sets it
  automatically. Add per-IP/per-account throttling and a lockout policy before
  any exposure beyond local use.
- Access tokens can't be revoked individually before `exp`. Deactivating the
  user, locking the account or changing the password revokes them. Keep
  `JWT_EXPIRE_MINUTES` short.
- There are no refresh tokens. The client logs in again when the token expires.
- Serve over HTTPS in any real deployment. The bearer token is a credential.
