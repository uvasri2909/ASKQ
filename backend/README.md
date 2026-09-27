# backend/

The ASKQ FastAPI service.

- **Phase 3** added the foundation: configuration, the two database connections,
  Argon2id passwords, JWT authentication, and role-based access control with a
  data-scope model.
- **Phase 4** adds the natural-language query pipeline: Claude drafts SQL, and the
  server validates it, authorizes it with row scope, bounds it and runs it as
  `askq_reader`, recording every step.
- **CAIR (Phase 5)** plugs into the pipeline's guard hook.

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
├── llm/
│   ├── sql_generator.py SqlGenerator protocol, GeneratedSql contract, error codes
│   └── claude.py      the only module that imports the Anthropic SDK
├── query/
│   ├── catalog.py     the queryable tables/views (application-controlled metadata)
│   ├── policy.py      per-role tables, hidden columns, row-scope templates
│   ├── schema_context.py  role-filtered schema text for the model
│   ├── sql_validator.py   layer 1: single safe SELECT (tokens, parse, allowlist, tables)
│   ├── authorization.py   layer 2: role/column checks, row-scope rewrite, LIMIT
│   ├── decision.py    Decision model; InferenceGuard hook (CAIR, Phase 5)
│   ├── executor.py    runs SQL as askq_reader only (timeout, row cap)
│   ├── service.py     the pipeline; writes query history through askq_app
│   └── schemas.py     request/response models
└── cli/set_password.py  provision a user's password (run by hand)
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | Liveness. Never touches the database. |
| GET | `/health/db` | none | `SELECT 1` through each account. `200 {"status":"ok","checks":{"app":"ok","reader":"ok"}}`, or `503` with `"unavailable"` per failed check. No host, user, version or error text. |
| POST | `/api/v1/auth/login` | none | `{"username","password"}` → `{"access_token","token_type":"bearer","expires_in","user":{id,username,role,permissions}}` |
| GET | `/api/v1/auth/me` | Bearer | `{id, username, role, permissions}` for the caller, re-read from the database |
| POST | `/api/v1/query` | Bearer + `ASK_QUESTIONS` | `{"question", "conversation_id"?}` → the decision, the executed SQL, columns/rows, chart hint and a security summary. See "Query pipeline". |
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
| `ANTHROPIC_API_KEY` | none | Required for `/api/v1/query` (503 without it); never logged |
| `ANTHROPIC_MODEL` | `claude-sonnet-5` | Any current Claude model id |
| `ANTHROPIC_MAX_TOKENS`, `ANTHROPIC_TIMEOUT_SECONDS`, `ANTHROPIC_MAX_RETRIES` | `16000`, `60`, `1` | |
| `SQL_MAX_ROWS` | `500` | Every executed query is bounded to this many rows |
| `SQL_TIMEOUT_MS` | `5000` | MySQL `max_execution_time` per executed query |
| `QUERY_CONTEXT_TURNS` | `5` | Earlier turns shown to the model for follow-ups |

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

## Query pipeline (Phase 4)

```
question ──► Claude ──► UNTRUSTED SQL ──► validate ──► authorize + row scope + LIMIT
          ──► guard (CAIR, Phase 5) ──► askq_reader (read-only) ──► result
every step ──► query_history / cair_assessments / security_audit_log (askq_app)
```

**The model is not trusted for anything.** It receives the role, a
description of the user's scope and a role-filtered schema, so that it can
write useful SQL. Its output is treated like input typed by an attacker. The
prompt tells it not to work around access rules, but nothing depends on it
obeying: every rule is enforced afterwards, in code, on the parsed SQL.
Conversation history is passed to the model as data to resolve follow-ups
("and for year 2?"). It never reaches the authorizer, so context can change
what is asked but never what is allowed.

**1. Generation (`llm/claude.py`).**
- **Call:** Anthropic SDK, `messages.create` with structured outputs
  (`output_config.format` = JSON schema), which returns `resolved_question`,
  `sql`, `explanation` and `chart`.
- **Validation of the output:** the reply is re-validated with a strict
  Pydantic model. Malformed JSON, extra fields, a refusal or truncation are
  rejected, never repaired.
- **Errors:** SDK errors map to codes such as `LLM_TIMEOUT` and
  `LLM_RATE_LIMITED`. Only the exception class name is logged.
- **Credentials:** the key comes only from Settings.
- **Caching:** the system prompt (instructions plus the role's schema) is marked
  for prompt caching.
- **Scope of the SDK:** the rest of the backend depends only on the
  `SqlGenerator` protocol. Tests replace it; no test calls the API.

**2. Role-filtered schema (`query/catalog.py`, `policy.py`, `schema_context.py`).**
The model sees a fixed, application-written description of the 15 tables and
2 views that `askq_reader` can read, minus the tables and columns the user's
role may not use. `users`, `roles`, `askq_system`, credentials and audit data
are never described to anyone. Nothing is discovered from `information_schema`.

**3. Validation (`query/sql_validator.py`): is it a single, plain SELECT?**
- **Tokens:** no comments of any kind and no `;`. The parser drops comments,
  but MySQL executes `/*!…*/` and honours `/*+…*/`.
- **Parse:** exactly one statement, rooted at `SELECT` (or `UNION` of `SELECT`s).
  DML, DDL, `GRANT`/`REVOKE`, `CALL`/`EXECUTE`/`PREPARE`, `SET`, `SHOW`,
  `HANDLER`, `INTO OUTFILE`/`DUMPFILE` all fail here.
- **Whole-tree allowlist of node types and functions:** anything not listed is
  rejected. This includes `INTO @var`, `FOR UPDATE`, `@var`/`@@sysvar`,
  placeholders, hex/charset literals, `COLLATE`, `INTERSECT`/`EXCEPT`, recursive
  CTEs, SELECT modifiers, index/partition hints, and every function not on the
  list (`SLEEP`, `BENCHMARK`, `LOAD_FILE`, `USER()`, `GET_LOCK`, ...). That
  closes the residual `askq_reader` exposures listed in `database/README.md`.
- **Tables:** only catalog tables, optionally qualified with `askq_university`.
  System schemas, `askq_system`, `users`/`roles` and unknown names all get the
  same "data not available" message, so the answer does not reveal what exists.
- **Canonical SQL:** from here on, the SQL is regenerated from the parsed tree,
  so what runs is exactly what was checked.

**4. Authorization (`query/authorization.py`): may this user run it, over which rows?**
- **Tables and columns:** a table outside the role's policy, or a hidden column
  (salary except for ADMIN; date of birth for HOD and TEACHER; gender for
  TEACHER), gives `DENIED`. For STUDENT, an explicit `student_id` literal other
  than their own is also `DENIED`.
- **Row scope by rewriting:** every reference to a scoped table, anywhere in
  the tree, is replaced by a derived table holding only the role's visible
  columns and only the user's rows, under the same alias:
  ```
  FROM students s  →  FROM (SELECT <visible columns> FROM askq_university.students
                            WHERE department_id = 3) AS s
  ```
  The model's predicates cannot widen this. A HOD asking for another
  department simply gets no rows.
- **Scope ids:** these are integers from the server-side `UserContext`.

  | Role | Rows visible (people, enrollments, grades, attendance, finance) |
  |---|---|
  | ADMIN | everything |
  | HOD | their department's teachers and students, and enrollments of those students or of the department's courses |
  | TEACHER | their department's teachers; students they teach or advise; enrollments in their offerings or of advisees. No financial tables. |
  | STUDENT | their own records; teachers of their offerings and their advisor |

  Reference data (departments, terms, grade scale, courses, offerings, class
  sessions, scholarship catalogue) is visible to all roles.
- **LIMIT:** the outermost query is bounded to `SQL_MAX_ROWS`. A missing LIMIT
  is added and a larger one is capped. Only literal LIMIT/OFFSET values are
  accepted.
- **Re-validation:** the rewritten SQL is validated again before it may run.

**5. Guard (`query/decision.py`): the Phase 5 hook.**
- **Interface:** `InferenceGuard.assess(GuardInput) -> GuardResult`, with
  ALLOW/RESTRICT/BLOCK, a risk score in [0, 1], reasons and a policy version.
  It receives the server's `UserContext`, the parsed query, the authorized and
  scoped query, and the conversation history.
- **Phase 4 guard:** `PassThroughGuard`, which always ALLOWs with risk 0 and
  says so in its recorded reason.
- **RESTRICT:** a guard may only narrow. RESTRICT SQL goes through validation
  and authorization again (role tables, hidden columns, row scope, LIMIT), so
  even a faulty guard cannot widen what the user sees. A BLOCK never reaches
  the reader.

**6. Execution (`query/executor.py`).**
- **Account:** only through `Database.reader_connection()`: `askq_reader`, a
  read-only session, `max_execution_time = SQL_TIMEOUT_MS`.
- **Row cap:** at most `SQL_MAX_ROWS` rows are fetched.
- **No parameter formatting:** statements run with `no_parameters=True`, so
  `LIKE '%x%'` is never %-formatted.
- **Separation:** no code path runs model-derived SQL on the app engine or as
  root, and the tests spy on both engines to prove it.

**Decisions.** Each question ends in exactly one server-controlled decision,
returned with a safe message and recorded:

| Decision | Meaning | `query_history.final_status` |
|---|---|---|
| ALLOW | Executed (possibly row-scoped / row-limited) | EXECUTED |
| RESTRICT | Executed in a narrower form chosen by the guard | RESTRICTED |
| BLOCK | Guard refused; not executed | BLOCKED |
| DENIED | Authorization refused (table, column or scope); not executed | DENIED |
| REJECTED | SQL validation refused; not executed | REJECTED |
| FAILED | System error at a stage (generation, validation, authorization, CAIR, execution) | FAILED |

All of these are `200` responses carrying the decision. HTTP errors are
reserved for the request itself: 401/403/404/422, and 503 when Claude or the
database is not configured.

**History.** One `query_history` row per question, through `askq_app`:
- **Turns:** each question is a `conversation_turns` row. Conversations are the
  caller's own; anyone else's conversation id is a 404.
- **What the row holds:** the resolved question, the model's generated SQL,
  each gate's outcome, the executed SQL, row count and timing, and the failure
  stage and code.
- **Assessments:** each guard result is written to `cair_assessments`.
- **Audit:** `QUERY_REJECTED`/`DENIED`/`BLOCKED` go to `security_audit_log`,
  plus `READER_ACCESS_DENIED` (CRITICAL) if MySQL ever refuses a query that
  passed the validator.
- **Never stored:** result rows, passwords, tokens or keys. Generated SQL is
  offered back to the model as context only for turns that actually ran.

**Phase 4 / Phase 5 boundary.** Phase 4 enforces everything about a *single*
query:
- it is safe SQL;
- it is within the role's tables and columns;
- it is restricted to the user's rows;
- it is bounded in size and time.

It does not reason across queries. Inference from sequences of individually
allowed answers (differencing, narrowing, arithmetic recovery, cross-view
linking, refusal side channels, context carry-over) is CAIR's job in Phase 5,
behind the guard interface above.

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

- **Phase 4 limits (by design, until Phase 5):**
  - The pass-through guard does no inference analysis.
  - Aggregates over small groups (e.g. the average of a group of one) are not
    suppressed yet.
  - A HOD or TEACHER may still see students' quasi-identifiers such as home
    region within their scope.
- The authorizer's hidden-column check is by column name, and hidden columns
  are also removed from every scoped derived table, so `SELECT *` cannot
  reveal them.
- There is no per-user rate limit on `/api/v1/query` yet, and each question
  costs one Claude call.

- **Rate limiting and automatic lockout are not implemented yet.** Failed
  attempts are counted and `locked_until` is honoured, but nothing sets it
  automatically. Add per-IP/per-account throttling and a lockout policy before
  any exposure beyond local use.
- Access tokens can't be revoked individually before `exp`. Deactivating the
  user, locking the account or changing the password revokes them. Keep
  `JWT_EXPIRE_MINUTES` short.
- There are no refresh tokens. The client logs in again when the token expires.
- Serve over HTTPS in any real deployment. The bearer token is a credential.
