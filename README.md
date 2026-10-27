# ASKQ: Ask Questions to your Data

A college research prototype: a secure natural-language-to-SQL analytics platform.
Users ask questions in plain English; a language model (Claude, or a local
Qwen model via Ollama) drafts SQL; the backend validates it,
enforces role-based access control, and runs **CAIR** (Conversation-Aware Inference
Risk) analysis. CAIR detects when a *sequence* of individually harmless queries could
reveal sensitive information. Only then is the query executed.

> **Status:** Phase 7 of 14 in progress (evaluation). Phases 1–6 are complete:
> scaffold, database and synthetic seed, authentication and RBAC, the secure
> NL-to-SQL pipeline, CAIR, and the web frontend. In Phase 7 the three-arm
> evaluation design (7A) and the frozen held-out benchmark (7B.1) are done;
> the K_ONLY and held-out results have not been produced yet.

See [docs/architecture.md](docs/architecture.md) for the design,
[backend/README.md](backend/README.md) for the API, authentication and RBAC,
[frontend/README.md](frontend/README.md) for the web app,
[database/README.md](database/README.md) for the databases, and
[docs/testing.md](docs/testing.md) for every test and check.

## The problem

People who need answers from an organisation's database usually cannot write
SQL. Letting a language model write it for them raises three problems:

1. **The model's SQL cannot be trusted.** It may modify data, read system
   tables or run expensive statements, whether by mistake or because a user
   steered it there.
2. **Not everyone may see everything.** A student, teacher, head of department
   and administrator each have a different right to rows and columns, and a
   model cannot be relied on to respect that.
3. **Harmless answers can add up.** A sequence of individually allowed
   aggregate questions (for example two averages that differ by one person) can
   reveal one person's private data.

ASKQ addresses the first two in code on the server, and the third with CAIR.
It is demonstrated on a university database filled with **synthetic** data.

## Features

- Plain-English questions, with follow-up questions inside a conversation.
- Two interchangeable SQL generators chosen by `LLM_PROVIDER`: a local Qwen
  model through Ollama (no API key, the local demo default) or the Claude API.
- SQL validation with sqlglot: exactly one read-only `SELECT`, a node and
  function allowlist, catalog tables only, no comments or stacked statements.
- Role-based access control for ADMIN, HOD, TEACHER and STUDENT: hidden
  columns, and row scope enforced by rewriting every table reference into a
  derived table limited to the user's rows.
- Execution only as the SELECT-only `askq_reader` MySQL account, with a row
  cap and a server-side statement timeout.
- CAIR: an aggregate-only statistical tier with a minimum group size, a
  per-user ledger and six inference audits (differencing, narrowing,
  arithmetic recovery, cross-view linking, refusal side channels, context
  carryover) deciding ALLOW / RESTRICT / BLOCK.
- Argon2id passwords, short-lived JWTs re-checked against the database on every
  request, and a security audit log.
- A React web app: sign-in, Ask page with tables and simple SVG charts, a
  "How ASKQ checked this" panel, conversation history and profile.
- A reproducible evaluation: six attack scenarios (C1–C6), benign workloads,
  three evaluation arms and a frozen held-out benchmark (`python -m app.evaluation`).

## Technology stack

| Layer | Technology |
|---|---|
| Frontend | React 19, TypeScript, Vite, Vitest, oxlint |
| Backend | Python 3.13, FastAPI, Pydantic, SQLAlchemy 2, PyMySQL, sqlglot, PyJWT, pwdlib (Argon2id) |
| Language model | Ollama with `qwen2.5-coder:7b` (local), or the Anthropic Claude API (optional) |
| Database | MySQL 8.0 (two databases, two least-privilege accounts) |
| Tests and tooling | pytest, ruff, PowerShell setup scripts |

## Project layout

```
ASKQ/
├── backend/     FastAPI application (Python 3.13)
├── frontend/    React + Vite + TypeScript dashboard
├── database/    MySQL schema, synthetic-data generator, DB accounts (see database/README.md)
└── docs/        Architecture, CAIR design, attack scenarios, evaluation
```

## Prerequisites

| Software | Version used |
|---|---|
| Python | 3.13 (tested; `backend/pyproject.toml` allows 3.12+) |
| Node.js | 24 (npm 11) |
| MySQL Server | 8.0 |
| Git | 2.x |
| Ollama (for `LLM_PROVIDER=ollama`) | with the `qwen2.5-coder:7b` model pulled |
| Anthropic API key (only for `LLM_PROVIDER=claude`) | optional |

The setup scripts (`backend\setup.ps1`, `database\setup_db.ps1`) are written for
**Windows PowerShell**, and the commands below use Windows paths. The
application code itself is not Windows-specific, but setup on other operating
systems has not been documented or tested.

All data in the databases is synthetic and generated deterministically by
`database/seed/generate_seed.py`; no real person or organisation appears. The
generated seed files are git-ignored and rebuilt by `setup_db.ps1`.

## Setup (Windows PowerShell)

```powershell
cd C:\ASKQ

# 1. Environment file (edit values as later phases require them)
Copy-Item .env.example .env

# 2. Backend: creates .venv, installs pinned deps, installs import-path isolation
cd backend
powershell -ExecutionPolicy Bypass -File .\setup.ps1
cd ..

# 3. Frontend
cd frontend
npm install
cd ..

# 4. Databases: first set DB_READER_PASSWORD / DB_APP_PASSWORD in .env and
#    create the askq_admin login path (both explained in database\README.md)
powershell -ExecutionPolicy Bypass -File .\database\setup_db.ps1

# 5. Authentication: set JWT_SECRET in .env (see .env.example), then give a
#    user a password (hidden prompt; see backend\README.md)
cd backend
.\.venv\Scripts\python -m app.cli.set_password admin
cd ..

# 6. Language model. For LLM_PROVIDER=ollama (the .env.example default),
#    install Ollama from https://ollama.com, then:
ollama pull qwen2.5-coder:7b
#    For LLM_PROVIDER=claude instead, set ANTHROPIC_API_KEY in .env.
```

Demo accounts come from the synthetic seed (`admin`, HOD `t0001`, teachers
such as `t0002`, students such as `s20230001`; see
[database/README.md](database/README.md#roles-foundation-for-backend-rbac)).
None of them has a password until you set one with `set_password`.

## Running

Use two terminals.

**Backend**, at http://127.0.0.1:8000 (API docs at `/docs`):

```powershell
cd C:\ASKQ\backend
.\.venv\Scripts\python -m uvicorn app.main:app --reload
```

**Frontend**, at http://localhost:5173:

```powershell
cd C:\ASKQ\frontend
npm run dev
```

Open http://localhost:5173 and sign in with a user that has a password (step 5
of the setup). The login page shows **Server: online** when the backend is up.
The dev server proxies `/api` and `/health` to the backend, so the browser only
ever talks to one origin. Asking questions needs a language model, chosen by
`LLM_PROVIDER` in `.env`:

- `ollama` (the local demo setup in `.env.example`): a local Ollama server with
  the model pulled, no API key. Install Ollama, then
  `ollama pull qwen2.5-coder:7b`; the backend calls `http://127.0.0.1:11434`.
  If Ollama is not running, questions fail with "The language model is
  unavailable".
- `claude` (the application default): needs a real `ANTHROPIC_API_KEY`; with
  the placeholder key, `/api/v1/query` answers
  `503 Service temporarily unavailable` and the app shows that message.

Signing in keeps the access token in memory only (never `localStorage` or
cookies), so reloading the page signs you out.

## Tests and checks

Prerequisites and what each suite covers are in [docs/testing.md](docs/testing.md).

```powershell
# Backend
cd C:\ASKQ\backend
.\.venv\Scripts\python -m pytest            # unit tests (no MySQL needed)
.\.venv\Scripts\python -m pytest --mysql    # + integration tests against the local MySQL
.\.venv\Scripts\python -m pytest --ollama   # + live smoke test against the local Ollama model
.\.venv\Scripts\python -m ruff check ..
.\.venv\Scripts\python -m ruff format --check ..

# Frontend
cd C:\ASKQ\frontend
npm test
npm run lint
npm run typecheck
npm run build

# Databases (rebuild from scratch; asks for confirmation)
cd C:\ASKQ
.\database\setup_db.ps1 -Reset
```

## Troubleshooting

- **`pytest` fails with an unexpected error inside a file in the global Python folder**
  (e.g. `EOFError` in `py.py`): personal scripts in the Python install folder are
  shadowing real modules. ASKQ fixes this inside its own venv only, without touching the
  global installation. Re-run `backend\setup.ps1`, which installs
  `backend\tools\askq_isolate_base_dir.pth` (explained in `backend\tools\README.md`).
  `tests\test_environment.py` checks this.
- **`setup.ps1` cannot be loaded because running scripts is disabled:** run it with
  `powershell -ExecutionPolicy Bypass -File .\setup.ps1` as shown above.

## Security notes

- Secrets live only in `.env` (git-ignored). `.env.example` contains placeholders.
- Passwords are stored as Argon2id hashes; access tokens are short-lived JWTs whose
  role is re-checked against the database on every request.
- The model's SQL (Claude or Ollama) is untrusted: it is parsed, validated against an allowlist,
  row-scoped by the server for the user's role, bounded, and run only as the
  read-only `askq_reader` account (see `backend/README.md`, "Query pipeline").
- The backend uses two MySQL accounts that are never merged: `askq_app` for its own
  data and `askq_reader` (read-only) for organisational data.
- LLM-generated SQL is never executed without validation, authorization and CAIR checks.
- The web app only displays what the backend decided. It sends the question (and
  a conversation id) and nothing else: no role, scope, SQL or security decision.
  It never shows SQL, risk scores or raw errors, and renders every value as text.
- CAIR is a heuristic, explainable risk detector, not a formal privacy guarantee.
  See [docs/cair.md](docs/cair.md) and [docs/attack-scenarios.md](docs/attack-scenarios.md);
  run the scenario evaluation with `backend\.venv\Scripts\python -m app.evaluation`.

## Known limitations

ASKQ is a research prototype for local use, not a production service.

- **CAIR is heuristic.** It looks at a bounded window (20 questions / 24 hours by
  default), does not link colluding accounts, does not equalise response
  timing, and refuses some legitimate statistical questions it cannot assess
  (subqueries, outer joins, computed aggregates). Full list:
  [docs/cair.md](docs/cair.md#limitations).
- **Login hardening is incomplete.** There is no rate limiting on login or
  `/api/v1/query`, and no automatic account lockout (failed attempts are counted
  and a manual `locked_until` is honoured).
- **Tokens.** Access tokens cannot be revoked individually before they expire,
  and there are no refresh tokens; reloading the web page signs you out.
- **No HTTPS** is configured. Serve it over HTTPS in any real deployment.
- **Local model accuracy.** A 7B local model writes worse SQL than Claude, so
  more questions end as unanswerable, rejected or failed. This never weakens a
  check, because every check runs on whatever SQL is returned.
- **Data retention.** Query history (questions and generated SQL) cannot be
  deleted by the application account; a purge policy has not been decided.
- **Setup is Windows-only** as documented (PowerShell scripts), and the dataset
  is a synthetic university, not real data.

## License

ASKQ is released under the [MIT License](LICENSE).
Copyright (c) 2026 UVASRI SELLADURAI and SRI HARSHINI V A.

Third-party dependencies (installed by `pip` and `npm`, not included in this
repository) keep their own licenses. The `qwen2.5-coder:7b` model is downloaded
separately by Ollama and is covered by its own license, not by this one.
