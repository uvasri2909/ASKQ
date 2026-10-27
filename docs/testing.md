# Testing and checks

Every command below is taken from the project's own configuration
(`backend/pyproject.toml`, `backend/tests/conftest.py`, `frontend/package.json`,
`database/setup_db.ps1`). Commands are for Windows PowerShell, matching the
setup scripts.

| Suite | Needs | Command (from) |
|---|---|---|
| Backend unit tests | backend venv only | `python -m pytest` (`backend/`) |
| Backend MySQL integration tests | built databases + `.env` | `python -m pytest --mysql` (`backend/`) |
| Live Ollama smoke test | Ollama running, model pulled | `python -m pytest --ollama` (`backend/`) |
| Backend lint / format | backend venv | `python -m ruff check ..`, `python -m ruff format --check ..` (`backend/`) |
| Frontend tests | `npm install` | `npm test` (`frontend/`) |
| Frontend lint / types / build | `npm install` | `npm run lint`, `npm run typecheck`, `npm run build` (`frontend/`) |
| Database verification | MySQL 8 + admin login | `database\setup_db.ps1` (runs every SQL and account check) |
| CAIR scenario evaluation | built databases + `.env` | `python -m app.evaluation` (`backend/`) |

In `backend/`, `python` means `.\.venv\Scripts\python` (created by `backend\setup.ps1`).

## Backend unit tests

```powershell
cd C:\ASKQ\backend
.\.venv\Scripts\python -m pytest
```

- **No MySQL, no `.env`, no network.** `tests/conftest.py` builds `Settings`
  with secrets generated per run and an in-memory SQLite database that attaches
  `askq_university` and `askq_system` with the production ORM models.
- **No language model.** Tests replace the `SqlGenerator`. The Claude generator
  is tested without calling the API, and the Ollama generator with
  `httpx.MockTransport`.
- Covers configuration, authentication, RBAC, the SQL validator, row-scope
  authorization, the statistical tier, CAIR detectors and adversarial
  scenarios, response privacy, history, the seed generator (four seeds), the
  database DDL and grants (parsed offline), and the frozen held-out benchmark's
  integrity.
- Tests marked `mysql` or `ollama` are collected but **reported as skipped**
  unless their flag is given (`-ra` in `pyproject.toml` lists the skip reasons).

Useful variants:

```powershell
.\.venv\Scripts\python -m pytest tests\test_sql_validator.py   # one file
.\.venv\Scripts\python -m pytest -k cair                       # by name
.\.venv\Scripts\python -m pytest --cov=app                     # coverage (pytest-cov is in requirements-dev.txt)
```

## Backend integration tests (MySQL)

```powershell
cd C:\ASKQ\backend
.\.venv\Scripts\python -m pytest --mysql
```

Prerequisites:

1. MySQL Server 8.0 on `127.0.0.1:3306`.
2. The databases and the `askq_reader` / `askq_app` accounts built by
   `database\setup_db.ps1` (see [database/README.md](../database/README.md)).
3. The real `C:\ASKQ\.env` with `DB_READER_PASSWORD`, `DB_APP_PASSWORD` and
   `JWT_SECRET` set.

The integration tests are in `backend/tests/integration/`:

| File | Checks |
|---|---|
| `test_mysql.py` | Both accounts connect; the reader is read-only and cannot reach `askq_system`; the app account cannot read organisational tables |
| `test_query_mysql.py` | The query pipeline against the seeded data, with a scripted SQL generator instead of a model |
| `test_history_mysql.py` | Conversations and history endpoints against MySQL |
| `test_cair_mysql.py` | The C1–C6 attack scenarios and benign workloads through CAIR |
| `test_evaluation_arms_mysql.py` | The three evaluation arms (NO_CONTROL, K_ONLY, CAIR) |
| `test_heldout_mysql.py` | The frozen held-out benchmark's premises hold on the seeded data (it does not evaluate ASKQ on it) |

Each test works inside an outer transaction that is **always rolled back**, so
`askq_system` and the seeded data stay unchanged. (A rolled-back `INSERT` still
advances `AUTO_INCREMENT` counters; see the docstring of `test_mysql.py`.)

## Live Ollama smoke test

```powershell
ollama pull qwen2.5-coder:7b        # once
cd C:\ASKQ\backend
.\.venv\Scripts\python -m pytest tests\integration\test_ollama_live.py --ollama
```

Calls the real local Ollama server configured by `OLLAMA_*` in `.env`. It checks
the integration (the reply matches the strict JSON schema, and the SQL is
accepted only if the unchanged validator accepts it), not the model's accuracy.
No database is touched. Generation on a local 7B model can take a while,
especially the first call while the model loads.

Both flags can be combined: `python -m pytest --mysql --ollama` runs everything.

## Lint and format

```powershell
cd C:\ASKQ\backend
.\.venv\Scripts\python -m ruff check ..          # lint backend/ and database/ (rules in backend/pyproject.toml)
.\.venv\Scripts\python -m ruff format --check .. # formatting, no changes written

cd C:\ASKQ\frontend
npm run lint        # oxlint (.oxlintrc.json)
npm run typecheck   # tsc -b
```

`ruff format ..` (without `--check`) rewrites files in place.

## Frontend tests and production build

```powershell
cd C:\ASKQ\frontend
npm test            # vitest run (jsdom; setup in src/test/setup.ts)
npm run build       # tsc -b && vite build, output in frontend/dist/ (git-ignored)
npm run preview     # serve the built bundle locally
```

The frontend tests mock `fetch` (`src/test/mockApi.ts`), so they need neither
the backend nor a database.

## Database verification

`database\setup_db.ps1` runs these on every build, and exits non-zero if any fails:

- `database/validation/verify_database.sql`: structure, row counts, temporal
  values, relationships and grant tables.
- `database/validation/verify_security_cohorts.sql`: the 34 security-cohort checks.
- `database/tools/verify_accounts.py`: logs in as each account and probes its privileges.

To rebuild from scratch (drops only `askq_university` and `askq_system`; asks
you to type `RESET`):

```powershell
cd C:\ASKQ
powershell -ExecutionPolicy Bypass -File .\database\setup_db.ps1 -Reset
```

## CAIR scenario evaluation

```powershell
cd C:\ASKQ\backend
.\.venv\Scripts\python -m app.evaluation                # default: --mode BOTH (CAIR + NO_CONTROL)
.\.venv\Scripts\python -m app.evaluation --mode ALL     # NO_CONTROL, K_ONLY and CAIR
.\.venv\Scripts\python -m app.evaluation --steps        # print every step
```

Needs the MySQL databases; runs are rolled back. Metrics and methodology are
in [cair.md](cair.md). The held-out benchmark (`backend/app/evaluation/heldout.py`
with `heldout_manifest.json`) is frozen: `tests/test_heldout_benchmark.py`
fails if its frozen definitions change.
