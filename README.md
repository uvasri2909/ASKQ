# ASKQ: Ask Questions to your Data

A college research prototype: a secure natural-language-to-SQL analytics platform.
Users ask questions in plain English; Claude drafts SQL; the backend validates it,
enforces role-based access control, and runs **CAIR** (Conversation-Aware Inference
Risk) analysis. CAIR detects when a *sequence* of individually harmless queries could
reveal sensitive information. Only then is the query executed.

> **Status:** Phase 2 of 14 (MySQL schema and deterministic synthetic data).
> Authentication, RBAC, CAIR and Claude integration are not implemented yet.

See [docs/architecture.md](docs/architecture.md) for the design.

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
| Python | 3.13 |
| Node.js | 24 (npm 11) |
| MySQL Server | 8.0 |
| Git | 2.x |

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
```

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

The page shows **Backend status: Online** when both are running.

## Tests and checks

```powershell
# Backend
cd C:\ASKQ\backend
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\python -m ruff check .

# Frontend
cd C:\ASKQ\frontend
npm test
npm run lint
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
- LLM-generated SQL is never executed without validation, authorization and CAIR checks.
- CAIR is a heuristic, explainable risk detector, not a formal privacy guarantee.
