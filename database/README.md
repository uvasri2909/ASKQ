# database/

Everything needed to build ASKQ's MySQL 8 databases from scratch: schema,
deterministic synthetic data, least-privilege accounts and verification.
All data is synthetic. No real person, email address or organisation appears anywhere.

```
database/
├── setup_db.ps1                    One command: build, seed, create accounts, verify
├── schema/                         DDL, run in numeric order
│   ├── 01_create_databases.sql       askq_university + askq_system (utf8mb4)
│   ├── 02_university_schema.sql      17 tables
│   ├── 03_system_schema.sql          10 tables for later phases (empty)
│   ├── 04_indexes.sql                secondary indexes for common queries
│   └── 05_views.sql                  v_fee_balances, v_attendance_summary
├── seed/
│   ├── generate_seed.py              CLI: writes seed/generated/ (stdlib only)
│   ├── askq_seed/                    generator package
│   │   ├── reference.py                fixed reference data + temporal constants
│   │   ├── cohorts.py                  the 14 planted security-demo students
│   │   ├── cohort_checks.py            34 property checks over the six cohorts
│   │   ├── generator.py                builds the dataset from the seed
│   │   └── sqlwriter.py                renders SQL
│   └── generated/                    (git-ignored build output)
│       ├── 01_reference_data.sql
│       ├── 02_synthetic_data.sql
│       ├── 03_security_demo_data.sql
│       └── security_demo_manifest.json
├── accounts/grants.sql             privileges for askq_reader / askq_app (no passwords)
├── reset/drop_askq_databases.sql   drops ONLY askq_university and askq_system
├── validation/
│   ├── verify_database.sql           65 PASS/FAIL checks (data, structure, time, grants)
│   ├── verify_security_cohorts.sql   the 34 cohort checks (committed, seed-independent)
│   └── sample_queries.sql            representative read-only questions
└── tools/verify_accounts.py        logs in as each account and probes its privileges
```

## Architecture

Two databases on one MySQL 8 server, kept logically separate. There are **no
cross-database foreign keys**, so either one can be rebuilt on its own.

| Database | Purpose | Written by | Read by |
|---|---|---|---|
| `askq_university` | Organisational data that users ask questions about | Seed scripts only | `askq_reader` (LLM-generated SELECTs); `askq_app` (login lookups only) |
| `askq_system` | ASKQ's own data: credentials, conversations, query history, CAIR, audit log, evaluation | `askq_app` | `askq_app` |

All tables use InnoDB and `utf8mb4` / `utf8mb4_0900_ai_ci`. Every table has a
primary key. Declared constraints: **73 CHECK, 34 foreign keys, 37 UNIQUE**.
`verify_database.sql` asserts these exact numbers, and a unit test keeps them in
sync with the DDL. Foreign keys never cascade, so a stray `DELETE` cannot
silently remove grades or payments. Enumerations are `VARCHAR` plus `CHECK`.
Derived values (fee balances, attendance rates) are views, not stored columns.

### askq_university tables

| Table | Rows (default seed) | Description |
|---|---:|---|
| `roles` | 4 | ADMIN, HOD, TEACHER, STUDENT. Ids pinned by `ck_roles_id_code` (1 ADMIN, 2 HOD, 3 TEACHER, 4 STUDENT). |
| `departments` | 7 | Code, name, building, `head_teacher_id` (HOD) |
| `academic_terms` | 2 | Spring 2026 (completed), Fall 2026 (current; at most one current, enforced by a unique generated column) |
| `grade_scale` | 9 | Letter grade, minimum marks, grade points (4.0 scale) |
| `teachers` | 40 | Staff: department, designation, hire date, **salary** |
| `students` | 1,000 | Department, year level, **gender, date of birth**, residency, home region, hostel, advisor, status |
| `users` | 1,041 | Login identities: username + role, linked to exactly one teacher/student (none for ADMIN), enforced by `ck_users_role_links`. **No password hashes.** |
| `courses` | 91 | 12 core courses per department (3 per year level) + 1 open elective each |
| `course_offerings` | 177 | A section of a course in a term, taught by one teacher (max 80 seats) |
| `enrollments` | 6,852 | Student in an offering: ENROLLED / COMPLETED / DROPPED |
| `grades` | 2,858 | Final marks and letter for completed (Spring 2026) enrollments |
| `class_sessions` | 3,048 | Scheduled meetings of an offering (twice weekly) |
| `attendance_records` | 115,608 | PRESENT / LATE / ABSENT / EXCUSED per session per enrolled student |
| `fees` | 7,374 | **Charges** per student per term: TUITION, LAB, LIBRARY, EXAM, HOSTEL |
| `fee_payments` | 6,841 | **Payments** against a fee (receipt number unique) |
| `scholarships` | 6 | Programme catalogue (merit, need-based, athletic, international, research) |
| `student_scholarships` | 198 | **Award** of a programme to a student for a term |

Views (both `SQL SECURITY INVOKER`):

- `v_fee_balances`: amount due, paid, balance, and `payment_status` (PAID / OVERDUE / PARTIAL / UNPAID) judged **as of the fixed reference date 2026-09-25**, exposed as `status_as_of`.
- `v_attendance_summary`: sessions attended and attendance % per enrollment.

### Important relationships

- `students.department_id`, `teachers.department_id` → `departments`; `departments.head_teacher_id` → `teachers` (unique: one head per department).
- `course_offerings` (course, term, teacher) ← `enrollments` (student) ← `grades` (1:1) and `attendance_records`.
- `attendance_records` has two composite foreign keys, `(session_id, offering_id)` and `(enrollment_id, offering_id)`. Together they guarantee a student can only be marked in sessions of an offering they are enrolled in.
- `fees` ← `fee_payments`; `scholarships` ← `student_scholarships` → `students`, `academic_terms`.
- `users.teacher_id` / `users.student_id` → the person behind a login.

### askq_system tables (empty until later phases)

| Table | Used from | Description |
|---|---|---|
| `app_user_credentials` | Phase 3 | Argon2id password hash, failed attempts, lock, last login per `user_id` |
| `conversations`, `conversation_turns` | Phase 6+ | Chat sessions and the user's questions |
| `query_history` | Phase 5+ | One row per pipeline run (see below) |
| `cair_assessments`, `cair_audit_findings` | Phase 8-9 | Why CAIR decided (policy version, reasons); one finding per audit (the six attack classes) |
| `cair_ledger_entries` | Phase 8-9 | Per-user knowledge ledger: query descriptor (JSON) + SHA-256 population fingerprint |
| `security_audit_log` | Phase 3+ | Logins (from Phase 3), denials, rejections, blocks |
| `evaluation_runs`, `evaluation_results` | Phase 12 | Baseline vs CAIR runs, per-step expected/actual decisions |

`user_id` columns here are logical references to `askq_university.users.user_id`.
`role_code` records the role at the time of the event.

#### query_history: reconstructing a request

```
conversations ─< conversation_turns ─< query_history ─1 cair_assessments ─< cair_audit_findings
                                            ├─< cair_ledger_entries
                                            ├─< security_audit_log
                                            └─< evaluation_results
```

One row is **written once**, when the pipeline finishes; `askq_app` has no
`UPDATE` on it. A row holds:

- **Where the question came from:** `conversation_id`, `turn_id`. A composite FK guarantees the turn belongs to that conversation.
- **The question, stored exactly once:** `conversation_turns.question` for chat, or `query_history.question_text` when there is no turn (e.g. evaluation). This is enforced by `ck_qh_question_source`.
- **`resolved_question`:** the self-contained question actually sent to the LLM after conversation context was applied. CAIR's context-carryover audit compares it with the raw question.
- **`generated_sql`:** what the LLM proposed. **`executed_sql`:** what actually ran (after RBAC rewriting or CAIR restriction), or NULL.
- **One outcome column per gate, in order:** `validation_status` → `authorization_status` → `cair_decision` + `risk_score` → execution (`result_row_count`, `execution_ms`). A gate's column is NULL when the pipeline never reached it; `ck_qh_stage_order` makes a later gate impossible without the earlier ones passing.
- **`final_status`**, one summary value, tied to the gate columns by `ck_qh_final_status`:

| final_status | Meaning | Ran? |
|---|---|---|
| `EXECUTED` | CAIR ALLOW | yes |
| `RESTRICTED` | CAIR RESTRICT; `executed_sql` is the restricted form (e.g. coarsened, small groups suppressed) | yes |
| `BLOCKED` | CAIR BLOCK | no |
| `DENIED` | RBAC authorization DENIED | no |
| `REJECTED` | SQL-safety validation REJECTED the generated SQL | no |
| `FAILED` | System error at `failure_stage` (GENERATION / VALIDATION / AUTHORIZATION / CAIR / EXECUTION) with `error_code` | only if EXECUTION |

The CAIR decision and risk score are stored once, in `query_history`.
`cair_assessments` holds the explanation. The ledger repeats `user_id` for CAIR's
per-user hot path, and a composite FK `(query_id, user_id)` guarantees it matches
the query's user. All CHECKs are NULL-safe (a CHECK that evaluates to NULL
counts as passed, so nullable columns are compared through `COALESCE`). A SQLite
truth-table test covers every valid and invalid combination.

**Retention and privacy:** questions and SQL can contain personal data (names,
student numbers). Result rows are never stored. `askq_app` cannot delete
history, so purging is an administrative task, to be decided before any use
beyond the demo.

## Temporal model (deterministic)

Nothing in the data depends on the machine's clock or time zone.

| Constant | Value | Used for |
|---|---|---|
| `DATA_AS_OF` | **2026-09-25** | Business "today". Attendance and payments stop here. `v_fee_balances` judges OVERDUE against `DATE '2026-09-25'` (never `CURRENT_DATE`). |
| `SNAPSHOT_AT` | **2026-09-25 18:00:00 UTC** | Every `created_at` / `updated_at` written by the seed. Each seed file runs `SET time_zone = '+00:00'; SET timestamp = 1790359200;` so MySQL's `CURRENT_TIMESTAMP` defaults return this instant, then `SET timestamp = DEFAULT`. |
| Terms | Spring 2026: Jan 12 – May 8 (completed, grades released May 20); Fall 2026: Aug 17 – Dec 11 (current) | All `DATE` values are fixed in `reference.py`. |

Tests check that the generator never reads the clock and that every seed file
pins it. `verify_database.sql` checks the stored values.
`askq_system` timestamps are real runtime times, stored as `TIMESTAMP(3)`
(UTC internally). The backend must connect with `time_zone = '+00:00'`.

## Security layers: who enforces what

| Layer | Enforced by | Protects against | Does NOT protect against |
|---|---|---|---|
| **1. Database constraints** | MySQL (FK, UNIQUE, CHECK) | Inconsistent data: orphan rows, invalid roles and links, a student marked in a class they don't take, contradictory `query_history` outcomes, ledger/query user mismatch | Anything about *who* may read what |
| **2. MySQL accounts** (defence in depth) | MySQL grants | Any write, DDL, `GRANT`, `FILE`, locking or temporary tables by the query account; any access to `askq_system`, `users`, `roles`, `mysql.*`, `sys`, other sessions and statement history | Reading any column or row of the 15 granted tables and 2 views, regardless of the end user's role (see "Residual exposure") |
| **3. Backend RBAC** (Phase 5) | FastAPI policy module | Role-specific tables, columns and rows: e.g. a STUDENT sees only their own rows, a TEACHER only their offerings and advisees, a HOD only their department; salary and date of birth only where the role allows | Inference across several allowed answers (layer 5) |
| **4. SQL-safety validation** (Phase 5) | sqlglot AST checks | Anything that is not a single read-only SELECT: stacked statements, system schemas (`information_schema`, `performance_schema`, `mysql`, `sys`), system variables, `SLEEP` / `BENCHMARK` / `LOAD_FILE`, session changes. Also enforces a row `LIMIT` and a statement timeout. | Inference from legitimate aggregates (layer 5) |
| **5. CAIR** (Phase 8-9) | Backend + `askq_system` ledger | Inference from *sequences* of individually allowed queries (the six attack classes below) | Single-query leaks (layers 3-4). It is a heuristic, not a formal privacy guarantee. |

### Sensitive data

Teacher salary, date of birth, gender, fees, payments and scholarships each live
**once**, in their normalised table. Role-specific visibility is not solved by
duplicating data into per-role tables or views. It is the backend's job (layers
3 and 4). `askq_reader` can read all of these columns, because one account
serves every role; its grants are a backstop against writes and system access,
not a per-role filter. All sensitive values sit in dedicated columns and tables,
so the backend can express column deny-lists and row predicates cleanly.

### Residual exposure of askq_reader (MySQL cannot remove these)

`tools/verify_accounts.py` reports these as `EXPOSED`. The Phase 5 validator must block each one:

- `SLEEP()`, `BENCHMARK()`: time and CPU abuse, and a timing side channel.
- System variables (`@@version`, `@@datadir`, `@@hostname`) and the world-readable `performance_schema.global_variables` / `session_status`: server fingerprinting.
- `SET SESSION ...` (e.g. raising `max_execution_time`): the backend sets the timeout per statement and only ever sends one validated SELECT.
- `information_schema` metadata for the granted tables: harmless (the backend describes the schema to the LLM itself), but blocked for consistency.

Probes also confirm what is **not** exposed. The reader sees no
`information_schema` rows for `askq_system`, `mysql`, `sys`, `users` or `roles`,
and no other users' sessions. `LOAD_FILE` returns NULL.

## Roles (foundation for backend RBAC)

The database records **who is who**; enforcement is the backend's (Phase 5).

| Role | Users | Scope derivable from the data |
|---|---:|---|
| ADMIN | 1 (`admin`) | Everything |
| HOD | 7 (`t0001`, `t0009`, ...) | Their department (`departments.head_teacher_id = users.teacher_id`), plus their own teaching |
| TEACHER | 33 (`t0002`, ...) | Offerings they teach (`course_offerings.teacher_id`) and their advisees (`students.advisor_teacher_id`) |
| STUDENT | 1,000 (`s20230001`, ...) | Their own rows (`users.student_id`) |

Constraints are compatible with the Phase 3 authentication (see `backend/README.md`):

- `users` never stores secrets. Hashes go into `askq_system.app_user_credentials`, which `askq_app` can write.
- `ck_users_role_links` fixes each role's link shape, and `ck_roles_id_code` pins the ids it relies on.
- Changing a user's role (e.g. teacher → HOD) is an admin operation. The app only reads `users`.
- `grades`, `attendance_records`, `fee_payments` and `class_sessions` have no direct `student_id`, so RBAC row scoping must join through `enrollments` / `fees`.

## Synthetic data generation

`seed/generate_seed.py` builds the dataset in memory, checks every cohort
property, and writes SQL. It uses only the standard library, has no database
connection, and fails if any cohort check fails.

- **Deterministic.** Default seed `20260926`. Each stage has its own
  `random.Random` seeded from `askq:<seed>:<stage>`. The same seed gives
  byte-identical files (tested), and the temporal model above removes all clock
  dependence.
- **Clearly synthetic.** Syllable-built names ("Galyn Ivelley"), the reserved
  `.example` email domain, and fictional regions, sponsors and buildings.
- **Realistic shape.** Year levels are about 27/26/24/23%. Gender is F 47%,
  M 51.5%, X 1.5%. About 4% of students are international and about 44% live in
  the hostel. Marks come from ability plus course difficulty and correlate with
  attendance. About 2% of enrollments are dropped. Fall fees are partly
  outstanding at mid-term.
- `setup_db.ps1 -Reset -Seed 12345` uses another seed. The cohort properties hold for every seed (tested on four).

## Security-demo data (CAIR attack cohorts)

The generator **plants 14 students** in small groups. They are ordinary rows,
with no marker column, and their ids are interleaved. Ordinary students are
re-generated whenever they would match a reserved attribute combination.
Planted students get noise-free marks and exact attendance rates, so the
properties below hold for every seed.

Each cohort is checked on three levels, using **34 checks** in `seed/askq_seed/cohort_checks.py`:

1. **The start of the attack:** the surrounding groups are large, so each query looks innocent (`>=` checks).
2. **The planted group:** its defining attributes and exact size.
3. **The payload:** the property that makes the attack worth demonstrating.

| Cohort | Attack class | Innocent context (`>=`) | Planted group (exact) | Payload verified |
|---|---|---|---|---|
| C1 | Differencing | ASTRO ≥ 15; ASTRO domestic ≥ 15 | ASTRO international = 1 | Target has Spring grades; target's average differs from the complement's by ≥ 5 marks |
| C2 | Narrowing | MATH year 3 ≥ 15; female ≥ 5 | + Highland = 2; + hostel = 1 | Target failed a Spring course; target holds a need-based scholarship |
| C3 | Arithmetic recovery | need-based awards overall ≥ 20 | Meridian recipients = 3, all CIVIL | 3 distinct amounts; Fall 2026 only; middle award = SUM − MIN − MAX |
| C4 | Cross-view linking | ECE year 2 ≥ 20; Saltmarsh elsewhere ≥ 5 | ECE year 2 from Saltmarsh = 1 | Fall fees with no payment; Fall attendance < 70% |
| C5 | Refusal side channel | BIOT year 2 ≥ 15; gender X outside BIOT ≥ 5 | BIOT gender X by year = 1 / 0 / 0 / 5 | Year 2 is an empty group inside a large one; year 4 sits exactly at a k = 5 threshold |
| C6 | Context carryover | CSE year 4 ≥ 30; + hostel ≥ 10; Chancellor holders ≥ 10 | + Chancellor = 1 | Target owes money for Fall; Fall attendance < 75% |

The same SQL, portable between SQLite and MySQL, runs in three places:

1. In the generator, against an in-memory SQLite copy.
2. In pytest, for four seeds, including a tampering test that proves the checks catch breakage.
3. Against MySQL, via the committed `validation/verify_security_cohorts.sql`.

That file doesn't depend on the seed or on generated output. Refresh it with
`generate_seed.py --refresh-validation`; a test fails while it is stale.
Student numbers for the default seed are in `seed/generated/security_demo_manifest.json`.

## Setup

### Host convention

- **Application accounts:** exist only as `'askq_reader'@'127.0.0.1'` and `'askq_app'@'127.0.0.1'`.
  The backend and `verify_accounts.py` connect to `DB_HOST=127.0.0.1` over TCP.
  An IP-literal account host matches that connection whether or not the server
  resolves host names, so no `skip-name-resolve` change is needed. `localhost` is
  avoided because it can mean `::1` or a named pipe. `setup_db.ps1` refuses any
  other `DB_HOST`, and `verify_database.sql` fails if an ASKQ account exists on another host.
- **Admin connection:** stays on your existing `root@localhost`, through the login path below.

### View DEFINER

Views use `DEFINER = CURRENT_USER SQL SECURITY INVOKER`:

- The definer is whichever admin account runs setup, which necessarily exists on that installation. Nothing assumes a named account such as `mysql.sys`, and no `SET_USER_ID` privilege is needed.
- With `INVOKER` security, the definer grants nothing at query time. Callers need SELECT on the underlying tables, which `askq_reader` has.

### One-time prerequisites

1. MySQL Server 8.0 running on port 3306, and `backend\setup.ps1` already run (the generator uses the backend venv).
2. **Admin connection (recommended).** In your own terminal:
   ```powershell
   mysql_config_editor set --login-path=askq_admin --host=localhost --user=root --password
   ```
   This writes `%APPDATA%\MySQL\.mylogin.cnf`, outside the project. The password
   is obfuscated but not encrypted. Remove it with
   `mysql_config_editor remove --login-path=askq_admin`. Without it, mysql asks
   for the root password once per run.
3. **Account passwords.** Create `C:\ASKQ\.env` (git-ignored) from `.env.example` and set **your own** values:

   | Variable | Required value |
   |---|---|
   | `DB_HOST`, `DB_PORT` | `127.0.0.1`, `3306` |
   | `DB_READER_USER` | `askq_reader` |
   | `DB_READER_PASSWORD` | ≥ 16 characters from `A-Z a-z 0-9 . _ ~ ! @ % ^ * + = : , -` |
   | `DB_APP_USER` | `askq_app` |
   | `DB_APP_PASSWORD` | Same rules; must differ from the reader password |

   The MySQL root password is never put in `.env`. `setup_db.ps1` validates all
   of this **before** connecting, and sends account passwords to mysql through
   stdin only (never printed, logged or written to a file).

### Build

```powershell
cd C:\ASKQ
powershell -ExecutionPolicy Bypass -File .\database\setup_db.ps1
```

The steps, in order:

1. Generate the seed SQL (and fail if a cohort check fails).
2. In **one** mysql session, run: schema → seed → accounts + `accounts\grants.sql` → `verify_database.sql` → `verify_security_cohorts.sql`.
3. Run `tools\verify_accounts.py` as each account.

Any failed check makes the script exit non-zero.

| Option | Effect |
|---|---|
| `-SkipAccounts` | Build the databases without creating the accounts |
| `-AccountsOnly` | Only (re)create the accounts, re-apply grants and verify (no generated files needed); re-sets passwords from `.env` |
| `-Reset` | Drop and rebuild **only** `askq_university` and `askq_system` (asks you to type `RESET`; `-Force` skips the prompt) |
| `-Seed N` | Use another data seed |
| `-LoginPath name` | Use a different login path than `askq_admin` |

### Reset / recreate safely

- Running setup on an existing installation **fails** (`CREATE DATABASE` without `IF NOT EXISTS`) rather than mixing old and new objects.
- `-Reset` runs `reset\drop_askq_databases.sql`: exactly `DROP DATABASE IF EXISTS askq_system` and `DROP DATABASE IF EXISTS askq_university`. No other database is touched.
- A reset erases `askq_system` too: history, CAIR ledger, evaluations and credentials. Re-provision credentials afterwards, because user ids depend on the seed.
- MySQL accounts survive a reset, and grants are re-applied on every run that includes accounts. To remove the accounts, run as root: `DROP USER 'askq_reader'@'127.0.0.1', 'askq_app'@'127.0.0.1';`

## Least-privilege database accounts

Table-level grants only (`accounts/grants.sql`), at most 20 connections each:

| Account | Privileges | Deliberately denied |
|---|---|---|
| `askq_reader@127.0.0.1` | `SELECT` on 15 tables (`departments`, `academic_terms`, `grade_scale`, `teachers`, `students`, `courses`, `course_offerings`, `enrollments`, `grades`, `class_sessions`, `attendance_records`, `fees`, `fee_payments`, `scholarships`, `student_scholarships`) and 2 views, all in `askq_university` | `users`, `roles`, all of `askq_system`, INSERT/UPDATE/DELETE, DDL, CREATE TEMPORARY TABLES, LOCK TABLES, routines, FILE, PROCESS, SUPER, GRANT OPTION, any global or database-level privilege |
| `askq_app@127.0.0.1` | `SELECT` on `askq_university.users`, `roles`, `departments`. In `askq_system`: `SELECT, INSERT, UPDATE` on credentials, conversations, turns, evaluation runs; `SELECT, INSERT` only on the append-only tables (query history, CAIR ledger/assessments/findings, audit log, evaluation results) | Other organisational data (including salary), any DELETE, UPDATE of append-only records, DDL, FILE, GRANT OPTION |

These are verified three ways:

1. **Offline (pytest):** a strict grammar and policy check of `grants.sql`. It checks MySQL 8.0 GRANT/REVOKE syntax for the forms used, real privilege names, existing objects, only the two `@127.0.0.1` accounts, and no wildcards or `WITH GRANT OPTION`.
2. **In MySQL:** `verify_database.sql` reads the grant tables: no global, database-level, role, column or routine privileges; reader SELECT-only on exactly 17 objects; app never UPDATE on append-only tables; no anonymous accounts.
3. **By behaviour:** `verify_accounts.py` logs in as each account and runs harmless probes. They cover allowed reads, denied writes, DDL and admin operations, metadata filtering, and a `query_history` row for every `final_status`. They also check that inconsistent rows and cross-conversation or cross-user links are refused by constraints.

The first successful `setup_db.ps1` run is what proves MySQL 8.0.46 accepts every statement.

## Verification summary

| What | Where | Needs MySQL |
|---|---|---|
| Determinism, clock pinning, key integrity, 34 cohort checks × 4 seeds, tampering detection | `backend/tests/test_seed_generator.py` | no |
| Constraint counts vs DDL, InnoDB/utf8mb4, view determinism and DEFINER, committed cohort SQL up to date, grants grammar and policy, host convention, `query_history` CHECK truth table, SQL parse (sqlglot, MySQL dialect), credential scan | `backend/tests/test_database_sql.py` | no |
| Row counts, structure, temporal values, relationships, RBAC foundations, business rules, grant tables | `validation/verify_database.sql` | yes |
| Cohort properties on the loaded data | `validation/verify_security_cohorts.sql` | yes |
| Account behaviour | `tools/verify_accounts.py` | yes |
