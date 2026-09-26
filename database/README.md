# database/

Everything needed to (re)build ASKQ's MySQL databases from scratch.
Contents are added in **Phase 2**.

| Path | Purpose |
|---|---|
| `schema/` | DDL scripts, run in numeric order (e.g. `01_university.sql`, `02_system.sql`) |
| `seed/` | Deterministic synthetic-data generator (fixed random seed, no real personal data) |

Two databases on the same MySQL 8 server:

- **`askq_university`**: organisational data (departments, students, courses,
  enrollments, grades, attendance, fees, scholarships, users, roles).
  LLM-generated SQL only ever runs against this, through the SELECT-only `askq_reader` account.
- **`askq_system`**: ASKQ's own data (conversations, query history, CAIR ledger,
  evaluation runs), written by the `askq_app` account.
