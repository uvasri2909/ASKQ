"""Renders a Dataset as MySQL seed scripts, plus the static cohort-check SQL.

Seed output (database/seed/generated/, git-ignored, deterministic per seed):
  01_reference_data.sql         roles, departments, terms, grade scale, courses, scholarships
  02_synthetic_data.sql         ordinary teachers, students, teaching, attendance, finance
  03_security_demo_data.sql     the planted security-demo students and all their rows
  security_demo_manifest.json   which student numbers belong to which cohort

Validation (database/validation/verify_security_cohorts.sql, committed):
  render_cohort_checks() output. It does not depend on the seed; a test keeps the
  committed file identical to this function's output.
"""

# S608 (SQL built from strings) is disabled for this file on purpose: it only
# assembles SQL from its own constants; no user or LLM input ever reaches it.
# ruff: noqa: S608

from __future__ import annotations

import json
from datetime import date
from decimal import Decimal

from askq_seed.cohort_checks import COHORT_CHECKS
from askq_seed.generator import GENERATOR_VERSION, Dataset, Table
from askq_seed.reference import SNAPSHOT_AT

REFERENCE_TABLES = (
    "roles",
    "departments",
    "academic_terms",
    "grade_scale",
    "courses",
    "scholarships",
)
# Insert order respects foreign keys.
DATA_TABLES = (
    "teachers",
    "students",
    "users",
    "course_offerings",
    "class_sessions",
    "enrollments",
    "grades",
    "attendance_records",
    "fees",
    "fee_payments",
    "student_scholarships",
)
ROWS_PER_INSERT = 500
SNAPSHOT_EPOCH = int(SNAPSHOT_AT.timestamp())


def _literal(value) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, Decimal)):
        return str(value)
    if isinstance(value, date):
        return f"'{value.isoformat()}'"
    if isinstance(value, str):
        return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"
    raise TypeError(f"unsupported value {value!r}")


def _header(title: str, seed: int, lines: list[str]) -> list[str]:
    return [
        "-- ============================================================",
        f"-- ASKQ seed: {title}",
        "-- GENERATED FILE - do not edit. Regenerate with database\\seed\\generate_seed.py",
        f"-- Generator version {GENERATOR_VERSION}, seed {seed}. Identical seed => identical file.",
        "-- All people, places and organisations are fictional.",
        *[f"-- {line}" for line in lines],
        "-- ============================================================",
        "",
        "SET NAMES utf8mb4;",
        "-- Clock pinning: every DEFAULT/ON UPDATE CURRENT_TIMESTAMP value written by",
        f"-- this file becomes the dataset snapshot time, {SNAPSHOT_AT:%Y-%m-%d %H:%M:%S} UTC,",
        "-- independent of the machine's clock and time zone.",
        "SET time_zone = '+00:00';",
        f"SET timestamp = {SNAPSHOT_EPOCH};",
        "USE askq_university;",
        "START TRANSACTION;",
        "",
    ]


def _inserts(table: Table, planted: bool | None) -> list[str]:
    rows = [
        row
        for row, is_planted in zip(table.rows, table.planted, strict=True)
        if planted is None or is_planted == planted
    ]
    if not rows:
        return []
    out = [f"-- {table.name}: {len(rows)} rows"]
    for start in range(0, len(rows), ROWS_PER_INSERT):
        chunk = rows[start : start + ROWS_PER_INSERT]
        out.append(f"INSERT INTO {table.name} ({', '.join(table.columns)}) VALUES")
        out.append(
            ",\n".join("(" + ", ".join(_literal(v) for v in row) + ")" for row in chunk) + ";"
        )
    out.append("")
    return out


def _render(lines: list[str]) -> str:
    return "\n".join([*lines, "COMMIT;", "SET timestamp = DEFAULT;", ""])


def render_cohort_checks() -> str:
    lines = [
        "-- ============================================================",
        "-- ASKQ: security-demo cohort checks (see database/README.md).",
        "-- GENERATED from database/seed/askq_seed/cohort_checks.py - do not edit by hand.",
        "-- Refresh with:  backend\\.venv\\Scripts\\python database\\seed\\generate_seed.py"
        " --refresh-validation",
        "-- (backend/tests/test_seed_generator.py fails if this file is out of date.)",
        "-- Independent of the seed: the checks hold for every generated dataset.",
        "-- Read-only. Ends with an INSERT that violates a CHECK constraint (error 3819)",
        "-- if any check failed, so the mysql session exits non-zero.",
        "-- ============================================================",
        "",
        "USE askq_university;",
        "DROP TEMPORARY TABLE IF EXISTS cohort_results;",
        "CREATE TEMPORARY TABLE cohort_results (",
        "    check_no INT AUTO_INCREMENT PRIMARY KEY, cohort VARCHAR(20),",
        "    attack_class VARCHAR(20), check_name VARCHAR(70), expected VARCHAR(10),",
        "    actual DECIMAL(12,2), result CHAR(4));",
        "",
    ]
    for c in COHORT_CHECKS:
        cmp = "=" if c.op == "=" else ">="
        lines += [
            f"-- {c.name}",
            "INSERT INTO cohort_results"
            " (cohort, attack_class, check_name, expected, actual, result)"
            f" SELECT {_literal(c.cohort)}, {_literal(c.attack_class)}, {_literal(c.name)},"
            f" {_literal(f'{c.op} {c.expected}')}, q.n,"
            f" CASE WHEN q.n {cmp} {c.expected} THEN 'PASS' ELSE 'FAIL' END"
            f" FROM (SELECT ({c.sql}) AS n) q;",
        ]
    lines += [
        "",
        "SELECT cohort, attack_class, check_name, expected, actual, result",
        "FROM cohort_results ORDER BY check_no;",
        "",
        "CREATE TEMPORARY TABLE cohort_gate (",
        "    failed_checks INT,",
        "    CONSTRAINT all_security_cohort_checks_must_pass CHECK (failed_checks = 0));",
        "INSERT INTO cohort_gate SELECT COUNT(*) FROM cohort_results WHERE result <> 'PASS';",
        "SELECT CONCAT('All ', COUNT(*), ' security-demo cohort checks passed')"
        " AS cohort_verification FROM cohort_results;",
        "DROP TEMPORARY TABLE cohort_gate;",
        "DROP TEMPORARY TABLE cohort_results;",
        "",
    ]
    return "\n".join(lines)


def render_manifest(dataset: Dataset) -> str:
    cohort_ids = list(dict.fromkeys(c.cohort for c in COHORT_CHECKS))
    manifest = {
        "generator_version": GENERATOR_VERSION,
        "seed": dataset.seed,
        "note": "Synthetic data. Cohorts exist to demonstrate inference attacks in later phases.",
        "cohorts": [
            {
                "cohort": cohort,
                "attack_class": next(c.attack_class for c in COHORT_CHECKS if c.cohort == cohort),
                "checks": [
                    {"name": c.name, "expected": f"{c.op} {c.expected}"}
                    for c in COHORT_CHECKS
                    if c.cohort == cohort
                ],
                "members": dataset.cohort_members.get(cohort, []),
            }
            for cohort in cohort_ids
        ],
    }
    return json.dumps(manifest, indent=2) + "\n"


def render_sql_files(dataset: Dataset) -> dict[str, str]:
    seed = dataset.seed
    t = dataset.tables

    ref = _header(
        "reference data", seed, ["Roles, departments, terms, grade scale, courses, scholarships."]
    )
    for name in REFERENCE_TABLES:
        ref += _inserts(t[name], planted=None)

    synthetic = _header(
        "synthetic population",
        seed,
        [
            "Ordinary teachers, students and all their academic and financial records.",
            "Security-demo students are loaded by 03_security_demo_data.sql; their ids are",
            "interleaved with these, so gaps in the id sequences here are expected.",
        ],
    )
    for name in DATA_TABLES:
        synthetic += _inserts(t[name], planted=False)
        if name == "teachers":
            synthetic.append("-- departments.head_teacher_id (needs teachers to exist first)")
            synthetic += [
                f"UPDATE departments SET head_teacher_id = {teacher_id} "
                f"WHERE department_id = {department_id};"
                for department_id, teacher_id in dataset.department_heads
            ]
            synthetic.append("")

    demo = _header(
        "security-demo cohorts",
        seed,
        [
            "Small, realistic subgroups planted for the six CAIR attack demonstrations.",
            "Defined in askq_seed/cohorts.py; documented in database/README.md.",
            "Requires 02_synthetic_data.sql (course offerings and class sessions).",
        ],
    )
    for name in DATA_TABLES:
        demo += _inserts(t[name], planted=True)

    return {
        "01_reference_data.sql": _render(ref),
        "02_synthetic_data.sql": _render(synthetic),
        "03_security_demo_data.sql": _render(demo),
        "security_demo_manifest.json": render_manifest(dataset),
    }
