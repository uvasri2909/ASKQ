"""Tests for the deterministic seed generator in database/seed (no MySQL needed)."""

import ast
import re
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

SEED_DIR = Path(__file__).resolve().parents[2] / "database" / "seed"
sys.path.insert(0, str(SEED_DIR))

from askq_seed import DEFAULT_SEED, build_dataset, render_sql_files  # noqa: E402
from askq_seed import generator as gen  # noqa: E402
from askq_seed.cohort_checks import COHORT_CHECKS  # noqa: E402
from askq_seed.generator import cohort_values  # noqa: E402
from askq_seed.reference import SNAPSHOT_AT  # noqa: E402

SIX_ATTACK_CLASSES = {
    "DIFFERENCING",
    "NARROWING",
    "ARITHMETIC_RECOVERY",
    "CROSS_VIEW_LINKING",
    "REFUSAL_SIDE_CHANNEL",
    "CONTEXT_CARRYOVER",
}


@pytest.fixture(scope="module")
def dataset():
    return build_dataset(DEFAULT_SEED)


@pytest.fixture(scope="module")
def files(dataset):
    return render_sql_files(dataset)


def column(dataset, table, name):
    t = dataset.table(table)
    i = t.columns.index(name)
    return [row[i] for row in t.rows]


# ---------- Reproducibility ----------


def test_same_seed_gives_identical_files(files):
    assert render_sql_files(build_dataset(DEFAULT_SEED)) == files


def test_different_seed_changes_data(files):
    other = render_sql_files(build_dataset(DEFAULT_SEED + 1))
    assert other["02_synthetic_data.sql"] != files["02_synthetic_data.sql"]


def test_generator_never_reads_the_clock():
    clock_calls = {"now", "today", "utcnow", "time", "time_ns", "localtime", "gmtime"}
    for path in (SEED_DIR / "askq_seed").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute) and node.attr in clock_calls:
                pytest.fail(f"{path.name}:{node.lineno} reads the clock ({node.attr})")


def test_seed_sql_pins_clock_and_time_zone(files):
    epoch = int(SNAPSHOT_AT.timestamp())
    assert epoch == 1790359200  # 2026-09-25 18:00:00 UTC
    for name in ("01_reference_data.sql", "02_synthetic_data.sql", "03_security_demo_data.sql"):
        sql = files[name]
        head = sql[: sql.index("START TRANSACTION;")]
        assert "SET time_zone = '+00:00';" in head, name
        assert f"SET timestamp = {epoch};" in head, name
        assert sql.rstrip().endswith("SET timestamp = DEFAULT;"), name


# ---------- Security-demo cohorts ----------


@pytest.mark.parametrize("seed", [DEFAULT_SEED, DEFAULT_SEED + 1, 1, 42])
def test_every_cohort_property_holds_for_several_seeds(seed):
    values = cohort_values(build_dataset(seed))
    failed = {c.name: values[c.name] for c in COHORT_CHECKS if not c.passes(values[c.name])}
    assert not failed


def test_cohorts_cover_all_six_attack_classes():
    assert {c.attack_class for c in COHORT_CHECKS} == SIX_ATTACK_CLASSES


def test_each_cohort_checks_more_than_its_size():
    """Every attack has surrounding-group (>=) checks and several exact property checks."""
    for attack in SIX_ATTACK_CLASSES:
        checks = [c for c in COHORT_CHECKS if c.attack_class == attack]
        assert any(c.op == ">=" for c in checks), attack
        assert sum(c.op == "=" for c in checks) >= 3, attack


def test_cohort_checks_actually_detect_breakage(dataset):
    """Tamper with the planted data: the relevant property checks must fail."""
    students = dataset.table("students")
    cols = students.columns
    target_rows = [
        i
        for i, row in enumerate(students.rows)
        if row[cols.index("home_region")] == "Saltmarsh"
        and row[cols.index("year_level")] == 2
        and row[cols.index("department_id")] == 2
    ]
    assert len(target_rows) == 1
    tampered_rows = list(students.rows)
    row = list(tampered_rows[target_rows[0]])
    row[cols.index("home_region")] = "North Vale"
    tampered_rows[target_rows[0]] = tuple(row)
    tampered = replace(
        dataset,
        tables={**dataset.tables, "students": replace(students, rows=tampered_rows)},
    )
    values = cohort_values(tampered)
    broken = {c.name for c in COHORT_CHECKS if not c.passes(values[c.name])}
    assert "C4 ECE year 2 from Saltmarsh (target)" in broken
    assert "C4 target has Fall 2026 fees and no Fall payment" in broken
    assert "C4 target Fall 2026 attendance below 70%" in broken
    with pytest.raises(AssertionError, match="cohort checks failed"):
        gen.self_check(tampered)


def test_planted_students_are_interleaved_not_appended(dataset):
    t = dataset.table("students")
    planted_ids = [row[0] for row, p in zip(t.rows, t.planted, strict=True) if p]
    assert len(planted_ids) == 14
    assert max(planted_ids) < 990  # not simply the last ids
    assert "cohort" not in " ".join(t.columns)  # no marker column


# ---------- Data integrity ----------


def test_headline_counts(dataset):
    assert len(dataset.table("students").rows) == 1000
    assert len(dataset.table("teachers").rows) == 40
    assert len(dataset.table("departments").rows) == 7
    assert len(dataset.table("users").rows) == 1 + 40 + 1000
    assert 6000 <= len(dataset.table("enrollments").rows) <= 8000


def test_primary_keys_unique_and_foreign_keys_resolve(dataset):
    for name, table in dataset.tables.items():
        ids = [row[0] for row in table.rows]
        assert len(ids) == len(set(ids)), name
    students = set(column(dataset, "students", "student_id"))
    offerings = set(column(dataset, "course_offerings", "offering_id"))
    enrollments = set(column(dataset, "enrollments", "enrollment_id"))
    fees = set(column(dataset, "fees", "fee_id"))
    assert set(column(dataset, "enrollments", "student_id")) <= students
    assert set(column(dataset, "enrollments", "offering_id")) <= offerings
    assert set(column(dataset, "grades", "enrollment_id")) <= enrollments
    assert set(column(dataset, "attendance_records", "enrollment_id")) <= enrollments
    assert set(column(dataset, "fee_payments", "fee_id")) <= fees


def test_natural_keys_unique(dataset):
    for table, col in [
        ("students", "student_no"),
        ("students", "email"),
        ("teachers", "employee_no"),
        ("teachers", "email"),
        ("users", "username"),
        ("courses", "course_code"),
        ("fee_payments", "receipt_no"),
    ]:
        values = column(dataset, table, col)
        assert len(values) == len(set(values)), (table, col)


def test_no_fee_is_overpaid(dataset):
    paid = Counter()
    for fee_id, amount in zip(
        column(dataset, "fee_payments", "fee_id"),
        column(dataset, "fee_payments", "amount"),
        strict=True,
    ):
        paid[fee_id] += amount
    for fee_id, amount in zip(
        column(dataset, "fees", "fee_id"), column(dataset, "fees", "amount"), strict=True
    ):
        assert paid[fee_id] <= amount


def test_no_dated_activity_after_the_snapshot(dataset):
    as_of = SNAPSHOT_AT.date()
    assert max(column(dataset, "fee_payments", "paid_on")) <= as_of
    assert max(column(dataset, "class_sessions", "session_date")) <= as_of


def test_only_reserved_example_email_domains(dataset):
    emails = column(dataset, "students", "email") + column(dataset, "teachers", "email")
    assert all(re.fullmatch(r"[a-z0-9.]+@(students|staff)\.askq-uni\.example", e) for e in emails)


def test_seed_sql_has_no_credentials_or_ddl(files):
    for name in ("01_reference_data.sql", "02_synthetic_data.sql", "03_security_demo_data.sql"):
        lowered = files[name].lower()
        for forbidden in ("password", "identified by", "create user", "grant ", "drop "):
            assert forbidden not in lowered, (name, forbidden)
