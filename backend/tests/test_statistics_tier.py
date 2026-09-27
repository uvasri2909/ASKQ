import pytest

from app.query.authorization import AuthorizationDenied, DenialCode
from app.query.catalog import CATALOG
from app.query.sql_validator import validate_sql
from app.query.statistics import (
    DIRECT_IDENTIFIERS,
    STATISTICAL_TABLES,
    STATISTICAL_TIER,
    StatisticsDenial,
    authorize_statistical,
)
from app.rbac.roles import Role
from app.rbac.scope import Scope, ScopeKind, UserContext

DB = "askq_university"
HOD = UserContext(
    17, "t0016", Role.HOD, Scope(ScopeKind.DEPARTMENT, department_id=3, teacher_id=16)
)
ADMIN = UserContext(1, "admin", Role.ADMIN, Scope(ScopeKind.ORGANIZATION))


def run(sql, user=HOD, k=5):
    validated = validate_sql(sql, catalog_tables=CATALOG, university_db=DB)
    return authorize_statistical(validated, user, university_db=DB, max_rows=500, min_group_size=k)


def denied(sql, user=HOD) -> AuthorizationDenied:
    with pytest.raises(AuthorizationDenied) as info:
        run(sql, user)
    return info.value


@pytest.mark.parametrize(
    ("sql", "key"),
    [
        ("SELECT COUNT(*) FROM students s", "s.student_id"),
        ("SELECT gender, COUNT(*) FROM students GROUP BY gender", "students.student_id"),
        ("SELECT AVG(marks) FROM grades g", "(SELECT cair_e.student_id FROM"),
        ("SELECT SUM(amount) FROM fee_payments", "(SELECT cair_f.student_id FROM"),
        (
            "SELECT AVG(g.marks) FROM grades g JOIN enrollments e "
            "ON e.enrollment_id = g.enrollment_id",
            "e.student_id",
        ),
    ],
)
def test_minimum_group_size_is_always_enforced(sql, key):
    result = run(sql)
    assert result.tier == STATISTICAL_TIER and result.status == "ALLOWED"
    assert "HAVING" in result.sql and f"COUNT(DISTINCT {key}" in result.sql
    assert result.sql.endswith(">= 5 LIMIT 500")


def test_existing_having_is_kept():
    result = run("SELECT gender, COUNT(*) FROM students GROUP BY gender HAVING COUNT(*) > 2")
    assert "HAVING COUNT(*) > 2 AND COUNT(DISTINCT students.student_id) >= 5" in result.sql


def test_configured_minimum_is_used():
    assert run("SELECT COUNT(*) FROM students s", k=11).sql.endswith(">= 11 LIMIT 500")


def test_union_branches_each_get_the_rule():
    result = run(
        "SELECT COUNT(*) FROM students s WHERE s.gender = 'F' "
        "UNION ALL SELECT COUNT(*) FROM students s WHERE s.gender = 'M'"
    )
    assert result.sql.count("COUNT(DISTINCT s.student_id) >= 5") == 2


def test_notes_do_not_reveal_the_threshold():
    statistical_note = run("SELECT COUNT(*) FROM students s", k=7).notes[0]
    assert "too small" in statistical_note
    assert not any(ch.isdigit() for ch in statistical_note)


@pytest.mark.parametrize(
    ("sql", "code"),
    [
        ("SELECT first_name, COUNT(*) FROM students GROUP BY first_name",
         DenialCode.COLUMN_NOT_PERMITTED),
        ("SELECT COUNT(*) FROM students WHERE student_no = 'S20230001'",
         DenialCode.COLUMN_NOT_PERMITTED),
        ("SELECT COUNT(*) FROM students WHERE email LIKE 'a%'", DenialCode.COLUMN_NOT_PERMITTED),
        ("SELECT AVG(YEAR(date_of_birth)) FROM students", DenialCode.COLUMN_NOT_PERMITTED),
        ("SELECT AVG(annual_salary) FROM teachers", DenialCode.TABLE_NOT_PERMITTED),
        ("SELECT COUNT(*) FROM students WHERE student_id = 7", StatisticsDenial.AGGREGATE_ONLY),
        ("SELECT COUNT(*) FROM grades WHERE enrollment_id IN (1, 2)",
         StatisticsDenial.AGGREGATE_ONLY),
        ("SELECT COUNT(*) FROM students WHERE student_id BETWEEN 1 AND 2",
         StatisticsDenial.AGGREGATE_ONLY),
        ("SELECT student_id, COUNT(*) FROM enrollments GROUP BY student_id",
         StatisticsDenial.AGGREGATE_ONLY),
        ("SELECT COUNT(*) FROM enrollments GROUP BY student_id ORDER BY student_id",
         StatisticsDenial.AGGREGATE_ONLY),
        ("SELECT marks FROM grades", StatisticsDenial.AGGREGATE_ONLY),
        ("SELECT * FROM students", StatisticsDenial.AGGREGATE_ONLY),
        ("SELECT DISTINCT gender FROM students", StatisticsDenial.AGGREGATE_ONLY),
        ("SELECT GROUP_CONCAT(marks) FROM grades", StatisticsDenial.AGGREGATE_ONLY),
        ("SELECT gender FROM students GROUP BY gender", StatisticsDenial.AGGREGATE_ONLY),
        ("SELECT RANK() OVER (ORDER BY marks) FROM grades", StatisticsDenial.AGGREGATE_ONLY),
        # Refused before any output check: no subqueries in the statistical tier.
        ("SELECT (SELECT MAX(marks) FROM grades) AS m, COUNT(*) FROM students",
         StatisticsDenial.UNSUPPORTED),
        ("SELECT COUNT(*) FROM courses", StatisticsDenial.UNSUPPORTED),
        ("WITH x AS (SELECT * FROM students) SELECT COUNT(*) FROM x", StatisticsDenial.UNSUPPORTED),
    ],
)  # fmt: skip
def test_only_aggregates_about_groups_of_people(sql, code):
    assert denied(sql).code == code


def test_record_keys_may_join_and_be_counted():
    run(
        "SELECT COUNT(DISTINCT e.student_id) FROM enrollments e "
        "JOIN students s ON s.student_id = e.student_id WHERE s.year_level = 2"
    )


def test_admin_has_no_statistical_tier():
    assert denied("SELECT COUNT(*) FROM students s", ADMIN).code == DenialCode.TABLE_NOT_PERMITTED


def test_policy_constants():
    assert "teachers" not in STATISTICAL_TABLES
    assert STATISTICAL_TABLES <= set(CATALOG)
    assert {"first_name", "student_no", "date_of_birth", "annual_salary"} <= DIRECT_IDENTIFIERS


def test_final_sql_revalidates():
    result = run("SELECT gender, COUNT(*) FROM students GROUP BY gender")
    validate_sql(result.sql, catalog_tables=CATALOG, university_db=DB)
