import pytest

from app.query.authorization import (
    AuthorizationDenied,
    AuthorizationStatus,
    DenialCode,
    authorize,
)
from app.query.catalog import CATALOG
from app.query.policy import ALL_TABLES, FINANCIAL_TABLES, POLICIES
from app.query.sql_validator import validate_sql
from app.rbac.roles import Role
from app.rbac.scope import Scope, ScopeKind, UserContext

DB = "askq_university"
ADMIN = UserContext(1, "admin", Role.ADMIN, Scope(ScopeKind.ORGANIZATION))
HOD = UserContext(
    2, "t0101", Role.HOD, Scope(ScopeKind.DEPARTMENT, department_id=1, teacher_id=101)
)
TEACHER = UserContext(3, "t0102", Role.TEACHER, Scope(ScopeKind.TEACHER, teacher_id=102))
STUDENT = UserContext(4, "s501", Role.STUDENT, Scope(ScopeKind.STUDENT, student_id=501))


def run(sql, user, max_rows=500):
    validated = validate_sql(sql, catalog_tables=CATALOG, university_db=DB)
    return authorize(validated, user, university_db=DB, max_rows=max_rows)


def denied(sql, user) -> AuthorizationDenied:
    with pytest.raises(AuthorizationDenied) as info:
        run(sql, user)
    return info.value


# ---------- policy table ----------


def test_policies_cover_every_role_and_only_catalog_tables():
    assert set(POLICIES) == set(Role)
    assert ALL_TABLES == set(CATALOG)
    for policy in POLICIES.values():
        assert policy.tables <= set(CATALOG)
        assert set(policy.row_scope) <= policy.tables
        for table, columns in policy.denied_columns.items():
            assert columns <= set(CATALOG[table].column_names)


def test_admin_is_unscoped_and_everyone_else_is_scoped_on_people_data():
    assert POLICIES[Role.ADMIN].row_scope == {}
    for role in (Role.HOD, Role.TEACHER, Role.STUDENT):
        assert {"students", "grades", "enrollments"} <= set(POLICIES[role].row_scope)


# ---------- ADMIN ----------


def test_admin_query_is_not_rewritten():
    result = run("SELECT COUNT(*) FROM students", ADMIN)
    assert result.status == AuthorizationStatus.ALLOWED
    assert result.scoped_tables == frozenset()
    assert result.sql == "SELECT COUNT(*) FROM students LIMIT 500"


def test_admin_may_see_salary():
    assert run("SELECT annual_salary FROM teachers", ADMIN).status == AuthorizationStatus.ALLOWED


# ---------- LIMIT ----------


@pytest.mark.parametrize(
    ("sql", "expected_limit"),
    [
        ("SELECT student_id FROM students", 500),
        ("SELECT student_id FROM students LIMIT 10", 10),
        ("SELECT student_id FROM students LIMIT 100000", 500),
        ("SELECT student_id FROM students LIMIT 5 OFFSET 20", 5),
        ("SELECT course_code FROM courses UNION SELECT course_code FROM courses", 500),
        ("SELECT course_code FROM courses UNION SELECT course_code FROM courses LIMIT 9999", 500),
    ],
)
def test_limit_is_added_or_capped(sql, expected_limit):
    result = run(sql, ADMIN)
    assert result.row_limit == expected_limit
    assert result.sql.endswith(f"LIMIT {expected_limit}") or f"LIMIT {expected_limit} OFFSET" in (
        result.sql
    )


def test_inner_limits_are_untouched_and_outer_limit_still_applied():
    result = run("SELECT * FROM (SELECT student_id FROM students LIMIT 100000) t", ADMIN)
    assert result.sql.endswith(") AS t LIMIT 500")


def test_configured_max_rows_is_respected():
    assert run("SELECT student_id FROM students LIMIT 50", ADMIN, max_rows=20).row_limit == 20


# ---------- HOD ----------


def test_hod_rows_are_scoped_to_their_department():
    result = run("SELECT COUNT(*) FROM students", HOD)
    assert result.status == AuthorizationStatus.REWRITTEN
    assert result.scoped_tables == {"students"}
    assert "FROM askq_university.students WHERE department_id = 1) AS students" in result.sql


def test_hod_star_select_never_includes_hidden_columns():
    result = run("SELECT * FROM students s", HOD)
    assert "date_of_birth" not in result.sql
    assert ") AS s LIMIT 500" in result.sql


def test_hod_hidden_columns_denied():
    assert denied("SELECT annual_salary FROM teachers", HOD).code == DenialCode.COLUMN_NOT_PERMITTED
    assert denied("SELECT date_of_birth FROM students", HOD).code == DenialCode.COLUMN_NOT_PERMITTED


def test_hod_may_query_department_fees():
    result = run("SELECT SUM(amount) FROM fees", HOD)
    assert "student_id IN (SELECT student_id FROM askq_university.students" in result.sql


def test_cross_department_filter_cannot_escape_the_scope():
    # The query asks for department 2; the rewritten table only contains department 1.
    result = run("SELECT * FROM students WHERE department_id = 2", HOD)
    assert "WHERE department_id = 1) AS students WHERE department_id = 2" in result.sql


# ---------- TEACHER ----------


def test_teacher_has_no_financial_data():
    for table in FINANCIAL_TABLES:
        assert denied(f"SELECT * FROM {table}", TEACHER).code == DenialCode.TABLE_NOT_PERMITTED


def test_teacher_hidden_columns():
    assert denied("SELECT gender FROM students", TEACHER).code == DenialCode.COLUMN_NOT_PERMITTED


def test_teacher_grades_scoped_to_own_offerings_and_advisees():
    result = run("SELECT AVG(marks) FROM grades", TEACHER)
    assert "course_offerings WHERE teacher_id = 102" in result.sql
    assert "advisor_teacher_id = 102" in result.sql


def test_cross_teacher_filter_cannot_escape_the_scope():
    result = run(
        "SELECT g.marks FROM grades g JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
        "JOIN course_offerings o ON o.offering_id = e.offering_id WHERE o.teacher_id = 201",
        TEACHER,
    )
    assert result.scoped_tables == {"grades", "enrollments"}


# ---------- STUDENT ----------


def test_student_rows_are_their_own():
    result = run("SELECT * FROM grades", STUDENT)
    assert "WHERE student_id = 501" in result.sql


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM students WHERE student_id = 601",
        "SELECT * FROM students WHERE 601 = student_id",
        "SELECT * FROM fees WHERE student_id IN (501, 601)",
        "SELECT g.marks FROM grades g JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
        "WHERE e.student_id = 601",
    ],
)
def test_student_explicitly_asking_for_another_student_is_denied(sql):
    assert denied(sql, STUDENT).code == DenialCode.OUTSIDE_SCOPE


def test_student_own_id_literal_is_fine():
    assert run("SELECT * FROM students WHERE student_id = 501", STUDENT).row_limit == 500


def test_student_cannot_see_salary_even_of_own_teachers():
    assert denied("SELECT annual_salary FROM teachers", STUDENT).code == (
        DenialCode.COLUMN_NOT_PERMITTED
    )


def test_missing_scope_id_fails_closed():
    broken = UserContext(9, "x", Role.STUDENT, Scope(ScopeKind.STUDENT))
    assert denied("SELECT * FROM grades", broken).code == DenialCode.SCOPE_UNAVAILABLE
    broken_hod = UserContext(9, "x", Role.HOD, Scope(ScopeKind.DEPARTMENT, teacher_id=1))
    assert denied("SELECT * FROM students", broken_hod).code == DenialCode.SCOPE_UNAVAILABLE


# ---------- rewriting reaches every reference ----------


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM students s JOIN enrollments e ON e.student_id = s.student_id",
        "SELECT * FROM courses WHERE course_id IN (SELECT o.course_id FROM course_offerings o "
        "JOIN enrollments e ON e.offering_id = o.offering_id)",
        "WITH x AS (SELECT * FROM grades) SELECT AVG(marks) FROM x",
        "SELECT student_id FROM enrollments UNION SELECT student_id FROM fees",
        "SELECT (SELECT COUNT(*) FROM grades) AS n FROM departments",
        "SELECT * FROM departments d WHERE EXISTS (SELECT 1 FROM students s "
        "WHERE s.department_id = d.department_id)",
    ],
)
def test_every_scoped_table_reference_is_rewritten(sql):
    result = run(sql, STUDENT)
    # No base reference to a scoped table survives outside the injected derived tables.
    remaining = result.sql
    for scoped in ("students", "enrollments", "grades", "fees"):
        remaining = remaining.replace(f"FROM askq_university.{scoped} WHERE", "")
    for scoped in ("students", "enrollments", "grades", "fees"):
        assert f"FROM {scoped} " not in remaining + " "
        assert f"JOIN {scoped} " not in remaining + " "


def test_final_sql_passes_the_validator_again():
    result = run(
        "SELECT d.department_code, COUNT(*) FROM students s "
        "JOIN departments d ON d.department_id = s.department_id GROUP BY d.department_code",
        TEACHER,
    )
    validate_sql(result.sql, catalog_tables=CATALOG, university_db=DB)


def test_notes_explain_scope_and_limit():
    notes = run("SELECT * FROM grades", HOD).notes
    assert notes == (
        "Results are limited to your own department (department_id = 1).",
        "Results are limited to 500 rows.",
    )
