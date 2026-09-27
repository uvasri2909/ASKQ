import json

import pytest

from app.cair.descriptor import describe
from app.cair.model import Measure
from app.query.catalog import CATALOG
from app.query.sql_validator import validate_sql
from app.rbac.roles import Role
from app.rbac.scope import Scope, ScopeKind, UserContext

HOD = UserContext(
    17, "t0016", Role.HOD, Scope(ScopeKind.DEPARTMENT, department_id=3, teacher_id=16)
)


def d(sql, tier="STATISTICAL"):
    return describe(
        validate_sql(sql, catalog_tables=CATALOG, university_db="askq_university"), tier, HOD
    )


MARKS = (
    "SELECT ROUND(AVG(g.marks), 2) FROM grades g "
    "JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
    "JOIN students s ON s.student_id = e.student_id "
    "JOIN departments d ON d.department_id = s.department_id "
    "WHERE d.department_code = 'ASTRO' AND s.residency_status = 'DOMESTIC'"
)


def test_descriptor_is_deterministic_json():
    first, second = d(MARKS).to_json(), d(MARKS).to_json()
    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_filters_measures_and_sensitivity():
    desc = d(MARKS)
    assert desc.tables == ["departments", "enrollments", "grades", "students"]
    assert desc.filter_dimensions == ["departments.department_code", "students.residency_status"]
    assert desc.measures == ["sum:grades.marks"]  # AVG is sum-like (AVG x COUNT = SUM)
    assert desc.sensitive_metrics == ["grades.marks"]
    assert set(desc.quasi_identifiers) == set(desc.filter_dimensions)
    assert desc.exposes["average"] and not desc.exposes["records"]
    assert desc.predicates == [
        {"op": "EQ", "columns": ["departments.department_code"], "values": ["'ASTRO'"]},
        {"op": "EQ", "columns": ["students.residency_status"], "values": ["'DOMESTIC'"]},
    ]


def test_aliases_do_not_change_the_descriptor():
    renamed = MARKS.replace(" g ", " gr ").replace("g.", "gr.").replace(" s ", " st ")
    renamed = renamed.replace("s.", "st.").replace("st.tudent", "s.tudent")
    a, b = d(MARKS), d(renamed)
    assert (a.filter_dimensions, a.measures, a.tables) == (
        b.filter_dimensions,
        b.measures,
        b.tables,
    )


def test_join_order_does_not_change_the_descriptor():
    reordered = (
        "SELECT ROUND(AVG(g.marks), 2) FROM students s "
        "JOIN departments d ON d.department_id = s.department_id "
        "JOIN enrollments e ON e.student_id = s.student_id "
        "JOIN grades g ON g.enrollment_id = e.enrollment_id "
        "WHERE s.residency_status = 'DOMESTIC' AND d.department_code = 'ASTRO'"
    )
    a, b = d(MARKS), d(reordered)
    assert (a.filter_dimensions, a.measures, a.predicates) == (
        b.filter_dimensions,
        b.measures,
        b.predicates,
    )


def test_grouping_and_alias_resolution():
    desc = d("SELECT YEAR(paid_on) AS y, SUM(amount) FROM fee_payments GROUP BY y")
    assert desc.group_dimensions == ["fee_payments.paid_on"]
    assert desc.measures == ["sum:fee_payments.amount"]
    assert desc.exposes["sum"]


@pytest.mark.parametrize(
    ("sql", "measures"),
    [
        ("SELECT COUNT(*) FROM students", ["count:*"]),
        ("SELECT COUNT(DISTINCT s.gender) FROM students s", ["count:*"]),
        ("SELECT MIN(amount), MAX(amount) FROM fees", ["max:fees.amount", "min:fees.amount"]),
        ("SELECT STDDEV(marks) FROM grades", ["spread:grades.marks"]),
    ],
)
def test_measures(sql, measures):
    assert d(sql).measures == measures


def test_nested_and_union_queries():
    union = (
        "SELECT COUNT(*) FROM students s WHERE s.gender = 'F' "
        "UNION ALL SELECT COUNT(*) FROM students s WHERE s.year_level = 2"
    )
    desc = d(union)
    assert desc.filter_dimensions == ["students.gender", "students.year_level"]
    nested = "SELECT COUNT(*) FROM students s WHERE s.student_id IN (SELECT student_id FROM fees)"
    assert d(nested).tables == ["fees", "students"]


def test_record_query_exposes_records():
    desc = d("SELECT first_name FROM students LIMIT 1", tier="RECORD")
    assert desc.exposes["records"] and desc.exposes["existence"]
    assert desc.tier == "RECORD" and desc.scope["department_id"] == 3


def test_measure_set_and_dimension_set():
    desc = d(MARKS)
    assert desc.measure_set() == {Measure("sum", "grades.marks")}
    assert desc.dimension_set() == {"departments.department_code", "students.residency_status"}
