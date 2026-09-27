"""Adversarial review of the statistical tier and the CAIR integration.

Uses the isolated test population of tests/test_cair_api.py (SQLite; the
Phase 2 seed is never involved). Exact group sizes, k = 5:
  CSE F 6 / M 6 (HOD's own department) | ECE X 1 / F 5 / M 6 | ME F 4 / M 2
"""

import pytest
from sqlalchemy import select, update

from app.cair import detectors as detectors_module
from app.cair import guard as guard_module
from app.cair.guard import CairGuard
from app.cair.model import AttackClass
from app.cair.population import PopulationProbe
from app.db.models import CairAssessment, CairLedgerEntry, QueryHistory
from app.evaluation.harness import CAIR, StepResult, compute_metrics
from app.evaluation.scenarios import Scenario, Step
from app.query import service as service_module
from app.query import statistics as statistics_module
from app.query.catalog import CATALOG
from app.query.executor import ReaderExecutor
from app.query.sql_validator import SqlValidationError, validate_sql
from app.query.statistics import AuthorizationDenied, authorize_statistical
from app.rbac.roles import Role
from app.rbac.scope import Scope, ScopeKind, UserContext
from tests.conftest import ACCOUNTS
from tests.test_cair_api import (  # noqa: F401  (pytest fixtures)
    ask,
    cair_db,
    cair_settings,
    cclient,
    gen,
    reader_spy,
)
from tests.test_query_api import Spy

HOD = ACCOUNTS.hod
_JOIN_DEPT = "JOIN departments d ON d.department_id = s.department_id "


def count(where: str) -> str:
    return "SELECT COUNT(*) AS n FROM students s " + _JOIN_DEPT + "WHERE " + where


def by_gender(where: str) -> str:
    return (
        "SELECT s.gender, COUNT(*) AS n FROM students s "
        + _JOIN_DEPT
        + f"WHERE {where} GROUP BY s.gender"
    )


def sorted_rows(body):
    return sorted(body["rows"])


# ====================================================================
# 3. Minimum group size on the FINAL result: exactly 4, 5 and 6
# ====================================================================


def test_group_of_4_is_refused(ask):
    body = ask(HOD, count("d.department_code = 'ME' AND s.gender = 'F'")).json()
    assert (body["decision"], body["reason_code"], body["rows"]) == ("BLOCK", "INFERENCE_RISK", [])


def test_group_of_5_is_permitted(ask):
    body = ask(HOD, count("d.department_code = 'ECE' AND s.gender = 'F'")).json()
    assert (body["decision"], body["rows"]) == ("ALLOW", [[5]])


@pytest.mark.parametrize(
    "where", ["d.department_code = 'ECE' AND s.gender = 'M'", "d.department_code = 'ME'"]
)
def test_group_of_6_is_permitted(ask, where):
    body = ask(HOD, count(where)).json()
    assert (body["decision"], body["rows"]) == ("ALLOW", [[6]])


def test_grouped_result_never_contains_a_group_below_5(ask):
    body = ask(
        HOD,
        "SELECT d.department_code, s.gender, COUNT(*) AS n FROM students s "
        + _JOIN_DEPT
        + "GROUP BY d.department_code, s.gender",
    ).json()
    assert body["decision"] == "ALLOW"
    # CSE F6 M6, ECE F5 M6 shown; ECE X1, ME F4, ME M2 absent (not shown as 0).
    assert sorted_rows(body) == [["CSE", "F", 6], ["CSE", "M", 6], ["ECE", "F", 5], ["ECE", "M", 6]]


def test_grouped_boundary_inside_one_department(ask):
    ece = ask(HOD, by_gender("d.department_code = 'ECE'")).json()
    assert (ece["decision"], sorted_rows(ece)) == ("ALLOW", [["F", 5], ["M", 6]])
    me = ask(HOD, by_gender("d.department_code = 'ME'")).json()  # F4, M2: nothing >= 5
    assert (me["decision"], me["rows"]) == ("BLOCK", [])


def test_zero_result_and_small_groups_look_the_same(ask):
    four = ask(HOD, count("d.department_code = 'ME' AND s.gender = 'F'")).json()
    one = ask(HOD, count("s.gender = 'X'")).json()
    zero = ask(HOD, count("s.gender = 'Z'")).json()
    fields = ("decision", "message", "reason_code", "rows", "sql", "row_count", "execution_ms")
    assert {tuple(str(b[f]) for f in fields) for b in (four, one, zero)} == {
        tuple(str(four[f]) for f in fields)
    }
    assert four["security"] == one["security"] == zero["security"]


@pytest.mark.parametrize(
    "having", ["HAVING COUNT(*) >= 1", "HAVING COUNT(*) >= 1 OR 1 = 1", "HAVING COUNT(*) > 0"]
)
def test_user_having_cannot_lower_the_threshold(ask, having):
    sql = (
        "SELECT d.department_code, COUNT(*) AS n FROM students s "
        + _JOIN_DEPT
        + f"WHERE s.gender = 'X' GROUP BY d.department_code {having}"
    )
    body = ask(HOD, sql).json()
    assert (body["decision"], body["rows"]) == ("BLOCK", [])


def test_user_having_is_parenthesised_before_the_rule():
    tree = validate_sql(
        "SELECT s.gender, COUNT(*) FROM students s GROUP BY s.gender HAVING COUNT(*) > 0 OR 1 = 1",
        catalog_tables=CATALOG,
        university_db="askq_university",
    )
    hod = UserContext(2, "t", Role.HOD, Scope(ScopeKind.DEPARTMENT, department_id=1, teacher_id=1))
    sql = authorize_statistical(
        tree, hod, university_db="askq_university", max_rows=500, min_group_size=5
    ).sql
    assert "HAVING (COUNT(*) > 0 OR 1 = 1) AND COUNT(DISTINCT s.student_id) >= 5" in sql


# ====================================================================
# 4. Complementary groups: totals must not reveal a withheld group
# ====================================================================

ECE_TOTAL = count("d.department_code = 'ECE'")
ECE_BY_GENDER = by_gender("d.department_code = 'ECE'")
ECE_F = count("d.department_code = 'ECE' AND s.gender = 'F'")
ECE_M = count("d.department_code = 'ECE' AND s.gender = 'M'")


def test_total_then_breakdown_withholds_a_complementary_group(ask):
    assert ask(HOD, ECE_TOTAL).json()["rows"] == [[12]]
    body = ask(HOD, ECE_BY_GENDER).json()
    # 12 - F5 - M6 would reveal X = 1: the smaller visible part (F) is withheld too.
    assert body["decision"] == "RESTRICT"
    assert body["rows"] == [["M", 6]]
    assert body["security"]["guard_reasons"] == [
        "Part of the result was withheld to protect individuals."
    ]


def test_withheld_group_cannot_be_recovered_afterwards(ask):
    ask(HOD, ECE_TOTAL)
    ask(HOD, ECE_BY_GENDER)  # RESTRICT: only M = 6 shown
    # Asking for F directly would complete 12 - 6 - F = X: refused.
    assert ask(HOD, ECE_F).json()["decision"] == "BLOCK"
    # M again adds nothing new: 12 - 6 leaves 6 unknown people (>= k).
    assert ask(HOD, ECE_M).json()["decision"] == "ALLOW"


def test_breakdown_then_total_is_refused(ask):
    first = ask(HOD, ECE_BY_GENDER).json()
    assert (first["decision"], sorted_rows(first)) == ("ALLOW", [["F", 5], ["M", 6]])
    assert ask(HOD, ECE_TOTAL).json()["decision"] == "BLOCK"


def test_recovery_with_averages_is_refused(ask):
    avg = (
        "SELECT AVG(g.marks) AS m FROM grades g "
        "JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
        "JOIN students s ON s.student_id = e.student_id " + _JOIN_DEPT
    )
    assert ask(HOD, avg + "WHERE d.department_code = 'ECE'").json()["decision"] == "ALLOW"
    grouped = ask(
        HOD,
        avg.replace("AVG(g.marks) AS m", "s.gender, AVG(g.marks) AS m")
        + "WHERE d.department_code = 'ECE' GROUP BY s.gender",
    ).json()
    assert grouped["decision"] == "RESTRICT" and [r[0] for r in grouped["rows"]] == ["M"]
    female = ask(HOD, avg + "WHERE d.department_code = 'ECE' AND s.gender = 'F'").json()
    assert female["decision"] == "BLOCK"


# ====================================================================
# 5. Adversarial shapes: refused (never executed) vs legitimate shapes
# ====================================================================

T = "s.home_region = 'R' AND s.department_id = 2 AND s.gender = 'X'"
BYPASSES = {
    "CASE inside AVG": "SELECT AVG(CASE WHEN " + T + " THEN g.marks END) FROM grades g "
    "JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
    "JOIN students s ON s.student_id = e.student_id",
    "IF inside SUM": "SELECT SUM(IF(" + T + ", 1, 0)) FROM students s",
    "boolean SUM": "SELECT SUM(s.gender = 'X') FROM students s",
    "COUNT(CASE)": "SELECT COUNT(CASE WHEN " + T + " THEN 1 END) FROM students s",
    "COUNT(DISTINCT CASE)": "SELECT COUNT(DISTINCT CASE WHEN " + T + " THEN s.gender END) "
    "FROM students s",
    "NULLIF in AVG": "SELECT AVG(NULLIF(g.marks, 50)) FROM grades g",
    "arithmetic inside aggregate": "SELECT SUM(g.marks * 0 + 1) FROM grades g",
    "division by zero nulling": "SELECT AVG(g.marks / (e.status <> 'COMPLETED')) FROM grades g "
    "JOIN enrollments e ON e.enrollment_id = g.enrollment_id",
    "scalar subquery": "SELECT (SELECT MAX(marks) FROM grades) AS m, COUNT(*) FROM students s",
    "uncorrelated WHERE oracle": "SELECT COUNT(*) FROM students s WHERE "
    "(SELECT AVG(g.marks) FROM grades g) > 50",
    "IN subquery": "SELECT COUNT(*) FROM students s WHERE s.department_id IN "
    "(SELECT department_id FROM departments)",
    "EXISTS": "SELECT COUNT(*) FROM students s WHERE EXISTS "
    "(SELECT 1 FROM enrollments e WHERE e.student_id = s.student_id)",
    "correlated subquery in aggregate": "SELECT AVG((SELECT MAX(g.marks) FROM grades g "
    "JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
    "WHERE e.student_id = s.student_id)) FROM students s",
    "derived table": "SELECT AVG(x.m) FROM students s JOIN (SELECT e.student_id, g.marks m "
    "FROM grades g JOIN enrollments e ON e.enrollment_id = g.enrollment_id) x "
    "ON x.student_id = s.student_id",
    "CTE": "WITH x AS (SELECT * FROM students) SELECT COUNT(*) FROM x",
    "LEFT JOIN with ON filter": "SELECT AVG(g.marks) FROM enrollments e LEFT JOIN grades g "
    "ON g.enrollment_id = e.enrollment_id AND e.offering_id = 2",
    "RIGHT JOIN": "SELECT AVG(g.marks) FROM enrollments e RIGHT JOIN grades g "
    "ON g.enrollment_id = e.enrollment_id",
    "CROSS JOIN": "SELECT AVG(g.marks) FROM students s CROSS JOIN grades g",
    "NATURAL JOIN": "SELECT COUNT(*) FROM students s NATURAL JOIN enrollments e",
    "STRAIGHT_JOIN": "SELECT COUNT(*) FROM students s STRAIGHT_JOIN enrollments e "
    "ON e.student_id = s.student_id",
    "comma join": "SELECT AVG(g.marks) FROM students s, grades g WHERE g.marks > 60",
    "join not on the person": "SELECT AVG(g.marks) FROM students s JOIN grades g ON g.marks > 60",
    "duplicate join not on the person": "SELECT COUNT(*) FROM students s JOIN students s2 "
    "ON s2.gender = s.gender",
    "link hidden under OR": "SELECT AVG(g.marks) FROM grades g JOIN enrollments e "
    "ON (e.enrollment_id = g.enrollment_id OR 1 = 1)",
    "SUM(record key)": "SELECT SUM(s.student_id) FROM students s",
    "GROUP BY record key expression": "SELECT COUNT(*) FROM students s GROUP BY s.student_id % 10",
    "record key vs literal": "SELECT COUNT(*) FROM students s WHERE s.student_id > 600",
    "ORDER BY record key": "SELECT COUNT(*) FROM students s ORDER BY s.student_id",
    "HAVING conditional oracle": "SELECT s.department_id, COUNT(*) FROM students s "
    "GROUP BY s.department_id HAVING SUM(CASE WHEN " + T + " THEN 1 ELSE 0 END) > 0",
    "ORDER BY conditional aggregate": "SELECT s.department_id, COUNT(*) FROM students s "
    "GROUP BY s.department_id ORDER BY SUM(CASE WHEN " + T + " THEN 1 ELSE 0 END)",
    "WITH ROLLUP": "SELECT s.gender, COUNT(*) FROM students s GROUP BY s.gender WITH ROLLUP",
    "window function": "SELECT COUNT(*) OVER () FROM students s",
    "DISTINCT rows": "SELECT DISTINCT s.gender FROM students s",
    "raw column": "SELECT s.home_region FROM students s",
    "direct identifier": "SELECT s.first_name, COUNT(*) FROM students s GROUP BY s.first_name",
    "teachers table": "SELECT AVG(t.annual_salary) FROM teachers t",
}
LEGITIMATE = {
    "aliases": "SELECT d.department_code AS dept, COUNT(*) AS n FROM students AS st "
    "INNER JOIN departments AS d ON d.department_id = st.department_id GROUP BY d.department_code",
    "USING": "SELECT s.gender, COUNT(*) AS n FROM students s JOIN enrollments e "
    "USING (student_id) GROUP BY s.gender",
    "three-way join on the person": "SELECT AVG(g.marks) AS m FROM grades g "
    "JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
    "JOIN students s ON s.student_id = e.student_id",
    "COUNT variations": "SELECT COUNT(*), COUNT(s.gender), COUNT(DISTINCT s.gender), "
    "COUNT(DISTINCT s.student_id) FROM students s",
    "arithmetic on aggregates": "SELECT SUM(g.marks) / COUNT(*) AS m, "
    "MAX(g.marks) - MIN(g.marks) AS spread FROM grades g",
    "CASE as a grouping key": "SELECT CASE WHEN s.department_id = 1 THEN 'own' ELSE 'other' END "
    "AS side, COUNT(*) AS n FROM students s GROUP BY side",
    "UNION of aggregates": "SELECT COUNT(*) FROM students s WHERE s.gender = 'F' "
    "UNION ALL SELECT COUNT(*) FROM students s WHERE s.gender = 'M'",
    "ORDER BY aggregate + LIMIT": "SELECT s.department_id, COUNT(*) AS n FROM students s "
    "GROUP BY s.department_id ORDER BY n DESC LIMIT 2",
    "plain HAVING": "SELECT s.department_id, COUNT(*) FROM students s "
    "GROUP BY s.department_id HAVING COUNT(*) > 5",
    "duplicate join on the person": "SELECT COUNT(*) FROM students s JOIN students s2 "
    "ON s2.student_id = s.student_id",
    "OR / NOT in WHERE": "SELECT COUNT(*) FROM students s WHERE NOT (s.gender = 'F' "
    "OR s.department_id = 3)",
    "nullable metric": "SELECT AVG(v.attendance_pct) FROM v_attendance_summary v "
    "JOIN students s ON s.student_id = v.student_id",
}
DB = "askq_university"
_USER = UserContext(2, "t", Role.HOD, Scope(ScopeKind.DEPARTMENT, department_id=1, teacher_id=1))


def _authorize(sql):
    tree = validate_sql(sql, catalog_tables=CATALOG, university_db=DB)
    return authorize_statistical(tree, _USER, university_db=DB, max_rows=500, min_group_size=5)


@pytest.mark.parametrize("name", list(BYPASSES))
def test_bypass_shape_is_refused(name):
    with pytest.raises((AuthorizationDenied, SqlValidationError)):
        _authorize(BYPASSES[name])


@pytest.mark.parametrize("name", list(LEGITIMATE))
def test_legitimate_shape_is_accepted_with_the_rules(name):
    result = _authorize(LEGITIMATE[name])
    assert result.tier == "STATISTICAL"
    assert result.sql.count(">= 5") == result.sql.count("HAVING")  # rule on every branch
    validate_sql(result.sql, catalog_tables=CATALOG, university_db=DB)


def test_nullable_metric_gets_is_not_null():
    assert "WHERE NOT v.attendance_pct IS NULL" in _authorize(LEGITIMATE["nullable metric"]).sql


@pytest.mark.parametrize(
    "name", ["CASE inside AVG", "LEFT JOIN with ON filter", "uncorrelated WHERE oracle", "CTE"]
)
def test_bypass_is_denied_end_to_end_and_never_executed(ask, reader_spy, name):
    body = ask(HOD, BYPASSES[name]).json()
    assert body["decision"] == "DENIED" and body["rows"] == [] and body["sql"] is None
    assert body["reason_code"].startswith("STATISTICS_") or "NOT_PERMITTED" in body["reason_code"]
    assert reader_spy.statements == []  # not even a CAIR probe ran


def test_equivalent_shapes_give_the_same_answer(ask):
    shapes = [
        "SELECT COUNT(*) AS n FROM students s JOIN departments d "
        "ON d.department_id = s.department_id WHERE d.department_code = 'ECE' AND s.gender = 'M'",
        "SELECT COUNT(*) AS n FROM departments dd INNER JOIN students x "
        "ON x.department_id = dd.department_id WHERE x.gender = 'M' AND dd.department_code = 'ECE'",
        "SELECT COUNT(DISTINCT s.student_id) AS n FROM students s JOIN departments d "
        "USING (department_id) WHERE d.department_code = 'ECE' AND s.gender <> 'F' "
        "AND s.gender <> 'X'",
    ]
    answers = [ask(HOD, sql).json() for sql in shapes]
    assert [(a["decision"], a["rows"]) for a in answers] == [("ALLOW", [[6]])] * 3


# ====================================================================
# Pipeline order (authorization and re-validation strictly before CAIR)
# ====================================================================


def test_pipeline_order(ask, monkeypatch):
    events: list[str] = []

    def wrap(owner, name, label):
        original = getattr(owner, name)

        def recorder(*args, **kwargs):
            events.append(label)
            return original(*args, **kwargs)

        monkeypatch.setattr(owner, name, recorder)

    wrap(service_module.queries, "recent_turns", "conversation")
    wrap(service_module, "validate_sql", "validate")
    wrap(service_module, "authorize_statistical", "authorize")
    wrap(statistics_module, "validate_sql", "revalidate_final_sql")
    wrap(CairGuard, "assess", "cair")
    wrap(ReaderExecutor, "execute", "execute")
    wrap(service_module.queries, "add_history", "history")
    ask(HOD, ECE_M)  # the generator is called between conversation and validate
    assert events == [
        "conversation",
        "validate",
        "authorize",
        "revalidate_final_sql",
        "cair",
        "execute",
        "history",
    ]


# ====================================================================
# Fail closed: a failure anywhere in CAIR runs nothing
# ====================================================================


def _boom(*args, **kwargs):
    raise RuntimeError("forced failure")


@pytest.mark.parametrize(
    ("owner", "name"),
    [
        (guard_module, "describe"),  # descriptor generation
        (guard_module, "build_probes"),  # population analysis
        (PopulationProbe, "_rows"),  # probe execution
        (guard_module, "load_state"),  # history loading
        (detectors_module, "differencing"),  # detector execution
        (guard_module, "assess"),  # scoring
    ],
    ids=["descriptor", "population", "probe", "history", "detector", "scoring"],
)
def test_cair_failures_fail_closed(ask, cair_db, reader_spy, monkeypatch, owner, name):
    monkeypatch.setattr(owner, name, _boom)
    body = ask(HOD, ECE_M).json()
    assert body["decision"] == "FAILED" and body["rows"] == [] and body["sql"] is None
    assert "forced" not in body["message"]
    assert not any(s.startswith("SELECT COUNT(*) AS n") for s in reader_spy.statements)
    with cair_db.app_session() as s:
        row = s.scalars(select(QueryHistory).order_by(QueryHistory.query_id.desc())).first()
        assert (row.final_status, row.failure_stage, row.executed_sql) == ("FAILED", "CAIR", None)
        assert s.scalars(select(CairLedgerEntry)).all() == []


def test_tampered_stored_probe_fails_closed(ask, cair_db, reader_spy):
    ask(HOD, ECE_M)
    with cair_db.app_session() as s:
        assessment = s.scalars(select(CairAssessment)).one()
        reasons = dict(assessment.reasons)
        reasons["probes"] = [{"branch": 0, "sql": "DELETE FROM students", "group_width": 0}]
        s.execute(
            update(CairAssessment)
            .where(CairAssessment.assessment_id == assessment.assessment_id)
            .values(reasons=reasons)
        )
        s.commit()
    reader_spy.statements.clear()
    body = ask(HOD, ECE_F).json()
    assert body["decision"] == "FAILED"
    assert not any("DELETE" in s for s in reader_spy.statements)


# ====================================================================
# Database separation
# ====================================================================


def test_probes_run_only_on_the_reader(ask, cair_db, reader_spy):
    app_spy = Spy(cair_db.app_engine)
    ask(HOD, ECE_TOTAL)
    ask(HOD, ECE_F)
    assert any("cair_subject" in s for s in reader_spy.statements)
    assert not any("cair_subject" in s for s in app_spy.statements)
    assert not any(s.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
                   for s in reader_spy.statements)  # fmt: skip


def test_blocked_query_is_never_executed(ask, reader_spy):
    ask(HOD, ECE_TOTAL)
    ask(HOD, ECE_BY_GENDER)
    reader_spy.statements.clear()
    body = ask(HOD, ECE_F).json()
    assert body["decision"] == "BLOCK"
    executed = [s for s in reader_spy.statements if "cair_subject" not in s]
    assert executed == []  # only CAIR's own probes touched the reader


# ====================================================================
# Evaluation metrics measure outcomes, not labels
# ====================================================================


def _result(scenario, attack, step, decision, classes, leaks, rows):
    return StepResult(
        scenario=scenario, attack=attack, step=step, question="q", tier_requested="university",
        decision=decision, reason_code=None, attack_classes=classes, expected_decision=None,
        expected_classes=[], leaks_if_answered=leaks,
        leaked=leaks and decision in ("ALLOW", "RESTRICT") and rows > 0,
        row_count=rows, accurate=None, query_ms=1.0, guard_ms=1.0, query_id=step,
    )  # fmt: skip


def test_a_block_for_the_wrong_reason_is_not_a_detection():
    scenarios = [Scenario("C1", "t", AttackClass.DIFFERENCING, "u", "p", (Step("q", "s"),))]
    results = [_result("C1", "DIFFERENCING", 1, "BLOCK", ["NARROWING"], True, 0)]
    metrics = compute_metrics(CAIR, scenarios, results)
    assert metrics.detection_rate == 0.0 and metrics.leakage_rate == 0.0


def test_leakage_is_measured_from_returned_rows():
    scenarios = [Scenario("C1", "t", AttackClass.DIFFERENCING, "u", "p", (Step("q", "s"),))]
    answered_empty = [_result("C1", "DIFFERENCING", 1, "ALLOW", [], True, 0)]
    answered_rows = [_result("C1", "DIFFERENCING", 1, "ALLOW", [], True, 1)]
    assert compute_metrics(CAIR, scenarios, answered_empty).leakage_rate == 0.0
    assert compute_metrics(CAIR, scenarios, answered_rows).leakage_rate == 1.0
    assert compute_metrics(CAIR, scenarios, answered_rows).attack_success_rate == 1.0
