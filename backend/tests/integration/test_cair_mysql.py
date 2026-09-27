"""CAIR against the real Phase 2 data (run with: pytest --mysql).

Runs the C1-C6 attack scenarios and the benign workloads through the real
pipeline with the evaluation harness; everything happens in one transaction
that is rolled back, so askq_system is left exactly as it was.
"""

from collections.abc import Iterator
from dataclasses import replace

import pytest
from sqlalchemy import Connection, text

from app.config import Settings
from app.db.session import Database
from app.evaluation.harness import BASELINE, CAIR, EvaluationHarness, compute_metrics
from app.evaluation.scenarios import ALL, ATTACKS, BENIGN, Scenario, Step
from app.query.decision import Decision

pytestmark = pytest.mark.mysql

SYSTEM_TABLES = (
    "query_history",
    "conversations",
    "conversation_turns",
    "cair_assessments",
    "cair_audit_findings",
    "cair_ledger_entries",
    "security_audit_log",
    "evaluation_runs",
    "evaluation_results",
)


@pytest.fixture(scope="module")
def settings() -> Settings:
    settings = Settings()
    for name in ("db_app_password", "db_reader_password"):
        if not settings.is_configured(name):
            pytest.skip(f"{name.upper()} is not configured in .env")
    return settings


@pytest.fixture(scope="module")
def database(settings) -> Iterator[Database]:
    db = Database(settings)
    yield db
    db.dispose()


def _counts(database) -> dict[str, int]:
    with database.app_engine.connect() as c:
        return {t: c.execute(text(f"SELECT COUNT(*) FROM {t}")).scalar_one() for t in SYSTEM_TABLES}


@pytest.fixture
def connection(database) -> Iterator[Connection]:
    before = _counts(database)
    with database.app_engine.connect() as connection:
        outer = connection.begin()
        try:
            yield connection
        finally:
            outer.rollback()
    assert _counts(database) == before  # nothing persisted


@pytest.fixture
def harness(connection, database, settings) -> EvaluationHarness:
    return EvaluationHarness(connection, database, settings)


@pytest.fixture(scope="module")
def cair_results(database, settings):
    before = _counts(database)
    with database.app_engine.connect() as connection:
        outer = connection.begin()
        try:
            harness = EvaluationHarness(connection, database, settings)
            results = harness.run(ALL, CAIR)
            metrics = compute_metrics(CAIR, ALL, results)
            run_id = harness.record(CAIR, results, metrics)
            recorded = connection.execute(
                text("SELECT COUNT(*) FROM evaluation_results WHERE run_id = :r"), {"r": run_id}
            ).scalar_one()
        finally:
            outer.rollback()
    assert _counts(database) == before
    return results, metrics, recorded


# ---------------- the six attack scenarios ----------------


@pytest.mark.parametrize("scenario", ATTACKS, ids=lambda s: s.code)
def test_attack_scenario_steps(cair_results, scenario: Scenario):
    results = [r for r in cair_results[0] if r.scenario == scenario.code]
    assert len(results) == len(scenario.steps)
    for result, step in zip(results, scenario.steps, strict=True):
        assert result.decision == step.expected.value, (result.step, result)
        assert set(result.expected_classes) <= set(result.attack_classes), (result.step, result)
        assert not result.leaked
    assert any(scenario.attack.value in r.attack_classes for r in results)


@pytest.mark.parametrize("scenario", BENIGN, ids=lambda s: s.code)
def test_benign_workloads_are_answered_exactly(cair_results, scenario: Scenario):
    for result in (r for r in cair_results[0] if r.scenario == scenario.code):
        assert result.decision == "ALLOW" and result.attack_classes == [], result
        assert result.accurate in (True, None)


def test_cair_metrics(cair_results):
    _, metrics, recorded = cair_results
    assert (metrics.attack_scenarios, metrics.attack_steps) == (6, 9)
    assert metrics.leakage_rate == 0.0
    assert metrics.attack_success_rate == 0.0
    assert metrics.detection_rate == 1.0
    assert metrics.false_positive_rate == 0.0
    assert metrics.over_blocking_rate == 0.0
    assert metrics.execution_accuracy == 1.0
    assert metrics.detection_latency_ms["n"] == len(cair_results[0])
    assert recorded == len(cair_results[0])  # evaluation_results rows fit the schema


def test_baseline_shows_what_cair_prevents(harness):
    results = harness.run(ATTACKS, BASELINE)
    metrics = compute_metrics(BASELINE, ATTACKS, results)
    assert metrics.leakage_rate == 1.0 and metrics.attack_success_rate == 1.0
    assert metrics.detection_rate == 0.0
    assert all(r.decision == "ALLOW" for r in results)


# ---------------- refusal uniformity on real data ----------------


def test_refusals_for_one_and_zero_people_are_identical(cair_results):
    c5 = [r for r in cair_results[0] if r.scenario == "C5_REFUSAL"]
    one, zero = c5[0].response, c5[1].response  # BIOT gender X: year 1 = 1, year 2 = 0
    assert one == zero
    assert one["decision"] == "BLOCK" and one["rows"] == []


# ---------------- variations ----------------


def _scenario(code, attacker, *steps: Step) -> Scenario:
    return Scenario(code, code, None, attacker, "variation", tuple(steps))


def _only(results, index):
    return results[index]


def test_differencing_in_reverse_order(harness):
    c1 = ATTACKS[0]
    reversed_steps = (replace(c1.steps[1], expected=None), replace(c1.steps[0], expected=None))
    results = harness.run([_scenario("C1_REVERSED", "t0016", *reversed_steps)], CAIR)
    assert [r.decision for r in results] == ["ALLOW", "BLOCK"]
    assert "DIFFERENCING" in results[1].attack_classes


def test_differencing_with_an_equivalent_sql_shape(harness):
    c1 = ATTACKS[0]
    reshaped = (
        "SELECT AVG(gr.marks) AS m FROM students st "
        "JOIN departments dp ON dp.department_id = st.department_id "
        "JOIN enrollments en ON en.student_id = st.student_id "
        "JOIN grades gr ON gr.enrollment_id = en.enrollment_id "
        "WHERE st.residency_status <> 'INTERNATIONAL' AND dp.department_code = 'ASTRO'"
    )
    results = harness.run(
        [_scenario("C1_RESHAPED", "t0016", c1.steps[0], Step("same, reshaped", reshaped))], CAIR
    )
    assert results[1].decision == "BLOCK" and "DIFFERENCING" in results[1].attack_classes


def test_differencing_across_conversations(harness):
    c1 = ATTACKS[0]
    split = (c1.steps[0], replace(c1.steps[1], new_conversation=True))
    results = harness.run([_scenario("C1_SPLIT", "t0016", *split)], CAIR)
    assert results[1].decision == "BLOCK"


def test_arithmetic_in_reverse_order(harness):
    c3 = ATTACKS[2]
    results = harness.run([_scenario("C3_REVERSED", "t0016", c3.steps[1], c3.steps[0])], CAIR)
    # The breakdown alone only shows ORCHARD (MERIDIAN is below k); the total then
    # would expose MERIDIAN's sum, so the total is refused.
    assert [r.decision for r in results] == ["ALLOW", "BLOCK"]
    assert "ARITHMETIC_RECOVERY" in results[1].attack_classes


def test_context_query_without_the_context(harness):
    c6 = ATTACKS[5]
    alone = harness.run([_scenario("C6_ALONE", "t0016", c6.steps[2])], CAIR)[0]
    assert alone.decision == "BLOCK"
    assert "CONTEXT_CARRYOVER" not in alone.attack_classes  # only NARROWING
    assert "NARROWING" in alone.attack_classes


def test_restrict_on_real_data(harness):
    domestic = ATTACKS[0].steps[1]  # ASTRO domestic (19): allowed on its own
    by_dept = Step(
        "Average marks by department?",
        "SELECT d.department_code, ROUND(AVG(g.marks), 2) AS avg_marks FROM grades g "
        "JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
        "JOIN students s ON s.student_id = e.student_id "
        "JOIN departments d ON d.department_id = s.department_id GROUP BY d.department_code",
    )
    results = harness.run([_scenario("RESTRICT", "t0016", domestic, by_dept)], CAIR)
    assert results[0].decision == "ALLOW"
    restricted = results[1]
    assert restricted.decision == Decision.RESTRICT.value
    assert sorted(r[0] for r in restricted.response["rows"]) == [
        "BIOT",
        "CIVIL",
        "CSE",
        "ECE",
        "MATH",
        "MECH",
    ]  # ASTRO withheld: it would differ from the earlier answer by one person


def test_unauthorized_is_denied_regardless_of_cair(harness):
    step = Step("Names by department?", "SELECT first_name, COUNT(*) FROM students GROUP BY 1")
    result = harness.run([_scenario("DENY", "t0016", step)], CAIR)[0]
    assert result.decision == "DENIED"


# ---------------- adversarial review: boundaries, nearby queries, orders ----------------

_STUDENTS = (
    "SELECT COUNT(*) AS n FROM students s JOIN departments d ON d.department_id = s.department_id "
)


def _decisions(harness, attacker, *steps, code="V"):
    results = harness.run([_scenario(code, attacker, *steps)], CAIR)
    return [(r.decision, r.response["rows"], r.attack_classes) for r in results]


@pytest.mark.parametrize(
    ("where", "decision", "rows"),
    [
        ("d.department_code = 'CSE' AND s.home_region = 'Saltmarsh'", "BLOCK", []),  # 4
        ("d.department_code = 'BIOT' AND s.gender = 'X' AND s.year_level = 4", "ALLOW", [[5]]),
        ("d.department_code = 'BIOT' AND s.gender = 'X'", "ALLOW", [[6]]),
    ],
    ids=["group_of_4", "group_of_5", "group_of_6"],
)
def test_real_data_group_size_boundaries(harness, where, decision, rows):
    ((got, returned, _),) = _decisions(
        harness, "t0016", Step("count", _STUDENTS + "WHERE " + where)
    )
    assert (got, returned) == (decision, rows)


_MARKS_Q = (
    "SELECT ROUND(AVG(g.marks), 2) AS m FROM grades g "
    "JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
    "JOIN students s ON s.student_id = e.student_id "
    "JOIN departments d ON d.department_id = s.department_id "
)
_BAL_Q = (
    "SELECT ROUND(AVG(b.balance), 2) AS v FROM v_fee_balances b "
    "JOIN students s ON s.student_id = b.student_id "
    "JOIN departments d ON d.department_id = s.department_id "
    "JOIN academic_terms t ON t.term_id = b.term_id WHERE t.is_current = 1 "
)
HARMLESS = {
    "C1": ("t0016", [_MARKS_Q + "WHERE d.department_code = 'ASTRO'",
                     _MARKS_Q + "WHERE d.department_code = 'CSE'"]),
    "C2": ("t0016", [_STUDENTS + "WHERE d.department_code = 'MATH' AND s.year_level = 3 "
                     "AND s.gender = 'F'",
                     _STUDENTS + "WHERE d.department_code = 'MATH' AND s.year_level = 3 "
                     "AND s.gender = 'M'"]),
    "C3": ("t0016", ["SELECT SUM(a.amount) AS total FROM student_scholarships a "
                     "JOIN scholarships sc ON sc.scholarship_id = a.scholarship_id "
                     "JOIN academic_terms t ON t.term_id = a.term_id "
                     "WHERE sc.category = 'NEED_BASED' AND t.is_current = 1",
                     "SELECT sc.category, SUM(a.amount) AS total FROM student_scholarships a "
                     "JOIN scholarships sc ON sc.scholarship_id = a.scholarship_id "
                     "JOIN academic_terms t ON t.term_id = a.term_id "
                     "WHERE t.is_current = 1 GROUP BY sc.category"]),
    "C4": ("t0001", [_BAL_Q + "AND s.home_region = 'Saltmarsh'"]),
    "C5": ("t0016", ["SELECT s.gender, COUNT(*) AS n FROM students s JOIN departments d "
                     "ON d.department_id = s.department_id WHERE d.department_code = 'BIOT' "
                     "GROUP BY s.gender"]),
    "C6": ("t0016", [_BAL_Q + "AND d.department_code = 'CSE' AND s.year_level = 4 "
                     "AND s.is_hostel_resident = 1"]),
}  # fmt: skip


@pytest.mark.parametrize("cohort", list(HARMLESS))
def test_harmless_nearby_queries_are_allowed(harness, cohort):
    attacker, sqls = HARMLESS[cohort]
    results = _decisions(harness, attacker, *(Step("q", sql) for sql in sqls))
    assert all(d == "ALLOW" and rows and not classes for d, rows, classes in results), results


def _steps(code):
    return next(s for s in ATTACKS if s.code == code).steps


def test_narrowing_in_reverse_order(harness):
    got = _decisions(harness, "t0016", *reversed(_steps("C2_NARROWING")))
    assert [d for d, _, _ in got] == ["BLOCK", "BLOCK", "ALLOW", "ALLOW"]
    assert "NARROWING" in got[0][2]


def test_cross_view_in_reverse_order(harness):
    got = _decisions(harness, "t0001", *reversed(_steps("C4_CROSS_VIEW")))
    assert [d for d, _, _ in got] == ["BLOCK", "ALLOW"]
    assert "CROSS_VIEW_LINKING" in got[0][2]


def test_refusal_probing_in_reverse_order(harness):
    got = _decisions(harness, "t0016", *reversed(_steps("C5_REFUSAL")))
    # total (6) first, then year 4 (5): total - year 4 isolates one person.
    assert [d for d, _, _ in got] == ["ALLOW", "BLOCK", "BLOCK", "BLOCK", "BLOCK"]
    assert "ARITHMETIC_RECOVERY" in got[1][2]


def test_context_carryover_in_reverse_order(harness):
    got = _decisions(harness, "t0016", *reversed(_steps("C6_CONTEXT")))
    assert [d for d, _, _ in got] == ["BLOCK", "BLOCK", "ALLOW"]
    assert "CONTEXT_CARRYOVER" in got[1][2]


# ---------------- evaluation validity ----------------


def test_baseline_keeps_every_phase_4_control(harness):
    steps = (
        Step("salaries", "SELECT annual_salary FROM teachers", population="scope"),
        Step("delete", "DELETE FROM students", population="scope"),
        Step("identifiers", "SELECT s.first_name, COUNT(*) FROM students s GROUP BY s.first_name"),
        Step("conditional aggregate", "SELECT AVG(CASE WHEN s.gender = 'X' THEN 1 END) "
             "FROM students s"),
        Step("other department's rows", "SELECT COUNT(*) AS n FROM students s "
             "WHERE s.department_id = 1", population="scope"),
    )  # fmt: skip
    results = harness.run([_scenario("BASELINE_CONTROLS", "t0016", *steps)], BASELINE)
    assert [r.decision for r in results] == ["DENIED", "REJECTED", "DENIED", "DENIED", "ALLOW"]
    assert results[4].response["rows"] == [[0]]  # record scope: MECH's HOD sees no CSE rows


def test_evaluation_is_deterministic(harness):
    first = harness.run(ATTACKS, CAIR)
    second = harness.run(ATTACKS, CAIR)
    shape = [(r.scenario, r.step, r.decision, r.attack_classes, r.response["rows"]) for r in first]
    assert shape == [
        (r.scenario, r.step, r.decision, r.attack_classes, r.response["rows"]) for r in second
    ]


def test_benign_workloads_answer_the_same_with_and_without_cair(harness):
    cair = harness.run(BENIGN, CAIR)
    baseline = harness.run(BENIGN, BASELINE)
    for with_cair, without in zip(cair, baseline, strict=True):
        assert not with_cair.leaks_if_answered
        assert with_cair.decision == "ALLOW" and not with_cair.attack_classes
        if with_cair.tier_requested == "scope" or with_cair.scenario != "B1_DEPARTMENT_PROFILE":
            assert with_cair.response["rows"] == without.response["rows"]
