"""Phase 7A: the three evaluation arms on the real Phase 2 data (pytest --mysql).

  * every arm runs the same secure pipeline (validation, authorization and row
    scope, statistical shape rules, re-validation, askq_reader execution,
    LIMIT, timeout); only the guard and the minimum group size differ;
  * NO_CONTROL (B0) and CAIR reproduce the published Phase 5 results exactly;
  * K_ONLY (B1) is the same pipeline with k and no guard: identical to CAIR
    wherever CAIR allowed, and never blocking or restricting anything.

The pinned per-step decisions and row counts below were recorded from the
Phase 5 harness before the arm refactor (they are the published behaviour).
The K_ONLY numbers are measured regression values, not targets. Everything
runs in one outer transaction that is rolled back.
"""

import pytest
from sqlalchemy import event, text

from app.evaluation import harness as harness_module
from app.evaluation.harness import (
    ARMS,
    BASELINE,
    CAIR,
    K_ONLY,
    NO_CONTROL,
    EvaluationHarness,
    compute_metrics,
)
from app.evaluation.scenarios import ALL, ATTACKS, Scenario, Step
from app.query.decision import PassThroughGuard
from tests.integration.test_cair_mysql import (  # noqa: F401  (pytest fixtures)
    _counts,
    _scenario,
    connection,
    database,
    harness,
    settings,
)

pytestmark = pytest.mark.mysql

# (scenario prefix, step, decision, row count) for ALL, from the Phase 5 harness.
PHASE5_BASELINE = [
    ("C1_", 1, "ALLOW", 1), ("C1_", 2, "ALLOW", 1),
    ("C2_", 1, "ALLOW", 1), ("C2_", 2, "ALLOW", 1), ("C2_", 3, "ALLOW", 1), ("C2_", 4, "ALLOW", 1),
    ("C3_", 1, "ALLOW", 1), ("C3_", 2, "ALLOW", 2),
    ("C4_", 1, "ALLOW", 17), ("C4_", 2, "ALLOW", 1),
    ("C5_", 1, "ALLOW", 1), ("C5_", 2, "ALLOW", 0), ("C5_", 3, "ALLOW", 0), ("C5_", 4, "ALLOW", 1),
    ("C5_", 5, "ALLOW", 1),
    ("C6_", 1, "ALLOW", 1), ("C6_", 2, "ALLOW", 1), ("C6_", 3, "ALLOW", 1),
    ("B1_", 1, "ALLOW", 7), ("B1_", 2, "ALLOW", 4), ("B1_", 3, "ALLOW", 7), ("B1_", 4, "ALLOW", 5),
    ("B1_", 5, "ALLOW", 7), ("B1_", 6, "ALLOW", 3),
    ("B2_", 1, "ALLOW", 1), ("B2_", 2, "ALLOW", 1), ("B2_", 3, "ALLOW", 1), ("B2_", 4, "ALLOW", 1),
    ("B3_", 1, "ALLOW", 1), ("B3_", 2, "ALLOW", 7),
    ("B4_", 1, "ALLOW", 1), ("B4_", 2, "ALLOW", 1),
]  # fmt: skip
PHASE5_CAIR = [
    ("C1_", 1, "ALLOW", 1), ("C1_", 2, "BLOCK", 0),
    ("C2_", 1, "ALLOW", 1), ("C2_", 2, "ALLOW", 1), ("C2_", 3, "BLOCK", 0), ("C2_", 4, "BLOCK", 0),
    ("C3_", 1, "ALLOW", 1), ("C3_", 2, "BLOCK", 0),
    ("C4_", 1, "ALLOW", 17), ("C4_", 2, "BLOCK", 0),
    ("C5_", 1, "BLOCK", 0), ("C5_", 2, "BLOCK", 0), ("C5_", 3, "BLOCK", 0), ("C5_", 4, "BLOCK", 0),
    ("C5_", 5, "BLOCK", 0),
    ("C6_", 1, "ALLOW", 1), ("C6_", 2, "BLOCK", 0), ("C6_", 3, "BLOCK", 0),
    ("B1_", 1, "ALLOW", 7), ("B1_", 2, "ALLOW", 4), ("B1_", 3, "ALLOW", 7), ("B1_", 4, "ALLOW", 4),
    ("B1_", 5, "ALLOW", 7), ("B1_", 6, "ALLOW", 3),
    ("B2_", 1, "ALLOW", 1), ("B2_", 2, "ALLOW", 1), ("B2_", 3, "ALLOW", 1), ("B2_", 4, "ALLOW", 1),
    ("B3_", 1, "ALLOW", 1), ("B3_", 2, "ALLOW", 7),
    ("B4_", 1, "ALLOW", 1), ("B4_", 2, "ALLOW", 1),
]  # fmt: skip
# Published Phase 5 metrics (docs/cair.md), latency excluded.
PHASE5_METRICS = {
    NO_CONTROL: (6, 9, 14, 1.0, 1.0, 0.0, 0.0, 0.0, 0.8333),
    CAIR: (6, 9, 14, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0),
}


def _shape(results):
    return [(r.scenario[:3], r.step, r.decision, r.row_count) for r in results]


def _headline(m):
    return (
        m.attack_scenarios, m.attack_steps, m.benign_queries, m.leakage_rate,
        m.attack_success_rate, m.detection_rate, m.false_positive_rate,
        m.over_blocking_rate, m.execution_accuracy,
    )  # fmt: skip


class _Recorder:
    """Records how the harness builds each question's service and runs its SQL."""

    def __init__(self) -> None:
        self.services: list[dict] = []
        self.executed: list[str] = []


@pytest.fixture(scope="module")
def runs(database, settings):
    """ALL scenarios through every arm (and the Phase 5 name BASELINE), rolled back."""
    recorder = _Recorder()
    original_service = harness_module.QueryService
    original_executor = harness_module.ReaderExecutor

    class RecordingService(original_service):
        def __init__(self, session, generator, guard, executor, settings_, **kwargs):
            recorder.services.append(
                {"generator": generator, "guard": guard, "executor": executor,
                 "settings": settings_, **kwargs}
            )  # fmt: skip
            super().__init__(session, generator, guard, executor, settings_, **kwargs)

    class RecordingExecutor(original_executor):
        def execute(self, sql):
            recorder.executed.append(sql)
            return super().execute(sql)

    before = _counts(database)
    results, metrics, services = {}, {}, {}
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(harness_module, "QueryService", RecordingService)
        patch.setattr(harness_module, "ReaderExecutor", RecordingExecutor)
        with database.app_engine.connect() as connection:
            outer = connection.begin()
            try:
                harness = EvaluationHarness(connection, database, settings)
                for name in (NO_CONTROL, K_ONLY, CAIR, BASELINE):
                    recorder.services.clear()
                    results[name] = harness.run(ALL, name)
                    metrics[name] = compute_metrics(name, ALL, results[name])
                    services[name] = list(recorder.services)
            finally:
                outer.rollback()
    assert _counts(database) == before  # nothing persisted
    return results, metrics, services


# ---------------- regression: B0 and CAIR are the published Phase 5 results ----------------


def test_b0_reproduces_the_phase5_baseline(runs):
    results, metrics, _ = runs
    assert _shape(results[NO_CONTROL]) == PHASE5_BASELINE
    assert _headline(metrics[NO_CONTROL]) == PHASE5_METRICS[NO_CONTROL]
    assert metrics[NO_CONTROL].detection_latency_ms is None


def test_phase5_name_baseline_is_exactly_b0(runs):
    results, metrics, _ = runs
    strip = [(r.scenario, r.step, r.decision, r.reason_code, r.response["rows"])
             for r in results[BASELINE]]  # fmt: skip
    assert strip == [
        (r.scenario, r.step, r.decision, r.reason_code, r.response["rows"])
        for r in results[NO_CONTROL]
    ]
    assert _headline(metrics[BASELINE]) == _headline(metrics[NO_CONTROL])


def test_cair_reproduces_the_phase5_results(runs):
    results, metrics, _ = runs
    assert _shape(results[CAIR]) == PHASE5_CAIR
    assert _headline(metrics[CAIR]) == PHASE5_METRICS[CAIR]
    by_code = {s.code: s for s in ALL}
    for r in results[CAIR]:  # the scenario's own expectations, unchanged
        step = by_code[r.scenario].steps[r.step - 1]
        assert r.decision == step.expected.value, r
        assert {c.value for c in step.classes} <= set(r.attack_classes), r


# ---------------- B1: k without CAIR ----------------


def test_k_only_never_detects_blocks_or_restricts(runs):
    results, metrics, _ = runs
    assert all(r.attack_classes == [] for r in results[K_ONLY])
    assert {r.decision for r in results[K_ONLY]} == {"ALLOW"}
    assert metrics[K_ONLY].detection_rate == 0.0
    assert metrics[K_ONLY].detection_latency_ms is None


def test_k_only_equals_cair_wherever_cair_allowed(runs):
    results, _, _ = runs
    compared = 0
    for k_only, cair in zip(results[K_ONLY], results[CAIR], strict=True):
        assert (k_only.scenario, k_only.step) == (cair.scenario, cair.step)
        if cair.decision == "ALLOW":
            compared += 1
            assert k_only.response["rows"] == cair.response["rows"], cair
    assert compared == sum(1 for r in results[CAIR] if r.decision == "ALLOW") > 0


def test_k_only_answers_benign_workloads_like_cair(runs):
    results, metrics, _ = runs
    benign = [(r.response["rows"], r.accurate) for r in results[K_ONLY] if r.attack is None]
    assert benign == [(r.response["rows"], r.accurate) for r in results[CAIR] if r.attack is None]
    for name in ("false_positive_rate", "over_blocking_rate", "execution_accuracy"):
        assert getattr(metrics[K_ONLY], name) == getattr(metrics[CAIR], name), name


def test_k_only_measured_results(runs):
    # Measured with this refactor (regression values, not targets): k alone
    # empties the narrowing (C2) and context-carryover (C6) cells, but answers
    # the differencing, arithmetic, cross-view and refusal-probe steps.
    _, metrics, _ = runs
    m = metrics[K_ONLY]
    assert _headline(m) == (6, 9, 14, 0.4444, 0.6667, 0.0, 0.0, 0.0, 1.0)


# ---------------- same pipeline in every arm ----------------


def test_every_arm_builds_the_same_service_except_inference_control(runs, settings):
    _, _, services = runs
    for name in (NO_CONTROL, K_ONLY, CAIR):
        assert len(services[name]) == len(ALL)
        for built in services[name]:
            assert built["settings"] is settings
            assert built["statistics_enabled"] is True
            assert type(built["generator"]).__name__ == "ScriptedGenerator"
            assert isinstance(built["executor"], harness_module.ReaderExecutor)
            inner = built["guard"].inner
            if ARMS[name].cair:
                assert type(inner).__name__ == "CairGuard"
            else:
                assert isinstance(inner, PassThroughGuard)
            assert built["statistics_min_group_size"] == {NO_CONTROL: 1, K_ONLY: 5, CAIR: 5}[name]
    # The executor is configured identically (reader engine, timeout, row cap).
    executors = {
        (b["executor"]._timeout_ms, b["executor"]._max_rows)
        for name in (NO_CONTROL, K_ONLY, CAIR)
        for b in services[name]
    }
    assert executors == {(settings.sql_timeout_ms, settings.sql_max_rows)}


CONTROLS = (
    Step("salaries", "SELECT annual_salary FROM teachers", population="scope"),
    Step("delete", "DELETE FROM students", population="scope"),
    Step("stacked", "SELECT COUNT(*) FROM students; DROP TABLE students", population="scope"),
    Step("comment", "SELECT COUNT(*) FROM students -- hidden", population="scope"),
    Step("system schema", "SELECT user FROM mysql.user", population="scope"),
    Step("outfile", "SELECT student_id FROM students INTO OUTFILE '/tmp/x'", population="scope"),
    Step("unsafe function", "SELECT SLEEP(5)", population="scope"),
    Step("identifiers", "SELECT s.first_name, COUNT(*) FROM students s GROUP BY s.first_name"),
    Step("conditional aggregate", "SELECT AVG(CASE WHEN s.gender = 'X' THEN 1 END) "
         "FROM students s"),
    Step("statistical subquery", "SELECT COUNT(*) AS n FROM students s WHERE s.student_id IN "
         "(SELECT e.student_id FROM enrollments e)"),
    Step("other department's rows", "SELECT COUNT(*) AS n FROM students s "
         "WHERE s.department_id = 1", population="scope"),
    Step("own department", "SELECT COUNT(*) AS n FROM students", population="scope"),
    Step("university statistic", "SELECT COUNT(*) AS n FROM students s"),
)  # fmt: skip
EXPECTED_CONTROLS = [
    "DENIED", "REJECTED", "REJECTED", "REJECTED", "REJECTED", "REJECTED", "REJECTED",
    "DENIED", "DENIED", "DENIED", "ALLOW", "ALLOW", "ALLOW",
]  # fmt: skip


@pytest.mark.parametrize("arm", [NO_CONTROL, K_ONLY, CAIR])
def test_every_phase4_control_is_active_in_every_arm(harness, database, arm, monkeypatch):
    executed: list[str] = []
    on_reader: list[str] = []
    on_app: list[str] = []
    original = harness_module.ReaderExecutor

    class RecordingExecutor(original):
        def execute(self, sql):
            executed.append(sql)
            return super().execute(sql)

    def reader_spy(conn, cursor, statement, *args):
        on_reader.append(statement)

    def app_spy(conn, cursor, statement, *args):
        on_app.append(statement)

    monkeypatch.setattr(harness_module, "ReaderExecutor", RecordingExecutor)
    event.listen(database.reader_engine, "before_cursor_execute", reader_spy)
    event.listen(database.app_engine, "before_cursor_execute", app_spy)
    try:
        results = harness.run([_scenario("CONTROLS", "t0016", *CONTROLS)], arm)
    finally:
        event.remove(database.reader_engine, "before_cursor_execute", reader_spy)
        event.remove(database.app_engine, "before_cursor_execute", app_spy)

    assert [r.decision for r in results] == EXPECTED_CONTROLS
    assert results[9].reason_code.startswith("STATISTICS_")  # unsupported shape
    assert results[10].response["rows"] == [[0]]  # record scope: MECH's HOD sees no CSE rows
    # Only the three allowed questions ran, each once, bounded, and on the reader.
    assert len(executed) == 3
    for sql in executed:
        assert sql.rstrip().endswith("LIMIT 500"), sql
        assert sql in on_reader and sql not in on_app
    # The statistical question carries this arm's minimum group size, and only it.
    k = ARMS[arm].group_size(harness._settings)
    assert f"COUNT(DISTINCT s.student_id) >= {k}" in executed[2]
    assert "COUNT(DISTINCT" not in executed[1]  # record tier: row scope, no k


@pytest.mark.parametrize("arm", [NO_CONTROL, K_ONLY, CAIR])
def test_statement_timeout_is_active_in_every_arm(connection, database, settings, arm):
    admin = connection.execute(
        text(
            "SELECT u.username FROM askq_university.users u "
            "JOIN askq_university.roles r ON r.role_id = u.role_id "
            "WHERE r.role_code = 'ADMIN' AND u.is_active = 1 ORDER BY u.user_id LIMIT 1"
        )
    ).scalar_one()
    slow = EvaluationHarness(
        connection, database, settings.model_copy(update={"sql_timeout_ms": 200})
    )
    heavy = Step(
        "heavy",
        "SELECT COUNT(*) AS n FROM attendance_records a "
        "JOIN attendance_records b ON a.status = b.status",
        population="scope",
    )
    (result,) = slow.run([_scenario("TIMEOUT", admin, heavy)], arm)
    assert (result.decision, result.reason_code) == ("FAILED", "QUERY_TIMEOUT")


def test_attack_scenarios_are_unchanged():
    # The development set is used as-is: six attacks, one per class, 18 steps.
    assert [s.code[:2] for s in ATTACKS] == ["C1", "C2", "C3", "C4", "C5", "C6"]
    assert sum(len(s.steps) for s in ATTACKS) == 18
    assert all(isinstance(s, Scenario) for s in ALL)


# ---------------- B1 isolation: k, not CAIR, explains every B1 difference ----------------


def test_b1_isolation_from_cair(harness, monkeypatch):
    """B0 = k 1 + pass-through; B1 = k 5 + pass-through; CAIR = k 5 + CairGuard.

    Counts every entry into CAIR's logic (the guard, its population probes and
    the six detectors) and records the SQL each arm executes on askq_reader.
    CAIR is the positive control that the counters work.
    """
    from app.cair import detectors
    from app.cair.guard import CairGuard
    from app.cair.population import PopulationProbe

    calls: dict[str, int] = {}

    def counted(owner, name):
        original = getattr(owner, name)

        def wrapper(*args, **kwargs):
            calls[name] = calls.get(name, 0) + 1
            return original(*args, **kwargs)

        monkeypatch.setattr(owner, name, wrapper)

    counted(CairGuard, "assess")
    counted(PopulationProbe, "__init__")
    for name in ("narrowing", "differencing", "arithmetic_recovery", "cross_view_linking",
                 "refusal_side_channel", "context_carryover"):  # fmt: skip
        counted(detectors, name)

    executed: list[str] = []
    original = harness_module.ReaderExecutor

    class RecordingExecutor(original):
        def execute(self, sql):
            executed.append(sql)
            return super().execute(sql)

    monkeypatch.setattr(harness_module, "ReaderExecutor", RecordingExecutor)

    runs = {}
    for name in (NO_CONTROL, K_ONLY, CAIR):
        calls.clear()
        executed.clear()
        results = harness.run(ALL, name)
        runs[name] = (results, dict(calls), list(executed))

    # Guard and k per arm, as built for every scenario.
    assert (ARMS[NO_CONTROL].group_size(harness._settings), ARMS[NO_CONTROL].cair) == (1, False)
    assert (ARMS[K_ONLY].group_size(harness._settings), ARMS[K_ONLY].cair) == (5, False)
    assert (ARMS[CAIR].group_size(harness._settings), ARMS[CAIR].cair) == (5, True)

    # No CAIR logic runs in B0 or B1; it demonstrably runs in CAIR.
    assert runs[NO_CONTROL][1] == {} and runs[K_ONLY][1] == {}
    assert runs[CAIR][1]["assess"] == len(runs[CAIR][0])
    assert runs[CAIR][1]["__init__"] > 0 and runs[CAIR][1]["differencing"] > 0

    # B0 and B1 execute every step (nothing refused by a guard), and the SQL
    # each runs is identical except the minimum-group-size literal. So every
    # B0/B1 difference in results comes from the k rule alone.
    b0_sql, b1_sql = runs[NO_CONTROL][2], runs[K_ONLY][2]
    assert len(b0_sql) == len(b1_sql) == len(ALL_STEPS)
    for b0, b1 in zip(b0_sql, b1_sql, strict=True):
        assert b1 == b0.replace(") >= 1", ") >= 5"), (b0, b1)
    assert sum(") >= 5" in s for s in b1_sql) > 0

    # Where CAIR allows, it executes exactly B1's SQL (same k, same pipeline).
    cair_results, _, cair_sql = runs[CAIR]
    allowed = [r for r in cair_results if r.decision == "ALLOW"]
    assert len(cair_sql) == len(allowed)
    b1_by_step = {(r.scenario, r.step): sql for r, sql in zip(runs[K_ONLY][0], b1_sql, strict=True)}
    for r, sql in zip(allowed, cair_sql, strict=True):
        assert sql == b1_by_step[(r.scenario, r.step)], r


ALL_STEPS = [step for scenario in ALL for step in scenario.steps]
