"""Runs scenarios through the real query pipeline and computes the metrics.

Arms (ARMS below) differ ONLY in inference control; every other layer
(authentication context, validation, authorization and row scope, the
statistical tier's shape rules, re-validation, askq_reader execution, LIMIT
and timeout) is the same pipeline in every arm:
  NO_CONTROL (B0)  no guard, minimum group size 1 (the Phase 5 "BASELINE").
  K_ONLY     (B1)  no guard, the configured minimum group size (k, default 5):
                   query-set-size restriction alone. Evaluation-only; never a
                   production configuration.
  CAIR             the CAIR guard and the configured k: production behaviour.

Everything except the language model is real: user contexts come from the
users table, SQL is validated and authorized, statistics execute as
askq_reader, history and CAIR state go through askq_app. Each scenario runs
in its own savepoint and is rolled back, so scenarios cannot influence each
other; the caller decides whether the run's evaluation_* rows are kept.

Metric definitions: docs/cair.md, "Evaluation".
"""

import json
import statistics
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from decimal import Decimal
from typing import Any

from sqlalchemy import Connection, select, text
from sqlalchemy.orm import Session

from app.auth.service import build_user_context
from app.cair.guard import CairGuard
from app.config import Settings
from app.db.models import CairAssessment, User
from app.db.session import Database
from app.evaluation.scenarios import Scenario, Step
from app.llm.sql_generator import ChartHint, GeneratedSql, GenerationRequest
from app.query.decision import Decision, GuardInput, GuardResult, PassThroughGuard
from app.query.executor import ReaderExecutor, to_json_value
from app.query.service import QueryOutcome, QueryService

CAIR = "CAIR"
BASELINE = "BASELINE"  # Phase 5 name of the NO_CONTROL arm (still accepted)
NO_CONTROL = "NO_CONTROL"
K_ONLY = "K_ONLY"


@dataclass(frozen=True, slots=True)
class Arm:
    """One evaluation configuration of the inference-control layer."""

    id: str
    # Minimum distinct people behind every statistic. None: the configured
    # production value (Settings.cair_min_group_size, 5 by default), so arms
    # that use it can only ever differ from CAIR in the guard.
    min_group_size: int | None
    cair: bool  # the CAIR guard assesses every statistical question
    description: str

    def group_size(self, settings: Settings) -> int:
        return self.min_group_size or settings.cair_min_group_size

    @property
    def record_mode(self) -> str:
        """evaluation_runs.mode (the schema allows BASELINE | CAIR: is CAIR on?)."""
        return CAIR if self.cair else BASELINE


ARMS: dict[str, Arm] = {
    arm.id: arm
    for arm in (
        Arm(NO_CONTROL, 1, False, "B0: no inference control (no guard, minimum group size 1)"),
        Arm(K_ONLY, None, False, "B1: minimum group size k only, no CAIR guard"),
        Arm(CAIR, None, True, "CAIR: minimum group size k and the CAIR guard (production)"),
    )
}
_ALIASES = {BASELINE: NO_CONTROL}


def get_arm(arm: Arm | str) -> Arm:
    """An Arm, or its id (the Phase 5 mode name BASELINE means NO_CONTROL)."""
    if isinstance(arm, Arm):
        return arm
    try:
        return ARMS[_ALIASES.get(arm, arm)]
    except KeyError:
        raise ValueError(f"unknown evaluation arm {arm!r}; expected one of {list(ARMS)}") from None


class ScriptedGenerator:
    """Returns the current step's SQL: evaluation never depends on a model."""

    def __init__(self) -> None:
        self.step: Step | None = None

    def generate(self, request: GenerationRequest) -> GeneratedSql:
        if self.step is None:
            raise RuntimeError("no scenario step is active")
        return GeneratedSql(
            resolved_question=self.step.question,
            sql=self.step.sql,
            explanation="Scripted evaluation step.",
            chart=ChartHint(type="table", x="", y=""),
            population=self.step.population,
        )


class TimedGuard:
    """Wraps a guard to measure detection latency."""

    def __init__(self, inner) -> None:
        self.inner = inner
        self.gates_statistics = getattr(inner, "gates_statistics", False)
        self.last_ms: float | None = None

    def assess(self, request: GuardInput) -> GuardResult:
        started = time.perf_counter()
        try:
            return self.inner.assess(request)
        finally:
            self.last_ms = (time.perf_counter() - started) * 1000


@dataclass
class StepResult:
    scenario: str
    attack: str | None
    step: int
    question: str
    tier_requested: str
    decision: str
    reason_code: str | None
    attack_classes: list[str]
    expected_decision: str | None
    expected_classes: list[str]
    leaks_if_answered: bool
    leaked: bool
    row_count: int
    accurate: bool | None
    query_ms: float
    guard_ms: float | None
    query_id: int
    response: dict[str, Any] = field(repr=False, default_factory=dict)

    @property
    def detected(self) -> bool:
        return bool(self.attack_classes)


@dataclass
class Metrics:
    mode: str
    attack_scenarios: int
    attack_steps: int
    benign_queries: int
    leakage_rate: float
    attack_success_rate: float
    detection_rate: float
    false_positive_rate: float
    over_blocking_rate: float
    execution_accuracy: float | None
    detection_latency_ms: dict[str, float] | None
    query_latency_ms: dict[str, float]


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _latency(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    p95 = ordered[max(0, int(round(0.95 * len(ordered))) - 1)] if ordered else 0.0
    return {
        "mean": round(statistics.fmean(ordered), 2) if ordered else 0.0,
        "p95": round(p95, 2),
        "max": round(ordered[-1], 2) if ordered else 0.0,
        "n": len(ordered),
    }


def compute_metrics(
    arm: Arm | str, scenarios: Iterable[Scenario], results: list[StepResult]
) -> Metrics:
    arm = get_arm(arm)
    scenarios = list(scenarios)
    attacks = [s for s in scenarios if s.attack is not None]
    attack_results = [r for r in results if r.attack is not None]
    benign = [r for r in results if r.attack is None]
    attack_steps = [r for r in attack_results if r.leaks_if_answered]
    leaked_steps = [r for r in attack_steps if r.leaked]
    succeeded = {r.scenario for r in leaked_steps}
    detected = {
        s.code
        for s in attacks
        if any(r.scenario == s.code and s.attack.value in r.attack_classes for r in attack_results)
    }
    false_positives = [r for r in benign if r.detected]
    over_blocked = [r for r in benign if r.decision == Decision.BLOCK.value]
    with_reference = [r for r in benign if r.accurate is not None]
    guard_times = [r.guard_ms for r in results if r.guard_ms is not None]
    return Metrics(
        mode=arm.id,
        attack_scenarios=len(attacks),
        attack_steps=len(attack_steps),
        benign_queries=len(benign),
        leakage_rate=_rate(len(leaked_steps), len(attack_steps)),
        attack_success_rate=_rate(len(succeeded), len(attacks)),
        detection_rate=_rate(len(detected), len(attacks)),
        false_positive_rate=_rate(len(false_positives), len(benign)),
        over_blocking_rate=_rate(len(over_blocked), len(benign)),
        execution_accuracy=(
            _rate(sum(1 for r in with_reference if r.accurate), len(with_reference))
            if with_reference
            else None
        ),
        detection_latency_ms=_latency(guard_times) if arm.cair else None,
        query_latency_ms=_latency([r.query_ms for r in results]),
    )


def _normalise_rows(rows: list[list[Any]]) -> list[tuple]:
    def value(v: Any) -> Any:
        v = to_json_value(v)
        return (
            round(float(v), 4)
            if isinstance(v, float | int | Decimal) and not isinstance(v, bool)
            else v
        )

    return sorted(tuple(value(v) for v in row) for row in rows)


class EvaluationHarness:
    def __init__(self, connection: Connection, database: Database, settings: Settings) -> None:
        self._connection = connection  # the caller's transaction on the app engine
        self._database = database
        self._settings = settings

    def _reference(self, sql: str) -> list[tuple]:
        with self._database.reader_engine.connect() as reader:
            rows = reader.execution_options(no_parameters=True).exec_driver_sql(sql).fetchall()
        return _normalise_rows([list(r) for r in rows])

    def run(self, scenarios: Iterable[Scenario], arm: Arm | str) -> list[StepResult]:
        arm = get_arm(arm)
        results: list[StepResult] = []
        for scenario in scenarios:
            savepoint = self._connection.begin_nested()
            try:
                results += self._scenario(scenario, arm)
            finally:
                savepoint.rollback()
        return results

    def _scenario(self, scenario: Scenario, arm: Arm) -> list[StepResult]:
        session = Session(bind=self._connection, join_transaction_mode="create_savepoint")
        try:
            user_row = session.scalars(select(User).where(User.username == scenario.attacker)).one()
            user = build_user_context(session, user_row)
            if user is None:
                raise RuntimeError(f"{scenario.attacker} has no usable scope")
            generator = ScriptedGenerator()
            # The arm configures only the inference-control layer: the guard and
            # the minimum group size. The service, executor and settings are the
            # same for every arm.
            inner = (
                CairGuard(session, self._database, self._settings)
                if arm.cair
                else PassThroughGuard()
            )
            guard = TimedGuard(inner)
            service = QueryService(
                session,
                generator,
                guard,
                ReaderExecutor(
                    self._database,
                    timeout_ms=self._settings.sql_timeout_ms,
                    max_rows=self._settings.sql_max_rows,
                ),
                self._settings,
                statistics_enabled=True,
                statistics_min_group_size=arm.group_size(self._settings),
            )
            conversation: str | None = None
            results = []
            for index, step in enumerate(scenario.steps, start=1):
                generator.step = step
                if step.new_conversation:
                    conversation = None
                guard.last_ms = None
                started = time.perf_counter()
                outcome = service.ask(user, step.question, conversation)
                elapsed = (time.perf_counter() - started) * 1000
                conversation = outcome.conversation_id
                results.append(self._result(scenario, index, step, outcome, elapsed, guard))
            return results
        finally:
            session.close()

    def _result(
        self,
        scenario: Scenario,
        index: int,
        step: Step,
        outcome: QueryOutcome,
        elapsed: float,
        guard: TimedGuard,
    ) -> StepResult:
        classes: list[str] = []
        assessment = self._connection.execute(
            select(CairAssessment.reasons).where(CairAssessment.query_id == outcome.query_id)
        ).scalar_one_or_none()
        if isinstance(assessment, str):
            assessment = json.loads(assessment)
        if isinstance(assessment, dict):
            classes = list(assessment.get("attack_classes", []))
        rows = outcome.result.rows if outcome.result else []
        executed = outcome.decision in (Decision.ALLOW, Decision.RESTRICT)
        accurate = None
        if step.reference_sql is not None:
            accurate = executed and _normalise_rows(rows) == self._reference(step.reference_sql)
        return StepResult(
            scenario=scenario.code,
            attack=scenario.attack.value if scenario.attack else None,
            step=index,
            question=step.question,
            tier_requested=step.population,
            decision=outcome.decision.value,
            reason_code=outcome.reason_code,
            attack_classes=classes,
            expected_decision=step.expected.value if step.expected else None,
            expected_classes=[c.value for c in step.classes],
            leaks_if_answered=step.leaks,
            leaked=step.leaks and executed and len(rows) > 0,
            row_count=len(rows),
            accurate=accurate,
            query_ms=round(elapsed, 3),
            guard_ms=round(guard.last_ms, 3) if guard.last_ms is not None else None,
            query_id=outcome.query_id,
            response={
                "decision": outcome.decision.value,
                "message": outcome.message,
                "reason_code": outcome.reason_code,
                "rows": rows,
            },
        )

    def record(self, arm: Arm | str, results: list[StepResult], metrics: Metrics) -> int:
        """Write evaluation_runs / evaluation_results in the caller's transaction."""
        arm = get_arm(arm)
        config = {
            "arm": arm.id,
            "metrics": asdict(metrics),
            "min_group_size": arm.group_size(self._settings),
            "window_queries": self._settings.cair_window_queries,
        }
        run_id = self._connection.execute(
            text(
                "INSERT INTO evaluation_runs (run_name, mode, config, status) "
                "VALUES (:name, :mode, :config, 'COMPLETED')"
            ),
            {
                "name": f"cair-scenarios-{arm.id.lower()}",
                "mode": arm.record_mode,
                "config": json.dumps(config),
            },
        ).lastrowid
        allowed = {"ALLOW", "RESTRICT", "BLOCK"}
        for result in results:
            self._connection.execute(
                text(
                    "INSERT INTO evaluation_results (run_id, scenario_code, step_no, attack_class, "
                    "question, expected_decision, actual_decision, risk_score, latency_ms, "
                    "query_id) VALUES (:run, :code, :step, :attack, :question, :expected, "
                    ":actual, NULL, :latency, NULL)"
                ),
                {
                    "run": run_id,
                    "code": result.scenario,
                    "step": result.step,
                    "attack": result.attack,
                    "question": result.question,
                    "expected": result.expected_decision or "ALLOW",
                    "actual": result.decision if result.decision in allowed else None,
                    "latency": int(result.query_ms),
                },
            )
        return int(run_id)
