"""The query pipeline: one question in, one recorded Decision out.

    generate (Claude) -> validate -> authorize (+ row scope, LIMIT) -> guard -> execute (reader)

The UserContext comes from the authenticated request only. The model sees the
role and scope so it can phrase useful SQL, but nothing it returns (and
nothing in the conversation) can change them: every stage after generation
treats its output as untrusted and enforces the policy itself.

Exactly one query_history row is written per question, whatever happens,
through the askq_app session; model-derived SQL only ever reaches the
ReaderExecutor (askq_reader). Nothing written contains passwords, tokens or
API keys; result rows are never stored.
"""

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal

from sqlalchemy.orm import Session

from app.clock import utcnow
from app.config import Settings
from app.db.models import Conversation, ConversationTurn, QueryHistory
from app.db.repositories import audit, queries
from app.llm.sql_generator import (
    ChartHint,
    GenerationCode,
    GenerationRequest,
    SqlGenerationError,
    SqlGenerator,
)
from app.query.authorization import (
    AuthorizationDenied,
    AuthorizationStatus,
    AuthorizedQuery,
    authorize,
)
from app.query.catalog import CATALOG
from app.query.decision import (
    FINAL_STATUS,
    Decision,
    GuardInput,
    GuardResult,
    InferenceGuard,
    PriorTurn,
)
from app.query.executor import ExecutionCode, QueryExecutionError, QueryResult, ReaderExecutor
from app.query.policy import policy_for, render
from app.query.schema_context import schema_context
from app.query.sql_validator import SqlValidationError, ValidatedQuery, validate_sql
from app.rbac.scope import UserContext

logger = logging.getLogger(__name__)


class Stage:
    GENERATION = "GENERATION"
    VALIDATION = "VALIDATION"
    AUTHORIZATION = "AUTHORIZATION"
    CAIR = "CAIR"
    EXECUTION = "EXECUTION"


class ConversationNotFound(Exception):
    """Unknown, archived, or another user's conversation (indistinguishable to the client)."""


_DECISION_MESSAGES = {
    Decision.ALLOW: "Query executed.",
    Decision.RESTRICT: "Query executed with additional restrictions.",
    Decision.BLOCK: "This query was blocked because it could reveal protected information.",
}
_INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass
class QueryOutcome:
    query_id: int
    conversation_id: str
    decision: Decision
    message: str
    question: str
    reason_code: str | None = None
    resolved_question: str | None = None
    explanation: str | None = None
    executed_sql: str | None = None
    result: QueryResult | None = None
    row_limit: int | None = None
    chart: ChartHint | None = None
    validation_status: str | None = None
    authorization_status: str | None = None
    guard: GuardResult | None = None
    notes: list[str] = field(default_factory=list)


class _Stop(Exception):
    """Ends the pipeline early with a decided outcome."""

    def __init__(self, decision: Decision, message: str, code: str | None, stage: str | None):
        super().__init__(code)
        self.decision, self.message, self.code, self.stage = decision, message, code, stage


class QueryService:
    def __init__(
        self,
        session: Session,
        generator: SqlGenerator,
        guard: InferenceGuard,
        executor: ReaderExecutor,
        settings: Settings,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._session = session
        self._generator = generator
        self._guard = guard
        self._executor = executor
        self._settings = settings
        self._clock = clock

    # ------------------------------------------------------------------ public
    def ask(
        self,
        user: UserContext,
        question: str,
        conversation_public_id: str | None = None,
        client_ip: str | None = None,
    ) -> QueryOutcome:
        session = self._session
        now = self._clock()
        conversation = self._conversation(user, conversation_public_id, question, now)
        history = queries.recent_turns(
            session, conversation.conversation_id, self._settings.query_context_turns
        )
        turn = queries.add_turn(session, conversation, question)

        record = QueryHistory(
            user_id=user.user_id,
            role_code=user.role.value,
            conversation_id=conversation.conversation_id,
            turn_id=turn.turn_id,
            question_text=None,  # stored once, in conversation_turns.question
        )
        outcome = QueryOutcome(
            query_id=0,
            conversation_id=conversation.public_id,
            decision=Decision.FAILED,
            message="",
            question=question,
        )
        stage = Stage.GENERATION
        try:
            self._run(user, question, conversation, history, record, outcome)
        except _Stop as stop:
            outcome.decision, outcome.message, outcome.reason_code = (
                stop.decision,
                stop.message,
                stop.code,
            )
            stage = stop.stage or stage
        except Exception:
            error_id = uuid.uuid4().hex
            logger.exception("query pipeline error %s", error_id)
            outcome.decision = Decision.FAILED
            outcome.message = "The question could not be processed because of an internal error."
            outcome.reason_code = _INTERNAL_ERROR
            stage = self._stage_reached(record)

        self._record(user, record, outcome, stage, turn, conversation, client_ip)
        return outcome

    # ---------------------------------------------------------------- pipeline
    def _run(
        self,
        user: UserContext,
        question: str,
        conversation: Conversation,
        history: tuple[PriorTurn, ...],
        record: QueryHistory,
        outcome: QueryOutcome,
    ) -> None:
        settings = self._settings
        db = settings.db_university_name
        policy = policy_for(user.role)

        # 1. Generation. Untrusted from here on.
        try:
            generated = self._generator.generate(
                GenerationRequest(
                    question=question,
                    role=user.role.value,
                    scope_description=render(policy.scope_description, user.scope, db),
                    schema_context=schema_context(user.role),
                    history=history,
                )
            )
        except SqlGenerationError as exc:
            raise _Stop(Decision.FAILED, exc.message, exc.code, Stage.GENERATION) from None
        record.resolved_question = generated.resolved_question
        outcome.resolved_question = generated.resolved_question
        outcome.explanation = generated.explanation
        outcome.chart = generated.chart
        if not generated.sql.strip():
            raise _Stop(
                Decision.FAILED,
                SqlGenerationError(GenerationCode.UNANSWERABLE).message,
                GenerationCode.UNANSWERABLE,
                Stage.GENERATION,
            )
        record.generated_sql = generated.sql

        # 2. Validation.
        try:
            validated = validate_sql(generated.sql, catalog_tables=CATALOG, university_db=db)
        except SqlValidationError as exc:
            record.validation_status = "REJECTED"
            outcome.validation_status = "REJECTED"
            logger.info("query rejected: %s (%s)", exc.code, exc.detail)
            raise _Stop(Decision.REJECTED, exc.message, exc.code, None) from None
        record.validation_status = outcome.validation_status = "PASSED"

        # 3. Authorization: role policy, row scope, LIMIT.
        try:
            authorized = authorize(
                validated, user, university_db=db, max_rows=settings.sql_max_rows
            )
        except AuthorizationDenied as exc:
            record.authorization_status = outcome.authorization_status = AuthorizationStatus.DENIED
            logger.info("query denied: %s (%s)", exc.code, exc.detail)
            raise _Stop(Decision.DENIED, exc.message, exc.code, None) from None
        record.authorization_status = outcome.authorization_status = authorized.status
        outcome.row_limit = authorized.row_limit
        outcome.notes.extend(authorized.notes)

        # 4. Inference guard (CAIR in Phase 5).
        result = self._guard.assess(
            GuardInput(
                user=user,
                conversation_id=conversation.conversation_id,
                question=question,
                resolved_question=generated.resolved_question,
                validated=validated,
                authorized=authorized,
                history=history,
            )
        )
        record.cair_decision = result.decision.value
        record.risk_score = Decimal(str(round(result.risk_score, 4)))
        outcome.guard = result
        if result.decision is Decision.BLOCK:
            raise _Stop(Decision.BLOCK, _DECISION_MESSAGES[Decision.BLOCK], "GUARD_BLOCK", None)
        sql = authorized.sql
        if result.decision is Decision.RESTRICT:
            sql = self._restricted_sql(result.restricted_sql or "", authorized, user, db)

        # 5. Execution through askq_reader only.
        record.executed_sql = sql
        try:
            executed = self._executor.execute(sql)
        except QueryExecutionError as exc:
            record.execution_ms = exc.elapsed_ms
            raise _Stop(Decision.FAILED, exc.message, exc.code, Stage.EXECUTION) from None
        record.result_row_count = executed.row_count
        record.execution_ms = executed.execution_ms
        outcome.executed_sql = sql
        outcome.result = executed
        outcome.decision = result.decision
        outcome.message = _DECISION_MESSAGES[result.decision]

    def _restricted_sql(
        self, restricted_sql: str, authorized: AuthorizedQuery, user: UserContext, db: str
    ) -> str:
        """A guard's RESTRICT output goes through validation AND authorization again.

        So even a faulty guard cannot widen what the user may see: role tables,
        hidden columns, row scope and the row limit are re-applied (re-scoping an
        already scoped query is idempotent). Any failure here fails closed.
        """
        validated: ValidatedQuery = validate_sql(
            restricted_sql, catalog_tables=CATALOG, university_db=db
        )
        return authorize(
            validated,
            user,
            university_db=db,
            max_rows=min(authorized.row_limit, self._settings.sql_max_rows),
        ).sql

    # ------------------------------------------------------------------ helpers
    def _conversation(
        self, user: UserContext, public_id: str | None, question: str, now: datetime
    ) -> Conversation:
        if public_id is None:
            return queries.create_conversation(self._session, user, question, now)
        conversation = queries.get_owned_conversation(self._session, public_id, user.user_id)
        if conversation is None:
            raise ConversationNotFound
        return conversation

    @staticmethod
    def _stage_reached(record: QueryHistory) -> str:
        """Where an unexpected error happened, from how far the record got."""
        if record.executed_sql is not None:
            return Stage.EXECUTION
        if record.cair_decision is not None or record.authorization_status is not None:
            # In the guard, or while applying its decision (nothing has run yet).
            return Stage.CAIR
        if record.validation_status is not None:
            return Stage.AUTHORIZATION
        if record.generated_sql is not None:
            return Stage.VALIDATION
        return Stage.GENERATION

    def _record(
        self,
        user: UserContext,
        record: QueryHistory,
        outcome: QueryOutcome,
        stage: str,
        turn: ConversationTurn,
        conversation: Conversation,
        client_ip: str | None,
    ) -> None:
        session = self._session
        decision = outcome.decision
        record.final_status = FINAL_STATUS[decision]
        if decision is Decision.FAILED:
            record.failure_stage = stage
            record.error_code = (outcome.reason_code or _INTERNAL_ERROR)[:50]
            record.result_row_count = None
            if stage != Stage.EXECUTION:
                record.executed_sql = None
        elif decision in (Decision.REJECTED, Decision.DENIED, Decision.BLOCK):
            record.error_code = outcome.reason_code
        queries.add_history(session, record)
        outcome.query_id = record.query_id

        if outcome.guard is not None:
            queries.add_assessment(
                session, record.query_id, outcome.guard.policy_version, list(outcome.guard.reasons)
            )
        event = {
            Decision.REJECTED: audit.AuditEvent.QUERY_REJECTED,
            Decision.DENIED: audit.AuditEvent.QUERY_DENIED,
            Decision.BLOCK: audit.AuditEvent.QUERY_BLOCKED,
        }.get(decision)
        if outcome.reason_code == ExecutionCode.ACCESS_DENIED:
            event = audit.AuditEvent.READER_ACCESS_DENIED
        if event is not None:
            audit.record(
                session,
                event,
                audit.Severity.CRITICAL
                if event is audit.AuditEvent.READER_ACCESS_DENIED
                else audit.Severity.WARNING,
                user_id=user.user_id,
                query_id=record.query_id,
                client_ip=client_ip,
                details={"reason_code": outcome.reason_code},
            )

        turn.answer_summary = (outcome.explanation or outcome.message)[:1000] or None
        conversation.last_activity_at = max(self._clock(), conversation.started_at)
        session.commit()
