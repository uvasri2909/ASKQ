"""POST /api/v1/query: ask a question in natural language.

Every pipeline outcome (ALLOW, RESTRICT, BLOCK, DENIED, REJECTED, FAILED) is a
200 response carrying the decision, because the request itself was valid and
authorized; the decision is about the generated query. HTTP errors are
reserved for the request: 401/403 (caller), 404 (conversation), 422 (body),
503 (question answering or database not available).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.cair.guard import CairGuard
from app.db.session import get_app_session
from app.errors import ErrorResponse
from app.llm.claude import ClaudeSqlGenerator
from app.llm.sql_generator import SqlGenerator
from app.query.decision import InferenceGuard, PassThroughGuard
from app.query.executor import ReaderExecutor
from app.query.schemas import QueryRequest, QueryResponse, SecuritySummary
from app.query.service import ConversationNotFound, QueryOutcome, QueryService
from app.rbac.dependencies import require_permission
from app.rbac.permissions import Permission
from app.rbac.scope import UserContext

router = APIRouter(tags=["query"])

can_ask = require_permission(Permission.ASK_QUESTIONS)


def get_sql_generator(request: Request) -> SqlGenerator:
    """One generator per app. Raises ConfigurationError (-> 503) without ANTHROPIC_API_KEY."""
    state = request.app.state
    generator = getattr(state, "sql_generator", None)
    if generator is None:
        generator = ClaudeSqlGenerator.from_settings(state.settings)
        state.sql_generator = generator
    return generator


def get_inference_guard(
    request: Request, session: Annotated[Session, Depends(get_app_session)]
) -> InferenceGuard:
    """CAIR when enabled; otherwise a pass-through (and no statistical tier)."""
    settings = request.app.state.settings
    if settings.cair_enabled:
        return CairGuard(session, request.app.state.database, settings)
    return PassThroughGuard()


def get_query_service(
    request: Request,
    session: Annotated[Session, Depends(get_app_session)],
    generator: Annotated[SqlGenerator, Depends(get_sql_generator)],
    guard: Annotated[InferenceGuard, Depends(get_inference_guard)],
) -> QueryService:
    settings = request.app.state.settings
    executor = ReaderExecutor(
        request.app.state.database,
        timeout_ms=settings.sql_timeout_ms,
        max_rows=settings.sql_max_rows,
    )
    # The aggregate-only statistical tier exists only behind a guard that gates it.
    statistics = settings.cair_enabled and getattr(guard, "gates_statistics", False)
    return QueryService(
        session, generator, guard, executor, settings, statistics_enabled=statistics
    )


def _response(outcome: QueryOutcome, user: UserContext) -> QueryResponse:
    result = outcome.result
    guard = outcome.guard
    return QueryResponse(
        query_id=outcome.query_id,
        conversation_id=outcome.conversation_id,
        decision=outcome.decision,
        message=outcome.message,
        reason_code=outcome.reason_code,
        question=outcome.question,
        resolved_question=outcome.resolved_question,
        explanation=outcome.explanation,
        sql=outcome.executed_sql,
        columns=result.columns if result else [],
        rows=result.rows if result else [],
        row_count=result.row_count if result else 0,
        row_limit=outcome.row_limit,
        execution_ms=result.execution_ms if result else None,
        chart=outcome.chart if result else None,
        security=SecuritySummary(
            validation=outcome.validation_status,
            authorization=outcome.authorization_status,
            guard_decision=guard.decision.value if guard else None,
            # CAIR does not disclose its score: thresholds must not be probeable.
            risk_score=guard.risk_score if guard and guard.disclose else None,
            guard_reasons=list(guard.reasons) if guard else [],
            scope=user.scope.kind,
            notes=outcome.notes,
        ),
    )


@router.post(
    "/query",
    response_model=QueryResponse,
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
)
def ask(
    body: QueryRequest,
    request: Request,
    user: Annotated[UserContext, Depends(can_ask)],
    service: Annotated[QueryService, Depends(get_query_service)],
) -> QueryResponse:
    client_ip = request.client.host if request.client else None
    conversation = str(body.conversation_id) if body.conversation_id else None
    try:
        outcome = service.ask(user, body.question, conversation, client_ip)
    except ConversationNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conversation not found.") from None
    return _response(outcome, user)
