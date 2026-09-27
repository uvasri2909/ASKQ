"""The caller's own conversations and query history (Phase 6, read-only).

    GET /api/v1/conversations                  the caller's conversations
    GET /api/v1/conversations/{conversation_id} one of them, with its turns
    GET /api/v1/history                         the caller's questions, newest first

Every endpoint requires VIEW_OWN_HISTORY and returns only rows whose user_id
is the authenticated user's: another user's conversation is a 404, exactly
like an unknown one. Responses carry user-facing fields only: the question,
a short summary, the decision and times. No SQL, risk scores, CAIR detail,
error codes or result rows. Reads go through the askq_app session.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.repositories import history as repo
from app.db.session import get_app_session
from app.errors import ErrorResponse
from app.query.decision import FINAL_STATUS, Decision
from app.rbac.dependencies import require_permission
from app.rbac.permissions import Permission
from app.rbac.scope import UserContext

router = APIRouter(tags=["history"])
can_view = require_permission(Permission.VIEW_OWN_HISTORY)

_DECISION = {status_: decision for decision, status_ in FINAL_STATUS.items()}
_ERRORS = {401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}}


def _decision(final_status: str | None) -> Decision | None:
    return _DECISION.get(final_status) if final_status else None


def _utc(value: datetime) -> datetime:
    """Stored timestamps are naive UTC; send them as aware UTC."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


class ConversationItem(BaseModel):
    id: str
    title: str | None
    started_at: datetime
    last_activity_at: datetime
    turns: int


class TurnItem(BaseModel):
    turn_no: int
    question: str
    summary: str | None
    decision: Decision | None
    asked_at: datetime


class ConversationDetail(BaseModel):
    id: str
    title: str | None
    started_at: datetime
    turns: list[TurnItem]


class HistoryEntry(BaseModel):
    query_id: int
    conversation_id: str | None
    turn_no: int | None
    question: str
    summary: str | None
    decision: Decision
    row_count: int | None
    asked_at: datetime


class Page(BaseModel):
    limit: int
    offset: int


class ConversationList(BaseModel):
    items: list[ConversationItem]
    page: Page


class HistoryList(BaseModel):
    items: list[HistoryEntry]
    page: Page


Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=100_000)]


@router.get("/conversations", response_model=ConversationList, responses=_ERRORS)
def conversations(
    user: Annotated[UserContext, Depends(can_view)],
    session: Annotated[Session, Depends(get_app_session)],
    limit: Limit = 20,
    offset: Offset = 0,
) -> ConversationList:
    rows = repo.list_conversations(session, user.user_id, limit=limit, offset=offset)
    return ConversationList(
        items=[
            ConversationItem(
                id=c.public_id,
                title=c.title,
                started_at=_utc(c.started_at),
                last_activity_at=_utc(c.last_activity_at),
                turns=c.turns,
            )
            for c in rows
        ],
        page=Page(limit=limit, offset=offset),
    )


@router.get(
    "/conversations/{conversation_id}",
    response_model=ConversationDetail,
    responses={**_ERRORS, 404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
def conversation(
    conversation_id: uuid.UUID,
    user: Annotated[UserContext, Depends(can_view)],
    session: Annotated[Session, Depends(get_app_session)],
) -> ConversationDetail:
    found = repo.conversation_turns(session, user.user_id, str(conversation_id))
    if found is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conversation not found.")
    record, turns = found
    return ConversationDetail(
        id=record.public_id,
        title=record.title,
        started_at=_utc(record.started_at),
        turns=[
            TurnItem(
                turn_no=t.turn_no,
                question=t.question,
                summary=t.summary,
                decision=_decision(t.final_status),
                asked_at=_utc(t.asked_at),
            )
            for t in turns
        ],
    )


@router.get("/history", response_model=HistoryList, responses=_ERRORS)
def history(
    user: Annotated[UserContext, Depends(can_view)],
    session: Annotated[Session, Depends(get_app_session)],
    limit: Limit = 50,
    offset: Offset = 0,
) -> HistoryList:
    rows = repo.list_history(session, user.user_id, limit=limit, offset=offset)
    return HistoryList(
        items=[
            HistoryEntry(
                query_id=h.query_id,
                conversation_id=h.conversation_id,
                turn_no=h.turn_no,
                question=h.question,
                summary=h.summary,
                decision=_decision(h.final_status) or Decision.FAILED,
                row_count=h.row_count,
                asked_at=_utc(h.asked_at),
            )
            for h in rows
        ],
        page=Page(limit=limit, offset=offset),
    )
