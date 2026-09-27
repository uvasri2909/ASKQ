"""Read-only views of a user's OWN conversations and query history (askq_app).

Every function takes the authenticated user's id and filters on it; nothing
here can return another user's rows. Only user-facing fields are selected:
never SQL, risk scores, CAIR assessments or findings, error codes or result
rows (which are not stored at all).
"""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Conversation, ConversationTurn, QueryHistory


@dataclass(frozen=True, slots=True)
class ConversationSummary:
    public_id: str
    title: str | None
    started_at: datetime
    last_activity_at: datetime
    turns: int


@dataclass(frozen=True, slots=True)
class TurnView:
    turn_no: int
    question: str
    summary: str | None
    final_status: str | None
    asked_at: datetime


@dataclass(frozen=True, slots=True)
class HistoryItem:
    query_id: int
    conversation_id: str | None
    turn_no: int | None
    question: str
    summary: str | None
    final_status: str
    row_count: int | None
    asked_at: datetime


def list_conversations(
    session: Session, user_id: int, *, limit: int, offset: int
) -> list[ConversationSummary]:
    turn_counts = (
        select(ConversationTurn.conversation_id, func.count().label("turns"))
        .group_by(ConversationTurn.conversation_id)
        .subquery()
    )
    rows = session.execute(
        select(Conversation, func.coalesce(turn_counts.c.turns, 0))
        .outerjoin(turn_counts, turn_counts.c.conversation_id == Conversation.conversation_id)
        .where(Conversation.user_id == user_id, Conversation.status == "ACTIVE")
        .order_by(Conversation.last_activity_at.desc(), Conversation.conversation_id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return [
        ConversationSummary(c.public_id, c.title, c.started_at, c.last_activity_at, int(n))
        for c, n in rows
    ]


def conversation_turns(
    session: Session, user_id: int, public_id: str
) -> tuple[Conversation, list[TurnView]] | None:
    """The user's ACTIVE conversation and its turns, oldest first; None if not theirs."""
    conversation = session.scalars(
        select(Conversation).where(
            Conversation.public_id == public_id,
            Conversation.user_id == user_id,
            Conversation.status == "ACTIVE",
        )
    ).one_or_none()
    if conversation is None:
        return None
    rows = session.execute(
        select(ConversationTurn, QueryHistory.final_status)
        .outerjoin(QueryHistory, QueryHistory.turn_id == ConversationTurn.turn_id)
        .where(ConversationTurn.conversation_id == conversation.conversation_id)
        .order_by(ConversationTurn.turn_no)
    ).all()
    turns = [
        TurnView(t.turn_no, t.question, t.answer_summary, status, t.created_at)
        for t, status in rows
    ]
    return conversation, turns


def list_history(session: Session, user_id: int, *, limit: int, offset: int) -> list[HistoryItem]:
    rows = session.execute(
        select(QueryHistory, ConversationTurn, Conversation.public_id)
        .outerjoin(ConversationTurn, ConversationTurn.turn_id == QueryHistory.turn_id)
        .outerjoin(Conversation, Conversation.conversation_id == QueryHistory.conversation_id)
        .where(QueryHistory.user_id == user_id)
        .order_by(QueryHistory.query_id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    items = []
    for history, turn, public_id in rows:
        items.append(
            HistoryItem(
                query_id=history.query_id,
                conversation_id=public_id,
                turn_no=turn.turn_no if turn is not None else None,
                question=turn.question if turn is not None else (history.question_text or ""),
                summary=turn.answer_summary if turn is not None else None,
                final_status=history.final_status,
                row_count=history.result_row_count,
                asked_at=history.created_at,
            )
        )
    return items
