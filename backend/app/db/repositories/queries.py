"""Conversations, turns, query history and guard assessments (askq_app)."""

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import CairAssessment, Conversation, ConversationTurn, QueryHistory
from app.query.decision import PriorTurn
from app.rbac.scope import UserContext

_EXECUTED = ("EXECUTED", "RESTRICTED")


def get_owned_conversation(session: Session, public_id: str, user_id: int) -> Conversation | None:
    """An ACTIVE conversation of this user, or None (someone else's is treated as missing)."""
    return session.scalars(
        select(Conversation).where(
            Conversation.public_id == public_id,
            Conversation.user_id == user_id,
            Conversation.status == "ACTIVE",
        )
    ).one_or_none()


def create_conversation(
    session: Session, user: UserContext, title: str, now: datetime
) -> Conversation:
    conversation = Conversation(
        public_id=str(uuid.uuid4()),
        user_id=user.user_id,
        role_code=user.role.value,
        title=title[:200],
        status="ACTIVE",
        started_at=now,
        last_activity_at=now,
    )
    session.add(conversation)
    session.flush()
    return conversation


def add_turn(session: Session, conversation: Conversation, question: str) -> ConversationTurn:
    last = session.scalar(
        select(func.max(ConversationTurn.turn_no)).where(
            ConversationTurn.conversation_id == conversation.conversation_id
        )
    )
    turn = ConversationTurn(
        conversation_id=conversation.conversation_id, turn_no=(last or 0) + 1, question=question
    )
    session.add(turn)
    session.flush()
    return turn


def recent_turns(session: Session, conversation_id: int, limit: int) -> tuple[PriorTurn, ...]:
    """The last `limit` turns, oldest first, with what the server recorded for each.

    SQL is included only for turns whose query actually ran, so a refused query
    is never offered back to the model as an example.
    """
    if limit <= 0:
        return ()
    rows = session.execute(
        select(ConversationTurn, QueryHistory)
        .outerjoin(QueryHistory, QueryHistory.turn_id == ConversationTurn.turn_id)
        .where(ConversationTurn.conversation_id == conversation_id)
        .order_by(ConversationTurn.turn_no.desc(), QueryHistory.query_id.desc())
        .limit(limit)
    ).all()
    turns = []
    for turn, history in reversed(rows):
        executed = history is not None and history.final_status in _EXECUTED
        turns.append(
            PriorTurn(
                question=turn.question,
                resolved_question=history.resolved_question if history else None,
                generated_sql=history.generated_sql if executed else None,
                final_status=history.final_status if history else None,
            )
        )
    return tuple(turns)


def add_history(session: Session, record: QueryHistory) -> QueryHistory:
    session.add(record)
    session.flush()
    return record


def add_assessment(
    session: Session, query_id: int, policy_version: str, reasons: list[str]
) -> None:
    session.add(
        CairAssessment(query_id=query_id, policy_version=policy_version[:20], reasons=reasons)
    )
