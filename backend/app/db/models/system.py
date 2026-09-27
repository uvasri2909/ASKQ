"""askq_system tables: credentials and audit log (Phase 3); conversations and query
history (Phase 4).

user_id is a logical reference to askq_university.users (no cross-database FK).
Timestamps are naive UTC datetimes (see app.clock).
"""

from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.engine import SYSTEM_SCHEMA
from app.db.models.base import Base, BigIntegerPK


class AppUserCredential(Base):
    __tablename__ = "app_user_credentials"
    __table_args__ = {"schema": SYSTEM_SCHEMA}

    user_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    # Argon2id PHC string; never the password itself.
    password_hash: Mapped[str] = mapped_column(String(255))
    password_changed_at: Mapped[datetime] = mapped_column(DateTime)
    failed_login_attempts: Mapped[int] = mapped_column(SmallInteger, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime)


class SecurityAuditEvent(Base):
    """Append-only (askq_app has INSERT/SELECT only)."""

    __tablename__ = "security_audit_log"
    __table_args__ = {"schema": SYSTEM_SCHEMA}

    audit_id: Mapped[int] = mapped_column(BigIntegerPK, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    user_id: Mapped[int | None] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(8))
    query_id: Mapped[int | None] = mapped_column(BigInteger)
    client_ip: Mapped[str | None] = mapped_column(String(45))
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON)


class Conversation(Base):
    __tablename__ = "conversations"
    __table_args__ = {"schema": SYSTEM_SCHEMA}

    conversation_id: Mapped[int] = mapped_column(BigIntegerPK, primary_key=True)
    # Opaque id shown to clients instead of the sequential key.
    public_id: Mapped[str] = mapped_column(String(36), unique=True)
    user_id: Mapped[int] = mapped_column(Integer)
    role_code: Mapped[str] = mapped_column(String(20))
    title: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(8), default="ACTIVE")
    started_at: Mapped[datetime] = mapped_column(DateTime)
    last_activity_at: Mapped[datetime] = mapped_column(DateTime)


class ConversationTurn(Base):
    __tablename__ = "conversation_turns"
    __table_args__ = {"schema": SYSTEM_SCHEMA}

    turn_id: Mapped[int] = mapped_column(BigIntegerPK, primary_key=True)
    conversation_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey(Conversation.conversation_id)
    )
    turn_no: Mapped[int] = mapped_column(Integer)
    question: Mapped[str] = mapped_column(Text)
    answer_summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class QueryHistory(Base):
    """One row per question that entered the pipeline; written once (askq_app: INSERT only)."""

    __tablename__ = "query_history"
    __table_args__ = {"schema": SYSTEM_SCHEMA}

    query_id: Mapped[int] = mapped_column(BigIntegerPK, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer)
    role_code: Mapped[str] = mapped_column(String(20))
    conversation_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey(Conversation.conversation_id)
    )
    turn_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey(ConversationTurn.turn_id))
    question_text: Mapped[str | None] = mapped_column(Text)
    resolved_question: Mapped[str | None] = mapped_column(Text)
    generated_sql: Mapped[str | None] = mapped_column(Text)
    validation_status: Mapped[str | None] = mapped_column(String(8))
    authorization_status: Mapped[str | None] = mapped_column(String(9))
    cair_decision: Mapped[str | None] = mapped_column(String(8))
    risk_score: Mapped[Decimal | None] = mapped_column(Numeric(5, 4))
    executed_sql: Mapped[str | None] = mapped_column(Text)
    final_status: Mapped[str] = mapped_column(String(10))
    failure_stage: Mapped[str | None] = mapped_column(String(13))
    error_code: Mapped[str | None] = mapped_column(String(50))
    result_row_count: Mapped[int | None] = mapped_column(Integer)
    execution_ms: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class CairAssessment(Base):
    """Why the guard decided what it did for one query (append-only)."""

    __tablename__ = "cair_assessments"
    __table_args__ = {"schema": SYSTEM_SCHEMA}

    assessment_id: Mapped[int] = mapped_column(BigIntegerPK, primary_key=True)
    query_id: Mapped[int] = mapped_column(BigInteger, ForeignKey(QueryHistory.query_id))
    policy_version: Mapped[str] = mapped_column(String(20))
    # Phase 4 pass-through: a list of reasons. CAIR: a structured object
    # (tier, public reasons, attack classes, probes; see app/cair/guard.py).
    reasons: Mapped[Any] = mapped_column(JSON)


class CairAuditFinding(Base):
    """One row per CAIR audit (attack class) behind an assessment (append-only)."""

    __tablename__ = "cair_audit_findings"
    __table_args__ = {"schema": SYSTEM_SCHEMA}

    finding_id: Mapped[int] = mapped_column(BigIntegerPK, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(BigInteger, ForeignKey(CairAssessment.assessment_id))
    audit_type: Mapped[str] = mapped_column(String(20))
    score: Mapped[Decimal] = mapped_column(Numeric(5, 4))
    triggered: Mapped[bool] = mapped_column(Boolean)
    explanation: Mapped[str] = mapped_column(String(1000))
    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON)


class CairLedgerEntry(Base):
    """What a user learned from one executed statistical query (append-only)."""

    __tablename__ = "cair_ledger_entries"
    __table_args__ = {"schema": SYSTEM_SCHEMA}

    entry_id: Mapped[int] = mapped_column(BigIntegerPK, primary_key=True)
    query_id: Mapped[int] = mapped_column(BigInteger, ForeignKey(QueryHistory.query_id))
    user_id: Mapped[int] = mapped_column(Integer)
    descriptor: Mapped[dict[str, Any]] = mapped_column(JSON)
    population_fingerprint: Mapped[str] = mapped_column(String(64))
    result_cardinality: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
