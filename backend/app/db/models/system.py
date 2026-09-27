"""askq_system tables used from Phase 3: credentials and the security audit log.

user_id is a logical reference to askq_university.users (no cross-database FK).
Timestamps are naive UTC datetimes (see app.clock).
"""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, SmallInteger, String, func
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
    client_ip: Mapped[str | None] = mapped_column(String(45))
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON)
