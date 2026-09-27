"""ORM models for the tables the backend itself reads or writes.

Only the columns the backend uses are mapped. The schema is owned by
database/schema/*.sql (Phase 2); these models never create or alter it, and
tests/integration checks them against the live MySQL tables.
"""

from app.db.models.base import Base
from app.db.models.system import (
    AppUserCredential,
    CairAssessment,
    CairAuditFinding,
    CairLedgerEntry,
    Conversation,
    ConversationTurn,
    QueryHistory,
    SecurityAuditEvent,
)
from app.db.models.university import Department, Role, User

__all__ = [
    "AppUserCredential",
    "Base",
    "CairAssessment",
    "CairAuditFinding",
    "CairLedgerEntry",
    "Conversation",
    "ConversationTurn",
    "Department",
    "QueryHistory",
    "Role",
    "SecurityAuditEvent",
    "User",
]
