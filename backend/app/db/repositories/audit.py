"""security_audit_log writer. Details must never contain passwords, hashes or tokens."""

from enum import StrEnum
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import SecurityAuditEvent


class AuditEvent(StrEnum):
    LOGIN_SUCCEEDED = "LOGIN_SUCCEEDED"
    LOGIN_FAILED = "LOGIN_FAILED"
    PASSWORD_SET = "PASSWORD_SET"  # noqa: S105 - event name, not a secret


class Severity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


def record(
    session: Session,
    event: AuditEvent,
    severity: Severity,
    *,
    user_id: int | None = None,
    client_ip: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    session.add(
        SecurityAuditEvent(
            event_type=event.value,
            severity=severity.value,
            user_id=user_id,
            client_ip=client_ip[:45] if client_ip else None,
            details=details,
        )
    )
