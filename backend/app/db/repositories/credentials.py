from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models import AppUserCredential

# failed_login_attempts is SMALLINT UNSIGNED.
_MAX_FAILED_ATTEMPTS = 65535


def get(session: Session, user_id: int) -> AppUserCredential | None:
    return session.get(AppUserCredential, user_id)


def set_password_hash(
    session: Session, user_id: int, password_hash: str, now: datetime
) -> AppUserCredential:
    """Create or replace a user's credential. Clears failed attempts and any lock."""
    credential = get(session, user_id)
    if credential is None:
        credential = AppUserCredential(user_id=user_id)
        session.add(credential)
    credential.password_hash = password_hash
    credential.password_changed_at = now
    credential.failed_login_attempts = 0
    credential.locked_until = None
    return credential


def record_successful_login(
    credential: AppUserCredential, now: datetime, rehashed: str | None = None
) -> None:
    credential.failed_login_attempts = 0
    credential.last_login_at = now
    if rehashed is not None:
        # Same password, stronger parameters: not a password change.
        credential.password_hash = rehashed


def record_failed_login(credential: AppUserCredential) -> None:
    credential.failed_login_attempts = min(
        credential.failed_login_attempts + 1, _MAX_FAILED_ATTEMPTS
    )
