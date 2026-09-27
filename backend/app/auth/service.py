"""Login and token authentication.

Every failure raises the same AuthenticationError, so the client cannot tell
an unknown user from a wrong password, a disabled or locked account, or a
missing credential. The real reason goes only to security_audit_log (login)
or the server log (tokens). Exactly one Argon2 verification runs per login
attempt, whichever way it ends, so timing does not reveal it either.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.auth import password as passwords
from app.auth.tokens import IssuedToken, TokenError, TokenService
from app.clock import utcnow
from app.db.models import User
from app.db.repositories import audit, credentials, users
from app.rbac.roles import role_from_database
from app.rbac.scope import UserContext, resolve_scope

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Generic authentication failure. Never tells the client why."""


@dataclass(frozen=True, slots=True)
class LoginResult:
    token: IssuedToken
    user: UserContext


def build_user_context(session: Session, user: User) -> UserContext | None:
    """Role and scope from the database. None (fail closed) if the account is inconsistent."""
    role = role_from_database(user.role_id, user.role.role_code)
    if role is None:
        return None
    headed = (
        users.department_headed_by(session, user.teacher_id)
        if user.teacher_id is not None
        else None
    )
    scope = resolve_scope(
        role,
        teacher_id=user.teacher_id,
        student_id=user.student_id,
        headed_department_id=headed,
    )
    if scope is None:
        return None
    return UserContext(user_id=user.user_id, username=user.username, role=role, scope=scope)


class AuthService:
    def __init__(
        self,
        session: Session,
        tokens: TokenService,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._session = session
        self._tokens = tokens
        self._clock = clock

    def login(self, username: str, password: str, client_ip: str | None = None) -> LoginResult:
        session = self._session
        now = self._clock()
        # Usernames are lowercase in the schema (ck_users_username).
        user = users.get_by_username(session, username.lower())
        credential = credentials.get(session, user.user_id) if user is not None else None

        if user is not None and credential is not None:
            matches, rehashed = passwords.verify_and_update(password, credential.password_hash)
        else:
            passwords.burn_verification_time(password)
            matches, rehashed = False, None

        reason: str | None = None
        context: UserContext | None = None
        if user is None:
            reason = "unknown_user"
        elif credential is None:
            reason = "no_credentials"
        elif not matches:
            reason = "wrong_password"
        elif not user.is_active:
            reason = "inactive"
        elif credential.locked_until is not None and credential.locked_until > now:
            reason = "locked"
        else:
            context = build_user_context(session, user)
            if context is None:
                reason = "inconsistent_account"

        if reason is not None or context is None or credential is None:
            if credential is not None and reason == "wrong_password":
                credentials.record_failed_login(credential)
            # The attempted username is not logged: users sometimes type a password into it.
            audit.record(
                session,
                audit.AuditEvent.LOGIN_FAILED,
                audit.Severity.WARNING,
                user_id=user.user_id if user is not None else None,
                client_ip=client_ip,
                details={"reason": reason},
            )
            session.commit()
            raise AuthenticationError

        credentials.record_successful_login(credential, now, rehashed)
        audit.record(
            session,
            audit.AuditEvent.LOGIN_SUCCEEDED,
            audit.Severity.INFO,
            user_id=context.user_id,
            client_ip=client_ip,
            details={"role": context.role.value},
        )
        session.commit()
        return LoginResult(self._tokens.issue(context.user_id, context.role), context)

    def authenticate_token(self, token: str) -> UserContext:
        """The UserContext for a bearer token, re-validated against the database. Read-only."""
        try:
            claims = self._tokens.decode(token)
        except TokenError as exc:
            logger.info("rejected access token: %s", exc)
            raise AuthenticationError from None

        session = self._session
        user = users.get_by_id(session, claims.user_id)
        credential = credentials.get(session, claims.user_id) if user is not None else None
        now = self._clock()
        if user is None or credential is None or not user.is_active:
            raise AuthenticationError
        if credential.locked_until is not None and credential.locked_until > now:
            raise AuthenticationError
        # Tokens issued before the last password change are revoked. iat has whole-second
        # precision, so the change time is truncated to the second before comparing.
        changed_at = credential.password_changed_at.replace(tzinfo=UTC, microsecond=0)
        if claims.issued_at < changed_at:
            raise AuthenticationError

        context = build_user_context(session, user)
        # The database role is authoritative; a token for another role is stale or forged.
        if context is None or context.role is not claims.role:
            raise AuthenticationError
        return context
