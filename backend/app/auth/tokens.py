"""JWT access tokens (PyJWT, HMAC).

Claims are the minimum needed: sub (user id), role, iat, exp, jti, iss.
No names, emails, scope ids or other personal data. The role claim is only a
hint: every request re-reads the user's role from the database, and a token
whose role no longer matches is rejected (see AuthService.authenticate_token).
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt

from app.config import Settings
from app.rbac.roles import Role

ISSUER = "askq-backend"
REQUIRED_CLAIMS = ("sub", "role", "iat", "exp", "jti", "iss")


class TokenError(Exception):
    """The token is not acceptable. The message is for server logs only."""


@dataclass(frozen=True, slots=True)
class TokenClaims:
    user_id: int
    role: Role
    issued_at: datetime  # aware, UTC
    expires_at: datetime  # aware, UTC
    token_id: str


@dataclass(frozen=True, slots=True)
class IssuedToken:
    token: str
    expires_in: int  # seconds
    claims: TokenClaims


class TokenService:
    def __init__(self, secret: str, algorithm: str, expire_minutes: int) -> None:
        self._secret = secret
        self._algorithm = algorithm
        self._lifetime = timedelta(minutes=expire_minutes)

    @classmethod
    def from_settings(cls, settings: Settings) -> "TokenService":
        """Raises ConfigurationError if JWT_SECRET is not configured (there is no fallback)."""
        return cls(
            settings.secret("jwt_secret"), settings.jwt_algorithm, settings.jwt_expire_minutes
        )

    def issue(self, user_id: int, role: Role, now: datetime | None = None) -> IssuedToken:
        issued_at = (now or datetime.now(UTC)).replace(microsecond=0)
        claims = TokenClaims(
            user_id=user_id,
            role=role,
            issued_at=issued_at,
            expires_at=issued_at + self._lifetime,
            token_id=uuid.uuid4().hex,
        )
        payload = {
            "sub": str(user_id),
            "role": role.value,
            "iat": int(claims.issued_at.timestamp()),
            "exp": int(claims.expires_at.timestamp()),
            "jti": claims.token_id,
            "iss": ISSUER,
        }
        token = jwt.encode(payload, self._secret, algorithm=self._algorithm)
        return IssuedToken(token, int(self._lifetime.total_seconds()), claims)

    def decode(self, token: str) -> TokenClaims:
        """Verify signature, algorithm, issuer, expiry and required claims."""
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                issuer=ISSUER,
                options={"require": list(REQUIRED_CLAIMS)},
            )
        except jwt.PyJWTError as exc:
            raise TokenError(type(exc).__name__) from None

        sub, role, jti = payload["sub"], payload["role"], payload["jti"]
        if not (isinstance(sub, str) and sub.isascii() and sub.isdigit()):
            raise TokenError("sub is not a user id")
        if not isinstance(jti, str) or not jti:
            raise TokenError("jti is empty")
        try:
            parsed_role = Role(role)
        except ValueError:
            raise TokenError("unknown role") from None
        return TokenClaims(
            user_id=int(sub),
            role=parsed_role,
            issued_at=datetime.fromtimestamp(payload["iat"], UTC),
            expires_at=datetime.fromtimestamp(payload["exp"], UTC),
            token_id=jti,
        )
