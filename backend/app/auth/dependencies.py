"""FastAPI dependencies for authentication.

get_current_user is the only way an endpoint learns who is calling. It trusts
nothing from the request except the bearer token's signature, and rebuilds the
user's role and scope from the database on every request.
"""

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.auth.service import AuthenticationError, AuthService
from app.auth.tokens import TokenService
from app.db.session import get_app_session
from app.rbac.scope import UserContext

_bearer = HTTPBearer(auto_error=False, description="Access token from POST /api/v1/auth/login")

UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated.",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_token_service(request: Request) -> TokenService:
    """Raises ConfigurationError (-> 503) if JWT_SECRET is not configured."""
    return TokenService.from_settings(request.app.state.settings)


def get_auth_service(
    session: Annotated[Session, Depends(get_app_session)],
    tokens: Annotated[TokenService, Depends(get_token_service)],
) -> AuthService:
    return AuthService(session, tokens)


def get_bearer_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> str:
    # Resolved before the auth service, so a request without a token gets 401
    # without opening a database session.
    if credentials is None or not credentials.credentials:
        raise UNAUTHENTICATED
    return credentials.credentials


def get_current_user(
    token: Annotated[str, Depends(get_bearer_token)],
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> UserContext:
    try:
        return service.authenticate_token(token)
    except AuthenticationError:
        raise UNAUTHENTICATED from None


# Alias with the name used by endpoint code that only needs "any logged-in user".
require_authenticated_user = get_current_user

CurrentUser = Annotated[UserContext, Depends(get_current_user)]
