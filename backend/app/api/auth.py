"""POST /api/v1/auth/login and GET /api/v1/auth/me."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.auth.dependencies import CurrentUser, get_auth_service
from app.auth.schemas import LoginRequest, LoginResponse, UserInfo
from app.auth.service import AuthenticationError, AuthService
from app.errors import ErrorResponse
from app.rbac.scope import UserContext

router = APIRouter(prefix="/auth", tags=["auth"])

# One message for every login failure (unknown user, wrong password, disabled,
# locked, no credential), so the response does not reveal which it was.
LOGIN_FAILED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password."
)


def _user_info(user: UserContext) -> UserInfo:
    return UserInfo(
        id=user.user_id,
        username=user.username,
        role=user.role,
        permissions=sorted(user.permissions),
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    responses={401: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
def login(
    body: LoginRequest,
    request: Request,
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> LoginResponse:
    client_ip = request.client.host if request.client else None
    try:
        result = service.login(body.username, body.password.get_secret_value(), client_ip)
    except AuthenticationError:
        raise LOGIN_FAILED from None
    return LoginResponse(
        access_token=result.token.token,
        expires_in=result.token.expires_in,
        user=_user_info(result.user),
    )


@router.get("/me", response_model=UserInfo, responses={401: {"model": ErrorResponse}})
def me(user: CurrentUser) -> UserInfo:
    return _user_info(user)
