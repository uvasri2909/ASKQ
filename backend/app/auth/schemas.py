from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app.auth.password import MAX_PASSWORD_LENGTH
from app.rbac.permissions import Permission
from app.rbac.roles import Role


class LoginRequest(BaseModel):
    # Unknown fields (e.g. "role") are rejected: the role comes only from the database.
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=50)
    password: SecretStr = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class UserInfo(BaseModel):
    """Safe identity information: no hashes, no personal data, no internal ids beyond user id."""

    id: int
    username: str
    role: Role
    permissions: list[Permission]


class LoginResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth2 token type, not a secret
    expires_in: int = Field(description="Token lifetime in seconds")
    user: UserInfo
