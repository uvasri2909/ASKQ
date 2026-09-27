"""Reusable RBAC guards for endpoints.

    can_audit = require_permission(Permission.VIEW_SECURITY_AUDIT)

    @router.get("/audit", dependencies=[Depends(can_audit)])
    def audit(user: Annotated[UserContext, Depends(require_admin)]): ...

require_roles(...) matches roles exactly: require_hod admits HODs only. An
endpoint open to several roles lists them, e.g. require_roles(Role.ADMIN, Role.HOD).
Every guard builds on get_current_user, so an unauthenticated request is 401
and an authenticated one without the role or permission is 403.
"""

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, status

from app.auth.dependencies import get_current_user
from app.rbac.permissions import Permission
from app.rbac.roles import Role
from app.rbac.scope import UserContext

FORBIDDEN = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="You do not have permission to perform this action.",
)

UserGuard = Callable[[UserContext], UserContext]


def require_roles(*roles: Role) -> UserGuard:
    if not roles:
        raise ValueError("require_roles needs at least one role")
    allowed = frozenset(Role(r) for r in roles)

    def guard(user: Annotated[UserContext, Depends(get_current_user)]) -> UserContext:
        if user.role not in allowed:
            raise FORBIDDEN
        return user

    guard.__name__ = "require_roles_" + "_".join(sorted(r.value.lower() for r in allowed))
    return guard


def require_permission(permission: Permission) -> UserGuard:
    permission = Permission(permission)

    def guard(user: Annotated[UserContext, Depends(get_current_user)]) -> UserContext:
        if not user.can(permission):
            raise FORBIDDEN
        return user

    guard.__name__ = f"require_permission_{permission.value.lower()}"
    return guard


require_admin = require_roles(Role.ADMIN)
require_hod = require_roles(Role.HOD)
require_teacher = require_roles(Role.TEACHER)
require_student = require_roles(Role.STUDENT)
