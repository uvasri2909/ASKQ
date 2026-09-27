"""The central role -> permission table.

Permissions answer "may this role use this feature?". Which ROWS a user may
see is a separate question, answered by the user's Scope (scope.py).
Endpoints guard with require_permission(...) instead of comparing role strings.
"""

from enum import StrEnum

from app.rbac.roles import Role


class Permission(StrEnum):
    # Ask natural-language questions (results always limited by the user's scope).
    ASK_QUESTIONS = "ASK_QUESTIONS"
    VIEW_OWN_HISTORY = "VIEW_OWN_HISTORY"
    # Administration.
    VIEW_ALL_HISTORY = "VIEW_ALL_HISTORY"
    VIEW_SECURITY_AUDIT = "VIEW_SECURITY_AUDIT"
    MANAGE_USERS = "MANAGE_USERS"
    RUN_EVALUATIONS = "RUN_EVALUATIONS"


_EVERYONE = frozenset({Permission.ASK_QUESTIONS, Permission.VIEW_OWN_HISTORY})

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: frozenset(Permission),
    Role.HOD: _EVERYONE,
    Role.TEACHER: _EVERYONE,
    Role.STUDENT: _EVERYONE,
}


def permissions_for(role: Role) -> frozenset[Permission]:
    return ROLE_PERMISSIONS[role]


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS[role]
