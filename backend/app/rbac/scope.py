"""Data scope: which rows of organisational data a user may see.

Resolved on the server from the user's database links, never from the client:

  ADMIN    ORGANIZATION  everything
  HOD      DEPARTMENT    the department they head (departments.head_teacher_id),
                         plus their own teaching (teacher_id)
  TEACHER  TEACHER       offerings they teach / students they advise (teacher_id)
  STUDENT  STUDENT       their own records (student_id)

Later phases (row-scope rewriting, CAIR) consume Scope; they must take it from
the request's UserContext and never from conversation context or model output.
Resolution fails closed: a user whose links are inconsistent gets no scope.
"""

from dataclasses import dataclass
from enum import StrEnum

from app.rbac.permissions import Permission, permissions_for
from app.rbac.roles import Role


class ScopeKind(StrEnum):
    ORGANIZATION = "ORGANIZATION"
    DEPARTMENT = "DEPARTMENT"
    TEACHER = "TEACHER"
    STUDENT = "STUDENT"


@dataclass(frozen=True, slots=True)
class Scope:
    kind: ScopeKind
    department_id: int | None = None
    teacher_id: int | None = None
    student_id: int | None = None


@dataclass(frozen=True, slots=True)
class UserContext:
    """The authenticated caller, as established by the server for this request. Immutable."""

    user_id: int
    username: str
    role: Role
    scope: Scope

    @property
    def permissions(self) -> frozenset[Permission]:
        return permissions_for(self.role)

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions


def resolve_scope(
    role: Role,
    *,
    teacher_id: int | None,
    student_id: int | None,
    headed_department_id: int | None,
) -> Scope | None:
    """The scope for a user's role and links, or None if the links don't fit the role."""
    if role is Role.ADMIN:
        if teacher_id is None and student_id is None:
            return Scope(ScopeKind.ORGANIZATION)
    elif role is Role.HOD:
        if teacher_id is not None and student_id is None and headed_department_id is not None:
            return Scope(
                ScopeKind.DEPARTMENT, department_id=headed_department_id, teacher_id=teacher_id
            )
    elif role is Role.TEACHER:
        if teacher_id is not None and student_id is None:
            return Scope(ScopeKind.TEACHER, teacher_id=teacher_id)
    elif role is Role.STUDENT:
        if student_id is not None and teacher_id is None:
            return Scope(ScopeKind.STUDENT, student_id=student_id)
    return None
