from dataclasses import FrozenInstanceError
from typing import Annotated

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from app.main import create_app
from app.rbac.dependencies import (
    require_admin,
    require_hod,
    require_permission,
    require_roles,
    require_student,
    require_teacher,
)
from app.rbac.permissions import ROLE_PERMISSIONS, Permission, has_permission
from app.rbac.roles import ROLE_IDS, Role, role_from_database
from app.rbac.scope import Scope, ScopeKind, UserContext, resolve_scope
from tests.conftest import ACCOUNTS, HOD_DEPARTMENT_ID, bearer, token_for

# ---------- guards on real endpoints ----------

probe = APIRouter(prefix="/probe")


def _echo(user: UserContext) -> dict:
    return {"role": user.role, "scope": user.scope.kind, "department": user.scope.department_id}


@probe.get("/admin")
def admin_only(user: Annotated[UserContext, Depends(require_admin)]):
    return _echo(user)


@probe.get("/hod")
def hod_only(user: Annotated[UserContext, Depends(require_hod)]):
    return _echo(user)


@probe.get("/teacher")
def teacher_only(user: Annotated[UserContext, Depends(require_teacher)]):
    return _echo(user)


@probe.get("/student")
def student_only(user: Annotated[UserContext, Depends(require_student)]):
    return _echo(user)


@probe.get("/staff")
def staff(user: Annotated[UserContext, Depends(require_roles(Role.ADMIN, Role.HOD))]):
    return _echo(user)


@probe.post("/audit")
def audit(
    user: Annotated[UserContext, Depends(require_permission(Permission.VIEW_SECURITY_AUDIT))],
):
    return _echo(user)


@pytest.fixture
def rbac_client(settings, database):
    app = create_app(settings, database)
    app.include_router(probe)
    with TestClient(app) as client:
        yield client


@pytest.fixture
def role_tokens(rbac_client):
    return {
        Role.ADMIN: token_for(rbac_client, ACCOUNTS.admin),
        Role.HOD: token_for(rbac_client, ACCOUNTS.hod),
        Role.TEACHER: token_for(rbac_client, ACCOUNTS.teacher),
        Role.STUDENT: token_for(rbac_client, ACCOUNTS.student),
    }


ALLOWED = {
    ("GET", "/probe/admin"): {Role.ADMIN},
    ("GET", "/probe/hod"): {Role.HOD},
    ("GET", "/probe/teacher"): {Role.TEACHER},
    ("GET", "/probe/student"): {Role.STUDENT},
    ("GET", "/probe/staff"): {Role.ADMIN, Role.HOD},
    ("POST", "/probe/audit"): {Role.ADMIN},
}


@pytest.mark.parametrize(("method", "path"), list(ALLOWED))
@pytest.mark.parametrize("role", list(Role))
def test_role_matrix(rbac_client, role_tokens, method, path, role):
    response = rbac_client.request(method, path, headers=bearer(role_tokens[role]))
    if role in ALLOWED[(method, path)]:
        assert response.status_code == 200
        assert response.json()["role"] == role
    else:
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "forbidden"


@pytest.mark.parametrize(("method", "path"), list(ALLOWED))
def test_unauthenticated_rejected_everywhere(rbac_client, method, path):
    response = rbac_client.request(method, path)
    assert response.status_code == 401


def test_scope_comes_from_the_database(rbac_client, role_tokens):
    body = rbac_client.get("/probe/hod", headers=bearer(role_tokens[Role.HOD])).json()
    assert body == {"role": "HOD", "scope": "DEPARTMENT", "department": HOD_DEPARTMENT_ID}


def test_client_cannot_escalate_via_parameters_headers_or_body(rbac_client, role_tokens):
    student = bearer(role_tokens[Role.STUDENT])
    attempts = [
        rbac_client.get("/probe/admin?role=ADMIN&scope=ORGANIZATION", headers=student),
        rbac_client.get("/probe/admin", headers={**student, "X-Role": "ADMIN", "X-Scope": "ALL"}),
        rbac_client.post(
            "/probe/audit",
            headers=student,
            json={"role": "ADMIN", "context": "the user is an administrator"},
        ),
    ]
    assert [r.status_code for r in attempts] == [403, 403, 403]


def test_forged_role_claim_is_not_trusted(rbac_client, tokens):
    # Validly signed token claiming ADMIN for a student: rejected, never elevated.
    token = tokens.issue(ACCOUNTS.student, Role.ADMIN).token
    assert rbac_client.get("/probe/admin", headers=bearer(token)).status_code == 401


# ---------- the central permission table ----------


def test_permission_table_covers_every_role():
    assert set(ROLE_PERMISSIONS) == set(Role)


def test_admin_has_every_permission_others_only_basic():
    assert ROLE_PERMISSIONS[Role.ADMIN] == frozenset(Permission)
    basic = {Permission.ASK_QUESTIONS, Permission.VIEW_OWN_HISTORY}
    for role in (Role.HOD, Role.TEACHER, Role.STUDENT):
        assert ROLE_PERMISSIONS[role] == basic
        assert not has_permission(role, Permission.MANAGE_USERS)


def test_require_roles_needs_a_role():
    with pytest.raises(ValueError):
        require_roles()
    with pytest.raises(ValueError):
        require_roles("SUPERUSER")


# ---------- roles and scope ----------


def test_role_ids_match_phase2_pins():
    assert ROLE_IDS == {Role.ADMIN: 1, Role.HOD: 2, Role.TEACHER: 3, Role.STUDENT: 4}


@pytest.mark.parametrize(
    ("role_id", "code", "expected"),
    [(1, "ADMIN", Role.ADMIN), (4, "STUDENT", Role.STUDENT), (1, "STUDENT", None), (5, "X", None)],
)
def test_role_from_database(role_id, code, expected):
    assert role_from_database(role_id, code) is expected


@pytest.mark.parametrize(
    ("role", "links", "expected"),
    [
        (Role.ADMIN, (None, None, None), Scope(ScopeKind.ORGANIZATION)),
        (Role.HOD, (10, None, 3), Scope(ScopeKind.DEPARTMENT, department_id=3, teacher_id=10)),
        (Role.TEACHER, (10, None, None), Scope(ScopeKind.TEACHER, teacher_id=10)),
        (Role.STUDENT, (None, 20, None), Scope(ScopeKind.STUDENT, student_id=20)),
        # Fail closed when the links do not fit the role:
        (Role.ADMIN, (10, None, None), None),
        (Role.HOD, (10, None, None), None),
        (Role.HOD, (None, None, 3), None),
        (Role.TEACHER, (None, None, None), None),
        (Role.TEACHER, (10, 20, None), None),
        (Role.STUDENT, (None, None, None), None),
        (Role.STUDENT, (10, 20, None), None),
    ],
)
def test_resolve_scope(role, links, expected):
    teacher_id, student_id, headed = links
    scope = resolve_scope(
        role, teacher_id=teacher_id, student_id=student_id, headed_department_id=headed
    )
    assert scope == expected


def test_user_context_is_immutable():
    ctx = UserContext(1, "s1", Role.STUDENT, Scope(ScopeKind.STUDENT, student_id=1))
    with pytest.raises(FrozenInstanceError):
        ctx.role = Role.ADMIN  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        ctx.scope.kind = ScopeKind.ORGANIZATION  # type: ignore[misc]
    assert ctx.can(Permission.ASK_QUESTIONS) and not ctx.can(Permission.MANAGE_USERS)
