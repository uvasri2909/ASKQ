from datetime import UTC, timedelta

import pytest
from sqlalchemy import select

from app.auth.tokens import TokenService
from app.clock import utcnow
from app.db.models import AppUserCredential, SecurityAuditEvent, User
from app.rbac.permissions import Permission
from app.rbac.roles import Role
from tests.conftest import (
    ACCOUNTS,
    TEST_PASSWORD,
    USERNAMES,
    bearer,
    login,
    make_settings,
    token_for,
)

GENERIC_FAILURE = {"error": {"code": "unauthenticated", "message": "Invalid username or password."}}


# ---------- login ----------


@pytest.mark.parametrize(
    ("user_id", "role"),
    [
        (ACCOUNTS.admin, "ADMIN"),
        (ACCOUNTS.hod, "HOD"),
        (ACCOUNTS.teacher, "TEACHER"),
        (ACCOUNTS.student, "STUDENT"),
    ],
)
def test_login_succeeds_for_each_role(client, user_id, role):
    response = login(client, USERNAMES[user_id])
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"access_token", "token_type", "expires_in", "user"}
    assert body["token_type"] == "bearer" and body["expires_in"] == 3600
    assert body["user"] == {
        "id": user_id,
        "username": USERNAMES[user_id],
        "role": role,
        "permissions": body["user"]["permissions"],
    }


def test_login_response_contains_no_secrets(client, password_hash):
    text = login(client, "admin").text
    assert TEST_PASSWORD not in text and password_hash not in text
    for word in ("password", "hash", "teacher_id", "student_id", "salary", "email"):
        assert word not in text.lower()


def test_username_is_case_insensitive(client):
    assert login(client, "ADMIN").status_code == 200


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("admin", TEST_PASSWORD + "x"),  # wrong password
        ("nobody", TEST_PASSWORD),  # unknown user
        (USERNAMES[ACCOUNTS.inactive], TEST_PASSWORD),  # disabled account
        (USERNAMES[ACCOUNTS.no_credential], TEST_PASSWORD),  # no password provisioned
        (USERNAMES[ACCOUNTS.orphan_hod], TEST_PASSWORD),  # role links inconsistent
    ],
)
def test_every_login_failure_looks_identical(client, username, password):
    response = login(client, username, password)
    assert response.status_code == 401
    assert response.json() == GENERIC_FAILURE
    assert "access_token" not in response.text


def test_locked_account_rejected_generically(client, db_session):
    credential = db_session.get(AppUserCredential, ACCOUNTS.teacher)
    credential.locked_until = utcnow() + timedelta(minutes=10)
    db_session.commit()
    response = login(client, USERNAMES[ACCOUNTS.teacher])
    assert (response.status_code, response.json()) == (401, GENERIC_FAILURE)


def test_expired_lock_no_longer_blocks(client, db_session):
    credential = db_session.get(AppUserCredential, ACCOUNTS.teacher)
    credential.locked_until = utcnow() - timedelta(minutes=1)
    db_session.commit()
    assert login(client, USERNAMES[ACCOUNTS.teacher]).status_code == 200


def test_failed_and_successful_logins_are_recorded(client, db_session):
    login(client, "admin", "definitely-wrong-password")
    login(client, "admin", "definitely-wrong-password")
    db_session.expire_all()
    assert db_session.get(AppUserCredential, ACCOUNTS.admin).failed_login_attempts == 2

    login(client, "admin")
    db_session.expire_all()
    credential = db_session.get(AppUserCredential, ACCOUNTS.admin)
    assert credential.failed_login_attempts == 0
    assert credential.last_login_at is not None

    events = db_session.scalars(select(SecurityAuditEvent).order_by(SecurityAuditEvent.audit_id))
    rows = [(e.event_type, e.severity, e.user_id, e.details) for e in events]
    assert rows == [
        ("LOGIN_FAILED", "WARNING", ACCOUNTS.admin, {"reason": "wrong_password"}),
        ("LOGIN_FAILED", "WARNING", ACCOUNTS.admin, {"reason": "wrong_password"}),
        ("LOGIN_SUCCEEDED", "INFO", ACCOUNTS.admin, {"role": "ADMIN"}),
    ]


def test_unknown_user_audit_does_not_store_the_attempted_username(client, db_session):
    login(client, "typed-my-password-here", TEST_PASSWORD)
    event = db_session.scalars(select(SecurityAuditEvent)).one()
    assert (event.user_id, event.details) == (None, {"reason": "unknown_user"})
    assert "typed-my-password-here" not in str(event.details)


@pytest.mark.parametrize("extra", [{"role": "ADMIN"}, {"scope": "ORGANIZATION"}, {"user_id": 1}])
def test_login_rejects_client_supplied_role_or_scope(client, extra):
    body = {"username": USERNAMES[ACCOUNTS.student], "password": TEST_PASSWORD, **extra}
    response = client.post("/api/v1/auth/login", json=body)
    assert response.status_code == 422
    assert "access_token" not in response.text


def test_validation_error_never_echoes_the_password(client):
    response = client.post("/api/v1/auth/login", json={"username": "", "password": TEST_PASSWORD})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert TEST_PASSWORD not in response.text


def test_oversized_password_rejected_before_hashing(client):
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "p" * 2000})
    assert response.status_code == 422


def test_login_without_jwt_secret_is_503_not_a_weak_token(database):
    from fastapi.testclient import TestClient

    from app.main import create_app

    settings = make_settings(jwt_secret=None)
    with TestClient(create_app(settings, database)) as client:
        response = login(client, "admin")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "service_unavailable"


# ---------- /me ----------


def test_me_returns_safe_identity(client):
    token = token_for(client, ACCOUNTS.hod)
    response = client.get("/api/v1/auth/me", headers=bearer(token))
    assert response.status_code == 200
    assert response.json() == {
        "id": ACCOUNTS.hod,
        "username": USERNAMES[ACCOUNTS.hod],
        "role": "HOD",
        "permissions": sorted([Permission.ASK_QUESTIONS, Permission.VIEW_OWN_HISTORY]),
    }


def test_me_admin_has_all_permissions(client):
    token = token_for(client, ACCOUNTS.admin)
    permissions = client.get("/api/v1/auth/me", headers=bearer(token)).json()["permissions"]
    assert set(permissions) == set(Permission)


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": ""},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer not-a-jwt"},
        {"Authorization": "Basic YWRtaW46eA=="},
        {"Authorization": "Token abc"},
    ],
)
def test_me_rejects_missing_or_invalid_token(client, headers):
    response = client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json() == {
        "error": {"code": "unauthenticated", "message": "Not authenticated."}
    }


def test_me_rejects_expired_token(client, tokens):
    expired = tokens.issue(
        ACCOUNTS.admin, Role.ADMIN, now=(utcnow() - timedelta(hours=2)).replace(tzinfo=UTC)
    )
    assert client.get("/api/v1/auth/me", headers=bearer(expired.token)).status_code == 401


def test_me_rejects_token_signed_with_another_secret(client):
    forged = TokenService("f" * 48, "HS256", 60).issue(ACCOUNTS.admin, Role.ADMIN)
    assert client.get("/api/v1/auth/me", headers=bearer(forged.token)).status_code == 401


def test_me_rejects_user_deactivated_after_login(client, db_session):
    token = token_for(client, ACCOUNTS.teacher)
    db_session.get(User, ACCOUNTS.teacher).is_active = False
    db_session.commit()
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401


def test_me_rejects_token_issued_before_password_change(client, db_session):
    token = token_for(client, ACCOUNTS.teacher)
    credential = db_session.get(AppUserCredential, ACCOUNTS.teacher)
    credential.password_changed_at = utcnow() + timedelta(seconds=5)
    db_session.commit()
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401


def test_me_rejects_token_whose_role_no_longer_matches_database(client, tokens):
    # Correctly signed, but claims ADMIN for a student account: the database wins.
    token = tokens.issue(ACCOUNTS.student, Role.ADMIN).token
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401


def test_me_rejects_token_for_deleted_user(client, tokens):
    token = tokens.issue(999, Role.ADMIN).token
    assert client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401
