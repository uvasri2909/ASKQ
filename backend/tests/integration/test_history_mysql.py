"""Phase 6 history endpoints against the local ASKQ MySQL (run with: pytest --mysql).

Everything happens inside the rolled-back environment of test_query_mysql.py,
so askq_system is left exactly as it was.
"""

import uuid

import pytest

from app.rbac.roles import Role
from tests.integration.test_query_mysql import (  # noqa: F401  (pytest fixtures)
    PASSWORD,
    Env,
    database,
    env,
    password_hash,
    settings,
)

pytestmark = pytest.mark.mysql


def _token(env: Env, role: Role) -> str:
    response = env.client.post(
        "/api/v1/auth/login",
        json={"username": env.users[role].username, "password": PASSWORD},
    )
    return response.json()["access_token"]


def _get(env: Env, token: str, path: str):
    return env.client.get(path, headers={"Authorization": f"Bearer {token}"})


def test_history_and_conversations_on_mysql(env):
    env.ask(Role.HOD, "SELECT COUNT(*) AS n FROM students", question="How many students?")
    env.ask(Role.HOD, "DELETE FROM students", question="Delete everything")
    token = _token(env, Role.HOD)

    history = _get(env, token, "/api/v1/history").json()["items"]
    assert [(h["question"], h["decision"]) for h in history] == [
        ("Delete everything", "REJECTED"),
        ("How many students?", "ALLOW"),
    ]
    conversations = _get(env, token, "/api/v1/conversations").json()["items"]
    assert len(conversations) == 2 and all(c["turns"] == 1 for c in conversations)
    detail = _get(env, token, f"/api/v1/conversations/{conversations[0]['id']}").json()
    assert detail["turns"][0]["question"] == "Delete everything"
    assert "SELECT" not in str(detail) and "DELETE FROM" not in str(detail)  # no SQL, ever

    # Another user sees none of it, and cannot open the conversation.
    other = _token(env, Role.STUDENT)
    assert _get(env, other, "/api/v1/history").json()["items"] == []
    assert _get(env, other, f"/api/v1/conversations/{conversations[0]['id']}").status_code == 404
    assert _get(env, other, f"/api/v1/conversations/{uuid.uuid4()}").status_code == 404


def test_history_reads_never_use_the_reader(env):
    env.ask(Role.ADMIN, "SELECT COUNT(*) AS n FROM courses")
    token = _token(env, Role.ADMIN)
    env.reader_statements.clear()
    assert _get(env, token, "/api/v1/history").status_code == 200
    assert _get(env, token, "/api/v1/conversations").status_code == 200
    assert env.reader_statements == []
