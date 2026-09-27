"""GET /api/v1/conversations, /api/v1/conversations/{id}, /api/v1/history (Phase 6).

Uses the Phase 4 fixtures: scripted SQL generator, SQLite stand-ins.
"""

import uuid

import pytest

from app.query.decision import Decision, GuardResult
from tests.conftest import ACCOUNTS, bearer, token_for
from tests.test_query_api import (  # noqa: F401  (pytest fixtures)
    ScriptedGuard,
    generator,
    guard_box,
    qclient,
    spies,
)

FORBIDDEN_KEYS = {"sql", "executed_sql", "generated_sql", "risk_score", "reason_code",
                  "error_code", "rows", "columns", "assessment", "findings", "user_id"}  # fmt: skip


def ask(client, token, question="How many students?", conversation=None):
    body = {"question": question}
    if conversation:
        body["conversation_id"] = conversation
    response = client.post("/api/v1/query", json=body, headers=bearer(token))
    assert response.status_code == 200, response.text
    return response.json()


def get(client, token, path):
    return client.get(path, headers=bearer(token))


def _keys(value) -> set[str]:
    if isinstance(value, dict):
        return set(value) | set().union(*(_keys(v) for v in value.values()))
    if isinstance(value, list):
        return set().union(*(_keys(v) for v in value)) if value else set()
    return set()


@pytest.mark.parametrize(
    "path", ["/api/v1/conversations", f"/api/v1/conversations/{uuid.uuid4()}", "/api/v1/history"]
)
def test_requires_authentication(qclient, path):
    assert qclient.get(path).status_code == 401


def test_empty_for_a_new_user(qclient):
    token = token_for(qclient, ACCOUNTS.teacher)
    assert get(qclient, token, "/api/v1/conversations").json()["items"] == []
    assert get(qclient, token, "/api/v1/history").json()["items"] == []


def test_conversations_list_and_detail(qclient):
    token = token_for(qclient, ACCOUNTS.hod)
    first = ask(qclient, token, "How many students?")
    ask(qclient, token, "And in year 2?", first["conversation_id"])
    second = ask(qclient, token, "A separate question")

    listing = get(qclient, token, "/api/v1/conversations").json()
    ids = [c["id"] for c in listing["items"]]
    assert set(ids) == {first["conversation_id"], second["conversation_id"]}
    assert ids[0] == second["conversation_id"]  # most recent activity first
    by_id = {c["id"]: c for c in listing["items"]}
    assert by_id[first["conversation_id"]]["turns"] == 2
    assert by_id[first["conversation_id"]]["title"] == "How many students?"

    detail = get(qclient, token, f"/api/v1/conversations/{first['conversation_id']}").json()
    assert [t["turn_no"] for t in detail["turns"]] == [1, 2]
    assert [t["question"] for t in detail["turns"]] == ["How many students?", "And in year 2?"]
    assert {t["decision"] for t in detail["turns"]} == {"ALLOW"}
    assert detail["turns"][0]["summary"] == "Test explanation."
    assert detail["turns"][0]["asked_at"].endswith(("Z", "+00:00"))


def test_history_lists_own_questions_newest_first(qclient, generator):
    token = token_for(qclient, ACCOUNTS.admin)
    ask(qclient, token, "first")
    generator.sql = "DELETE FROM students"
    ask(qclient, token, "second")
    items = get(qclient, token, "/api/v1/history").json()["items"]
    assert [i["question"] for i in items] == ["second", "first"]
    assert [i["decision"] for i in items] == ["REJECTED", "ALLOW"]
    assert items[1]["row_count"] == 1 and items[0]["row_count"] is None


@pytest.mark.parametrize(
    ("setup", "decision"),
    [
        ({"sql": "SELECT COUNT(*) AS n FROM students"}, "ALLOW"),
        ({"sql": "SELECT SUM(amount) FROM fees", "as": ACCOUNTS.teacher}, "DENIED"),
        ({"sql": "DROP TABLE students"}, "REJECTED"),
        ({"sql": "", "as": ACCOUNTS.admin}, "FAILED"),
        ({"guard": Decision.BLOCK}, "BLOCK"),
        ({"guard": Decision.RESTRICT}, "RESTRICT"),
    ],
)
def test_every_decision_is_reported(qclient, generator, guard_box, setup, decision):
    if "sql" in setup:
        generator.sql = setup["sql"]
    if setup.get("guard") is Decision.BLOCK:
        guard_box["guard"] = ScriptedGuard(GuardResult(Decision.BLOCK, 0.9, "t", ("r",)))
    if setup.get("guard") is Decision.RESTRICT:
        guard_box["guard"] = ScriptedGuard(
            GuardResult(Decision.RESTRICT, 0.5, "t", ("r",), "SELECT COUNT(*) AS n FROM courses")
        )
    token = token_for(qclient, setup.get("as", ACCOUNTS.admin))
    ask(qclient, token)
    (item,) = get(qclient, token, "/api/v1/history").json()["items"]
    assert item["decision"] == decision


def test_no_internal_or_sensitive_fields(qclient, generator, guard_box):
    token = token_for(qclient, ACCOUNTS.admin)
    guard_box["guard"] = ScriptedGuard(GuardResult(Decision.BLOCK, 0.93, "t", ("secret-reason",)))
    first = ask(qclient, token)
    for path in (
        "/api/v1/conversations",
        f"/api/v1/conversations/{first['conversation_id']}",
        "/api/v1/history",
    ):
        body = get(qclient, token, path).json()
        assert not (_keys(body) & FORBIDDEN_KEYS), path
        text = str(body)
        assert "SELECT" not in text and "secret-reason" not in text and "0.93" not in text


def test_other_users_data_is_invisible(qclient):
    hod = token_for(qclient, ACCOUNTS.hod)
    student = token_for(qclient, ACCOUNTS.student)
    mine = ask(qclient, hod, "HOD question")
    assert get(qclient, student, "/api/v1/conversations").json()["items"] == []
    assert get(qclient, student, "/api/v1/history").json()["items"] == []
    foreign = get(qclient, student, f"/api/v1/conversations/{mine['conversation_id']}")
    unknown = get(qclient, student, f"/api/v1/conversations/{uuid.uuid4()}")
    assert foreign.status_code == unknown.status_code == 404
    assert foreign.json() == unknown.json()  # indistinguishable


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/conversations/not-a-uuid",
        "/api/v1/history?limit=0",
        "/api/v1/history?limit=101",
        "/api/v1/history?offset=-1",
        "/api/v1/conversations?limit=1000",
    ],
)
def test_bad_parameters_are_validation_errors(qclient, path):
    token = token_for(qclient, ACCOUNTS.admin)
    response = get(qclient, token, path)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_pagination(qclient):
    token = token_for(qclient, ACCOUNTS.admin)
    for n in range(3):
        ask(qclient, token, f"q{n}")
    page = get(qclient, token, "/api/v1/history?limit=2&offset=1").json()
    assert [i["question"] for i in page["items"]] == ["q1", "q0"]
    assert page["page"] == {"limit": 2, "offset": 1}


def test_reads_do_not_write(qclient, spies):
    token = token_for(qclient, ACCOUNTS.admin)
    ask(qclient, token)
    spies["app"].statements.clear()
    spies["reader"].statements.clear()
    get(qclient, token, "/api/v1/history")
    get(qclient, token, "/api/v1/conversations")
    writes = [s for s in spies["app"].statements if s.lstrip().upper().startswith(
        ("INSERT", "UPDATE", "DELETE"))]  # fmt: skip
    assert writes == []
    assert spies["reader"].statements == []  # history never touches the reader
