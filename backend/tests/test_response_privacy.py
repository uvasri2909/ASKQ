"""Phase 6 regression: what POST /api/v1/query may reveal to the browser.

Anything in the JSON body is visible in the network inspector, whatever the UI
shows. So for every decision the response must carry no SQL (generated,
executed, restricted or probe), no risk score, no reason code, no detector
name and nothing about withheld groups. Those stay in askq_system for audit.

Uses the real CAIR guard over the isolated SQLite population of
tests/test_cair_api.py (k = 5; ECE has one student with gender X).
"""

import json

import pytest

from app.api.query import PUBLIC_GUARD_REASONS
from app.cair import guard as guard_module
from app.cair.model import AttackClass
from app.llm.sql_generator import GenerationCode, SqlGenerationError
from app.main import create_app
from app.query.decision import Decision, GuardResult
from tests.conftest import ACCOUNTS
from tests.test_cair_api import (  # noqa: F401  (pytest fixtures)
    MARKS_BY_DEPT,
    MARKS_ECE,
    MARKS_ECE_NOT_X,
    ask,
    cair_db,
    cair_settings,
    cclient,
    gen,
    reader_spy,
    stored,
)
from tests.test_query_api import ScriptedGuard

HOD = ACCOUNTS.hod

RESPONSE_KEYS = {
    "query_id",
    "conversation_id",
    "decision",
    "message",
    "question",
    "resolved_question",
    "explanation",
    "columns",
    "rows",
    "row_count",
    "row_limit",
    "execution_ms",
    "chart",
    "security",
}
SECURITY_KEYS = {"validation", "authorization", "guard_decision", "guard_reasons", "scope", "notes"}
# SQL fragments; plain words such as "SELECT" can appear in approved messages
# ("Only read-only SELECT queries are allowed."), so the stored SQL itself is
# also checked verbatim below.
SQL_MARKERS = (" FROM ", "HAVING", "WHERE ", "NOT (", "COUNT(DISTINCT", ">= 5", "LIMIT 5")
DETECTORS = [c.value for c in AttackClass]


def _keys(value) -> list[str]:
    if isinstance(value, dict):
        return [*value, *(k for v in value.values() for k in _keys(v))]
    if isinstance(value, list):
        return [k for v in value for k in _keys(v)]
    return []


def assert_private(body: dict, db) -> None:
    """The shared contract: exact keys, no SQL, no score, no codes, no detectors."""
    assert set(body) == RESPONSE_KEYS
    assert set(body["security"]) == SECURITY_KEYS
    text = json.dumps(body)
    for marker in SQL_MARKERS:
        assert marker not in text, marker
    for key in _keys(body):
        for name in ("sql", "risk", "code", "probe", "finding", "detector", "excluded"):
            assert name not in key.lower(), key
    for detector in DETECTORS:
        assert detector not in text, detector
    assert set(body["security"]["guard_reasons"]) <= PUBLIC_GUARD_REASONS
    row = stored(db, body)
    for sql in (row.generated_sql, row.executed_sql):
        if sql:
            assert sql not in text
    if row.error_code:  # the internal code exists, but only in the audit row
        assert row.error_code not in text


# ---------------- every decision, produced for real ----------------


def test_allow_statistic_has_no_sql_or_threshold(ask, cair_db):
    body = ask(HOD, MARKS_ECE).json()
    assert body["decision"] == "ALLOW" and body["rows"]
    assert_private(body, cair_db)
    assert "COUNT(DISTINCT" in stored(cair_db, body).executed_sql  # audited, not returned


def test_allow_record_tier_has_no_scope_predicate(ask, cair_db):
    body = ask(ACCOUNTS.student, "SELECT COUNT(*) AS n FROM fees", population="scope").json()
    assert body["decision"] == "ALLOW"
    assert_private(body, cair_db)
    assert "student_id" in stored(cair_db, body).executed_sql


def test_restrict_hides_the_withheld_group_and_the_rule(ask, cair_db):
    assert ask(HOD, MARKS_ECE_NOT_X).json()["decision"] == "ALLOW"
    body = ask(HOD, MARKS_BY_DEPT).json()
    assert body["decision"] == "RESTRICT"
    assert_private(body, cair_db)
    assert "ECE" not in json.dumps(body)  # the withheld group is not even named
    assert body["security"]["guard_reasons"] == [
        "Part of the result was withheld to protect individuals."
    ]
    assert "NOT (d.department_code = 'ECE')" in stored(cair_db, body).executed_sql


def test_block_hides_detector_and_code(ask, cair_db):
    ask(HOD, MARKS_ECE)
    body = ask(HOD, MARKS_ECE_NOT_X).json()
    assert body["decision"] == "BLOCK" and body["rows"] == []
    assert_private(body, cair_db)
    assert stored(cair_db, body).error_code == "INFERENCE_RISK"


def test_denied_hides_the_denial_code(ask, cair_db):
    body = ask(HOD, "SELECT first_name, COUNT(*) FROM students GROUP BY first_name").json()
    assert body["decision"] == "DENIED" and body["rows"] == []
    assert_private(body, cair_db)


def test_rejected_hides_the_validation_code(ask, cair_db):
    body = ask(HOD, "DELETE FROM students").json()
    assert body["decision"] == "REJECTED" and body["rows"] == []
    assert_private(body, cair_db)


def test_failed_generation_hides_the_code(ask, gen, cair_db):
    gen.error = SqlGenerationError(GenerationCode.TIMEOUT)
    body = ask(HOD, "unused").json()
    assert body["decision"] == "FAILED"
    assert_private(body, cair_db)


def test_failed_execution_hides_the_executed_sql(ask, cair_db):
    body = ask(ACCOUNTS.admin, "SELECT no_such_column FROM students", population="scope").json()
    assert body["decision"] == "FAILED"
    assert_private(body, cair_db)
    assert stored(cair_db, body).executed_sql is not None


def test_failed_cair_hides_everything(ask, cair_db, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("detector DIFFERENCING crashed on probe SELECT ...")

    monkeypatch.setattr(guard_module, "load_state", boom)
    body = ask(HOD, MARKS_ECE).json()
    assert body["decision"] == "FAILED"
    assert_private(body, cair_db)


# ---------------- a guard that tries to disclose ----------------


@pytest.mark.parametrize("decision", [Decision.ALLOW, Decision.BLOCK])
def test_a_disclosing_guard_cannot_leak_score_or_reasons(cair_settings, cair_db, gen, decision):
    from fastapi.testclient import TestClient

    from app.api.query import get_inference_guard, get_sql_generator
    from tests.conftest import bearer, token_for

    leaky = GuardResult(
        decision,
        0.87,
        "leaky-guard",
        (
            "DIFFERENCING fired: group of 1 in ECE",
            "No inference risk was found for this statistic.",
        ),
        disclose=True,
    )
    app = create_app(cair_settings, cair_db)
    app.dependency_overrides[get_sql_generator] = lambda: gen
    app.dependency_overrides[get_inference_guard] = lambda: ScriptedGuard(leaky)
    with TestClient(app) as client:
        gen.sql = "SELECT COUNT(*) AS n FROM students"
        body = client.post(
            "/api/v1/query", json={"question": "q"}, headers=bearer(token_for(client, HOD))
        ).json()
        assert body["decision"] == decision.value
        assert_private(body, cair_db)  # (the in-memory database closes with the client)
    assert "0.87" not in json.dumps(body)
    assert body["security"]["guard_reasons"] == ["No inference risk was found for this statistic."]


# ---------------- the published contract ----------------


def test_openapi_schema_has_no_sensitive_fields(cclient):
    schemas = cclient.get("/openapi.json").json()["components"]["schemas"]
    assert set(schemas["QueryResponse"]["properties"]) == RESPONSE_KEYS
    assert set(schemas["SecuritySummary"]["properties"]) == SECURITY_KEYS
