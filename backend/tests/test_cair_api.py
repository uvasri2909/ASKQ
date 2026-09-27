"""CAIR through POST /api/v1/query with the real CairGuard, on SQLite stand-ins.

The reader side gets its own 30-student population (test-only; the Phase 2
seed is never touched). k = 5, and the group sizes are exact on purpose:
  department 1 (CSE): 501-512, F 6 / M 6    -> the HOD account's record scope
  department 2 (ECE): 601-612, X 1 / F 5 / M 6   (601 is the only gender X)
  department 3 (ME) : 701-706, F 4 / M 2    -> a group of exactly 4, total 6
Every student has one Spring grade.
"""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.pool import StaticPool

from app.api.query import get_sql_generator
from app.cair import guard as guard_module
from app.db.models import (
    CairAssessment,
    CairAuditFinding,
    CairLedgerEntry,
    QueryHistory,
    SecurityAuditEvent,
)
from app.db.repositories.cair import recent_statistical_assessments
from app.db.session import Database
from app.main import create_app
from app.query.catalog import TABLES
from tests.conftest import (
    ACCOUNTS,
    bearer,
    make_settings,
    make_sqlite_engine,
    seed,
    token_for,
)
from tests.test_query_api import FakeGenerator, Spy


def _students():
    rows = []
    genders = {
        1: "FM" * 6,  # F 6, M 6
        2: "X" + "MF" * 5 + "M",  # X 1, F 5, M 6
        3: "FFFFMM",  # F 4, M 2
    }
    for dept, first, count in ((1, 501, 12), (2, 601, 12), (3, 701, 6)):
        for i in range(count):
            sid = first + i
            gender = genders[dept][i]
            rows.append((sid, f"S{sid:08d}", "N", "N", f"{sid}@x.example", gender, "2005-01-01",
                         dept, 2023, 2, "DOMESTIC", "R", 0, None, "ACTIVE"))  # fmt: skip
    return rows


def _university_rows() -> dict[str, list[tuple]]:
    students = _students()
    enrollments, grades = [], []
    for i, s in enumerate(students):
        sid, dept = s[0], s[7]
        enrollments.append((10_000 + i, sid, dept, "2026-01-10", "COMPLETED"))
        grades.append((20_000 + i, 10_000 + i, 50 + (sid % 40), "C", "2026-05-20"))
    return {
        "departments": [
            (1, "CSE", "Computing", "A", 1998, 101),
            (2, "ECE", "Electronics", "B", 1999, 201),
            (3, "ME", "Mechanical", "C", 2000, None),
        ],
        "teachers": [
            (101, "T0101", "H", "H", "h@x.example", 1, "Professor", "2010-01-01", 1, 1),
            (102, "T0102", "T", "T", "t@x.example", 1, "Lecturer", "2011-01-01", 1, 1),
            (201, "T0201", "O", "O", "o@x.example", 2, "Lecturer", "2012-01-01", 1, 1),
        ],
        "courses": [
            (1, "CSE101", "A", 1, 100, 4, 0, 1),
            (2, "ECE101", "B", 2, 100, 4, 0, 1),
            (3, "ME101", "C", 3, 100, 4, 0, 1),
        ],  # fmt: skip
        "course_offerings": [
            (1, 1, 1, "A", 102, 40, "R"),
            (2, 2, 1, "A", 201, 40, "R"),
            (3, 3, 1, "A", 201, 40, "R"),
        ],  # fmt: skip
        "academic_terms": [
            (1, "2026-SPRING", "Spring", "2025-2026", "SPRING", "2026-01-12", "2026-05-08", 0)
        ],  # fmt: skip
        "students": students,
        "enrollments": enrollments,
        "grades": grades,
    }


def make_cair_reader(settings):
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    db = settings.db_university_name

    @event.listens_for(engine, "connect")
    def _attach(dbapi_connection, _record) -> None:
        dbapi_connection.execute(f"ATTACH DATABASE ':memory:' AS {db}")

    rows = _university_rows()
    with engine.begin() as connection:
        for table in TABLES:
            columns = ", ".join(c.name for c in table.columns)
            connection.exec_driver_sql(f"CREATE TABLE {db}.{table.name} ({columns})")
            if rows.get(table.name):
                marks = ", ".join("?" for _ in table.columns)
                connection.exec_driver_sql(
                    f"INSERT INTO {db}.{table.name} VALUES ({marks})", rows[table.name]
                )
    return engine


@pytest.fixture
def cair_settings():
    return make_settings()


@pytest.fixture
def cair_db(cair_settings, password_hash) -> Iterator[Database]:
    db = Database(
        cair_settings,
        app_engine=make_sqlite_engine(cair_settings),
        reader_engine=make_cair_reader(cair_settings),
    )
    with db.app_session() as session:
        seed(session, password_hash)
    yield db
    db.dispose()


@pytest.fixture
def gen() -> FakeGenerator:
    return FakeGenerator()


@pytest.fixture
def reader_spy(cair_db) -> Spy:
    return Spy(cair_db.reader_engine)


def _client(settings, db, gen) -> TestClient:
    app = create_app(settings, db)
    app.dependency_overrides[get_sql_generator] = lambda: gen
    return TestClient(app)


@pytest.fixture
def cclient(cair_settings, cair_db, gen) -> Iterator[TestClient]:
    with _client(cair_settings, cair_db, gen) as client:
        yield client


class Asker:
    def __init__(self, client, gen):
        self.client, self.gen, self.tokens = client, gen, {}

    def __call__(self, who, sql, *, population="university", conversation=None, body=None):
        if who not in self.tokens:
            self.tokens[who] = token_for(self.client, who)
        self.gen.sql = sql
        self.gen.population = population
        body = {"question": "q", **(body or {})}
        if conversation:
            body["conversation_id"] = conversation
        return self.client.post("/api/v1/query", json=body, headers=bearer(self.tokens[who]))


@pytest.fixture
def ask(cclient, gen, monkeypatch) -> Asker:
    # FakeGenerator from the Phase 4 tests has no population; add it here.
    original = gen.generate

    def generate(request):
        result = original(request)
        return result.model_copy(update={"population": getattr(gen, "population", "scope")})

    monkeypatch.setattr(gen, "generate", generate)
    return Asker(cclient, gen)


BY_DEPT = (
    "SELECT d.department_code, COUNT(*) AS n FROM students s "
    "JOIN departments d ON d.department_id = s.department_id GROUP BY d.department_code"
)
MARKS_BY_DEPT = (
    "SELECT d.department_code, AVG(g.marks) AS avg_marks FROM grades g "
    "JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
    "JOIN students s ON s.student_id = e.student_id "
    "JOIN departments d ON d.department_id = s.department_id GROUP BY d.department_code"
)
MARKS_ECE_NOT_X = (
    "SELECT AVG(g.marks) AS avg_marks FROM grades g "
    "JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
    "JOIN students s ON s.student_id = e.student_id "
    "JOIN departments d ON d.department_id = s.department_id "
    "WHERE d.department_code = 'ECE' AND s.gender <> 'X'"
)
MARKS_ECE = MARKS_ECE_NOT_X.replace(" AND s.gender <> 'X'", "")


def history(db) -> list[QueryHistory]:
    with db.app_session() as s:
        return list(s.scalars(select(QueryHistory).order_by(QueryHistory.query_id)))


def rows_of(db, model):
    with db.app_session() as s:
        return list(s.scalars(select(model)))


# ---------------- statistical tier: ALLOW ----------------


def test_university_statistic_is_allowed_and_recorded(ask, cair_db):
    body = ask(ACCOUNTS.hod, BY_DEPT).json()
    assert body["decision"] == "ALLOW", body
    assert sorted(body["rows"]) == [["CSE", 12], ["ECE", 12], ["ME", 6]]
    assert "HAVING COUNT(DISTINCT s.student_id) >= 5" in body["sql"]
    assert body["security"]["risk_score"] is None  # never disclosed
    assert body["security"]["guard_reasons"] == ["No inference risk was found for this statistic."]
    (row,) = history(cair_db)
    assert (row.final_status, row.authorization_status, row.cair_decision) == (
        "EXECUTED",
        "ALLOWED",
        "ALLOW",
    )
    (assessment,) = rows_of(cair_db, CairAssessment)
    assert assessment.policy_version == "cair-1.0"
    assert assessment.reasons["tier"] == "STATISTICAL"
    assert assessment.reasons["attack_classes"] == []
    findings = rows_of(cair_db, CairAuditFinding)
    assert sorted(f.audit_type for f in findings) == sorted(
        ["DIFFERENCING", "NARROWING", "ARITHMETIC_RECOVERY", "CROSS_VIEW_LINKING",
         "REFUSAL_SIDE_CHANNEL", "CONTEXT_CARRYOVER"]
    )  # fmt: skip
    assert not any(f.triggered for f in findings)
    (ledger,) = rows_of(cair_db, CairLedgerEntry)
    assert (ledger.query_id, ledger.user_id, ledger.result_cardinality) == (
        row.query_id,
        ACCOUNTS.hod,
        3,
    )
    assert len(ledger.population_fingerprint) == 64
    assert "probes" in ledger.descriptor and "descriptor" in ledger.descriptor


def test_nothing_personal_is_stored(ask, cair_db):
    ask(ACCOUNTS.hod, BY_DEPT)
    (ledger,) = rows_of(cair_db, CairLedgerEntry)
    (assessment,) = rows_of(cair_db, CairAssessment)
    stored = str(ledger.descriptor) + str(assessment.reasons)
    for student in ("501", "601", "S00000601", "@x.example"):
        assert student not in stored.replace("5 ", "")


# ---------------- BLOCK ----------------


def test_differencing_is_blocked_and_never_reaches_the_reader(ask, cair_db, reader_spy):
    assert ask(ACCOUNTS.hod, MARKS_ECE).json()["decision"] == "ALLOW"
    reader_spy.statements.clear()
    body = ask(ACCOUNTS.hod, MARKS_ECE_NOT_X).json()
    assert body["decision"] == "BLOCK"
    assert body["reason_code"] == "INFERENCE_RISK"
    assert body["rows"] == [] and body["sql"] is None
    # CAIR's own population probes ran; the query itself did not.
    assert not any(s.startswith("SELECT AVG(g.marks)") for s in reader_spy.statements)
    blocked = history(cair_db)[-1]
    assert (blocked.final_status, blocked.cair_decision, blocked.executed_sql) == (
        "BLOCKED",
        "BLOCK",
        None,
    )
    with cair_db.app_session() as s:
        triggered = s.scalars(
            select(CairAuditFinding.audit_type).where(CairAuditFinding.triggered.is_(True))
        ).all()
        events = s.scalars(select(SecurityAuditEvent.event_type)).all()
    assert "DIFFERENCING" in triggered
    assert "QUERY_BLOCKED" in events
    assert len(rows_of(cair_db, CairLedgerEntry)) == 1  # nothing learned from the block


def test_detection_spans_conversations(ask):
    first = ask(ACCOUNTS.hod, MARKS_ECE).json()
    second = ask(ACCOUNTS.hod, MARKS_ECE_NOT_X).json()  # a NEW conversation
    assert first["conversation_id"] != second["conversation_id"]
    assert second["decision"] == "BLOCK"


def test_block_responses_are_uniform(ask):
    # Exactly one student has gender X; nobody has gender Z.
    one = ask(ACCOUNTS.hod, "SELECT COUNT(*) AS n FROM students s WHERE s.gender = 'X'")
    none = ask(ACCOUNTS.hod, "SELECT COUNT(*) AS n FROM students s WHERE s.gender = 'Z'")
    a, b = one.json(), none.json()
    assert a["decision"] == b["decision"] == "BLOCK"
    for key in ("message", "reason_code", "rows", "sql", "row_count", "execution_ms", "chart"):
        assert a[key] == b[key], key
    assert a["security"] == b["security"]


# ---------------- RESTRICT ----------------


def test_restrict_withholds_the_implicated_group_and_is_reauthorized(ask, cair_db):
    assert ask(ACCOUNTS.hod, MARKS_ECE_NOT_X).json()["decision"] == "ALLOW"  # 11 people
    body = ask(ACCOUNTS.hod, MARKS_BY_DEPT).json()  # ECE cell = those 11 + the X student
    assert body["decision"] == "RESTRICT", body
    assert sorted(r[0] for r in body["rows"]) == ["CSE", "ME"]
    # Withheld group + the statistical tier's own minimum-size rule, re-applied.
    assert "NOT (d.department_code = 'ECE')" in body["sql"]
    assert "COUNT(DISTINCT e.student_id) >= 5" in body["sql"]
    assert body["security"]["guard_reasons"] == [
        "Part of the result was withheld to protect individuals."
    ]
    row = history(cair_db)[-1]
    assert (row.final_status, row.cair_decision) == ("RESTRICTED", "RESTRICT")
    assessment = rows_of(cair_db, CairAssessment)[-1]
    assert assessment.reasons["excluded"] == [[0, "ECE"]]


# ---------------- authorization is untouched ----------------


def test_unauthorized_is_still_denied_whatever_cair_would_say(ask):
    teacher_fees = ask(ACCOUNTS.teacher, "SELECT SUM(amount) FROM fees", population="scope")
    assert teacher_fees.json()["decision"] == "DENIED"
    names = ask(ACCOUNTS.hod, "SELECT first_name, COUNT(*) FROM students GROUP BY first_name")
    assert names.json()["decision"] == "DENIED"
    targeted = ask(ACCOUNTS.hod, "SELECT COUNT(*) FROM students WHERE student_id = 601")
    assert targeted.json()["decision"] == "DENIED"
    records = ask(ACCOUNTS.hod, "SELECT gender FROM students")  # rows, not an aggregate
    assert records.json()["reason_code"] == "STATISTICS_AGGREGATE_ONLY"


def test_admin_questions_stay_in_the_record_tier(ask, cair_db):
    body = ask(ACCOUNTS.admin, "SELECT COUNT(*) AS n FROM students s").json()
    assert body["decision"] == "ALLOW" and body["rows"] == [[30]]
    assert "HAVING" not in body["sql"]
    assert rows_of(cair_db, CairAssessment)[-1].reasons["tier"] == "RECORD"
    assert rows_of(cair_db, CairLedgerEntry) == []


def test_record_tier_is_unchanged_for_other_roles(ask):
    body = ask(ACCOUNTS.hod, "SELECT COUNT(*) AS n FROM students", population="scope").json()
    assert body["decision"] == "ALLOW" and body["rows"] == [[12]]  # own department only
    assert body["security"]["guard_reasons"] == ["Record-level access within your permitted scope."]


def test_disabling_cair_disables_the_statistical_tier(cair_db, gen, monkeypatch):
    settings = make_settings(cair_enabled=False)
    with _client(settings, cair_db, gen) as client:
        asker = Asker(client, gen)
        original = gen.generate
        monkeypatch.setattr(
            gen, "generate", lambda r: original(r).model_copy(update={"population": "university"})
        )
        body = asker(ACCOUNTS.hod, "SELECT COUNT(*) AS n FROM students").json()
    assert body["rows"] == [[12]]  # fell back to the HOD's own department


# ---------------- state cannot be forged ----------------


@pytest.mark.parametrize(
    "field",
    ["risk_score", "cair_state", "revealed", "decision", "population", "tier", "history"],
)
def test_client_cannot_supply_security_state(ask, field):
    response = ask(ACCOUNTS.hod, BY_DEPT, body={field: "x"})
    assert response.status_code == 422


def test_state_is_per_user(ask, cair_db):
    ask(ACCOUNTS.hod, MARKS_ECE)
    from datetime import datetime

    with cair_db.app_session() as s:
        mine = recent_statistical_assessments(s, ACCOUNTS.hod, datetime(2000, 1, 1), 20)
        theirs = recent_statistical_assessments(s, ACCOUNTS.teacher, datetime(2000, 1, 1), 20)
    assert len(mine) == 1 and theirs == []
    # The teacher asks the second half of the attack: no history of theirs to combine.
    body = ask(ACCOUNTS.teacher, MARKS_ECE_NOT_X).json()
    assert body["decision"] == "ALLOW"


def test_history_window_is_bounded(cair_db, gen, monkeypatch):
    settings = make_settings(cair_window_queries=2)
    with _client(settings, cair_db, gen) as client:
        original = gen.generate
        state = {"population": "university"}
        monkeypatch.setattr(gen, "generate", lambda r: original(r).model_copy(update=state))
        asker = Asker(client, gen)
        asker(ACCOUNTS.hod, MARKS_ECE)
        asker(ACCOUNTS.hod, BY_DEPT)
        asker(ACCOUNTS.hod, "SELECT COUNT(*) AS n FROM students s")
        # MARKS_ECE is now outside the 2-query window: the pair is not combined.
        body = asker(ACCOUNTS.hod, MARKS_ECE_NOT_X).json()
    assert body["decision"] == "ALLOW"


def test_only_statistical_assessments_form_the_state(ask, cair_db):
    ask(ACCOUNTS.hod, "SELECT COUNT(*) AS n FROM students", population="scope")
    from datetime import datetime

    with cair_db.app_session() as s:
        assert recent_statistical_assessments(s, ACCOUNTS.hod, datetime(2000, 1, 1), 20) == []


# ---------------- failure is safe ----------------


def test_cair_failure_fails_closed(ask, cair_db, reader_spy, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("probe exploded")

    monkeypatch.setattr(guard_module, "build_probes", broken)
    body = ask(ACCOUNTS.hod, BY_DEPT).json()
    assert body["decision"] == "FAILED"
    assert "probe" not in body["message"]
    assert not any("GROUP BY" in s for s in reader_spy.statements)
    row = history(cair_db)[-1]
    assert (row.final_status, row.failure_stage) == ("FAILED", "CAIR")
