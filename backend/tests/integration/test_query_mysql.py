"""The query pipeline against the local ASKQ MySQL (run with: pytest --mysql).

Claude is replaced by a scripted generator; everything else is real: login,
validation, row-scope rewriting, execution as askq_reader, and history rows
checked by the Phase 2 CHECK constraints. askq_system writes happen inside an
outer transaction that is always rolled back.
"""

import secrets
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, select, text
from sqlalchemy.orm import Session

from app.api.query import get_inference_guard, get_sql_generator
from app.auth.password import hash_password
from app.clock import utcnow
from app.config import Settings
from app.db.models import QueryHistory, User
from app.db.repositories import credentials
from app.db.session import Database, get_app_session
from app.main import create_app
from app.query.catalog import TABLES
from app.query.decision import Decision, GuardResult, PassThroughGuard
from app.rbac.roles import ROLE_IDS, Role
from tests.test_query_api import FakeGenerator, ScriptedGuard

pytestmark = pytest.mark.mysql

PASSWORD = secrets.token_urlsafe(18)


@pytest.fixture(scope="module")
def settings() -> Settings:
    settings = Settings()
    for name in ("db_app_password", "db_reader_password", "jwt_secret"):
        if not settings.is_configured(name):
            pytest.skip(f"{name.upper()} is not configured in .env")
    return settings


@pytest.fixture(scope="module")
def database(settings: Settings) -> Iterator[Database]:
    db = Database(settings)
    yield db
    db.dispose()


@pytest.fixture(scope="module")
def password_hash() -> str:
    return hash_password(PASSWORD)


def _reader_scalar(database: Database, sql: str, **params):
    with database.reader_engine.connect() as connection:
        return connection.execute(text(sql), params).scalar_one()


def _system_counts(database: Database) -> dict[str, int]:
    tables = ("app_user_credentials", "conversations", "conversation_turns", "query_history")
    tables += ("cair_assessments", "security_audit_log")
    with database.app_engine.connect() as connection:
        return {
            t: connection.execute(text(f"SELECT COUNT(*) FROM {t}")).scalar_one() for t in tables
        }  # noqa: S608


@dataclass
class Env:
    client: TestClient
    session: Session
    users: dict[Role, User]
    generator: FakeGenerator
    guard: dict
    reader_statements: list[str]
    app_statements: list[str]
    hod_department: int

    def ask(self, role: Role, sql: str, question: str = "q") -> dict:
        self.generator.sql = sql
        login = self.client.post(
            "/api/v1/auth/login",
            json={"username": self.users[role].username, "password": PASSWORD},
        )
        assert login.status_code == 200, login.text
        token = login.json()["access_token"]
        response = self.client.post(
            "/api/v1/query",
            json={"question": question},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200, response.text
        return response.json()

    def history(self, query_id: int) -> QueryHistory:
        return self.session.get(QueryHistory, query_id)


def _make_env(settings, database, password_hash, overrides=None) -> Iterator[Env]:
    before = _system_counts(database)
    connection = database.app_engine.connect()
    outer = connection.begin()
    reader_statements: list[str] = []
    app_statements: list[str] = []

    def on_reader(conn, cursor, statement, *args):
        reader_statements.append(statement)

    def on_app(conn, cursor, statement, *args):
        app_statements.append(statement)

    event.listen(database.reader_engine, "before_cursor_execute", on_reader)
    event.listen(database.app_engine, "before_cursor_execute", on_app)
    try:
        session = Session(bind=connection, join_transaction_mode="create_savepoint")
        users: dict[Role, User] = {}
        for role in Role:
            users[role] = session.scalars(
                select(User)
                .where(User.role_id == ROLE_IDS[role], User.is_active.is_(True))
                .order_by(User.user_id)
                .limit(1)
            ).one()
            credentials.set_password_hash(session, users[role].user_id, password_hash, utcnow())
        session.flush()
        hod_department = session.execute(
            text(
                "SELECT department_id FROM askq_university.departments WHERE head_teacher_id = :t"
            ),
            {"t": users[Role.HOD].teacher_id},
        ).scalar_one()

        generator = FakeGenerator()
        guard = {"guard": PassThroughGuard()}
        app = create_app(settings.model_copy(update=overrides or {}), database)

        def app_session() -> Iterator[Session]:
            yield session

        app.dependency_overrides[get_app_session] = app_session
        app.dependency_overrides[get_sql_generator] = lambda: generator
        app.dependency_overrides[get_inference_guard] = lambda: guard["guard"]
        with TestClient(app) as client:
            yield Env(
                client,
                session,
                users,
                generator,
                guard,
                reader_statements,
                app_statements,
                hod_department,
            )
        session.close()
    finally:
        event.remove(database.reader_engine, "before_cursor_execute", on_reader)
        event.remove(database.app_engine, "before_cursor_execute", on_app)
        outer.rollback()
        connection.close()
    assert _system_counts(database) == before  # nothing persisted


@pytest.fixture
def env(settings, database, password_hash) -> Iterator[Env]:
    yield from _make_env(settings, database, password_hash)


def _ran_on_reader(env: Env, sql: str) -> bool:
    return any(sql in s for s in env.reader_statements)


# ---------- the catalog matches the live schema ----------


def test_catalog_matches_live_tables_and_views(database, settings):
    with database.reader_engine.connect() as connection:
        for table in TABLES:
            live = {
                r[0]
                for r in connection.execute(
                    text(
                        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
                        "WHERE TABLE_SCHEMA = :s AND TABLE_NAME = :t"
                    ),
                    {"s": settings.db_university_name, "t": table.name},
                )
            }
            assert live, f"{table.name} not visible to askq_reader"
            assert set(table.column_names) <= live, table.name


# ---------- ALLOW with real row scope ----------


def test_admin_sees_the_whole_university(env):
    body = env.ask(Role.ADMIN, "SELECT COUNT(*) AS n FROM students")
    assert body["decision"] == "ALLOW" and body["rows"] == [[1000]]
    executed = env.history(body["query_id"]).executed_sql
    assert "sql" not in body
    assert _ran_on_reader(env, executed)
    assert not any(executed in s for s in env.app_statements)


def test_hod_sees_only_their_department(env, database):
    expected = _reader_scalar(
        database, "SELECT COUNT(*) FROM students WHERE department_id = :d", d=env.hod_department
    )
    body = env.ask(Role.HOD, "SELECT COUNT(*) AS n FROM students")
    assert body["rows"] == [[expected]] and 0 < expected < 1000
    other = env.ask(
        Role.HOD,
        f"SELECT COUNT(*) AS n FROM students WHERE department_id <> {env.hod_department}",
    )
    assert other["rows"] == [[0]]


def test_teacher_sees_grades_of_own_offerings_and_advisees(env, database):
    teacher_id = env.users[Role.TEACHER].teacher_id
    expected = _reader_scalar(
        database,
        "SELECT COUNT(*) FROM grades WHERE enrollment_id IN (SELECT enrollment_id FROM enrollments "
        "WHERE offering_id IN (SELECT offering_id FROM course_offerings WHERE teacher_id = :t) "
        "OR student_id IN (SELECT student_id FROM students WHERE advisor_teacher_id = :t))",
        t=teacher_id,
    )
    total = _reader_scalar(database, "SELECT COUNT(*) FROM grades")
    body = env.ask(Role.TEACHER, "SELECT COUNT(*) AS n FROM grades")
    assert body["rows"] == [[expected]] and expected < total


def test_student_sees_only_themselves(env, database):
    student_id = env.users[Role.STUDENT].student_id
    own = _reader_scalar(
        database,
        "SELECT COUNT(*) FROM grades g JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
        "WHERE e.student_id = :s",
        s=student_id,
    )
    assert env.ask(Role.STUDENT, "SELECT COUNT(*) AS n FROM students")["rows"] == [[1]]
    assert env.ask(Role.STUDENT, "SELECT COUNT(*) AS n FROM grades")["rows"] == [[own]]
    someone_else = _reader_scalar(
        database, "SELECT student_no FROM students WHERE student_id <> :s LIMIT 1", s=student_id
    )
    cross = env.ask(
        Role.STUDENT,
        "SELECT g.marks FROM grades g JOIN enrollments e ON e.enrollment_id = g.enrollment_id "
        f"JOIN students s ON s.student_id = e.student_id WHERE s.student_no = '{someone_else}'",
    )
    assert cross["decision"] == "ALLOW" and cross["rows"] == []


def test_like_patterns_are_not_treated_as_parameters(env, database):
    expected = _reader_scalar(database, "SELECT COUNT(*) FROM students WHERE last_name LIKE '%a%'")
    body = env.ask(Role.ADMIN, "SELECT COUNT(*) AS n FROM students WHERE last_name LIKE '%a%'")
    assert body["rows"] == [[expected]]


def test_results_are_bounded(env):
    body = env.ask(Role.ADMIN, "SELECT attendance_id FROM attendance_records")
    assert body["row_count"] == 500
    assert env.history(body["query_id"]).executed_sql.endswith("LIMIT 500")


# ---------- every final_status satisfies the Phase 2 CHECK constraints ----------


def test_executed_row(env):
    body = env.ask(Role.HOD, "SELECT COUNT(*) AS n FROM grades")
    row = env.history(body["query_id"])
    assert (row.final_status, row.authorization_status, row.cair_decision) == (
        "EXECUTED",
        "REWRITTEN",
        "ALLOW",
    )


def test_rejected_row_and_reader_untouched(env):
    body = env.ask(Role.ADMIN, "SELECT * FROM askq_system.app_user_credentials")
    assert body["decision"] == "REJECTED"
    assert not any("app_user_credentials" in s for s in env.reader_statements)
    assert env.history(body["query_id"]).final_status == "REJECTED"


def test_denied_row_and_reader_untouched(env):
    body = env.ask(Role.TEACHER, "SELECT SUM(amount) AS total FROM fees")
    assert body["decision"] == "DENIED"
    assert not any("fees" in s for s in env.reader_statements)
    assert env.history(body["query_id"]).final_status == "DENIED"


def test_blocked_and_restricted_rows(env):
    env.guard["guard"] = ScriptedGuard(GuardResult(Decision.BLOCK, 0.9, "test", ("r",)))
    blocked = env.ask(Role.ADMIN, "SELECT COUNT(*) AS n FROM teachers")
    assert blocked["decision"] == "BLOCK"
    assert not any("teachers" in s for s in env.reader_statements)
    assert env.history(blocked["query_id"]).final_status == "BLOCKED"

    env.guard["guard"] = ScriptedGuard(
        GuardResult(Decision.RESTRICT, 0.5, "test", ("r",), "SELECT COUNT(*) AS n FROM courses")
    )
    restricted = env.ask(Role.ADMIN, "SELECT COUNT(*) AS n FROM teachers")
    assert restricted["decision"] == "RESTRICT" and restricted["rows"] == [[91]]
    assert env.history(restricted["query_id"]).final_status == "RESTRICTED"


def test_a_guard_cannot_widen_the_row_scope(env, database):
    expected = _reader_scalar(
        database, "SELECT COUNT(*) FROM students WHERE department_id = :d", d=env.hod_department
    )
    env.guard["guard"] = ScriptedGuard(
        GuardResult(Decision.RESTRICT, 0.5, "test", (), "SELECT COUNT(*) AS n FROM students")
    )
    body = env.ask(Role.HOD, "SELECT COUNT(*) AS n FROM students")
    assert body["decision"] == "RESTRICT" and body["rows"] == [[expected]]
    assert env.history(body["query_id"]).final_status == "RESTRICTED"


def test_failed_rows(env):
    unknown = env.ask(Role.ADMIN, "SELECT no_such_column FROM students")
    row = env.history(unknown["query_id"])
    assert (row.final_status, row.failure_stage, row.error_code) == (
        "FAILED",
        "EXECUTION",
        "EXECUTION_ERROR",
    )
    env.generator.sql = ""
    unanswerable = env.ask(Role.ADMIN, "")
    assert env.history(unanswerable["query_id"]).failure_stage == "GENERATION"


# ---------- statement timeout ----------


@pytest.fixture
def slow_env(settings, database, password_hash) -> Iterator[Env]:
    yield from _make_env(settings, database, password_hash, {"sql_timeout_ms": 200})


def test_statement_timeout_is_enforced(slow_env):
    body = slow_env.ask(
        Role.ADMIN,
        "SELECT COUNT(*) AS n FROM attendance_records a "
        "JOIN attendance_records b ON a.status = b.status",
    )
    assert body["decision"] == "FAILED" and "reason_code" not in body
    row = slow_env.history(body["query_id"])
    assert (row.failure_stage, row.error_code) == ("EXECUTION", "QUERY_TIMEOUT")
