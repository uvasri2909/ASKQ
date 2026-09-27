"""Shared fixtures.

Unit tests never read the real .env or touch MySQL: they build Settings with
generated secrets and an in-memory SQLite database that attaches
askq_university / askq_system and uses the same ORM models and
schema_translate_map as production.

Tests marked `mysql` (tests/integration) use the local ASKQ MySQL instance and
the real .env. They are skipped unless pytest runs with --mysql.
"""

import secrets
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.auth.password import hash_password
from app.auth.tokens import TokenService
from app.clock import utcnow
from app.config import Settings
from app.db.engine import schema_translate_map
from app.db.models import AppUserCredential, Base, Department, Role, User
from app.db.session import Database
from app.main import create_app

# Generated per run: no literal credentials in the repository.
TEST_PASSWORD = secrets.token_urlsafe(18)
TEST_JWT_SECRET = secrets.token_urlsafe(48)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--mysql",
        action="store_true",
        help="also run integration tests against the local ASKQ MySQL (uses the real .env)",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "mysql: needs the local ASKQ MySQL; run with --mysql")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--mysql"):
        return
    skip = pytest.mark.skip(reason="MySQL integration test; run with --mysql")
    for item in items:
        if "mysql" in item.keywords:
            item.add_marker(skip)


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "app_env": "test",
        "jwt_secret": TEST_JWT_SECRET,
        "db_reader_password": secrets.token_urlsafe(24),
        "db_app_password": secrets.token_urlsafe(24),
        # Never a real key: unit tests replace the SQL generator; nothing calls the API.
        "anthropic_api_key": "test-" + secrets.token_urlsafe(24),
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def make_sqlite_engine(settings: Settings) -> Engine:
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
        execution_options={"schema_translate_map": schema_translate_map(settings)},
    )

    @event.listens_for(engine, "connect")
    def _attach(dbapi_connection, _record) -> None:
        for name in (settings.db_university_name, settings.db_system_name):
            dbapi_connection.execute(f"ATTACH DATABASE ':memory:' AS {name}")

    Base.metadata.create_all(engine)
    return engine


# ---- organisational data for the reader side (catalog tables, tiny population) ----
#
# dept 1: head teacher 101 (the HOD account), teacher 102 (the TEACHER account)
#         teaches offering 1 and advises student 501; students 501 (the STUDENT
#         account) and 502 are enrolled in offering 1.
# dept 2: teacher 201 teaches offering 2; student 601 is enrolled in it.
UNIVERSITY_ROWS: dict[str, list[tuple]] = {
    "departments": [
        (1, "CSE", "Computing", "A", 1998, 101),
        (2, "ECE", "Electronics", "B", 1999, 201),
    ],
    "academic_terms": [
        (1, "2026-FALL", "Fall 2026", "2026-2027", "FALL", "2026-08-17", "2026-12-11", 1)
    ],
    "grade_scale": [("A", 85, 4.0, "Excellent"), ("F", 0, 0.0, "Fail")],
    "teachers": [
        (101, "T0101", "Hana", "Head", "h@x.example", 1, "Professor", "2010-01-01", 90000, 1),
        (102, "T0102", "Tao", "Teach", "t@x.example", 1, "Lecturer", "2015-01-01", 60000, 1),
        (201, "T0201", "Ola", "Other", "o@x.example", 2, "Lecturer", "2016-01-01", 61000, 1),
    ],
    "students": [
        (
            501,
            "S00000501",
            "Sam",
            "Self",
            "s@x.example",
            "F",
            "2005-01-01",
            1,
            2023,
            2,
            "DOMESTIC",
            "North",
            1,
            102,
            "ACTIVE",
        ),
        (
            502,
            "S00000502",
            "Pat",
            "Peer",
            "p@x.example",
            "M",
            "2005-02-02",
            1,
            2023,
            2,
            "DOMESTIC",
            "South",
            0,
            None,
            "ACTIVE",
        ),
        (
            601,
            "S00000601",
            "Eli",
            "Else",
            "e@x.example",
            "X",
            "2005-03-03",
            2,
            2023,
            2,
            "INTERNATIONAL",
            "East",
            0,
            201,
            "ACTIVE",
        ),
    ],
    "courses": [
        (11, "CSE101", "Intro", 1, 100, 4, 0, 1),
        (21, "ECE101", "Circuits", 2, 100, 4, 0, 1),
    ],
    "course_offerings": [(1, 11, 1, "A", 102, 40, "R1"), (2, 21, 1, "A", 201, 40, "R2")],
    "enrollments": [
        (1001, 501, 1, "2026-08-10", "ENROLLED"),
        (1002, 502, 1, "2026-08-10", "ENROLLED"),
        (2001, 601, 2, "2026-08-10", "ENROLLED"),
    ],
    "grades": [
        (1, 1001, 91, "A", "2026-09-01"),
        (2, 1002, 40, "F", "2026-09-01"),
        (3, 2001, 88, "A", "2026-09-01"),
    ],
    "class_sessions": [(1, 1, 1, "2026-08-18"), (2, 2, 1, "2026-08-18")],
    "attendance_records": [
        (1, 1, 1001, 1, "PRESENT"),
        (2, 1, 1002, 1, "ABSENT"),
        (3, 2, 2001, 2, "LATE"),
    ],
    "fees": [
        (1, 501, 1, "TUITION", 1000, "2026-09-01"),
        (2, 502, 1, "TUITION", 1000, "2026-09-01"),
        (3, 601, 1, "TUITION", 1000, "2026-09-01"),
    ],
    "fee_payments": [
        (1, 1, 400, "2026-08-20", "CARD", "R-1"),
        (2, 3, 1000, "2026-08-20", "CASH", "R-3"),
    ],
    "scholarships": [(1, "MERIT", "Merit Award", "MERIT", "Uni", None, 500, 1)],
    "student_scholarships": [
        (1, 501, 1, 1, 500, "ACTIVE", "2026-08-01"),
        (2, 601, 1, 1, 500, "ACTIVE", "2026-08-01"),
    ],
    "v_fee_balances": [
        (1, 501, 1, "TUITION", 1000, 400, 600, "2026-09-01", "2026-09-25", "OVERDUE"),
        (2, 502, 1, "TUITION", 1000, 0, 1000, "2026-09-01", "2026-09-25", "OVERDUE"),
        (3, 601, 1, "TUITION", 1000, 1000, 0, "2026-09-01", "2026-09-25", "PAID"),
    ],
    "v_attendance_summary": [
        (1001, 501, 1, 1, 1, 0, 0, 100.0),
        (1002, 502, 1, 1, 0, 1, 0, 0.0),
        (2001, 601, 2, 1, 1, 0, 0, 100.0),
    ],
}


def make_reader_sqlite_engine(settings: Settings) -> Engine:
    """The reader side: the catalog tables (views as plain tables) in an attached schema."""
    from app.query.catalog import TABLES

    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    db = settings.db_university_name

    @event.listens_for(engine, "connect")
    def _attach(dbapi_connection, _record) -> None:
        dbapi_connection.execute(f"ATTACH DATABASE ':memory:' AS {db}")

    with engine.begin() as connection:
        for table in TABLES:
            columns = ", ".join(c.name for c in table.columns)
            connection.exec_driver_sql(f"CREATE TABLE {db}.{table.name} ({columns})")
            marks = ", ".join("?" for _ in table.columns)
            connection.exec_driver_sql(
                f"INSERT INTO {db}.{table.name} VALUES ({marks})", UNIVERSITY_ROWS[table.name]
            )
    return engine


@pytest.fixture(scope="session")
def password_hash() -> str:
    return hash_password(TEST_PASSWORD)


@dataclass(frozen=True)
class Accounts:
    """user_ids of the seeded accounts."""

    admin: int = 1
    hod: int = 2
    teacher: int = 3
    student: int = 4
    inactive: int = 5
    no_credential: int = 6
    orphan_hod: int = 7  # HOD role but heads no department -> fails closed


ACCOUNTS = Accounts()
USERNAMES = {
    ACCOUNTS.admin: "admin",
    ACCOUNTS.hod: "t0001",
    ACCOUNTS.teacher: "t0002",
    ACCOUNTS.student: "s20230001",
    ACCOUNTS.inactive: "s20230002",
    ACCOUNTS.no_credential: "s20230003",
    ACCOUNTS.orphan_hod: "t0003",
}
HOD_DEPARTMENT_ID = 1


def seed(session: Session, password_hash: str) -> None:
    session.add_all(
        [
            Role(role_id=1, role_code="ADMIN", role_name="Administrator"),
            Role(role_id=2, role_code="HOD", role_name="Head of Department"),
            Role(role_id=3, role_code="TEACHER", role_name="Teacher"),
            Role(role_id=4, role_code="STUDENT", role_name="Student"),
            Department(
                department_id=HOD_DEPARTMENT_ID,
                department_code="CSE",
                department_name="Computer Science",
                head_teacher_id=101,
            ),
            Department(department_id=2, department_code="ECE", department_name="Electronics"),
        ]
    )
    session.flush()
    rows = [
        (ACCOUNTS.admin, 1, None, None, True),
        (ACCOUNTS.hod, 2, 101, None, True),
        (ACCOUNTS.teacher, 3, 102, None, True),
        (ACCOUNTS.student, 4, None, 501, True),  # teacher 102 is this student's advisor
        (ACCOUNTS.inactive, 4, None, 502, False),
        (ACCOUNTS.no_credential, 4, None, 503, True),
        (ACCOUNTS.orphan_hod, 2, 103, None, True),
    ]
    for user_id, role_id, teacher_id, student_id, active in rows:
        session.add(
            User(
                user_id=user_id,
                username=USERNAMES[user_id],
                role_id=role_id,
                teacher_id=teacher_id,
                student_id=student_id,
                is_active=active,
            )
        )
        if user_id != ACCOUNTS.no_credential:
            session.add(
                AppUserCredential(
                    user_id=user_id,
                    password_hash=password_hash,
                    password_changed_at=utcnow().replace(year=2026, month=1, day=1),
                    failed_login_attempts=0,
                )
            )
    session.commit()


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def database(settings: Settings, password_hash: str) -> Iterator[Database]:
    app_engine = make_sqlite_engine(settings)
    reader_engine = make_reader_sqlite_engine(settings)
    db = Database(settings, app_engine=app_engine, reader_engine=reader_engine)
    with db.app_session() as session:
        seed(session, password_hash)
    yield db
    db.dispose()


@pytest.fixture
def db_session(database: Database) -> Iterator[Session]:
    with database.app_session() as session:
        yield session


@pytest.fixture
def app(settings: Settings, database: Database) -> FastAPI:
    return create_app(settings, database)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def tokens(settings: Settings) -> TokenService:
    return TokenService.from_settings(settings)


def login(client: TestClient, username: str, password: str = TEST_PASSWORD):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def token_for(client: TestClient, user_id: int) -> str:
    response = login(client, USERNAMES[user_id])
    assert response.status_code == 200, response.text
    return response.json()["access_token"]
