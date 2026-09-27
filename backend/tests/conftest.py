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
        (ACCOUNTS.student, 4, None, 501, True),
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
    reader_engine = make_sqlite_engine(settings)
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
