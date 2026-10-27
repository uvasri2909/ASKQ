"""Integration tests against the local ASKQ MySQL (run with: pytest --mysql).

Uses the real .env (values are never printed). Everything is read-only except
test_login_and_me_end_to_end, which writes credentials and audit rows inside
an outer transaction that is always rolled back, so askq_system stays empty
and the Phase 2 data is untouched. (A rolled-back INSERT still advances an
AUTO_INCREMENT counter; that is harmless.)
"""

import secrets
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.auth.password import hash_password
from app.auth.service import build_user_context
from app.clock import utcnow
from app.config import Settings
from app.db.models import Base, Department, User
from app.db.repositories import credentials
from app.db.session import Database, get_app_session
from app.main import create_app
from app.rbac.roles import ROLE_IDS, Role

pytestmark = pytest.mark.mysql

PRIVILEGE_DENIED = (1142, 1143, 1044)  # table / column / database access denied


@pytest.fixture(scope="module")
def settings() -> Settings:
    settings = Settings()
    if not (
        settings.is_configured("db_app_password") and settings.is_configured("db_reader_password")
    ):
        pytest.skip("DB_APP_PASSWORD / DB_READER_PASSWORD are not configured in .env")
    return settings


@pytest.fixture(scope="module")
def database(settings: Settings) -> Iterator[Database]:
    db = Database(settings)
    yield db
    db.dispose()


def _scalar(engine, sql: str):
    with engine.connect() as connection:
        return connection.execute(text(sql)).scalar_one()


def _denied(engine, sql: str) -> bool:
    try:
        with engine.connect() as connection:
            connection.execute(text(sql)).all()
    except DBAPIError as exc:
        return exc.orig.args[0] in PRIVILEGE_DENIED
    return False


def _system_row_counts(database: Database) -> tuple[int, int]:
    with database.app_engine.connect() as connection:
        return (
            connection.execute(text("SELECT COUNT(*) FROM app_user_credentials")).scalar_one(),
            connection.execute(text("SELECT COUNT(*) FROM security_audit_log")).scalar_one(),
        )


# ---------- connection separation ----------


def test_app_engine_connects_as_askq_app_in_utc(database):
    engine = database.app_engine
    assert _scalar(engine, "SELECT CURRENT_USER()") == "askq_app@127.0.0.1"
    assert _scalar(engine, "SELECT @@session.time_zone") == "+00:00"
    assert _scalar(engine, "SELECT @@session.transaction_read_only") == 0
    assert _scalar(engine, "SELECT DATABASE()") == "askq_system"


def test_reader_engine_connects_as_askq_reader_read_only(database):
    engine = database.reader_engine
    assert _scalar(engine, "SELECT CURRENT_USER()") == "askq_reader@127.0.0.1"
    assert _scalar(engine, "SELECT @@session.time_zone") == "+00:00"
    assert _scalar(engine, "SELECT @@session.transaction_read_only") == 1
    assert _scalar(engine, "SELECT DATABASE()") == "askq_university"
    assert _scalar(engine, "SELECT COUNT(*) FROM students") == 1000


def test_reader_cannot_reach_system_or_authentication_tables(database):
    engine = database.reader_engine
    assert _denied(engine, "SELECT 1 FROM askq_system.app_user_credentials LIMIT 1")
    assert _denied(engine, "SELECT 1 FROM askq_system.query_history LIMIT 1")
    assert _denied(engine, "SELECT 1 FROM askq_university.users LIMIT 1")
    assert _denied(engine, "SELECT 1 FROM askq_university.roles LIMIT 1")


def test_reader_session_refuses_writes(database):
    # 1142: UPDATE not granted; 1792: statement not allowed in a READ ONLY transaction.
    with pytest.raises(DBAPIError) as info, database.reader_connection() as connection:
        connection.execute(text("UPDATE grade_scale SET min_marks = min_marks WHERE 1 = 0"))
    assert info.value.orig.args[0] in (1142, 1792)


def test_app_cannot_read_organisational_data(database):
    assert _denied(database.app_engine, "SELECT 1 FROM askq_university.students LIMIT 1")
    assert _denied(database.app_engine, "SELECT 1 FROM askq_university.teachers LIMIT 1")


def test_orm_models_match_live_tables(database, settings):
    schemas = {"university": settings.db_university_name, "system": settings.db_system_name}
    with database.app_engine.connect() as connection:
        for table in Base.metadata.sorted_tables:
            live = {
                row.COLUMN_NAME: row.IS_NULLABLE == "YES"
                for row in connection.execute(
                    text(
                        "SELECT COLUMN_NAME, IS_NULLABLE FROM information_schema.COLUMNS "
                        "WHERE TABLE_SCHEMA = :s AND TABLE_NAME = :t"
                    ),
                    {"s": schemas[table.schema], "t": table.name},
                )
            }
            assert live, f"{table.fullname} not visible to askq_app"
            for column in table.columns:
                assert column.name in live, f"{table.fullname}.{column.name} missing"
                assert column.nullable == live[column.name], f"{table.fullname}.{column.name}"


def test_phase2_data_intact(database):
    with database.app_engine.connect() as connection:
        roles = dict(
            connection.execute(text("SELECT role_code, role_id FROM askq_university.roles")).all()
        )
        users = connection.execute(text("SELECT COUNT(*) FROM askq_university.users")).scalar_one()
    assert roles == {role.value: role_id for role, role_id in ROLE_IDS.items()}
    assert users == 1041


def test_health_db_against_mysql(settings, database):
    with TestClient(create_app(settings, database)) as client:
        response = client.get("/health/db")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "checks": {"app": "ok", "reader": "ok"}}


# ---------- authentication end to end (rolled back) ----------


def test_login_and_me_end_to_end(settings, database):
    if not settings.is_configured("jwt_secret"):
        pytest.skip("JWT_SECRET is not configured in .env")
    before = _system_row_counts(database)
    password = secrets.token_urlsafe(18)
    password_hash = hash_password(password)

    connection = database.app_engine.connect()
    outer = connection.begin()
    try:
        session = Session(bind=connection, join_transaction_mode="create_savepoint")
        # The audit log keeps earlier real activity; only rows after this mark are ours.
        last_audit_id = session.execute(
            text("SELECT COALESCE(MAX(audit_id), 0) FROM security_audit_log")
        ).scalar_one()

        # One real account per role, straight from the seeded data.
        picked: dict[Role, User] = {}
        for role in Role:
            picked[role] = session.scalars(
                select(User)
                .where(User.role_id == ROLE_IDS[role], User.is_active.is_(True))
                .order_by(User.user_id)
                .limit(1)
            ).one()
            credentials.set_password_hash(session, picked[role].user_id, password_hash, utcnow())
        session.flush()
        hod_department = session.scalars(
            select(Department.department_id).where(
                Department.head_teacher_id == picked[Role.HOD].teacher_id
            )
        ).one()

        def override() -> Iterator[Session]:
            yield session

        app = create_app(settings, database)
        app.dependency_overrides[get_app_session] = override
        with TestClient(app) as client:
            for role, user in picked.items():
                response = client.post(
                    "/api/v1/auth/login", json={"username": user.username, "password": password}
                )
                assert response.status_code == 200, role
                body = response.json()
                assert body["user"]["role"] == role and body["user"]["id"] == user.user_id
                token = body["access_token"]
                me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
                assert me.status_code == 200 and me.json()["role"] == role

            wrong = client.post(
                "/api/v1/auth/login",
                json={"username": picked[Role.STUDENT].username, "password": password + "x"},
            )
            assert wrong.status_code == 401

        hod = build_user_context(session, picked[Role.HOD])
        assert hod is not None and hod.scope.department_id == hod_department
        events = session.execute(
            text(
                "SELECT event_type, COUNT(*) FROM security_audit_log "
                "WHERE audit_id > :last GROUP BY event_type"
            ),
            {"last": last_audit_id},
        ).all()
        assert dict(events) == {"LOGIN_SUCCEEDED": 4, "LOGIN_FAILED": 1}
        session.close()
    finally:
        outer.rollback()
        connection.close()

    assert _system_row_counts(database) == before
