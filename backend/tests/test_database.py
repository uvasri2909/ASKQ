"""Engine configuration and app/reader separation (no MySQL connection needed)."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from app.config import ConfigurationError
from app.db.engine import (
    APP_SESSION_INIT,
    READER_SESSION_INIT,
    build_app_engine,
    build_reader_engine,
)
from app.db.session import Database
from app.main import create_app
from tests.conftest import make_settings


@pytest.fixture
def mysql_settings():
    return make_settings()


def test_app_engine_uses_the_app_account(mysql_settings):
    engine = build_app_engine(mysql_settings)
    try:
        url = engine.url
        assert (url.drivername, url.username) == ("mysql+pymysql", "askq_app")
        assert (url.host, url.port, url.database) == ("127.0.0.1", 3306, "askq_system")
        assert url.query["charset"] == "utf8mb4"
    finally:
        engine.dispose()


def test_reader_engine_uses_the_reader_account_read_only(mysql_settings):
    engine = build_reader_engine(mysql_settings)
    try:
        assert (engine.url.username, engine.url.database) == ("askq_reader", "askq_university")
        assert "transaction_read_only = ON" in READER_SESSION_INIT
        assert "read_only" not in APP_SESSION_INIT
    finally:
        engine.dispose()


def test_engines_never_mix_accounts(mysql_settings):
    app_engine = build_app_engine(mysql_settings)
    reader_engine = build_reader_engine(mysql_settings)
    try:
        assert app_engine is not reader_engine
        assert app_engine.url.username != reader_engine.url.username
        assert app_engine.url.password == mysql_settings.secret("db_app_password")
        assert reader_engine.url.password == mysql_settings.secret("db_reader_password")
    finally:
        app_engine.dispose()
        reader_engine.dispose()


def test_passwords_never_rendered(mysql_settings):
    engine = build_app_engine(mysql_settings)
    try:
        secret = mysql_settings.secret("db_app_password")
        assert secret not in str(engine.url) and secret not in repr(engine)
        assert "***" in str(engine.url)
    finally:
        engine.dispose()


def test_pool_and_session_settings(mysql_settings):
    engine = build_app_engine(mysql_settings)
    try:
        assert engine.pool.size() == 5
        assert engine.pool._pre_ping is True
        assert engine.pool._recycle == 1800
        assert engine.hide_parameters is True
        assert engine.get_execution_options()["schema_translate_map"] == {
            "university": "askq_university",
            "system": "askq_system",
        }
    finally:
        engine.dispose()


def test_session_init_sets_utc():
    assert "time_zone = '+00:00'" in APP_SESSION_INIT
    assert "time_zone = '+00:00'" in READER_SESSION_INIT


@pytest.mark.parametrize("missing", ["db_app_password", "db_reader_password"])
def test_missing_password_is_a_configuration_error(missing):
    settings = make_settings(**{missing: None})
    builder = build_app_engine if missing == "db_app_password" else build_reader_engine
    with pytest.raises(ConfigurationError, match=missing.upper()):
        builder(settings)


def test_database_is_lazy():
    # No passwords configured: constructing is fine; only using an engine fails.
    db = Database(make_settings(db_app_password=None, db_reader_password=None))
    with pytest.raises(ConfigurationError):
        _ = db.app_engine
    with pytest.raises(ConfigurationError):
        _ = db.reader_engine


def test_app_session_is_bound_to_the_app_engine_only(database):
    with database.app_session() as session:
        assert session.get_bind() is database.app_engine
        assert session.get_bind() is not database.reader_engine


def test_reader_connection_is_a_plain_connection_on_the_reader_engine(database):
    with database.reader_connection() as connection:
        assert connection.engine is database.reader_engine


# ---------- /health/db ----------


def test_health_db_ok(client):
    response = client.get("/health/db")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "checks": {"app": "ok", "reader": "ok"}}


def test_health_db_unconfigured_is_503_without_details():
    settings = make_settings(db_app_password=None, db_reader_password=None)
    with TestClient(create_app(settings, Database(settings))) as client:
        response = client.get("/health/db")
    assert response.status_code == 503
    assert response.json() == {
        "status": "unavailable",
        "checks": {"app": "unavailable", "reader": "unavailable"},
    }


def test_health_db_reports_a_broken_connection_generically(settings, database):
    broken = create_engine("sqlite:///Z:/no/such/dir/askq.db")
    db = Database(settings, app_engine=database.app_engine, reader_engine=broken)
    with TestClient(create_app(settings, db)) as client:
        response = client.get("/health/db")
    assert response.status_code == 503
    assert response.json()["checks"] == {"app": "ok", "reader": "unavailable"}
    assert "sqlite" not in response.text.lower() and "no/such" not in response.text


def test_health_does_not_need_the_database():
    settings = make_settings(db_app_password=None, db_reader_password=None)
    with TestClient(create_app(settings, Database(settings))) as client:
        assert client.get("/health").status_code == 200
