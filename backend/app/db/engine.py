"""Engine construction for the two MySQL accounts.

Engines are built lazily (by app.db.session.Database) and never connect at
construction time. Credentials go into a sqlalchemy URL object, whose repr
masks the password; hide_parameters keeps bound values out of error messages.
"""

from typing import Any

from sqlalchemy import URL, Engine, create_engine

from app.config import Settings

# Logical schema names used by the ORM models, mapped to the configured
# database names at execution time.
UNIVERSITY_SCHEMA = "university"
SYSTEM_SCHEMA = "system"

# Every ASKQ connection works in UTC (askq_system uses TIMESTAMP(3)).
APP_SESSION_INIT = "SET SESSION time_zone = '+00:00'"
# The reader session is additionally read-only, as defence in depth on top of
# its SELECT-only grants.
READER_SESSION_INIT = "SET SESSION time_zone = '+00:00', SESSION transaction_read_only = ON"


def schema_translate_map(settings: Settings) -> dict[str, str]:
    return {
        UNIVERSITY_SCHEMA: settings.db_university_name,
        SYSTEM_SCHEMA: settings.db_system_name,
    }


def _url(settings: Settings, user: str, password: str, database: str) -> URL:
    return URL.create(
        "mysql+pymysql",
        username=user,
        password=password,
        host=settings.db_host,
        port=settings.db_port,
        database=database,
        query={"charset": "utf8mb4"},
    )


def _engine_options(settings: Settings, init_command: str) -> dict[str, Any]:
    return {
        "pool_pre_ping": True,
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_recycle": settings.db_pool_recycle_seconds,
        "pool_timeout": 10,
        "hide_parameters": True,
        "connect_args": {
            "connect_timeout": settings.db_connect_timeout_seconds,
            "init_command": init_command,
        },
        "execution_options": {"schema_translate_map": schema_translate_map(settings)},
    }


def build_app_engine(settings: Settings) -> Engine:
    """askq_app: authentication lookups and askq_system bookkeeping."""
    url = _url(
        settings,
        settings.db_app_user,
        settings.secret("db_app_password"),
        settings.db_system_name,
    )
    return create_engine(url, **_engine_options(settings, APP_SESSION_INIT))


def build_reader_engine(settings: Settings) -> Engine:
    """askq_reader: SELECT-only access to organisational data, read-only session."""
    url = _url(
        settings,
        settings.db_reader_user,
        settings.secret("db_reader_password"),
        settings.db_university_name,
    )
    return create_engine(url, **_engine_options(settings, READER_SESSION_INIT))
