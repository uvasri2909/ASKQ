"""The Database container and the FastAPI dependencies that hand out connections.

Separation of responsibilities is structural:
* app_session() returns an ORM Session bound ONLY to the askq_app engine.
* reader_connection() returns a plain Connection on the askq_reader engine,
  whose MySQL session is read-only. No ORM session is ever bound to it, so
  application metadata cannot be written through it.
"""

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from fastapi import Request
from sqlalchemy import Connection, Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.db.engine import build_app_engine, build_reader_engine


class Database:
    def __init__(
        self,
        settings: Settings,
        *,
        app_engine: Engine | None = None,
        reader_engine: Engine | None = None,
    ) -> None:
        self._settings = settings
        self._app_engine = app_engine
        self._reader_engine = reader_engine
        self._sessionmaker: sessionmaker[Session] | None = None
        self._lock = threading.Lock()

    @property
    def app_engine(self) -> Engine:
        """Raises ConfigurationError if DB_APP_PASSWORD is not configured."""
        with self._lock:
            if self._app_engine is None:
                self._app_engine = build_app_engine(self._settings)
            return self._app_engine

    @property
    def reader_engine(self) -> Engine:
        """Raises ConfigurationError if DB_READER_PASSWORD is not configured."""
        with self._lock:
            if self._reader_engine is None:
                self._reader_engine = build_reader_engine(self._settings)
            return self._reader_engine

    def app_session(self) -> Session:
        engine = self.app_engine
        with self._lock:
            if self._sessionmaker is None:
                self._sessionmaker = sessionmaker(bind=engine, expire_on_commit=False)
            return self._sessionmaker()

    @contextmanager
    def reader_connection(self) -> Iterator[Connection]:
        """A read-only connection for organisational data. Rolled back on exit, never committed."""
        with self.reader_engine.connect() as connection:
            yield connection

    def dispose(self) -> None:
        with self._lock:
            for engine in (self._app_engine, self._reader_engine):
                if engine is not None:
                    engine.dispose()


def get_database(request: Request) -> Database:
    return request.app.state.database


def get_app_session(request: Request) -> Iterator[Session]:
    """One askq_app ORM session per request; uncommitted work is rolled back on close."""
    with get_database(request).app_session() as session:
        yield session


def get_reader_connection(request: Request) -> Iterator[Connection]:
    """One askq_reader read-only connection per request (for the future query executor)."""
    with get_database(request).reader_connection() as connection:
        yield connection
