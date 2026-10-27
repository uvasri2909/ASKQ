"""Runs an authorized SELECT through askq_reader, and nothing else.

The only way in is Database.reader_connection(): the askq_reader account
(SELECT-only grants) on a read-only MySQL session. There is no code path that
runs model-derived SQL on the askq_app engine or as root.

Per statement: max_execution_time (server-side timeout) is set on the session
first; the SQL runs with no_parameters=True so PyMySQL never %-formats it
(LIKE '%x%' stays literal); at most max_rows rows are fetched.
"""

import logging
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from datetime import time as dtime
from decimal import Decimal
from typing import Any

from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from app.db.session import Database

logger = logging.getLogger(__name__)

# MySQL error numbers
_TIMEOUT = 3024  # ER_QUERY_TIMEOUT (max_execution_time exceeded)
_ACCESS_DENIED = (1142, 1143, 1044, 1227)
# Errors whose message names only schema objects (columns, tables, functions),
# never row values, e.g. 1054 "Unknown column 'c.x' in 'on clause'". Their text
# is logged at DEBUG for diagnosis. Others are logged by number only: some quote
# data (1292 "Truncated incorrect DOUBLE value: '<value>'") or the account (1142).
_IDENTIFIER_ONLY_ERRORS = frozenset({1052, 1054, 1055, 1146, 1248, 1305})
_MAX_LOGGED_MESSAGE = 300


class ExecutionCode:
    QUERY_TIMEOUT = "QUERY_TIMEOUT"
    ACCESS_DENIED = "READER_ACCESS_DENIED"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    DATABASE_UNAVAILABLE = "DATABASE_UNAVAILABLE"


_MESSAGES = {
    ExecutionCode.QUERY_TIMEOUT: "The query took too long and was stopped.",
    ExecutionCode.ACCESS_DENIED: "The query could not be run.",
    ExecutionCode.EXECUTION_ERROR: "The query could not be run.",
    ExecutionCode.DATABASE_UNAVAILABLE: "The database is temporarily unavailable.",
}


class QueryExecutionError(Exception):
    def __init__(self, code: str, elapsed_ms: int) -> None:
        super().__init__(code)
        self.code = code
        self.message = _MESSAGES[code]
        self.elapsed_ms = elapsed_ms


@dataclass(frozen=True, slots=True)
class QueryResult:
    columns: list[str]
    rows: list[list[Any]]
    execution_ms: int

    @property
    def row_count(self) -> int:
        return len(self.rows)


def to_json_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime | date | dtime):
        return value.isoformat()
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, bytes | bytearray):
        return value.decode("utf-8", errors="replace")
    return value


def _safe_message(exc: DBAPIError, number: Any) -> str:
    """MySQL's message for identifier-only errors, on one line; else withheld."""
    args = exc.orig.args if exc.orig is not None else ()
    if number not in _IDENTIFIER_ONLY_ERRORS or len(args) < 2:
        return "(message withheld)"
    return " ".join(str(args[1]).split())[:_MAX_LOGGED_MESSAGE]


class ReaderExecutor:
    def __init__(self, database: Database, *, timeout_ms: int, max_rows: int) -> None:
        self._database = database
        self._timeout_ms = int(timeout_ms)
        self._max_rows = int(max_rows)

    def execute(self, sql: str) -> QueryResult:
        started = time.perf_counter()

        def elapsed() -> int:
            return int((time.perf_counter() - started) * 1000)

        try:
            with self._database.reader_connection() as connection:
                if connection.dialect.name == "mysql":
                    connection.exec_driver_sql(
                        f"SET SESSION max_execution_time = {self._timeout_ms}"
                    )
                result = connection.execution_options(no_parameters=True).exec_driver_sql(sql)
                columns = list(result.keys())
                rows = [[to_json_value(v) for v in row] for row in result.fetchmany(self._max_rows)]
                result.close()
        except DBAPIError as exc:
            number = exc.orig.args[0] if exc.orig is not None and exc.orig.args else None
            if number == _TIMEOUT:
                code = ExecutionCode.QUERY_TIMEOUT
            elif number in _ACCESS_DENIED:
                # The validator and authorizer let through something MySQL refused:
                # defence in depth worked, but it must be investigated.
                code = ExecutionCode.ACCESS_DENIED
                logger.error("askq_reader privilege error %s on a validated query", number)
            elif exc.connection_invalidated:
                code = ExecutionCode.DATABASE_UNAVAILABLE
            else:
                code = ExecutionCode.EXECUTION_ERROR
            logger.warning("query execution failed: %s (mysql error %s)", code, number)
            logger.debug("mysql error %s: %s", number, _safe_message(exc, number))
            raise QueryExecutionError(code, elapsed()) from None
        except SQLAlchemyError as exc:
            logger.warning("query execution failed: %s", type(exc).__name__)
            raise QueryExecutionError(ExecutionCode.DATABASE_UNAVAILABLE, elapsed()) from None
        return QueryResult(columns=columns, rows=rows, execution_ms=elapsed())
