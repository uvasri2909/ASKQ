"""ReaderExecutor failure logging, with a fake reader connection (no MySQL).

MySQL's message is logged at DEBUG only for errors that name schema objects;
messages that can quote row values are withheld. The caller's error is the
same generic one either way.
"""

import logging
from contextlib import contextmanager

import pytest
from sqlalchemy.exc import OperationalError

from app.query.executor import ExecutionCode, QueryExecutionError, ReaderExecutor

SQL = "SELECT d.department_name FROM departments d JOIN course_offerings co ON 1 = 1"
SECRET_VALUE = "row-value-must-not-be-logged"


class FakeMySQLError(Exception):
    """Shaped like pymysql's errors: args = (number, message)."""


class FailingConnection:
    class dialect:
        name = "mysql"

    def __init__(self, error: Exception) -> None:
        self._error = error

    def execution_options(self, **_):
        return self

    def exec_driver_sql(self, sql: str):
        if sql.startswith("SET SESSION"):
            return None
        raise OperationalError(sql, None, self._error)


class FakeDatabase:
    def __init__(self, error: Exception) -> None:
        self._error = error

    @contextmanager
    def reader_connection(self):
        yield FailingConnection(self._error)


def run(number: int, message: str) -> QueryExecutionError:
    executor = ReaderExecutor(
        FakeDatabase(FakeMySQLError(number, message)), timeout_ms=1000, max_rows=10
    )
    with pytest.raises(QueryExecutionError) as info:
        executor.execute(SQL)
    return info.value


def test_unknown_column_message_is_logged_at_debug(caplog):
    caplog.set_level(logging.DEBUG, logger="app.query.executor")
    error = run(1054, "Unknown column 'co.department_id' in 'on clause'")
    assert error.code == ExecutionCode.EXECUTION_ERROR
    assert error.message == "The query could not be run."
    assert "co.department_id" not in error.message + str(error)
    debug = [r for r in caplog.records if r.levelno == logging.DEBUG]
    assert [r.getMessage() for r in debug] == [
        "mysql error 1054: Unknown column 'co.department_id' in 'on clause'"
    ]
    assert SQL not in caplog.text


def test_message_is_not_logged_above_debug(caplog):
    caplog.set_level(logging.INFO, logger="app.query.executor")
    run(1054, "Unknown column 'co.department_id' in 'on clause'")
    assert "co.department_id" not in caplog.text
    assert "EXECUTION_ERROR (mysql error 1054)" in caplog.text


@pytest.mark.parametrize(
    "number, message",
    [
        (1292, f"Truncated incorrect DOUBLE value: '{SECRET_VALUE}'"),
        (1366, f"Incorrect integer value: '{SECRET_VALUE}' for column 'x' at row 1"),
        (1142, f"SELECT command denied to user '{SECRET_VALUE}'@'localhost' for table 'users'"),
    ],
)
def test_messages_that_can_quote_data_are_withheld(number, message, caplog):
    caplog.set_level(logging.DEBUG, logger="app.query.executor")
    run(number, message)
    assert SECRET_VALUE not in caplog.text
    assert f"mysql error {number}: (message withheld)" in caplog.text


def test_logged_message_is_one_bounded_line(caplog):
    caplog.set_level(logging.DEBUG, logger="app.query.executor")
    run(1054, "Unknown column 'a'\nFAKE LOG LINE " + "x" * 1000)
    (record,) = [r for r in caplog.records if r.levelno == logging.DEBUG]
    assert "\n" not in record.getMessage()
    assert len(record.getMessage()) < 340
