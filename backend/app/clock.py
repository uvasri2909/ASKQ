"""The one place the backend reads the wall clock.

askq_system stores TIMESTAMP(3) values and every connection runs with
time_zone '+00:00', so values are exchanged as naive datetimes in UTC.
"""

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Current time as a naive UTC datetime (millisecond precision, like TIMESTAMP(3))."""
    now = datetime.now(UTC).replace(tzinfo=None)
    return now.replace(microsecond=now.microsecond // 1000 * 1000)
