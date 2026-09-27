"""Set (or reset) the login password of an existing ASKQ user.

    cd C:\\ASKQ\\backend
    .venv\\Scripts\\python -m app.cli.set_password admin

The password is typed twice at a hidden prompt (never a command-line argument,
so it stays out of shell history and process lists), hashed with Argon2id, and
stored in askq_system.app_user_credentials through the askq_app account. It is
never printed or logged. Setting a password clears failed attempts and any
lock, and revokes tokens issued before the change.
"""

import argparse
import getpass
import sys
from collections.abc import Callable

from sqlalchemy.orm import Session

from app.auth.password import hash_password, password_policy_problems
from app.clock import utcnow
from app.config import ConfigurationError, get_settings
from app.db.repositories import audit, credentials, users
from app.db.session import Database


def set_password(
    session: Session,
    username: str,
    prompt: Callable[[str], str],
    out: Callable[[str], None] = print,
) -> int:
    """Returns a process exit code. prompt must not echo (getpass.getpass)."""
    user = users.get_by_username(session, username.lower())
    if user is None:
        out(f"No user named '{username}'.")
        return 1
    if not user.is_active:
        out(f"User '{user.username}' is inactive; activate the account first.")
        return 1

    password = prompt("New password: ")
    problems = password_policy_problems(password, user.username)
    if problems:
        out("Password rejected: " + "; ".join(problems) + ".")
        return 1
    if prompt("Repeat new password: ") != password:
        out("Passwords do not match.")
        return 1

    credentials.set_password_hash(session, user.user_id, hash_password(password), utcnow())
    audit.record(
        session,
        audit.AuditEvent.PASSWORD_SET,
        audit.Severity.INFO,
        user_id=user.user_id,
        details={"source": "cli"},
    )
    session.commit()
    out(f"Password set for '{user.username}' ({user.role.role_code}).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("username", help="existing askq_university.users username")
    args = parser.parse_args(argv)
    if not sys.stdin.isatty():
        print("Run this interactively: the password is read from a hidden prompt.")
        return 2

    database = Database(get_settings())
    try:
        with database.app_session() as session:
            return set_password(session, args.username, getpass.getpass)
    except ConfigurationError as exc:
        print(f"Not configured: {exc}")
        return 2
    finally:
        database.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
