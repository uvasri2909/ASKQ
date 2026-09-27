"""Password hashing with Argon2id (pwdlib / argon2-cffi).

Parameters are the argon2-cffi defaults (RFC 9106 low-memory profile:
t=3, m=64 MiB, p=4, 16-byte salt). Hashes are self-describing PHC strings, so
the parameters can be raised later and old hashes upgraded on the next login
(verify_and_update). Nothing here logs or returns a plaintext password.
"""

import secrets
from functools import lru_cache

from pwdlib import PasswordHash
from pwdlib.exceptions import PwdlibError
from pwdlib.hashers.argon2 import Argon2Hasher

MIN_PASSWORD_LENGTH = 12
# Bounds hashing cost for oversized input (Argon2 accepts any length).
MAX_PASSWORD_LENGTH = 1024

_hasher = PasswordHash((Argon2Hasher(),))


def hash_password(password: str) -> str:
    """A fresh salted Argon2id hash of the password."""
    if not password:
        raise ValueError("password must not be empty")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"password must be at most {MAX_PASSWORD_LENGTH} characters")
    return _hasher.hash(password)


def verify_and_update(password: str, password_hash: str) -> tuple[bool, str | None]:
    """(matches, upgraded_hash). upgraded_hash is set only when the parameters are outdated.

    A malformed or unknown hash counts as "no match". pwdlib's UnknownHashError
    carries the hash in its message, so it is swallowed here, never re-raised.
    """
    if not password or len(password) > MAX_PASSWORD_LENGTH:
        return False, None
    try:
        return _hasher.verify_and_update(password, password_hash)
    except PwdlibError:
        return False, None


def verify_password(password: str, password_hash: str) -> bool:
    return verify_and_update(password, password_hash)[0]


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return _hasher.hash(secrets.token_urlsafe(32))


def burn_verification_time(password: str) -> None:
    """Do the work of one real verification, so a login for an unknown user takes as long."""
    verify_password(password[:MAX_PASSWORD_LENGTH] or "x", _dummy_hash())


def password_policy_problems(password: str, username: str) -> list[str]:
    """Reasons a NEW password is unacceptable (empty list = acceptable)."""
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        problems.append(f"must be at most {MAX_PASSWORD_LENGTH} characters")
    if password.strip() != password:
        problems.append("must not start or end with whitespace")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    return problems
