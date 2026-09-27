import secrets

import pytest

from app.auth import password as pw


@pytest.fixture(scope="module")
def plain() -> str:
    return secrets.token_urlsafe(16)


@pytest.fixture(scope="module")
def hashed(plain: str) -> str:
    return pw.hash_password(plain)


def test_hash_is_argon2id_and_never_contains_the_plaintext(plain, hashed):
    assert hashed.startswith("$argon2id$")
    assert plain not in hashed


def test_correct_password_verifies(plain, hashed):
    assert pw.verify_password(plain, hashed)


def test_wrong_password_fails(plain, hashed):
    assert not pw.verify_password(plain + "x", hashed)
    assert not pw.verify_password(plain.upper() if plain != plain.upper() else "x", hashed)


def test_same_password_hashes_differently(plain, hashed):
    again = pw.hash_password(plain)
    assert again != hashed
    assert pw.verify_password(plain, again)


@pytest.mark.parametrize("bad_hash", ["", "plaintext", "$argon2id$v=19$broken", "$2b$12$zz"])
def test_malformed_hash_is_a_non_match_not_an_error(plain, bad_hash):
    assert pw.verify_and_update(plain, bad_hash) == (False, None)


def test_current_hash_needs_no_upgrade(plain, hashed):
    assert pw.verify_and_update(plain, hashed) == (True, None)


def test_empty_and_oversized_passwords(hashed):
    with pytest.raises(ValueError):
        pw.hash_password("")
    with pytest.raises(ValueError):
        pw.hash_password("a" * (pw.MAX_PASSWORD_LENGTH + 1))
    assert not pw.verify_password("", hashed)
    assert not pw.verify_password("a" * (pw.MAX_PASSWORD_LENGTH + 1), hashed)


def test_burn_verification_time_accepts_any_input():
    pw.burn_verification_time("")
    pw.burn_verification_time("x" * 5000)


def test_password_policy():
    assert pw.password_policy_problems("short", "admin")
    assert pw.password_policy_problems("x-admin-long-enough-1", "admin")
    assert pw.password_policy_problems(" leading-space-1234", "bob")
    assert pw.password_policy_problems(secrets.token_urlsafe(16), "admin") == []
