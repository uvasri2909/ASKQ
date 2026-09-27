import secrets

from sqlalchemy import select

from app.auth.password import verify_password
from app.cli import set_password as cli
from app.db.models import AppUserCredential, SecurityAuditEvent
from tests.conftest import ACCOUNTS, USERNAMES


def _run(session, username, answers):
    prompts = iter(answers)
    output: list[str] = []
    code = cli.set_password(session, username, lambda _msg: next(prompts), output.append)
    return code, "\n".join(output)


def test_sets_a_hashed_password_and_audits(db_session):
    new = secrets.token_urlsafe(16)
    code, output = _run(db_session, USERNAMES[ACCOUNTS.no_credential], [new, new])
    assert code == 0
    assert new not in output
    credential = db_session.get(AppUserCredential, ACCOUNTS.no_credential)
    assert credential.password_hash.startswith("$argon2id$")
    assert new not in credential.password_hash
    assert verify_password(new, credential.password_hash)
    event = db_session.scalars(select(SecurityAuditEvent)).one()
    assert (event.event_type, event.details) == ("PASSWORD_SET", {"source": "cli"})


def test_reset_clears_lock_and_failed_attempts(db_session):
    credential = db_session.get(AppUserCredential, ACCOUNTS.teacher)
    credential.failed_login_attempts = 9
    db_session.commit()
    new = secrets.token_urlsafe(16)
    assert _run(db_session, USERNAMES[ACCOUNTS.teacher], [new, new])[0] == 0
    assert db_session.get(AppUserCredential, ACCOUNTS.teacher).failed_login_attempts == 0


def test_rejects_mismatch_weak_unknown_and_inactive(db_session):
    new = secrets.token_urlsafe(16)
    assert _run(db_session, "admin", [new, new + "x"]) == (1, "Passwords do not match.")
    assert _run(db_session, "admin", ["short", "short"])[0] == 1
    assert _run(db_session, "nobody", [])[0] == 1
    assert _run(db_session, USERNAMES[ACCOUNTS.inactive], [])[0] == 1
    assert db_session.scalars(select(SecurityAuditEvent)).all() == []


def test_refuses_non_interactive_input(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert cli.main(["admin"]) == 2
