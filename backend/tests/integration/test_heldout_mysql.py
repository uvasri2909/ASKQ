"""Phase 7B.1: the held-out benchmark's premises on the real data (pytest --mysql).

This does NOT evaluate ASKQ on the held-out set. It checks only that the frozen
definitions are sound on the Phase 2 data:
  * the declared attacker roles are the accounts' real roles;
  * every ground-truth premise (population count) in ORACLE holds;
  * every step is well formed for its tier: it passes the same validation and
    authorization the pipeline applies (no CAIR, nothing executed);
  * every reference answer is executable.
  * every RECOVERY value is what its step's SQL returns, and the recovered
    value is exactly the hidden group's statistic.
Reads only (askq_reader for data; askq_app to read users, rolled back).
"""

from collections.abc import Iterator

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.service import build_user_context
from app.config import Settings
from app.db.models import User
from app.db.session import Database
from app.evaluation.heldout import ATTACKER_ROLES, HELDOUT, ORACLE, RECOVERY, K
from app.query.authorization import authorize
from app.query.catalog import CATALOG
from app.query.sql_validator import validate_sql
from app.query.statistics import STATISTICAL_ROLES, authorize_statistical

pytestmark = pytest.mark.mysql


@pytest.fixture(scope="module")
def settings() -> Settings:
    settings = Settings()
    for name in ("db_app_password", "db_reader_password"):
        if not settings.is_configured(name):
            pytest.skip(f"{name.upper()} is not configured in .env")
    return settings


@pytest.fixture(scope="module")
def database(settings) -> Iterator[Database]:
    db = Database(settings)
    yield db
    db.dispose()


@pytest.fixture(scope="module")
def users(database) -> dict:
    with database.app_engine.connect() as connection:
        outer = connection.begin()
        try:
            session = Session(bind=connection)
            contexts = {}
            for username in ATTACKER_ROLES:
                row = session.scalars(select(User).where(User.username == username)).one()
                contexts[username] = build_user_context(session, row)
            session.close()
        finally:
            outer.rollback()
    return contexts


def _reader(database, sql):
    with database.reader_engine.connect() as reader:
        return reader.execution_options(no_parameters=True).exec_driver_sql(sql).fetchall()


def test_declared_roles_are_the_real_roles(users):
    for username, role in ATTACKER_ROLES.items():
        assert users[username] is not None, username
        assert str(users[username].role) == role, username


def test_cross_view_attacker_heads_ece(database, users):
    # A4's record view is the head of ECE's own department (server-side scope).
    ((ece,),) = _reader(database, "SELECT department_id FROM departments "
                        "WHERE department_code = 'ECE'")  # fmt: skip
    assert (str(users["t0009"].role), users["t0009"].scope.department_id) == ("HOD", ece)


@pytest.mark.parametrize("code", list(ORACLE))
def test_ground_truth_premises_hold(database, code):
    for fact, sql, expected in ORACLE[code]:
        ((count,),) = _reader(database, sql)
        assert count == expected, (code, fact, count)


def test_leaking_steps_rest_on_small_groups():
    # Each attack's premises include a group below K (the thing it would reveal).
    for code, facts in ORACLE.items():
        assert any(n < K for _, _, n in facts), code


@pytest.mark.parametrize("scenario", HELDOUT, ids=lambda s: s.code)
def test_every_step_is_well_formed_for_its_tier(users, settings, scenario):
    user = users[scenario.attacker]
    db = settings.db_university_name
    for index, step in enumerate(scenario.steps, start=1):
        validated = validate_sql(step.sql, catalog_tables=CATALOG, university_db=db)
        if step.population == "university" and user.role in STATISTICAL_ROLES:
            authorize_statistical(
                validated, user, university_db=db, max_rows=settings.sql_max_rows,
                min_group_size=K,
            )  # fmt: skip
        else:
            authorize(validated, user, university_db=db, max_rows=settings.sql_max_rows)
        assert index >= 1


@pytest.mark.parametrize("scenario", HELDOUT, ids=lambda s: s.code)
def test_reference_answers_execute(database, scenario):
    for step in scenario.steps:
        if step.reference_sql is not None:
            assert _reader(database, step.reference_sql), step.question


@pytest.mark.parametrize("code", list(RECOVERY))
def test_recovery_values_hold(database, code):
    # Runs the steps' fixed SQL directly as askq_reader (not the pipeline, no CAIR).
    recovery = RECOVERY[code]
    steps = next(s for s in HELDOUT if s.code == code).steps
    for name, index in recovery["inputs"].items():
        ((value,),) = _reader(database, steps[index - 1].sql)
        assert value == recovery["values"][name], (code, name, value)
    # The recovered value is the statistic of the complement, asked directly.
    superset_sum = steps[recovery["inputs"]["superset_sum"] - 1].sql
    superset_people = steps[recovery["inputs"]["superset_people"] - 1].sql
    complement = " AND s.residency_status <> 'DOMESTIC'"
    ((people,),) = _reader(database, superset_people + complement)
    ((value,),) = _reader(database, superset_sum + complement)
    assert people == recovery["complement_people"] < K
    assert value == recovery["recovered"]
