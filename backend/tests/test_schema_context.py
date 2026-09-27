import pytest

from app.query.catalog import CATALOG
from app.query.policy import POLICIES
from app.query.schema_context import schema_context
from app.rbac.roles import Role

NEVER = ("users", "roles", "askq_system", "password", "credential", "query_history", "jwt")


def _tables(text: str) -> set[str]:
    return {
        line.split()[1].rstrip(":")
        for line in text.splitlines()
        if line.startswith(("TABLE ", "VIEW "))
    }


@pytest.mark.parametrize("role", list(Role))
def test_only_permitted_tables_and_columns_are_described(role):
    text = schema_context(role)
    policy = POLICIES[role]
    assert _tables(text) == policy.tables
    for hidden in policy.denied_columns.values():
        for column in hidden:
            assert f"  {column} " not in text
    for word in NEVER:
        assert word not in text.lower().replace("_id", "")


def test_admin_sees_everything_teacher_sees_no_finance():
    assert _tables(schema_context(Role.ADMIN)) == set(CATALOG)
    teacher = schema_context(Role.TEACHER)
    assert "fees" not in _tables(teacher) and "v_fee_balances" not in _tables(teacher)


def test_scoped_tables_are_marked():
    text = schema_context(Role.STUDENT)
    assert (
        "TABLE grades: Final grade of a completed enrollment (Spring 2026). Rows are limited"
        in text
    )
    assert "Rows are limited" not in schema_context(Role.ADMIN)


def test_deterministic():
    assert schema_context(Role.HOD) == schema_context(Role.HOD)
