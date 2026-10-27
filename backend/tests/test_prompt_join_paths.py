"""Join-path guidance in the schema context and the shared system prompt.

Regression for qwen2.5-coder joining departments to course_offerings on a
department_id that table does not have (MySQL error 1054). The guidance must
be present and must match the catalog, which mirrors the real schema.
"""

import re

import pytest
import sqlglot
from sqlglot import exp
from sqlglot.errors import OptimizeError
from sqlglot.optimizer.qualify import qualify

from app.evaluation.heldout import HELDOUT
from app.llm.prompt import WORKED_EXAMPLES, system_prompt
from app.llm.sql_generator import GenerationRequest
from app.query.catalog import CATALOG, TABLES
from app.query.schema_context import schema_context
from app.query.sql_validator import validate_sql
from app.rbac.roles import Role

OFFERING_TO_DEPARTMENT = "course_offerings.course_id = courses.course_id"


def prompt_for(role: Role) -> str:
    return system_prompt(
        GenerationRequest(
            question="How many students are enrolled in each department?",
            role=role.value,
            scope_description="your own department (department_id = 1)",
            schema_context=schema_context(role),
        )
    )


def test_hod_schema_says_offerings_have_no_department_id():
    text = schema_context(Role.HOD)
    offerings = text[text.index("TABLE course_offerings:") :].split("\n\n", 1)[0]
    assert "Has NO department_id" in offerings
    assert OFFERING_TO_DEPARTMENT in offerings
    assert "courses.department_id" in offerings
    assert "  department_id " not in offerings


@pytest.mark.parametrize("role", list(Role))
def test_prompt_has_join_paths(role):
    text = prompt_for(role)
    assert "Join paths:" in text
    assert OFFERING_TO_DEPARTMENT in text
    assert "then courses.department_id" in text
    assert "Department of a student: students.department_id" in text


def test_department_id_tables_match_the_catalog():
    with_department = {t.name for t in TABLES if "department_id" in t.column_names}
    line = next(line for line in prompt_for(Role.HOD).splitlines() if line.startswith("- Only "))
    listed = line.removeprefix("- Only ").split(" have department_id")[0]
    named = set(re.findall(r"[a-z_]+", listed)) - {"and"}
    assert named == with_department
    for table in ("course_offerings", "enrollments", "grades", "attendance_records"):
        assert "department_id" not in CATALOG[table].column_names


def test_every_column_named_in_join_paths_exists():
    section = prompt_for(Role.HOD).split("Join paths:", 1)[1].split("\n\n", 1)[0]
    for table, column in re.findall(r"\b([a-z_]+)\.([a-z_]+)\b", section):
        assert column in CATALOG[table].column_names, f"{table}.{column}"


# ---------- worked examples ----------


def _catalog_schema() -> dict[str, dict[str, str]]:
    return {t.name: dict.fromkeys(t.column_names, "INT") for t in TABLES}


def qualified_columns(sql: str) -> set[tuple[str, str]]:
    """(table, column) for every column, resolved against the catalog. Raises on unknown ones."""
    tree = qualify(
        sqlglot.parse_one(sql, read="mysql"),
        schema=_catalog_schema(),
        dialect="mysql",
        validate_qualify_columns=True,
    )
    aliases = {t.alias_or_name: t.name for t in tree.find_all(exp.Table)}
    return {(aliases[c.table], c.name) for c in tree.find_all(exp.Column) if c.table in aliases}


def test_qualified_columns_rejects_the_qwen_join():
    with pytest.raises(OptimizeError):
        qualified_columns(
            "SELECT d.department_name FROM departments d"
            " JOIN course_offerings co ON d.department_id = co.department_id"
        )


@pytest.mark.parametrize("role", list(Role))
def test_prompt_has_the_worked_examples(role):
    text = prompt_for(role)
    assert "Worked examples" in text
    for question, sql in WORKED_EXAMPLES:
        assert f"Question: {question}\nSQL:\n{sql}\n" in text


@pytest.mark.parametrize(("question", "sql"), WORKED_EXAMPLES)
def test_worked_example_uses_only_catalog_identifiers(question, sql):
    columns = qualified_columns(sql)  # raises on an unknown table or column
    assert columns and all(column in CATALOG[table].column_names for table, column in columns)
    assert ("course_offerings", "department_id") not in columns
    validate_sql(sql, catalog_tables=CATALOG, university_db="askq_university")


@pytest.mark.parametrize(("question", "sql"), WORKED_EXAMPLES)
def test_worked_examples_follow_the_prompt_rules(question, sql):
    tree = sqlglot.parse_one(sql, read="mysql")
    assert tree.args.get("group") is not None and tree.args.get("limit") is None
    assert tree.args.get("where") is None  # no model-added scope filters
    if "enrollments" in {t.name for t in tree.find_all(exp.Table)}:
        assert any(isinstance(c.this, exp.Distinct) for c in tree.find_all(exp.Count))


def _tables(sql: str) -> set[str]:
    return {t.name for t in sqlglot.parse_one(sql, read="mysql").find_all(exp.Table)}


def _heldout_steps():
    return [step for scenario in HELDOUT for step in scenario.steps]


@pytest.mark.parametrize(("question", "sql"), WORKED_EXAMPLES)
def test_worked_examples_do_not_preview_the_heldout_benchmark(question, sql):
    """No worked example may be a sub-pattern of a held-out query.

    The first version had "How many students are in each department?" over
    departments + students, a held-out answer minus one GROUP BY column. Any
    example whose tables are all used by one held-out query is rejected.
    """
    steps = _heldout_steps()
    assert question.lower() not in {step.question.lower() for step in steps}
    example = _tables(sql)
    for step in steps:
        for heldout_sql in (step.sql, step.reference_sql):
            if heldout_sql:
                assert not example <= _tables(heldout_sql), question


def test_enrollment_example_joins_through_courses():
    _, sql = WORKED_EXAMPLES[1]
    columns = qualified_columns(sql)
    assert {
        ("courses", "department_id"),
        ("course_offerings", "course_id"),
        ("enrollments", "offering_id"),
    } <= columns
