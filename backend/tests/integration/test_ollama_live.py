"""Live smoke test: the real local Ollama server and model (skipped by default).

Run with:  python -m pytest tests/integration/test_ollama_live.py --ollama

Uses OLLAMA_BASE_URL / OLLAMA_MODEL / ... from the real .env (defaults:
http://127.0.0.1:11434, qwen2.5-coder:7b). It checks the integration, not the
model's accuracy: the answer must match the strict schema, and whatever SQL
the model wrote is still only accepted if the unchanged validator accepts it.
One regression checks the department join path that qwen2.5-coder got wrong
(course_offerings has no department_id) against the catalog, statically.
No database is touched.
"""

import pytest
import sqlglot
from sqlglot import exp

from app.config import Settings
from app.llm.ollama import OllamaSqlGenerator
from app.llm.sql_generator import GeneratedSql, GenerationRequest
from app.query.catalog import CATALOG
from app.query.schema_context import schema_context
from app.query.sql_validator import SqlValidationError, validate_sql
from app.rbac.roles import Role
from tests.test_prompt_join_paths import qualified_columns

pytestmark = pytest.mark.ollama


@pytest.fixture(scope="module")
def live_settings() -> Settings:
    return Settings().model_copy(update={"llm_provider": "ollama"})


@pytest.fixture(scope="module")
def generator(live_settings) -> OllamaSqlGenerator:
    return OllamaSqlGenerator.from_settings(live_settings)


def _request(
    question: str, role: Role = Role.ADMIN, scope: str = "the whole university"
) -> GenerationRequest:
    return GenerationRequest(
        question=question,
        role=role.value,
        scope_description=scope,
        schema_context=schema_context(role),
    )


def test_simple_question_returns_valid_structured_select(generator, live_settings):
    result = generator.generate(_request("How many students are there?"))
    assert isinstance(result, GeneratedSql)
    assert result.sql, "the model should answer a question the schema covers"
    validate_sql(
        result.sql,
        catalog_tables=CATALOG,
        university_db=live_settings.db_university_name,
    )


def test_destructive_request_never_yields_executable_ddl_or_dml(generator, live_settings):
    result = generator.generate(_request("Delete all students and drop the grades table."))
    if not result.sql:
        return  # declined: the pipeline reports UNANSWERABLE
    # Whatever the model wrote, the validator must not let a write through.
    try:
        validate_sql(
            result.sql,
            catalog_tables=CATALOG,
            university_db=live_settings.db_university_name,
        )
    except SqlValidationError:
        return
    assert result.sql.lstrip().upper().startswith(("SELECT", "WITH", "("))


def test_department_enrollment_count_uses_real_join_path(generator, live_settings):
    """Regression: qwen2.5-coder joined course_offerings on a department_id it lacks."""
    result = generator.generate(
        _request(
            "How many students are enrolled in each department?",
            Role.HOD,
            "your own department (department_id = 1)",
        )
    )
    assert result.sql, "the model should answer a question the schema covers"
    sql = result.sql.strip().rstrip(";")
    columns = qualified_columns(sql)  # raises on an unknown table or column
    assert ("course_offerings", "department_id") not in columns
    tree = sqlglot.parse_one(sql, read="mysql")
    assert tree.args.get("limit") is None, "a count per department returns every department"
    if "enrollments" in {t.name for t in tree.find_all(exp.Table)}:
        assert ("courses", "department_id") in columns or ("students", "department_id") in columns
        assert any(isinstance(c.this, exp.Distinct) for c in tree.find_all(exp.Count))
    validate_sql(
        result.sql,
        catalog_tables=CATALOG,
        university_db=live_settings.db_university_name,
    )
