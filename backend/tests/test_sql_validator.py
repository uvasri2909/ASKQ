import re
from pathlib import Path

import pytest

from app.query.catalog import CATALOG
from app.query.sql_validator import (
    MAX_SQL_LENGTH,
    SqlValidationError,
    ValidationCode,
    validate_sql,
)

DB = "askq_university"


def validate(sql):
    return validate_sql(sql, catalog_tables=CATALOG, university_db=DB)


def rejected(sql) -> SqlValidationError:
    with pytest.raises(SqlValidationError) as info:
        validate(sql)
    return info.value


def _sample_queries() -> list[str]:
    path = Path(__file__).resolve().parents[2] / "database" / "validation" / "sample_queries.sql"
    text = re.sub(r"--[^\n]*", "", path.read_text(encoding="utf-8"))
    return [
        s.strip() for s in text.split(";") if s.strip() and not s.strip().upper().startswith("USE")
    ]


VALID = [
    *_sample_queries(),
    "SELECT COUNT(*) FROM students",
    "SELECT YEAR(paid_on) AS y, SUM(amount) FROM fee_payments GROUP BY y",
    "SELECT DATE_FORMAT(paid_on, '%Y-%m') AS ym, COUNT(*) FROM fee_payments GROUP BY ym",
    "SELECT student_id, RANK() OVER (PARTITION BY department_id ORDER BY admission_year DESC) r "
    "FROM students",
    "SELECT DATEDIFF(end_date, start_date), DATE_ADD(start_date, INTERVAL 7 DAY) "
    "FROM academic_terms",
    "WITH x AS (SELECT department_id, COUNT(*) c FROM students GROUP BY department_id) "
    "SELECT MAX(c) FROM x",
    "SELECT course_code FROM courses UNION ALL SELECT course_code FROM courses LIMIT 5",
    "SELECT * FROM askq_university.students s WHERE EXISTS "
    "(SELECT 1 FROM enrollments e WHERE e.student_id = s.student_id)",
    "SELECT GROUP_CONCAT(course_code ORDER BY course_code SEPARATOR ', ') FROM courses",
    "SELECT CASE WHEN marks >= 85 THEN 'A' ELSE 'B' END, IF(marks > 50, 1, 0) FROM grades",
    "select count(*) from STUDENTS",  # identifiers are case-insensitive
    "SELECT COUNT(*) FROM students;",  # one trailing terminator is tolerated
    "SELECT '/* not a comment */', '-- nor this', '# nor this' FROM students",
]


@pytest.mark.parametrize("sql", VALID)
def test_valid_selects_pass(sql):
    validated = validate(sql)
    assert validated.tables <= set(CATALOG)


def test_validated_query_exposes_tables_columns_and_canonical_sql():
    v = validate(
        "SELECT d.department_name, COUNT(*) FROM students s "
        "JOIN departments d ON d.department_id = s.department_id GROUP BY d.department_name"
    )
    assert v.tables == {"students", "departments"}
    assert v.columns == {"department_id", "department_name"}
    assert v.sql.startswith("SELECT d.department_name, COUNT(*) FROM students AS s")


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO students (student_id) VALUES (1)",
        "UPDATE students SET year_level = 1",
        "DELETE FROM students",
        "REPLACE INTO students (student_id) VALUES (1)",
        "DROP TABLE students",
        "ALTER TABLE students ADD x INT",
        "CREATE TABLE x (a INT)",
        "CREATE VIEW v AS SELECT 1",
        "TRUNCATE students",
        "GRANT SELECT ON *.* TO x",
        "REVOKE SELECT ON students FROM x",
        "CALL p()",
        "EXECUTE stmt",
        "PREPARE s FROM 'SELECT 1'",
        "SET SESSION max_execution_time = 0",
        "SHOW TABLES",
        "HANDLER students OPEN",
        "LOCK TABLES students READ",
        "TABLE students",
        "VALUES ROW(1)",
        "DO SLEEP(1)",
    ],
)
def test_non_select_statements_rejected(sql):
    assert rejected(sql).code in {
        ValidationCode.NOT_SELECT,
        ValidationCode.PARSE_ERROR,
        ValidationCode.UNSUPPORTED_FEATURE,
    }


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1 FROM students; DROP TABLE students",
        "SELECT 1 FROM students; SELECT 2 FROM students",
        "SELECT 1 FROM students;;",
    ],
)
def test_multiple_statements_rejected(sql):
    assert rejected(sql).code == ValidationCode.MULTIPLE_STATEMENTS


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM students -- trailing",
        "SELECT * FROM students # hash",
        "SELECT /* block */ * FROM students",
        "SELECT /*!50000 SLEEP(5) */ 1 FROM students",  # MySQL EXECUTES this
        "SELECT /*+ MAX_EXECUTION_TIME(1) */ * FROM students",  # optimizer hint
    ],
)
def test_comments_of_every_kind_rejected(sql):
    assert rejected(sql).code == ValidationCode.COMMENTS


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM students INTO OUTFILE '/tmp/x'",
        "SELECT * FROM students INTO DUMPFILE '/tmp/x'",
        "SELECT * INTO OUTFILE '/tmp/x' FROM students",
    ],
)
def test_file_output_rejected(sql):
    assert rejected(sql).code in {ValidationCode.PARSE_ERROR, ValidationCode.UNSUPPORTED_FEATURE}


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM mysql.user",
        "SELECT * FROM information_schema.tables",
        "SELECT * FROM INFORMATION_SCHEMA.COLUMNS",
        "SELECT * FROM performance_schema.threads",
        "SELECT * FROM sys.version",
        "SELECT * FROM askq_system.query_history",
        "SELECT * FROM `askq_system`.`app_user_credentials`",
        "SELECT * FROM students WHERE student_id IN "
        "(SELECT user_id FROM askq_system.app_user_credentials)",
        "SELECT * FROM users",
        "SELECT * FROM roles",
        "SELECT * FROM askq_university.users",
        "SELECT * FROM no_such_table",
        "SELECT * FROM other_db.students",
    ],
)
def test_data_outside_the_catalog_rejected(sql):
    assert rejected(sql).code == ValidationCode.DATA_NOT_AVAILABLE


def test_protected_and_missing_tables_are_indistinguishable():
    protected = rejected("SELECT * FROM askq_system.app_user_credentials")
    missing = rejected("SELECT * FROM askq_system.no_such_table")
    users = rejected("SELECT * FROM users")
    unknown = rejected("SELECT * FROM no_such_table")
    assert protected.message == missing.message == users.message == unknown.message
    for error in (protected, users):
        assert "app_user_credentials" not in error.message and "users" not in error.message


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT SLEEP(5) FROM students",
        "SELECT BENCHMARK(1000000, MD5('a')) FROM students",
        "SELECT LOAD_FILE('/etc/passwd') FROM students",
        "SELECT GET_LOCK('x', 10) FROM students",
        "SELECT USER() FROM students",
        "SELECT CURRENT_USER() FROM students",
        "SELECT DATABASE() FROM students",
        "SELECT VERSION() FROM students",
        "SELECT @@version FROM students",
        "SELECT @@datadir FROM students",
        "SELECT @x FROM students",
        "SELECT @x := 1 FROM students",
        "SELECT COUNT(*) INTO @x FROM students",
        "SELECT * FROM students FOR UPDATE",
        "SELECT * FROM students LOCK IN SHARE MODE",
        "SELECT SQL_NO_CACHE * FROM students",
        "SELECT HIGH_PRIORITY * FROM students",
        "SELECT * FROM students USE INDEX (PRIMARY)",
        "SELECT * FROM students PARTITION (p0)",
        "SELECT student_id FROM students INTERSECT SELECT student_id FROM enrollments",
        "SELECT student_id FROM students EXCEPT SELECT student_id FROM enrollments",
        "WITH RECURSIVE r AS (SELECT 1 n UNION ALL SELECT n + 1 FROM r WHERE n < 9) "
        "SELECT * FROM r, students",
        "WITH students AS (SELECT 1 AS student_id) SELECT * FROM students",
        "SELECT * FROM students LIMIT ?",
        "SELECT 0x41 FROM students",
        "SELECT _utf8'a' FROM students",
        "SELECT first_name COLLATE utf8mb4_bin FROM students",
        "SELECT * FROM students WHERE MATCH(first_name) AGAINST ('x')",
        "SELECT JSON_EXTRACT('{}', '$.a') FROM students",
        "SELECT * FROM students s WHERE askq_university.s.student_id = 1",
        "SELECT * FROM JSON_TABLE('[1]', '$[*]' COLUMNS (a INT PATH '$')) j",
    ],
)
def test_unsafe_features_rejected(sql):
    assert rejected(sql).code in {
        ValidationCode.UNSUPPORTED_FEATURE,
        ValidationCode.PARSE_ERROR,
        ValidationCode.DATA_NOT_AVAILABLE,
        ValidationCode.NOT_SELECT,  # INTERSECT / EXCEPT roots
    }


@pytest.mark.parametrize("sql", [None, "", "   ", ";"])
def test_empty_rejected(sql):
    assert rejected(sql).code == ValidationCode.EMPTY


def test_constant_selects_rejected():
    assert rejected("SELECT 1").code == ValidationCode.DATA_NOT_AVAILABLE
    assert rejected("SELECT NOW()").code == ValidationCode.DATA_NOT_AVAILABLE


def test_oversized_sql_rejected():
    sql = "SELECT student_id FROM students WHERE " + " OR ".join(
        f"student_id = {i}" for i in range(2000)
    )
    assert len(sql) > MAX_SQL_LENGTH
    assert rejected(sql).code == ValidationCode.TOO_LARGE


def test_messages_do_not_describe_the_checks():
    error = rejected("SELECT SLEEP(5) FROM students")
    assert "SLEEP" not in error.message and "allowlist" not in error.message.lower()
    assert "SLEEP" in error.detail  # the specific reason stays server-side
