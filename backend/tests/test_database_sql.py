"""Offline checks of the database/ SQL, grants and scripts (no MySQL connection).

What cannot be proven here, and is only proven when database/setup_db.ps1 runs
against a real server: that MySQL 8.0.46 accepts every statement. These tests
check structure, policy and consistency so that run has no surprises.
"""

import re
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DB = ROOT / "database"
sys.path.insert(0, str(DB / "seed"))
sys.path.insert(0, str(DB / "tools"))

import verify_accounts as va  # noqa: E402
from askq_seed import render_cohort_checks  # noqa: E402
from askq_seed.reference import DATA_AS_OF  # noqa: E402

UNIVERSITY_DDL = (DB / "schema" / "02_university_schema.sql").read_text(encoding="utf-8")
SYSTEM_DDL = (DB / "schema" / "03_system_schema.sql").read_text(encoding="utf-8")
VIEWS = (DB / "schema" / "05_views.sql").read_text(encoding="utf-8")
VERIFY = (DB / "validation" / "verify_database.sql").read_text(encoding="utf-8")
GRANTS = (DB / "accounts" / "grants.sql").read_text(encoding="utf-8")
SETUP = (DB / "setup_db.ps1").read_text(encoding="utf-8")


def _sql_code(text: str) -> str:
    """SQL with '--' comment lines removed."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("--"))


def _tables(ddl: str) -> set[str]:
    return set(re.findall(r"^CREATE TABLE (\w+)", ddl, re.M))


# ---------- Structure counts stay in sync with verify_database.sql ----------


def test_verify_database_constraint_counts_match_ddl():
    ddl = _sql_code(UNIVERSITY_DDL) + _sql_code(SYSTEM_DDL)
    declared = {
        "enforced check constraints": len(re.findall(r"CONSTRAINT ck_\w+\s+CHECK", ddl)),
        "foreign keys (both databases)": len(re.findall(r"FOREIGN KEY", ddl)),
        "unique keys (both databases)": len(re.findall(r"UNIQUE KEY", ddl)),
        "askq_university base tables": len(_tables(UNIVERSITY_DDL)),
        "askq_system base tables": len(_tables(SYSTEM_DDL)),
    }
    assert declared == {
        "enforced check constraints": 73,
        "foreign keys (both databases)": 34,
        "unique keys (both databases)": 37,
        "askq_university base tables": 17,
        "askq_system base tables": 10,
    }
    for name, count in declared.items():
        assert f"'{name}', '= {count}'" in VERIFY, name


def test_every_table_is_innodb_utf8mb4():
    for ddl in (UNIVERSITY_DDL, SYSTEM_DDL):
        bodies = re.findall(r"^CREATE TABLE \w+ \(.*?^\) (ENGINE=[^;]*);", ddl, re.M | re.S)
        assert len(bodies) == len(_tables(ddl))
        for tail in bodies:
            assert "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci" in tail


# ---------- Views: deterministic, portable DEFINER ----------


def test_views_do_not_read_the_clock():
    code = _sql_code(VIEWS).upper()
    for fn in ("CURRENT_DATE", "CURDATE", "NOW(", "SYSDATE", "CURRENT_TIMESTAMP", "UTC_DATE"):
        assert fn not in code, fn


def test_view_reference_date_is_the_dataset_date():
    dates = set(re.findall(r"DATE '(\d{4}-\d{2}-\d{2})'", _sql_code(VIEWS)))
    assert dates == {DATA_AS_OF.isoformat()}


def test_views_use_current_user_definer_and_invoker_security():
    code = _sql_code(VIEWS)
    creates = re.findall(r"CREATE (.*?)\s*\nVIEW (\w+)", code)
    assert [name for _, name in creates] == ["v_fee_balances", "v_attendance_summary"]
    for clause, name in creates:
        assert clause == "DEFINER = CURRENT_USER SQL SECURITY INVOKER", name
    assert "mysql.sys" not in code


# ---------- Security-demo cohort SQL ----------


def test_committed_cohort_check_sql_is_up_to_date():
    committed = (DB / "validation" / "verify_security_cohorts.sql").read_text(encoding="utf-8")
    assert committed == render_cohort_checks(), (
        "run: backend\\.venv\\Scripts\\python database\\seed\\generate_seed.py --refresh-validation"
    )


def test_setup_uses_committed_cohort_sql_not_generated_output():
    assert "validation\\verify_security_cohorts.sql" in SETUP
    assert "generated\\verify_security_cohorts.sql" not in SETUP
    assert "Join-Path $generated 'verify_security_cohorts.sql'" not in SETUP


# ---------- Grants: strict MySQL 8.0 grammar (the forms used) + policy ----------

MYSQL_STATIC_PRIVILEGES = {
    "ALTER", "ALTER ROUTINE", "CREATE", "CREATE ROLE", "CREATE ROUTINE", "CREATE TABLESPACE",
    "CREATE TEMPORARY TABLES", "CREATE USER", "CREATE VIEW", "DELETE", "DROP", "DROP ROLE",
    "EVENT", "EXECUTE", "FILE", "GRANT OPTION", "INDEX", "INSERT", "LOCK TABLES", "PROCESS",
    "PROXY", "REFERENCES", "RELOAD", "REPLICATION CLIENT", "REPLICATION SLAVE", "SELECT",
    "SHOW DATABASES", "SHOW VIEW", "SHUTDOWN", "SUPER", "TRIGGER", "UPDATE", "USAGE",
}  # fmt: skip
_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_ACCOUNT = r"'(?P<user>[a-z_]+)'@'(?P<host>[^']+)'"
GRANT_RE = re.compile(
    rf"GRANT (?P<privs>[A-Z]+(?: [A-Z]+)*(?:, [A-Z]+(?: [A-Z]+)*)*) "
    rf"ON (?P<db>{_IDENT})\.(?P<obj>{_IDENT}) TO {_ACCOUNT}"
)
REVOKE_RE = re.compile(rf"REVOKE ALL PRIVILEGES, GRANT OPTION FROM {_ACCOUNT}")


def _grant_statements():
    code = _sql_code(GRANTS)
    assert code.rstrip().endswith(";")
    return [" ".join(s.split()) for s in code.split(";") if s.strip()]


@pytest.fixture(scope="module")
def grants():
    """{(user, host): {(db, object): {privileges}}}, after validating every statement."""
    objects = {
        "askq_university": _tables(UNIVERSITY_DDL) | set(re.findall(r"^VIEW (\w+)", VIEWS, re.M)),
        "askq_system": _tables(SYSTEM_DDL),
    }
    result: dict = {}
    revoked = set()
    for statement in _grant_statements():
        if m := REVOKE_RE.fullmatch(statement):
            revoked.add((m["user"], m["host"]))
            continue
        m = GRANT_RE.fullmatch(statement)
        assert m, f"not a valid table-level GRANT: {statement}"
        privileges = {p.strip() for p in m["privs"].split(",")}
        assert privileges <= MYSQL_STATIC_PRIVILEGES, statement
        assert m["obj"] in objects.get(m["db"], set()), f"unknown object: {statement}"
        account = (m["user"], m["host"])
        assert account in revoked, f"grant before its REVOKE: {statement}"
        result.setdefault(account, {}).setdefault((m["db"], m["obj"]), set()).update(privileges)
    return result


def test_grants_only_for_the_two_accounts_on_127_0_0_1(grants):
    assert set(grants) == {("askq_reader", "127.0.0.1"), ("askq_app", "127.0.0.1")}
    assert "localhost" not in _sql_code(GRANTS)
    assert "*" not in _sql_code(GRANTS)  # no database-wide or global grants
    assert "WITH GRANT OPTION" not in GRANTS.upper()


def test_reader_is_select_only_on_intended_university_objects(grants):
    reader = grants[("askq_reader", "127.0.0.1")]
    assert {db for db, _ in reader} == {"askq_university"}
    assert all(privs == {"SELECT"} for privs in reader.values())
    readable = {obj for _, obj in reader}
    assert readable == (_tables(UNIVERSITY_DDL) - {"users", "roles"}) | {
        "v_fee_balances",
        "v_attendance_summary",
    }
    assert len(readable) == 17


def test_app_privileges_are_minimal(grants):
    app = grants[("askq_app", "127.0.0.1")]
    append_only = {
        "query_history", "cair_ledger_entries", "cair_assessments", "cair_audit_findings",
        "security_audit_log", "evaluation_results",
    }  # fmt: skip
    for (db, obj), privs in app.items():
        assert privs <= {"SELECT", "INSERT", "UPDATE"}, obj
        if db == "askq_university":
            assert obj in {"users", "roles", "departments"} and privs == {"SELECT"}, obj
        elif obj in append_only:
            assert privs == {"SELECT", "INSERT"}, obj
    assert {obj for db, obj in app if db == "askq_system"} == _tables(SYSTEM_DDL)


# ---------- Host convention ----------


def test_accounts_are_created_on_127_0_0_1_only():
    assert "$AccountHost = '127.0.0.1'" in SETUP
    account_lines = [ln for ln in SETUP.splitlines() if "USER" in ln and "IDENTIFIED BY" in ln]
    assert len(account_lines) == 2
    assert all("@'$AccountHost'" in ln for ln in account_lines)
    assert va.EXPECTED_HOST == "127.0.0.1"
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert re.search(r"^DB_HOST=127\.0\.0\.1$", env_example, re.M)


# ---------- query_history constraints: truth table in SQLite ----------


def _query_history_sqlite():
    body = re.search(r"CREATE TABLE query_history \((.*?)\n\) ENGINE", SYSTEM_DDL, re.S)[1]
    columns = re.findall(
        r"^    (\w+)\s+(?:BIGINT|INT|VARCHAR|TEXT|MEDIUMTEXT|DECIMAL|TIMESTAMP)", body, re.M
    )
    checks = []
    for m in re.finditer(r"CONSTRAINT (ck_qh_\w+)\s+CHECK \(", body):
        depth, i = 1, m.end()
        while depth:
            depth += {"(": 1, ")": -1}.get(body[i], 0)
            i += 1
        checks.append((m[1], body[m.end() - 1 : i]))
    assert len(checks) == 11
    con = sqlite3.connect(":memory:")
    con.execute(
        "CREATE TABLE query_history ("
        + ", ".join(columns)
        + "".join(f", CONSTRAINT {name} CHECK {expr}" for name, expr in checks)
        + ")"
    )
    return con


def _insert(con, row):
    con.execute((va._QH + row).replace("askq_system.", ""))


@pytest.mark.parametrize("name", list(va.QH_VALID))
def test_query_history_accepts_every_valid_final_status(name):
    _insert(_query_history_sqlite(), va.QH_VALID[name])


@pytest.mark.parametrize("name", list(va.QH_INVALID))
def test_query_history_rejects_inconsistent_rows(name):
    with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
        _insert(_query_history_sqlite(), va.QH_INVALID[name])


def test_valid_rows_cover_all_final_statuses():
    statuses = {
        re.search(r"'(EXECUTED|RESTRICTED|BLOCKED|DENIED|REJECTED|FAILED)'", r)[1]
        for r in va.QH_VALID.values()
    }
    assert statuses == {"EXECUTED", "RESTRICTED", "BLOCKED", "DENIED", "REJECTED", "FAILED"}


# ---------- Account probe logic (pure) ----------


def test_probe_evaluation_rules():
    assert va.evaluate(va.deny("d", "x"), 1142, None)[0] == "PASS"
    assert va.evaluate(va.deny("d", "x"), None, None) == ("FAIL", "was ALLOWED")
    assert va.evaluate(va.deny("d", "x"), 1062, None)[0] == "FAIL"  # not a privilege error
    assert va.evaluate(va.allow("a", "x"), None, 5)[0] == "PASS"
    assert va.evaluate(va.value("v", "x", 0), None, 0)[0] == "PASS"
    assert va.evaluate(va.value("v", "x", 0), None, 3)[0] == "FAIL"
    assert va.evaluate(va.reject("r", "x", {3819}), 3819, None)[0] == "PASS"
    assert va.evaluate(va.reject("r", "x", {3819}), None, None)[0] == "FAIL"
    assert va.evaluate(va.observe("o", "x"), None, None)[0] == "EXPOSED"
    assert va.evaluate(va.observe("o", "x"), 1142, None)[0] == "not exposed"


def test_reader_probes_cover_metadata_and_dangerous_functions():
    text = " ".join(str(p.sql) for p in va.READER_PROBES)
    for needle in (
        "information_schema.TABLES",
        "information_schema.COLUMNS",
        "information_schema.PROCESSLIST",
        "performance_schema.threads",
        "performance_schema.global_variables",
        "sys.version",
        "mysql.user",
        "askq_system.",
        "SLEEP(",
        "BENCHMARK(",
        "LOAD_FILE(",
        "INTO OUTFILE",
        "@@datadir",
        "SET GLOBAL",
        "SET SESSION",
        "LOCK TABLES",
        "FOR UPDATE",
        "CREATE TEMPORARY TABLE",
        "GRANT ",
    ):
        assert needle in text, needle


# ---------- Static credential scan ----------

_SKIP_DIRS = {".git", ".venv", "node_modules", "generated", "__pycache__", ".pytest_cache",
              ".ruff_cache", "dist"}  # fmt: skip
_SECRET_PATTERNS = [
    re.compile(r"IDENTIFIED BY '(?!\$pw')"),
    re.compile(r"sk-ant-[A-Za-z0-9_-]{10,}"),
    re.compile(r"(?i)\bpassword\s*=\s*['\"][^'\"$]{6,}['\"]"),
    re.compile(r"(?i)^(DB_\w*PASSWORD|JWT_SECRET|ANTHROPIC_API_KEY)=(?!change-me|your-)\S+", re.M),
]


def _project_files():
    this_file = Path(__file__).resolve()
    for path in ROOT.rglob("*"):
        if path == this_file:  # contains the patterns themselves
            continue
        if path.is_file() and not _SKIP_DIRS & set(path.relative_to(ROOT).parts):
            yield path


def _is_local_env_file(path):
    """The real .env (and .env.*) holds the account passwords by design; it is git-ignored."""
    return (
        path.parent == ROOT
        and (path.name == ".env" or path.name.startswith(".env."))
        and (path.name != ".env.example")
    )


def test_env_file_ignored_and_no_hardcoded_credentials():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert {".env", ".env.*", "!.env.example"} <= set(ignored), ".env must stay git-ignored"
    hits = []
    for path in _project_files():
        if _is_local_env_file(path):
            continue
        if path.suffix.lower() in {".png", ".ico", ".svg", ".lock"} or path.name.endswith(
            "lock.json"
        ):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in _SECRET_PATTERNS:
            for m in pattern.finditer(text):
                hits.append(f"{path.relative_to(ROOT)}: {m[0][:40]}")
    assert not hits


# ---------- SQL syntax (sqlglot, MySQL dialect) ----------

SQL_FILES = [
    *sorted((DB / "schema").glob("*.sql")),
    *sorted((DB / "validation").glob("*.sql")),
    DB / "reset" / "drop_askq_databases.sql",
]


@pytest.mark.parametrize("path", SQL_FILES, ids=lambda p: p.name)
def test_sql_file_parses_as_mysql(path):
    """Every statement must fully parse (no fallback to an opaque 'Command').

    sqlglot does not model MySQL's view DEFINER / SQL SECURITY clause, so that
    clause (checked separately above) is removed before parsing the view bodies.
    """
    import logging

    import sqlglot
    from sqlglot import exp

    text = path.read_text(encoding="utf-8").replace(
        "CREATE DEFINER = CURRENT_USER SQL SECURITY INVOKER\nVIEW", "CREATE VIEW"
    )
    logging.disable(logging.WARNING)
    try:
        statements = [
            s for s in sqlglot.parse(text, read="mysql", error_level=sqlglot.ErrorLevel.RAISE) if s
        ]
    finally:
        logging.disable(logging.NOTSET)
    assert statements
    assert not [s.sql()[:60] for s in statements if isinstance(s, exp.Command)]
