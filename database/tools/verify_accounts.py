"""Prove the askq_reader / askq_app privileges by logging in as each account.

Reads DB_HOST, DB_PORT, DB_READER_USER/PASSWORD and DB_APP_USER/PASSWORD from
the project .env. Credentials are never printed. Every probe that must be
refused is written so that it would be harmless even if it were wrongly
allowed (WHERE 1 = 0, a non-existent probe object, or a rolled-back
transaction), and every permitted write is rolled back.

Probe kinds:
  allow    must succeed
  deny     must fail with a privilege error
  value    must succeed and return the expected first value
  reject   must fail with one of the given error codes (e.g. 3819 = CHECK violated)
  observe  reported, never fails: a known residual exposure that MySQL grants
           cannot remove; the backend SQL-safety layer (Phase 5) must block it

Usage (from C:\\ASKQ):  backend\\.venv\\Scripts\\python database\\tools\\verify_accounts.py
Exit code 0 = no allow/deny/value/reject probe failed.
"""

# S608 (SQL built from strings) is disabled for this file on purpose: it only
# assembles SQL from its own constants; no user or LLM input ever reaches it.
# ruff: noqa: S608

import sys
from dataclasses import dataclass
from pathlib import Path

import pymysql

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_HOST = "127.0.0.1"
PROBE = "askq_privilege_probe"  # never exists

# MySQL error codes that mean "you are not allowed to do that".
DENIED = {
    1044,  # access denied to database
    1045,  # access denied (e.g. FILE privilege for INTO OUTFILE)
    1142,  # command denied on table
    1143,  # column access denied
    1227,  # needs a privilege such as SUPER / CREATE USER / SYSTEM_VARIABLES_ADMIN
    1290,  # --secure-file-priv refuses the file operation
    1370,  # routine access denied
    1410,  # not allowed to create a user with GRANT
}
CHECK_VIOLATION = {3819}
FK_VIOLATION = {1452}


@dataclass(frozen=True)
class Probe:
    kind: str
    description: str
    sql: str | tuple[str, ...]
    expected: object = None


def allow(d, sql):
    return Probe("allow", d, sql)


def deny(d, sql):
    return Probe("deny", d, sql)


def value(d, sql, expected):
    return Probe("value", d, sql, expected)


def reject(d, sql, codes):
    return Probe("reject", d, sql, codes)


def observe(d, sql):
    return Probe("observe", d, sql)


U = "askq_university"
S = "askq_system"

READER_PROBES = [
    # What it is for.
    allow("read students", f"SELECT COUNT(*) FROM {U}.students"),
    allow(
        "join grades to enrollments",
        f"SELECT COUNT(*) FROM {U}.grades g JOIN {U}.enrollments e "
        "ON e.enrollment_id = g.enrollment_id",
    ),
    allow("read view v_fee_balances (INVOKER)", f"SELECT COUNT(*) FROM {U}.v_fee_balances"),
    allow(
        "read view v_attendance_summary (INVOKER)",
        f"SELECT COUNT(*) FROM {U}.v_attendance_summary",
    ),
    # Application metadata and other databases.
    deny("read askq_university.users (login identities)", f"SELECT COUNT(*) FROM {U}.users"),
    deny("read askq_university.roles", f"SELECT COUNT(*) FROM {U}.roles"),
    deny(
        "read askq_system.app_user_credentials",
        f"SELECT COUNT(*) FROM {S}.app_user_credentials",
    ),
    deny("read askq_system.query_history", f"SELECT COUNT(*) FROM {S}.query_history"),
    deny("USE askq_system", f"USE {S}"),
    deny("read mysql.user", "SELECT COUNT(*) FROM mysql.user"),
    deny("read sys schema", "SELECT * FROM sys.version"),
    deny(
        "read performance_schema.threads (other sessions)",
        "SELECT COUNT(*) FROM performance_schema.threads",
    ),
    deny(
        "read performance_schema statement history (other users' SQL)",
        "SELECT COUNT(*) FROM performance_schema.events_statements_history_long",
    ),
    deny("SHOW GRANTS for another account", "SHOW GRANTS FOR 'root'@'localhost'"),
    # Metadata is filtered to what the account may read.
    value(
        "information_schema: askq_system/mysql/sys tables visible",
        "SELECT COUNT(*) FROM information_schema.TABLES "
        f"WHERE TABLE_SCHEMA IN ('{S}', 'mysql', 'sys')",
        0,
    ),
    value(
        "information_schema: columns of users/roles visible",
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        f"WHERE TABLE_SCHEMA = '{U}' AND TABLE_NAME IN ('users', 'roles')",
        0,
    ),
    value(
        "information_schema: other users' sessions visible",
        "SELECT COUNT(*) FROM information_schema.PROCESSLIST "
        "WHERE USER <> SUBSTRING_INDEX(CURRENT_USER(), '@', 1)",
        0,
    ),
    value(
        "LOAD_FILE reads a server file (1 = NULL, i.e. no FILE privilege)",
        "SELECT LOAD_FILE('C:/Windows/win.ini') IS NULL",
        1,
    ),
    # Writes, DDL, administration.
    deny("INSERT", f"INSERT INTO {U}.grade_scale VALUES ('Z', 1, 0, 'probe')"),
    deny("UPDATE", f"UPDATE {U}.students SET first_name = first_name WHERE 1 = 0"),
    deny("DELETE", f"DELETE FROM {U}.grades WHERE 1 = 0"),
    deny(
        "SELECT ... FOR UPDATE (row locks)",
        f"SELECT student_id FROM {U}.students WHERE 1 = 0 FOR UPDATE",
    ),
    deny("LOCK TABLES", f"LOCK TABLES {U}.students READ"),
    deny("CREATE TEMPORARY TABLE", f"CREATE TEMPORARY TABLE {U}.{PROBE} (id INT)"),
    deny("CREATE TABLE", f"CREATE TABLE {U}.{PROBE} (id INT)"),
    deny("ALTER TABLE", f"ALTER TABLE {U}.{PROBE} ADD COLUMN x INT"),
    deny("DROP TABLE", f"DROP TABLE {U}.{PROBE}"),
    deny("TRUNCATE", f"TRUNCATE TABLE {U}.{PROBE}"),
    deny("CREATE VIEW", f"CREATE VIEW {U}.{PROBE} AS SELECT 1"),
    deny("CREATE PROCEDURE", f"CREATE PROCEDURE {U}.{PROBE}() SELECT 1"),
    deny("CREATE DATABASE", f"CREATE DATABASE {PROBE}"),
    deny("CREATE USER", f"CREATE USER '{PROBE}'@'127.0.0.1'"),
    deny("GRANT", f"GRANT SELECT ON {U}.students TO '{PROBE}'@'127.0.0.1'"),
    deny("SET GLOBAL", "SET GLOBAL max_connections = 151"),
    deny("write a file (INTO OUTFILE)", f"SELECT 1 INTO OUTFILE '{PROBE}.txt'"),
    # Residual exposure: cannot be removed with grants; Phase 5 validator must block.
    observe("SLEEP() executes (time-based side channel / slow query)", "SELECT SLEEP(0.01)"),
    observe("BENCHMARK() executes (CPU burn)", "SELECT BENCHMARK(1000, MD5('askq'))"),
    observe(
        "system variables readable (@@version, @@datadir, @@hostname)",
        "SELECT @@version, @@datadir, @@hostname",
    ),
    observe(
        "performance_schema.global_variables readable",
        "SELECT COUNT(*) FROM performance_schema.global_variables",
    ),
    observe(
        "performance_schema.session_status readable",
        "SELECT COUNT(*) FROM performance_schema.session_status",
    ),
    observe(
        "own session variables settable (e.g. max_execution_time)",
        "SET SESSION max_execution_time = 1000",
    ),
    observe(
        "information_schema metadata of granted tables readable",
        f"SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{U}'",
    ),
]

# query_history rows for every final_status (all rolled back).
_QH = (
    f"INSERT INTO {S}.query_history (user_id, role_code, question_text, generated_sql, "
    "validation_status, authorization_status, cair_decision, risk_score, executed_sql, "
    "final_status, failure_stage, error_code, result_row_count) VALUES "
)
_SQL = "'SELECT 1'"
QH_VALID = {
    "EXECUTED": f"(1, 'ADMIN', 'q', {_SQL}, 'PASSED', 'ALLOWED', 'ALLOW', 0.1, {_SQL}, "
    "'EXECUTED', NULL, NULL, 1)",
    "RESTRICTED": f"(1, 'ADMIN', 'q', {_SQL}, 'PASSED', 'REWRITTEN', 'RESTRICT', 0.6, {_SQL}, "
    "'RESTRICTED', NULL, NULL, 1)",
    "BLOCKED": f"(1, 'ADMIN', 'q', {_SQL}, 'PASSED', 'ALLOWED', 'BLOCK', 0.9, NULL, "
    "'BLOCKED', NULL, NULL, NULL)",
    "DENIED": f"(1, 'STUDENT', 'q', {_SQL}, 'PASSED', 'DENIED', NULL, NULL, NULL, "
    "'DENIED', NULL, NULL, NULL)",
    "REJECTED": f"(1, 'STUDENT', 'q', {_SQL}, 'REJECTED', NULL, NULL, NULL, NULL, "
    "'REJECTED', NULL, NULL, NULL)",
    "FAILED (execution)": f"(1, 'ADMIN', 'q', {_SQL}, 'PASSED', 'ALLOWED', 'ALLOW', 0.1, "
    f"{_SQL}, 'FAILED', 'EXECUTION', 'TIMEOUT', NULL)",
    "FAILED (generation)": "(1, 'ADMIN', 'q', NULL, NULL, NULL, NULL, NULL, NULL, "
    "'FAILED', 'GENERATION', 'LLM_UNAVAILABLE', NULL)",
}
QH_INVALID = {
    "BLOCKED but executed": f"(1, 'ADMIN', 'q', {_SQL}, 'PASSED', 'ALLOWED', 'BLOCK', 0.9, "
    f"{_SQL}, 'BLOCKED', NULL, NULL, NULL)",
    "EXECUTED after DENIED": f"(1, 'ADMIN', 'q', {_SQL}, 'PASSED', 'DENIED', 'ALLOW', 0.1, "
    f"{_SQL}, 'EXECUTED', NULL, NULL, 1)",
    "CAIR decision after REJECTED": f"(1, 'ADMIN', 'q', {_SQL}, 'REJECTED', NULL, 'ALLOW', 0.1, "
    "NULL, 'REJECTED', NULL, NULL, NULL)",
    "no question anywhere": f"(1, 'ADMIN', NULL, {_SQL}, 'REJECTED', NULL, NULL, NULL, NULL, "
    "'REJECTED', NULL, NULL, NULL)",
    "FAILED without a stage": "(1, 'ADMIN', 'q', NULL, NULL, NULL, NULL, NULL, NULL, "
    "'FAILED', NULL, 'X', NULL)",
}

APP_PROBES = [
    allow("read users (authentication lookup)", f"SELECT COUNT(*) FROM {U}.users"),
    allow("read roles", f"SELECT COUNT(*) FROM {U}.roles"),
    allow("read departments (HOD scope)", f"SELECT COUNT(*) FROM {U}.departments"),
    allow(
        "conversation > turn > query > CAIR assessment > finding > ledger > audit (rolled back)",
        (
            f"INSERT INTO {S}.conversations (public_id, user_id, role_code) "
            "VALUES ('00000000-0000-0000-0000-00000000a5c0', 1, 'ADMIN')",
            "SET @c = LAST_INSERT_ID()",
            f"INSERT INTO {S}.conversation_turns (conversation_id, turn_no, question) "
            "VALUES (@c, 1, 'How many students are there?')",
            "SET @t = LAST_INSERT_ID()",
            f"INSERT INTO {S}.query_history (user_id, role_code, conversation_id, turn_id, "
            "resolved_question, generated_sql, validation_status, authorization_status, "
            "cair_decision, risk_score, executed_sql, final_status, result_row_count) VALUES "
            "(1, 'ADMIN', @c, @t, 'How many students are there?', "
            "'SELECT COUNT(*) FROM students', 'PASSED', 'ALLOWED', 'ALLOW', 0.05, "
            "'SELECT COUNT(*) FROM students', 'EXECUTED', 1)",
            "SET @q = LAST_INSERT_ID()",
            f"INSERT INTO {S}.cair_assessments (query_id, policy_version, reasons) "
            "VALUES (@q, 'probe', JSON_ARRAY())",
            f"INSERT INTO {S}.cair_audit_findings (assessment_id, audit_type, score, triggered, "
            "explanation) VALUES (LAST_INSERT_ID(), 'NARROWING', 0.05, 0, 'probe')",
            f"INSERT INTO {S}.cair_ledger_entries (query_id, user_id, descriptor, "
            "population_fingerprint) VALUES (@q, 1, JSON_OBJECT(), REPEAT('a', 64))",
            f"INSERT INTO {S}.security_audit_log (user_id, event_type, severity, query_id) "
            "VALUES (1, 'PRIVILEGE_PROBE', 'INFO', @q)",
        ),
    ),
    reject(
        "turn from a different conversation (composite FK)",
        (
            f"INSERT INTO {S}.conversations (public_id, user_id, role_code) "
            "VALUES ('00000000-0000-0000-0000-00000000a5c1', 1, 'ADMIN')",
            "SET @c1 = LAST_INSERT_ID()",
            f"INSERT INTO {S}.conversations (public_id, user_id, role_code) "
            "VALUES ('00000000-0000-0000-0000-00000000a5c2', 1, 'ADMIN')",
            "SET @c2 = LAST_INSERT_ID()",
            f"INSERT INTO {S}.conversation_turns (conversation_id, turn_no, question) "
            "VALUES (@c1, 1, 'q')",
            f"INSERT INTO {S}.query_history (user_id, role_code, conversation_id, turn_id, "
            "final_status, failure_stage, error_code) "
            "VALUES (1, 'ADMIN', @c2, LAST_INSERT_ID(), 'FAILED', 'GENERATION', 'X')",
        ),
        FK_VIOLATION,
    ),
    reject(
        "ledger user differs from query user (composite FK)",
        (
            _QH + QH_VALID["EXECUTED"],
            f"INSERT INTO {S}.cair_ledger_entries (query_id, user_id, descriptor, "
            "population_fingerprint) VALUES (LAST_INSERT_ID(), 2, JSON_OBJECT(), REPEAT('a', 64))",
        ),
        FK_VIOLATION,
    ),
    *[
        allow(f"record final_status {name} (rolled back)", _QH + row)
        for name, row in QH_VALID.items()
    ],
    *[
        reject(f"inconsistent query_history refused: {name}", _QH + row, CHECK_VIOLATION)
        for name, row in QH_INVALID.items()
    ],
    deny("read students (organisational data)", f"SELECT COUNT(*) FROM {U}.students"),
    deny("read teachers (salary)", f"SELECT COUNT(*) FROM {U}.teachers"),
    deny("write askq_university", f"UPDATE {U}.users SET is_active = is_active WHERE 1 = 0"),
    deny(
        "UPDATE append-only query_history",
        f"UPDATE {S}.query_history SET error_code = error_code WHERE 1 = 0",
    ),
    deny(
        "UPDATE append-only CAIR ledger",
        f"UPDATE {S}.cair_ledger_entries SET result_cardinality = 0 WHERE 1 = 0",
    ),
    deny("DELETE audit log", f"DELETE FROM {S}.security_audit_log WHERE 1 = 0"),
    deny("DELETE conversations", f"DELETE FROM {S}.conversations WHERE 1 = 0"),
    deny("CREATE TABLE", f"CREATE TABLE {S}.{PROBE} (id INT)"),
    deny("DROP TABLE", f"DROP TABLE {S}.{PROBE}"),
    deny("read mysql.user", "SELECT COUNT(*) FROM mysql.user"),
    deny("write a file (INTO OUTFILE)", f"SELECT 1 INTO OUTFILE '{PROBE}.txt'"),
]


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            values[key.strip()] = val.strip()
    return values


def evaluate(probe: Probe, code: int | None, first) -> tuple[str, str]:
    """Maps a probe's outcome to (status, detail). Pure; unit-tested without MySQL."""
    if probe.kind == "observe":
        return ("EXPOSED", "backend must block") if code is None else ("not exposed", f"{code}")
    if probe.kind == "allow":
        return ("PASS", "") if code is None else ("FAIL", f"failed with error {code}")
    if probe.kind == "deny":
        if code in DENIED:
            return "PASS", ""
        return "FAIL", "was ALLOWED" if code is None else f"error {code} is not a privilege error"
    if probe.kind == "value":
        if code is not None:
            return "FAIL", f"error {code}"
        if first == probe.expected:
            return "PASS", ""
        return "FAIL", f"returned {first!r}, expected {probe.expected!r}"
    if probe.kind == "reject":
        if code in probe.expected:
            return "PASS", ""
        return "FAIL", "was ACCEPTED" if code is None else f"error {code}"
    raise ValueError(probe.kind)


def run_probe(conn, cur, probe: Probe) -> tuple[str, str]:
    statements = probe.sql if isinstance(probe.sql, tuple) else (probe.sql,)
    code, first = None, None
    try:
        conn.begin()
        for statement in statements:
            cur.execute(statement)
            if cur.description:
                row = cur.fetchone()
                first = row[0] if row else None
    except pymysql.MySQLError as exc:
        code = exc.args[0] if exc.args else -1
    finally:
        conn.rollback()
    return evaluate(probe, code, first)


def run_account(label: str, conn, probes: list[Probe]) -> int:
    failures = 0
    print(f"\n{label}")
    with conn.cursor() as cur:
        for probe in probes:
            status, detail = run_probe(conn, cur, probe)
            failures += status == "FAIL"
            suffix = f"  ({detail})" if detail else ""
            print(f"  [{status:>11}] {probe.kind:7} {probe.description}{suffix}")
        cur.execute("SHOW GRANTS")
        print("  grants:")
        for (grant,) in cur.fetchall():
            print(f"    {grant}")
    return failures


def main() -> int:
    env = load_env(ROOT / ".env")
    host = env.get("DB_HOST", EXPECTED_HOST)
    if host != EXPECTED_HOST:
        print(
            f"DB_HOST must be {EXPECTED_HOST} (accounts are created @'{EXPECTED_HOST}')",
            file=sys.stderr,
        )
        return 2
    port = int(env.get("DB_PORT", "3306"))
    failures = 0
    for label, user_key, pw_key, probes in (
        (
            "askq_reader (executes LLM-generated SELECTs)",
            "DB_READER_USER",
            "DB_READER_PASSWORD",
            READER_PROBES,
        ),
        ("askq_app (backend bookkeeping)", "DB_APP_USER", "DB_APP_PASSWORD", APP_PROBES),
    ):
        user, password = env.get(user_key), env.get(pw_key)
        if not user or not password:
            print(f"{user_key}/{pw_key} missing from .env", file=sys.stderr)
            return 2
        try:
            conn = pymysql.connect(
                host=host,
                port=port,
                user=user,
                password=password,
                autocommit=False,
                connect_timeout=10,
                init_command="SET time_zone = '+00:00'",
            )
        except pymysql.MySQLError as exc:
            print(f"Cannot connect as {user} to {host}:{port}: {exc.args}", file=sys.stderr)
            return 2
        try:
            failures += run_account(f"{label} as {user}@{host}:{port}", conn, probes)
        finally:
            conn.close()
    print(
        "\nEXPOSED items are residual risks that MySQL grants cannot remove; "
        "the Phase 5 SQL-safety layer must block them (see database/README.md)."
    )
    print(f"Account privilege checks: {'ALL PASSED' if failures == 0 else f'{failures} FAILED'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
