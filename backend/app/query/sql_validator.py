"""Layer 1 of the SQL checks: is this a single, plain, read-only SELECT over known data?

The input is UNTRUSTED (model output). The checks, in order:

1. Size limits.
2. Token stream (MySQL tokenizer): no comments of any kind and no statement
   separators. Comments matter because the parser drops them, while MySQL
   EXECUTES "/*!50000 ... */" comments and honours "/*+ ... */" hints.
3. Parse (sqlglot, MySQL dialect): exactly one statement, rooted at SELECT
   or UNION of SELECTs. INTO OUTFILE/DUMPFILE, CALL, SET, SHOW, HANDLER, DDL
   and DML either fail to parse or have another root, and are rejected.
4. Whole-tree ALLOWLIST of node types. Anything not listed is rejected:
   INTO @var, FOR UPDATE / LOCK IN SHARE MODE, @var / @@system variables,
   placeholders, hex/bit literals and charset introducers, COLLATE,
   INTERSECT/EXCEPT, and every function not explicitly allowed (SLEEP,
   BENCHMARK, LOAD_FILE, USER(), DATABASE(), VERSION(), GET_LOCK, ...).
5. Tables: only catalog tables, optionally qualified with the university
   database. System schemas (mysql, information_schema, performance_schema,
   sys), askq_system, users/roles and unknown names are all "not available",
   with one message, so the response does not reveal which of them exist.
   Table hints (USE INDEX, PARTITION) are rejected; so are recursive CTEs
   and CTEs that shadow a catalog table.

The caller executes SQL regenerated from the validated tree, never the input
text, so what runs is exactly what was checked.
"""

import logging
from collections.abc import Collection
from dataclasses import dataclass

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError
from sqlglot.tokens import TokenType

MAX_SQL_LENGTH = 10_000
MAX_NODES = 5_000

_DIALECT = "mysql"

ALLOWED_NODES: frozenset[type[exp.Expression]] = frozenset(
    {
        # structure
        exp.Select, exp.Union, exp.Subquery, exp.From, exp.Join, exp.Where, exp.Group,
        exp.Having, exp.Order, exp.Ordered, exp.Limit, exp.Offset, exp.With, exp.CTE,
        exp.TableAlias, exp.Table, exp.Identifier, exp.Column, exp.Star, exp.Alias,
        exp.Distinct, exp.Exists, exp.Paren, exp.Tuple,
        # literals and operators
        exp.Literal, exp.Boolean, exp.Null, exp.Var, exp.Interval,
        exp.And, exp.Or, exp.Not, exp.EQ, exp.NEQ, exp.GT, exp.GTE, exp.LT, exp.LTE,
        exp.Is, exp.In, exp.Between, exp.Like,
        exp.Add, exp.Sub, exp.Mul, exp.Div, exp.IntDiv, exp.Mod, exp.Neg,
        # conditionals and conversion
        exp.Case, exp.If, exp.Coalesce, exp.Nullif, exp.Greatest, exp.Least,
        exp.Cast, exp.DataType, exp.DataTypeParam,
        # aggregates and window functions
        exp.Count, exp.Sum, exp.Avg, exp.Min, exp.Max, exp.Stddev, exp.StddevPop,
        exp.StddevSamp, exp.Variance, exp.VariancePop, exp.GroupConcat,
        exp.Window, exp.WindowSpec, exp.RowNumber, exp.Rank, exp.DenseRank,
        # numeric
        exp.Round, exp.Floor, exp.Ceil, exp.Abs,
        # strings
        exp.Concat, exp.ConcatWs, exp.Upper, exp.Lower, exp.Length, exp.Substring,
        exp.Trim, exp.Left, exp.Right,
        # dates
        exp.Year, exp.Month, exp.Day, exp.Quarter, exp.DayOfWeek, exp.DateDiff,
        exp.DateAdd, exp.DateSub, exp.CurrentDate, exp.TimeToStr, exp.TsOrDsToDate,
        exp.TsOrDsToTimestamp,
    }
)  # fmt: skip

# Functions sqlglot does not model (exp.Anonymous) are rejected unless named here.
ALLOWED_ANONYMOUS_FUNCTIONS = frozenset({"NOW"})

# Table node arguments that may be present: name, database, alias. Anything
# else (index hints, PARTITION, catalog, ...) is rejected.
_ALLOWED_TABLE_ARGS = frozenset({"this", "db", "alias"})


class ValidationCode:
    EMPTY = "EMPTY"
    TOO_LARGE = "TOO_LARGE"
    COMMENTS = "COMMENTS"
    MULTIPLE_STATEMENTS = "MULTIPLE_STATEMENTS"
    PARSE_ERROR = "PARSE_ERROR"
    NOT_SELECT = "NOT_SELECT"
    UNSUPPORTED_FEATURE = "UNSUPPORTED_FEATURE"
    DATA_NOT_AVAILABLE = "DATA_NOT_AVAILABLE"


# Deliberately coarse: enough for a user to understand, not a map of the checks.
_MESSAGES = {
    ValidationCode.EMPTY: "No SQL query was produced.",
    ValidationCode.TOO_LARGE: "The generated query is too large.",
    ValidationCode.COMMENTS: "The generated query contains comments, which are not allowed.",
    ValidationCode.MULTIPLE_STATEMENTS: "Only a single SQL statement is allowed.",
    ValidationCode.PARSE_ERROR: "The generated query is not valid SQL.",
    ValidationCode.NOT_SELECT: "Only read-only SELECT queries are allowed.",
    ValidationCode.UNSUPPORTED_FEATURE: "The generated query uses an SQL feature that is not allowed.",  # noqa: E501
    ValidationCode.DATA_NOT_AVAILABLE: "The generated query refers to data that is not available.",
}  # fmt: skip


class SqlValidationError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        # detail is for server-side logs/audit only; message is safe for clients.
        super().__init__(code)
        self.code = code
        self.message = _MESSAGES[code]
        self.detail = detail


@dataclass(frozen=True, slots=True)
class ValidatedQuery:
    ast: exp.Query
    tables: frozenset[str]  # catalog tables referenced (lower case)
    columns: frozenset[str]  # column names referenced (lower case)
    cte_names: frozenset[str]

    @property
    def sql(self) -> str:
        return self.ast.sql(dialect=_DIALECT)


def _fail(code: str, detail: str = "") -> SqlValidationError:
    return SqlValidationError(code, detail)


def _strip_terminator(sql: str) -> str:
    sql = sql.strip()
    if sql.endswith(";"):
        sql = sql[:-1].rstrip()
    return sql


def _check_tokens(sql: str) -> None:
    try:
        tokens = sqlglot.Dialect.get_or_raise(_DIALECT).tokenize(sql)
    except TokenError:
        raise _fail(ValidationCode.PARSE_ERROR, "tokenizer error") from None
    for token in tokens:
        if token.comments:
            raise _fail(ValidationCode.COMMENTS)
        if token.token_type == TokenType.SEMICOLON:
            raise _fail(ValidationCode.MULTIPLE_STATEMENTS)


def _parse(sql: str) -> exp.Expression:
    logger = logging.getLogger("sqlglot")
    previous = logger.level
    logger.setLevel(logging.ERROR)  # "falling back to Command" warnings; Command is rejected
    try:
        statements = [s for s in sqlglot.parse(sql, read=_DIALECT) if s is not None]
    except (ParseError, TokenError):
        raise _fail(ValidationCode.PARSE_ERROR, "parse error") from None
    finally:
        logger.setLevel(previous)
    if len(statements) != 1:
        raise _fail(ValidationCode.MULTIPLE_STATEMENTS)
    return statements[0]


def _is_select_tree(node: exp.Expression) -> bool:
    if isinstance(node, exp.Select):
        return True
    if type(node) is exp.Union:
        return _is_select_tree(node.this) and _is_select_tree(node.expression)
    if isinstance(node, exp.Subquery):
        return _is_select_tree(node.this)
    return False


def validate_sql(
    sql: str | None,
    *,
    catalog_tables: Collection[str],
    university_db: str,
) -> ValidatedQuery:
    """Raise SqlValidationError unless sql is one safe SELECT over catalog tables."""
    if sql is None or not sql.strip():
        raise _fail(ValidationCode.EMPTY)
    if len(sql) > MAX_SQL_LENGTH:
        raise _fail(ValidationCode.TOO_LARGE)
    sql = _strip_terminator(sql)
    if not sql:
        raise _fail(ValidationCode.EMPTY)
    _check_tokens(sql)
    root = _parse(sql)
    if not _is_select_tree(root):
        raise _fail(ValidationCode.NOT_SELECT, type(root).__name__)
    if not isinstance(root, exp.Query):  # narrowing for type checkers; implied above
        raise _fail(ValidationCode.NOT_SELECT)

    catalog = {t.lower() for t in catalog_tables}
    university_db = university_db.lower()

    cte_names: set[str] = set()
    for cte in root.find_all(exp.CTE):
        name = cte.alias_or_name.lower()
        if name in catalog:
            raise _fail(ValidationCode.UNSUPPORTED_FEATURE, f"CTE shadows table {name}")
        cte_names.add(name)
    for with_ in root.find_all(exp.With):
        if with_.args.get("recursive"):
            raise _fail(ValidationCode.UNSUPPORTED_FEATURE, "recursive CTE")

    tables: set[str] = set()
    columns: set[str] = set()
    count = 0
    for node in root.walk():
        count += 1
        if count > MAX_NODES:
            raise _fail(ValidationCode.TOO_LARGE)
        kind = type(node)
        if kind is exp.Anonymous:
            if node.name.upper() not in ALLOWED_ANONYMOUS_FUNCTIONS:
                raise _fail(ValidationCode.UNSUPPORTED_FEATURE, f"function {node.name}")
            continue
        if kind not in ALLOWED_NODES:
            raise _fail(ValidationCode.UNSUPPORTED_FEATURE, kind.__name__)

        if kind is exp.Select:
            for arg in ("into", "locks", "hint", "operation_modifiers", "kind"):
                if node.args.get(arg):
                    raise _fail(ValidationCode.UNSUPPORTED_FEATURE, f"SELECT {arg}")
        elif kind is exp.Table:
            extra = {k for k, v in node.args.items() if v and k not in _ALLOWED_TABLE_ARGS}
            if extra:
                raise _fail(ValidationCode.UNSUPPORTED_FEATURE, f"table {sorted(extra)}")
            name = node.name.lower()
            db = node.db.lower()
            if not name:
                raise _fail(ValidationCode.UNSUPPORTED_FEATURE, "table expression")
            if db and db != university_db:
                raise _fail(ValidationCode.DATA_NOT_AVAILABLE, f"schema {db}")
            if not db and name in cte_names:
                continue
            if name not in catalog:
                raise _fail(ValidationCode.DATA_NOT_AVAILABLE, f"table {name}")
            tables.add(name)
        elif kind is exp.Column:
            if node.args.get("db") or node.args.get("catalog"):
                raise _fail(ValidationCode.UNSUPPORTED_FEATURE, "schema-qualified column")
            if node.name:
                columns.add(node.name.lower())
        elif kind in (exp.Limit, exp.Offset):
            value = node.expression
            if not (isinstance(value, exp.Literal) and value.is_int):
                raise _fail(ValidationCode.UNSUPPORTED_FEATURE, "non-literal LIMIT/OFFSET")

    if not tables:
        # Constant-only SELECTs (SELECT 1, SELECT NOW()) answer nothing about the data.
        raise _fail(ValidationCode.DATA_NOT_AVAILABLE, "no tables")
    return ValidatedQuery(
        ast=root,
        tables=frozenset(tables),
        columns=frozenset(columns),
        cte_names=frozenset(cte_names),
    )
