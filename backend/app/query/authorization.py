"""Layer 2 of the SQL checks: may THIS user run this query, and over which rows?

Input is a ValidatedQuery. Enforcement, all server-side:

1. Tables outside the role's policy -> DENIED.
2. Columns hidden from the role (salary, date of birth, ...) -> DENIED.
3. STUDENT only: an explicit student_id literal other than the user's own
   -> DENIED (an obvious attempt to read another student's records).
4. Row scope by REWRITING: every reference to a scoped table, anywhere in the
   tree (joins, subqueries, CTEs, UNION branches), is replaced by a derived
   table that selects only the role's visible columns and only the rows in
   the user's scope, under the same alias:

       FROM students s   ->   FROM (SELECT <visible cols> FROM askq_university.students
                                    WHERE department_id = 3) AS s

   A query can therefore never see rows outside the scope, whatever its
   predicates say; asking for another department simply returns nothing.
5. LIMIT: the outermost query is bounded to max_rows (added if missing,
   capped if larger).

The final SQL is regenerated from the rewritten tree and validated again.
"""

from dataclasses import dataclass

import sqlglot
from sqlglot import exp

from app.query.catalog import CATALOG
from app.query.policy import RolePolicy, ScopeError, policy_for, render
from app.query.sql_validator import ValidatedQuery, validate_sql
from app.rbac.roles import Role
from app.rbac.scope import UserContext

_DIALECT = "mysql"


class AuthorizationStatus:
    ALLOWED = "ALLOWED"
    REWRITTEN = "REWRITTEN"
    DENIED = "DENIED"


class DenialCode:
    TABLE_NOT_PERMITTED = "TABLE_NOT_PERMITTED"
    COLUMN_NOT_PERMITTED = "COLUMN_NOT_PERMITTED"
    OUTSIDE_SCOPE = "OUTSIDE_SCOPE"
    SCOPE_UNAVAILABLE = "SCOPE_UNAVAILABLE"


_MESSAGES = {
    DenialCode.TABLE_NOT_PERMITTED: (
        "Your role is not permitted to query some of the requested data."
    ),
    DenialCode.COLUMN_NOT_PERMITTED: (
        "Your role is not permitted to see some of the requested fields."
    ),
    DenialCode.OUTSIDE_SCOPE: "You can only query records within your own scope.",
    DenialCode.SCOPE_UNAVAILABLE: "Your account's data scope could not be determined.",
}  # fmt: skip


class AuthorizationDenied(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.message = _MESSAGES[code]
        self.detail = detail  # server-side only


@dataclass(frozen=True, slots=True)
class AuthorizedQuery:
    ast: exp.Query
    sql: str  # what will be executed
    status: str  # ALLOWED | REWRITTEN
    row_limit: int
    scoped_tables: frozenset[str]
    notes: tuple[str, ...]


def _deny(code: str, detail: str = "") -> AuthorizationDenied:
    return AuthorizationDenied(code, detail)


def _check_student_literals(tree: exp.Expression, own_student_id: int) -> None:
    def is_student_id(node: exp.Expression) -> bool:
        return isinstance(node, exp.Column) and node.name.lower() == "student_id"

    def other_ids(values: list[exp.Expression]) -> bool:
        for value in values:
            if (
                isinstance(value, exp.Literal)
                and value.is_int
                and int(value.this) != own_student_id
            ):
                return True
        return False

    for node in tree.find_all(exp.EQ, exp.In):
        if isinstance(node, exp.EQ):
            left, right = node.this, node.expression
            if (is_student_id(left) and other_ids([right])) or (
                is_student_id(right) and other_ids([left])
            ):
                raise _deny(DenialCode.OUTSIDE_SCOPE, "student_id literal")
        elif is_student_id(node.this) and other_ids(node.expressions):
            raise _deny(DenialCode.OUTSIDE_SCOPE, "student_id IN literal")


def _derived_table(
    table: exp.Table, policy: RolePolicy, user: UserContext, university_db: str
) -> exp.Subquery:
    name = table.name.lower()
    hidden = policy.hidden_columns(name)
    columns = ", ".join(c for c in CATALOG[name].column_names if c not in hidden)
    # Built only from catalog constants, the configured database name and int scope ids.
    sql = f"SELECT {columns} FROM {university_db}.{name}"  # noqa: S608
    predicate = policy.row_scope.get(name)
    if predicate is not None:
        sql += " WHERE " + render(predicate, user.scope, university_db)
    derived = sqlglot.parse_one(sql, read=_DIALECT)
    if not isinstance(derived, exp.Select):
        raise TypeError("scope template did not produce a SELECT")
    return derived.subquery(alias=table.alias_or_name)


def bound_limit(tree: exp.Query, max_rows: int) -> tuple[int, str | None]:
    """Bound the outermost query: add LIMIT max_rows if missing, cap a larger one."""
    limit = tree.args.get("limit")
    if limit is None:
        tree.set("limit", exp.Limit(expression=exp.Literal.number(max_rows)))
        return max_rows, f"Results are limited to {max_rows} rows."
    requested = int(limit.expression.this)
    if requested > max_rows:
        limit.set("expression", exp.Literal.number(max_rows))
        return max_rows, f"The row limit was reduced to {max_rows}."
    return requested, None


def authorize(
    validated: ValidatedQuery,
    user: UserContext,
    *,
    university_db: str,
    max_rows: int,
) -> AuthorizedQuery:
    policy = policy_for(user.role)

    forbidden_tables = validated.tables - policy.tables
    if forbidden_tables:
        raise _deny(DenialCode.TABLE_NOT_PERMITTED, ",".join(sorted(forbidden_tables)))

    hidden_anywhere = set().union(*(policy.hidden_columns(t) for t in validated.tables))
    if validated.columns & hidden_anywhere:
        raise _deny(
            DenialCode.COLUMN_NOT_PERMITTED, ",".join(sorted(validated.columns & hidden_anywhere))
        )

    tree = validated.ast.copy()
    if user.role is Role.STUDENT:
        if user.scope.student_id is None:
            raise _deny(DenialCode.SCOPE_UNAVAILABLE)
        _check_student_literals(tree, user.scope.student_id)

    # Collect first, then replace, so the injected derived tables are not revisited.
    to_wrap = [
        table
        for table in tree.find_all(exp.Table)
        if table.name.lower() in validated.tables
        and not (not table.db and table.name.lower() in validated.cte_names)
        and (table.name.lower() in policy.row_scope or policy.hidden_columns(table.name.lower()))
    ]
    try:
        for table in to_wrap:
            table.replace(_derived_table(table, policy, user, university_db))
    except ScopeError as exc:
        raise _deny(DenialCode.SCOPE_UNAVAILABLE, str(exc)) from None

    row_limit, limit_note = bound_limit(tree, max_rows)

    sql = tree.sql(dialect=_DIALECT)
    # Defence in depth: the executable SQL must itself pass the validator.
    validate_sql(sql, catalog_tables=CATALOG, university_db=university_db)

    notes = []
    scoped = frozenset(t.name.lower() for t in to_wrap)
    if scoped:
        description = render(policy.scope_description, user.scope, university_db)
        notes.append(f"Results are limited to {description}.")
    if limit_note:
        notes.append(limit_note)
    return AuthorizedQuery(
        ast=tree,
        sql=sql,
        status=AuthorizationStatus.REWRITTEN if scoped else AuthorizationStatus.ALLOWED,
        row_limit=row_limit,
        scoped_tables=scoped,
        notes=tuple(notes),
    )
