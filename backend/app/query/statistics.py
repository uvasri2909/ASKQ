"""The aggregate-only STATISTICAL tier (Phase 5).

Phase 4's RECORD tier is unchanged: a user sees individual rows only within
their row scope. The statistical tier lets HOD, TEACHER and STUDENT users ask
for aggregates over the whole university, under rules that keep individuals
out of the answer:

1. Only the statistical tables (people, enrollment, grade, attendance,
   finance and award data plus reference tables; never `teachers`).
2. Direct identifiers (names, e-mail, student/employee numbers, date of
   birth, receipt numbers, salary) may not appear anywhere in the query.
3. Record keys (student_id, enrollment_id, ...) only join tables
   (column = column) or are counted; never compared with a literal,
   projected, grouped, ordered or summed.
4. The outermost query (each UNION branch) must be purely aggregate: every
   output is an aggregate, a GROUP BY key, or arithmetic on those.
5. The people behind every aggregate must be exactly the population CAIR
   probes, so:
   * no subqueries, derived tables or CTEs (oracles / smuggled values);
   * only plain INNER JOIN ... ON/USING (no outer, cross, natural, comma);
   * every person-bearing table joined on the SAME person (key equalities
     on student_id / enrollment_id / fee_id);
   * aggregate arguments are plain: *, a column or DISTINCT column (no CASE,
     IF, comparisons, arithmetic or NULLIF inside, anywhere in the query);
   * <column> IS NOT NULL is added for every aggregated column.
6. Every such query gets HAVING COUNT(DISTINCT <person>) >= k added, so no
   statistic over fewer than k people is ever returned, and a small group
   and an empty group look the same (both absent).

Shapes these rules cannot vouch for are refused (STATISTICS_UNSUPPORTED or
STATISTICS_AGGREGATE_ONLY), never assessed optimistically.

The tier is reachable only while CAIR is enabled; CAIR (app/cair) then judges
what the user could learn by combining the answer with earlier ones. Choosing
the tier grants nothing by itself: both tiers are enforced here, on the SQL.
"""

import sqlglot
from sqlglot import exp

from app.query.authorization import (
    AuthorizationDenied,
    AuthorizedQuery,
    DenialCode,
    bound_limit,
)
from app.query.catalog import CATALOG
from app.query.policy import REFERENCE_TABLES
from app.query.sql_validator import ValidatedQuery, validate_sql
from app.rbac.roles import Role
from app.rbac.scope import UserContext

_DIALECT = "mysql"

RECORD_TIER = "RECORD"
STATISTICAL_TIER = "STATISTICAL"

STATISTICAL_ROLES = frozenset({Role.HOD, Role.TEACHER, Role.STUDENT})
STATISTICAL_TABLES = REFERENCE_TABLES | frozenset(
    {
        "students",
        "enrollments",
        "grades",
        "attendance_records",
        "v_attendance_summary",
        "fees",
        "fee_payments",
        "v_fee_balances",
        "student_scholarships",
    }
)
DIRECT_IDENTIFIERS = frozenset(
    {
        "student_no",
        "first_name",
        "last_name",
        "email",
        "date_of_birth",
        "receipt_no",
        "employee_no",
        "annual_salary",
    }
)
RECORD_KEYS = frozenset(
    {
        "student_id",
        "enrollment_id",
        "grade_id",
        "attendance_id",
        "fee_id",
        "payment_id",
        "award_id",
        "session_id",
        "advisor_teacher_id",
    }
)
AGGREGATES: tuple[type[exp.Expression], ...] = (
    exp.Count,
    exp.Sum,
    exp.Avg,
    exp.Min,
    exp.Max,
    exp.Stddev,
    exp.StddevPop,
    exp.StddevSamp,
    exp.Variance,
    exp.VariancePop,
)
# Nodes allowed around aggregates in an output expression (ROUND(AVG(x), 1), SUM(a) / COUNT(*)).
_AGGREGATE_WRAPPERS: tuple[type[exp.Expression], ...] = (
    exp.Round,
    exp.Add,
    exp.Sub,
    exp.Mul,
    exp.Div,
    exp.Paren,
    exp.Coalesce,
    exp.Cast,
    exp.DataType,
    exp.DataTypeParam,
    exp.Literal,
    exp.Neg,
    exp.Alias,
    exp.Identifier,
)


class StatisticsDenial:
    AGGREGATE_ONLY = "STATISTICS_AGGREGATE_ONLY"
    UNSUPPORTED = "STATISTICS_UNSUPPORTED"


_MESSAGES = {
    StatisticsDenial.AGGREGATE_ONLY: (
        "University-wide statistics are available only as aggregates over groups of people."
    ),
    StatisticsDenial.UNSUPPORTED: (
        "This statistic cannot be computed safely. Try a simpler aggregate question."
    ),
}


class StatisticsDenied(AuthorizationDenied):
    def __init__(self, code: str, detail: str = "") -> None:
        Exception.__init__(self, code)
        self.code = code
        self.message = _MESSAGES[code]
        self.detail = detail


# ---------------------------------------------------------------- subject keys
# The person ("subject") a row is about, per table: a column reference or a
# correlated lookup. {a} = the table's alias in the query, {db} = university db.
_DIRECT_SUBJECT = {
    "students": "{a}.student_id",
    "enrollments": "{a}.student_id",
    "fees": "{a}.student_id",
    "student_scholarships": "{a}.student_id",
    "v_fee_balances": "{a}.student_id",
    "v_attendance_summary": "{a}.student_id",
}
_INDIRECT_SUBJECT = {
    "grades": (
        "(SELECT cair_e.student_id FROM {db}.enrollments AS cair_e "
        "WHERE cair_e.enrollment_id = {a}.enrollment_id)"
    ),
    "attendance_records": (
        "(SELECT cair_e.student_id FROM {db}.enrollments AS cair_e "
        "WHERE cair_e.enrollment_id = {a}.enrollment_id)"
    ),
    "fee_payments": (
        "(SELECT cair_f.student_id FROM {db}.fees AS cair_f WHERE cair_f.fee_id = {a}.fee_id)"
    ),
}


def _base_table(source: exp.Expression, university_db: str) -> str | None:
    """The catalog table behind a FROM/JOIN source: a table, or a scope wrapper around one."""
    if isinstance(source, exp.Table):
        return source.name.lower() if source.name.lower() in CATALOG else None
    if isinstance(source, exp.Subquery) and isinstance(source.this, exp.Select):
        inner = source.this.args.get("from_")
        if inner is not None and isinstance(inner.this, exp.Table):
            table = inner.this
            if table.db.lower() == university_db.lower() and table.name.lower() in CATALOG:
                return table.name.lower()
    return None


def _sources(select: exp.Select) -> list[exp.Expression]:
    sources = []
    from_ = select.args.get("from_")
    if from_ is not None:
        sources.append(from_.this)
    for join in select.args.get("joins") or []:
        sources.append(join.this)
    return sources


def subject_key(select: exp.Select, university_db: str) -> exp.Expression | None:
    """An expression giving the student each row of `select` is about, or None if none."""
    direct, indirect = None, None
    for source in _sources(select):
        table = _base_table(source, university_db)
        alias = source.alias_or_name
        if table is None or not alias:
            continue
        if direct is None and table in _DIRECT_SUBJECT:
            direct = _DIRECT_SUBJECT[table].format(a=alias, db=university_db)
        if indirect is None and table in _INDIRECT_SUBJECT:
            indirect = _INDIRECT_SUBJECT[table].format(a=alias, db=university_db)
    template = direct or indirect
    if template is None:
        return None
    return sqlglot.parse_one(template, read=_DIALECT)


def outer_selects(tree: exp.Query) -> list[exp.Select]:
    """The SELECTs whose outputs the user sees: the query itself, or each UNION branch."""
    if isinstance(tree, exp.Select):
        return [tree]
    if isinstance(tree, exp.Union):
        return outer_selects(tree.this) + outer_selects(tree.expression)
    if isinstance(tree, exp.Subquery):
        return outer_selects(tree.this)
    return []


def group_expressions(select: exp.Select) -> list[exp.Expression]:
    """GROUP BY expressions with references to output aliases resolved."""
    aliases = {
        e.alias.lower(): e.this for e in select.expressions if isinstance(e, exp.Alias) and e.alias
    }
    group = select.args.get("group")
    resolved = []
    for g in group.expressions if group is not None else []:
        if isinstance(g, exp.Column) and not g.table and g.name.lower() in aliases:
            resolved.append(aliases[g.name.lower()].copy())
        else:
            resolved.append(g.copy())
    return resolved


# ------------------------------------------------------------------ checks
def _is_pure_aggregate(expression: exp.Expression, group_sql: set[str]) -> bool:
    node = expression.this if isinstance(expression, exp.Alias) else expression
    if node.sql(dialect=_DIALECT) in group_sql:
        return True
    if isinstance(node, exp.Column):
        return node.sql(dialect=_DIALECT) in group_sql or node.name.lower() in {
            g.split(".")[-1].strip("`").lower() for g in group_sql
        }
    if isinstance(node, AGGREGATES):
        return not any(isinstance(n, exp.Window) for n in node.walk())
    if isinstance(node, exp.Literal):
        return True
    if isinstance(node, _AGGREGATE_WRAPPERS):
        return all(
            _is_pure_aggregate(child, group_sql)
            for child in node.iter_expressions()
            if not isinstance(child, (exp.DataType, exp.DataTypeParam, exp.Identifier))
        )
    return False


# How each person-bearing table identifies its person. Two rows share a person if
# they share a student, an enrollment (one student) or a fee (one student).
PERSON_KEYS: dict[str, dict[str, str]] = {
    "students": {"student_id": "student"},
    "enrollments": {"student_id": "student", "enrollment_id": "enrollment"},
    "grades": {"enrollment_id": "enrollment"},
    "attendance_records": {"enrollment_id": "enrollment"},
    "v_attendance_summary": {"student_id": "student", "enrollment_id": "enrollment"},
    "fees": {"student_id": "student", "fee_id": "fee"},
    "fee_payments": {"fee_id": "fee"},
    "v_fee_balances": {"student_id": "student", "fee_id": "fee"},
    "student_scholarships": {"student_id": "student"},
}


def _deny(detail: str, code: str = StatisticsDenial.AGGREGATE_ONLY) -> StatisticsDenied:
    return StatisticsDenied(code, detail)


def _check_no_subqueries(tree: exp.Query, outers: list[exp.Select]) -> None:
    """Only the output SELECTs themselves: a subquery can be an oracle about one
    person (uncorrelated) or smuggle one person's value into an aggregate (correlated)."""
    if len(list(tree.find_all(exp.Select))) != len(outers) or tree.find(exp.With):
        raise _deny("subquery, derived table or CTE", StatisticsDenial.UNSUPPORTED)


def _check_joins(select: exp.Select) -> None:
    """Plain inner joins with ON/USING only: an outer join or a join without a
    condition can pair rows about one person with rows about everyone else."""
    for join in select.args.get("joins") or []:
        kind = (join.args.get("kind") or "").upper()
        if (
            join.args.get("side")
            or join.args.get("method")
            or kind not in ("", "INNER")
            or not (join.args.get("on") or join.args.get("using"))
        ):
            raise _deny("only INNER JOIN ... ON/USING", StatisticsDenial.UNSUPPORTED)


def _conjuncts(condition: exp.Expression | None) -> list[exp.Expression]:
    if condition is None:
        return []
    if isinstance(condition, exp.Paren):
        return _conjuncts(condition.this)
    if isinstance(condition, exp.And):
        return _conjuncts(condition.this) + _conjuncts(condition.expression)
    return [condition]


def _check_single_person(select: exp.Select, university_db: str) -> None:
    """Every person-bearing table must be joined on the SAME person (union-find over
    key equalities), so every row of a group is about one person of that group and
    the population probe is exactly the set of contributors."""
    person_aliases: dict[str, str] = {}
    for source in _sources(select):
        table = _base_table(source, university_db)
        if table in PERSON_KEYS:
            person_aliases[source.alias_or_name.lower()] = table
    parent = {alias: alias for alias in person_aliases}

    def find(a: str) -> str:
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    def kind(column: exp.Column) -> tuple[str, str] | None:
        alias = column.table.lower()
        table = person_aliases.get(alias)
        if table is None:
            return None
        key_kind = PERSON_KEYS[table].get(column.name.lower())
        return (alias, key_kind) if key_kind else None

    conditions = [select.args.get("where")]
    for join in select.args.get("joins") or []:
        conditions.append(join.args.get("on"))
    for condition in conditions:
        body = condition.this if isinstance(condition, exp.Where) else condition
        for atom in _conjuncts(body):
            if isinstance(atom, exp.EQ) and all(
                isinstance(side, exp.Column) for side in (atom.this, atom.expression)
            ):
                left, right = kind(atom.this), kind(atom.expression)
                if left and right and left[1] == right[1]:
                    parent[find(left[0])] = find(right[0])
    # USING (k): the joined table shares k with an earlier table of the same key kind.
    seen: list[str] = []
    joins = [None, *(select.args.get("joins") or [])]
    for source, join in zip(_sources(select), joins, strict=True):
        alias = source.alias_or_name.lower()
        if join is not None and alias in person_aliases:
            for ident in join.args.get("using") or []:
                name = ident.name.lower()
                key_kind = PERSON_KEYS[person_aliases[alias]].get(name)
                for other in seen:
                    if key_kind and PERSON_KEYS[person_aliases[other]].get(name) == key_kind:
                        parent[find(alias)] = find(other)
        if alias in person_aliases:
            seen.append(alias)
    if len({find(a) for a in person_aliases}) > 1:
        raise _deny("tables not joined on the same person", StatisticsDenial.UNSUPPORTED)


def _check_aggregates(tree: exp.Query) -> None:
    """Aggregate arguments are plain: *, a column, or DISTINCT column. Anything else
    (CASE, IF, comparisons, arithmetic, NULLIF, ...) can make one person's value the
    only non-NULL input while everyone else pads the group."""
    if tree.find(exp.Window, exp.GroupConcat):
        raise _deny("window function or GROUP_CONCAT")
    for aggregate in tree.find_all(*AGGREGATES):
        argument = aggregate.this
        if isinstance(argument, exp.Distinct):
            values = argument.expressions
            argument = values[0] if len(values) == 1 else None
        plain = isinstance(argument, exp.Column) or (
            isinstance(aggregate, exp.Count) and isinstance(argument, exp.Star)
        )
        if not plain or aggregate.args.get("expressions"):
            raise _deny("aggregate over an expression")


def _check_record_keys(tree: exp.Query) -> None:
    """Record keys only join tables (column = column) or are counted."""
    for column in tree.find_all(exp.Column):
        if column.name.lower() not in RECORD_KEYS:
            continue
        parent = column.parent
        if isinstance(parent, exp.Distinct):
            parent = parent.parent
        if isinstance(parent, exp.Count):
            continue
        if isinstance(parent, exp.EQ) and all(
            isinstance(side, exp.Column) for side in (parent.this, parent.expression)
        ):
            continue
        raise _deny("record key used outside a join or COUNT")


def _require_contributors(select: exp.Select) -> None:
    """Add <column> IS NOT NULL for every aggregated column, so the rows that
    contribute to each aggregate are exactly the rows of the population probe."""
    columns = {}
    for aggregate in select.find_all(*AGGREGATES):
        for column in aggregate.find_all(exp.Column):
            columns[column.sql(dialect=_DIALECT)] = column
    if not columns:
        return
    conditions = [
        exp.Not(this=exp.Is(this=c.copy(), expression=exp.Null()))
        for _, c in sorted(columns.items())
    ]
    where = select.args.get("where")
    condition = exp.and_(*([where.this] if where is not None else []), *conditions)
    select.set("where", exp.Where(this=condition))


def authorize_statistical(
    validated: ValidatedQuery,
    user: UserContext,
    *,
    university_db: str,
    max_rows: int,
    min_group_size: int,
) -> AuthorizedQuery:
    if user.role not in STATISTICAL_ROLES:
        raise AuthorizationDenied(DenialCode.TABLE_NOT_PERMITTED, "role has no statistical tier")
    forbidden_tables = validated.tables - STATISTICAL_TABLES
    if forbidden_tables:
        raise AuthorizationDenied(
            DenialCode.TABLE_NOT_PERMITTED, ",".join(sorted(forbidden_tables))
        )
    identifiers = validated.columns & DIRECT_IDENTIFIERS
    if identifiers:
        raise AuthorizationDenied(DenialCode.COLUMN_NOT_PERMITTED, ",".join(sorted(identifiers)))

    tree = validated.ast.copy()
    outers = outer_selects(tree)
    if not outers:
        raise StatisticsDenied(StatisticsDenial.UNSUPPORTED, "no outer SELECT")
    _check_no_subqueries(tree, outers)
    _check_aggregates(tree)
    _check_record_keys(tree)

    for select in outers:
        _check_joins(select)
        _check_single_person(select, university_db)
        if select.args.get("distinct"):
            raise StatisticsDenied(StatisticsDenial.AGGREGATE_ONLY, "DISTINCT rows")
        group_sql = {g.sql(dialect=_DIALECT) for g in group_expressions(select)}
        for expression in select.expressions:
            if isinstance(expression, exp.Star) or not _is_pure_aggregate(expression, group_sql):
                raise StatisticsDenied(StatisticsDenial.AGGREGATE_ONLY, "non-aggregate output")
        if not any(select.find_all(*AGGREGATES)):
            raise StatisticsDenied(StatisticsDenial.AGGREGATE_ONLY, "no aggregate")
        key = subject_key(select, university_db)
        if key is None:
            raise StatisticsDenied(StatisticsDenial.UNSUPPORTED, "no person behind the rows")
        _require_contributors(select)
        minimum = exp.GTE(
            this=exp.Count(this=exp.Distinct(expressions=[key])),
            expression=exp.Literal.number(int(min_group_size)),
        )
        having = select.args.get("having")
        condition = minimum if having is None else exp.and_(having.this, minimum)
        select.set("having", exp.Having(this=condition))

    row_limit, limit_note = bound_limit(tree, max_rows)
    sql = tree.sql(dialect=_DIALECT)
    validate_sql(sql, catalog_tables=CATALOG, university_db=university_db)

    notes = ["University-wide statistic: groups too small to protect individuals are not shown."]
    if limit_note:
        notes.append(limit_note)
    return AuthorizedQuery(
        ast=tree,
        sql=sql,
        status="ALLOWED",
        row_limit=row_limit,
        scoped_tables=frozenset(),
        notes=tuple(notes),
        tier=STATISTICAL_TIER,
    )
