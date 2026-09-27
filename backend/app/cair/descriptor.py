"""The CAIR descriptor: a query's security-relevant shape, from the parsed SQL only.

Built from the validated tree (the model's query as parsed) plus the tier and
the server-side user context; never from the model's explanation. Every list
is sorted, so the same query always yields the same JSON.
"""

from dataclasses import asdict, dataclass
from typing import Any

from sqlglot import exp

from app.cair.model import Measure
from app.query.catalog import CATALOG
from app.query.sql_validator import ValidatedQuery
from app.query.statistics import AGGREGATES, group_expressions, outer_selects
from app.rbac.scope import UserContext

_DIALECT = "mysql"

# Attributes that, combined, can single people out (used for dimension tracking).
QUASI_IDENTIFIERS = frozenset(
    {
        "students.department_id",
        "departments.department_code",
        "departments.department_name",
        "students.year_level",
        "students.gender",
        "students.residency_status",
        "students.home_region",
        "students.is_hostel_resident",
        "students.admission_year",
        "students.enrollment_status",
        "scholarships.scholarship_code",
        "scholarships.category",
    }
)
# Values about a person that statistics may reveal.
SENSITIVE_METRICS = frozenset(
    {
        "grades.marks",
        "grades.letter_grade",
        "v_attendance_summary.attendance_pct",
        "attendance_records.status",
        "fees.amount",
        "fee_payments.amount",
        "v_fee_balances.balance",
        "v_fee_balances.amount_paid",
        "v_fee_balances.amount_due",
        "student_scholarships.amount",
    }
)

_KIND = {
    exp.Count: "count",
    exp.Sum: "sum",
    exp.Avg: "sum",  # an average and a count give the sum
    exp.Min: "min",
    exp.Max: "max",
    exp.Stddev: "spread",
    exp.StddevPop: "spread",
    exp.StddevSamp: "spread",
    exp.Variance: "spread",
    exp.VariancePop: "spread",
}


@dataclass(frozen=True, slots=True)
class QueryDescriptor:
    tier: str
    role: str
    scope: dict[str, Any]
    tables: list[str]
    columns: list[str]
    predicates: list[dict[str, Any]]
    filter_dimensions: list[str]
    group_dimensions: list[str]
    aggregates: list[dict[str, str]]
    measures: list[str]
    ordering: list[str]
    limit: int | None
    exposes: dict[str, bool]
    quasi_identifiers: list[str]
    sensitive_metrics: list[str]

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    def measure_set(self) -> frozenset[Measure]:
        return frozenset(Measure(*m.split(":", 1)) for m in self.measures)

    def dimension_set(self) -> frozenset[str]:
        return frozenset(self.filter_dimensions) | frozenset(self.group_dimensions)


def _alias_map(tree: exp.Expression) -> dict[str, str]:
    aliases = {}
    for table in tree.find_all(exp.Table):
        name = table.name.lower()
        if name in CATALOG:
            aliases[table.alias_or_name.lower()] = name
    return aliases


def _qualify(column: exp.Column, aliases: dict[str, str], tables: list[str]) -> str:
    name = column.name.lower()
    if column.table:
        table = aliases.get(column.table.lower())
        if table:
            return f"{table}.{name}"
    for table in tables:  # unqualified: the first referenced table that has it
        if name in CATALOG[table].column_names:
            return f"{table}.{name}"
    return name


def _predicates(where: exp.Expression | None, aliases, tables) -> list[dict[str, Any]]:
    if where is None:
        return []
    atoms: list[dict[str, Any]] = []

    def visit(node: exp.Expression) -> None:
        if isinstance(node, exp.And):
            visit(node.this)
            visit(node.expression)
            return
        if isinstance(node, exp.Paren):
            visit(node.this)
            return
        columns = sorted({_qualify(c, aliases, tables) for c in node.find_all(exp.Column)})
        values = sorted(v.sql(dialect=_DIALECT) for v in node.find_all(exp.Literal))
        atoms.append({"op": type(node).__name__.upper(), "columns": columns, "values": values})

    visit(where.this if isinstance(where, exp.Where) else where)
    return sorted(atoms, key=lambda a: (a["columns"], a["op"], a["values"]))


def describe(validated: ValidatedQuery, tier: str, user: UserContext) -> QueryDescriptor:
    tree = validated.ast
    tables = sorted(validated.tables)
    aliases = _alias_map(tree)
    outers = outer_selects(tree)

    predicates: list[dict[str, Any]] = []
    groups: set[str] = set()
    aggregates: list[dict[str, str]] = []
    measures: set[str] = set()
    ordering: list[str] = []
    for select in outers:
        predicates += _predicates(select.args.get("where"), aliases, tables)
        for g in group_expressions(select):
            for c in g.find_all(exp.Column):
                groups.add(_qualify(c, aliases, tables))
        for agg in (n for e in select.expressions for n in e.find_all(*AGGREGATES)):
            cols = [c for c in agg.find_all(exp.Column)]
            metric = _qualify(cols[0], aliases, tables) if cols else "*"
            kind = _KIND[type(agg)]
            if kind == "count":
                metric = "*"
            aggregates.append({"func": type(agg).__name__.upper(), "column": metric})
            measures.add(Measure(kind, metric).as_key())
        order = select.args.get("order")
        if order is not None:
            ordering += [o.sql(dialect=_DIALECT) for o in order.expressions]

    filters = sorted({c for p in predicates for c in p["columns"]})
    limit_node = tree.args.get("limit")
    limit = int(limit_node.expression.this) if limit_node is not None else None
    where_sql = " ".join(
        s.args["where"].sql(dialect=_DIALECT) for s in outers if s.args.get("where") is not None
    ).upper()
    columns = sorted(
        {_qualify(c, aliases, tables) for c in tree.find_all(exp.Column)} | set(filters)
    )
    kinds = {m.split(":", 1)[0] for m in measures}
    has_aggregate = bool(aggregates)
    exposes = {
        "count": "count" in kinds,
        "sum": any(a["func"] == "SUM" for a in aggregates),
        "average": any(a["func"] == "AVG" for a in aggregates),
        "min_max": bool(kinds & {"min", "max"}),
        "records": not has_aggregate,
        "existence": "EXISTS" in where_sql or (limit == 1 and not has_aggregate),
    }
    dimensions = set(filters) | groups
    scope = {
        "kind": user.scope.kind.value,
        "department_id": user.scope.department_id,
        "teacher_id": user.scope.teacher_id,
        "student_id": user.scope.student_id,
    }
    return QueryDescriptor(
        tier=tier,
        role=user.role.value,
        scope=scope,
        tables=tables,
        columns=columns,
        predicates=predicates,
        filter_dimensions=filters,
        group_dimensions=sorted(groups),
        aggregates=sorted(aggregates, key=lambda a: (a["func"], a["column"])),
        measures=sorted(measures),
        ordering=ordering,
        limit=limit,
        exposes=exposes,
        quasi_identifiers=sorted(dimensions & QUASI_IDENTIFIERS),
        sensitive_metrics=sorted({a["column"] for a in aggregates} & SENSITIVE_METRICS),
    )
