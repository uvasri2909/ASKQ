"""WHO a statistic is about: server-generated population probes.

For each output SELECT of an authorized query, CAIR derives a probe:

    SELECT DISTINCT <group expressions>, <person id> AS cair_subject
    FROM <same FROM/JOINs> WHERE <same WHERE>          -- no HAVING / ORDER / LIMIT

The probe is built from the AUTHORIZED tree, so it can never see more rows
than the query itself; it returns person ids only (never names or values),
passes the SQL validator, and runs as askq_reader with the statement timeout.
Ids stay in memory; only the probe SQL and sizes are stored.

Probes are recomputed from the stored SQL when the history is re-examined, so
the ledger never has to hold lists of people.
"""

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from sqlglot import exp

from app.cair.model import Cell
from app.query.catalog import CATALOG
from app.query.sql_validator import validate_sql
from app.query.statistics import group_expressions, outer_selects, subject_key

_DIALECT = "mysql"
SUBJECT = "cair_subject"


class PopulationUnavailable(Exception):
    """No person can be attributed to the rows, or the population is too large to hold."""


@dataclass(frozen=True, slots=True)
class Probe:
    branch: int
    sql: str
    group_width: int

    def to_json(self) -> dict[str, Any]:
        return {"branch": self.branch, "sql": self.sql, "group_width": self.group_width}

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Probe":
        return cls(int(data["branch"]), str(data["sql"]), int(data["group_width"]))


def build_probes(tree: exp.Query, university_db: str) -> list[Probe]:
    root_with = tree.args.get("with_")
    probes = []
    for branch, select in enumerate(outer_selects(tree)):
        key = subject_key(select, university_db)
        if key is None:
            raise PopulationUnavailable("no person behind the rows")
        groups = group_expressions(select)
        probe = select.copy()
        for arg in ("group", "having", "order", "limit", "offset", "distinct"):
            probe.set(arg, None)
        if root_with is not None and probe.args.get("with_") is None and select is not tree:
            probe.set("with_", root_with.copy())
        outputs = [exp.alias_(g, f"cair_g{i}") for i, g in enumerate(groups)]
        outputs.append(exp.alias_(key, SUBJECT))
        probe.set("expressions", outputs)
        probe.set("distinct", exp.Distinct())
        sql = probe.sql(dialect=_DIALECT)
        validate_sql(sql, catalog_tables=CATALOG, university_db=university_db)
        probes.append(Probe(branch, sql, len(groups)))
    return probes


def _normalise(value: Any) -> Any:
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, bytes | bytearray):
        return value.decode("utf-8", errors="replace")
    return value


class PopulationProbe:
    """Runs probes on the reader connection (askq_reader, read-only, time-limited)."""

    def __init__(self, database, *, timeout_ms: int, cap: int, university_db: str) -> None:
        self._database = database
        self._university_db = university_db
        self._timeout_ms = int(timeout_ms)
        self._cap = int(cap)
        self._cache: dict[str, list[tuple]] = {}

    def _rows(self, sql: str) -> list[tuple]:
        if sql not in self._cache:
            # Re-validated every time: stored probes are re-run from askq_system.
            validate_sql(sql, catalog_tables=CATALOG, university_db=self._university_db)
            with self._database.reader_connection() as connection:
                if connection.dialect.name == "mysql":
                    connection.exec_driver_sql(
                        f"SET SESSION max_execution_time = {self._timeout_ms}"
                    )
                result = connection.execution_options(no_parameters=True).exec_driver_sql(sql)
                rows = [tuple(r) for r in result.fetchmany(self._cap + 1)]
                result.close()
            if len(rows) > self._cap:
                raise PopulationUnavailable("population larger than the configured cap")
            self._cache[sql] = rows
        return self._cache[sql]

    def cells(self, probes: list[Probe]) -> tuple[Cell, ...]:
        grouped: dict[tuple, set[int]] = defaultdict(set)
        for probe in probes:
            for row in self._rows(probe.sql):
                *group, subject = row
                if subject is None:
                    continue
                key = (probe.branch, *(_normalise(v) for v in group[: probe.group_width]))
                grouped[key].add(int(subject))
        return tuple(
            Cell(key, frozenset(ids))
            for key, ids in sorted(grouped.items(), key=lambda i: repr(i[0]))
        )

    def ids(self, probes: list[Probe]) -> frozenset[int]:
        people: set[int] = set()
        for cell in self.cells(probes):
            people |= cell.ids
        return frozenset(people)


def fingerprint(ids: frozenset[int], fallback: str = "") -> str:
    """SHA-256 of the population (sorted person ids); of the probe SQL if ids are unknown."""
    material = ",".join(str(i) for i in sorted(ids)) if ids else f"sql:{fallback}"
    return hashlib.sha256(f"student:{material}".encode()).hexdigest()
