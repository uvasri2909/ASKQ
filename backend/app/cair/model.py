"""Value types shared by the CAIR modules."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class AttackClass(StrEnum):
    # Names match askq_system.cair_audit_findings.audit_type (ck_findings_audit_type).
    DIFFERENCING = "DIFFERENCING"
    NARROWING = "NARROWING"
    ARITHMETIC_RECOVERY = "ARITHMETIC_RECOVERY"
    CROSS_VIEW_LINKING = "CROSS_VIEW_LINKING"
    REFUSAL_SIDE_CHANNEL = "REFUSAL_SIDE_CHANNEL"
    CONTEXT_CARRYOVER = "CONTEXT_CARRYOVER"


@dataclass(frozen=True, slots=True)
class Cell:
    """One statistic's population: the people behind one output row (group)."""

    key: tuple[Any, ...]  # (branch, group values...); () for an ungrouped query
    ids: frozenset[int]

    @property
    def size(self) -> int:
        return len(self.ids)


@dataclass(frozen=True, slots=True)
class Measure:
    """What a statistic reveals: kind in {count, sum, min, max, spread} over a metric."""

    kind: str
    metric: str  # "table.column", or "*" for counts

    def as_key(self) -> str:
        return f"{self.kind}:{self.metric}"


@dataclass(frozen=True, slots=True)
class Observation:
    """One statistical query as CAIR sees it: now, or recomputed from the history."""

    query_id: int | None
    conversation_id: int | None
    decision: str  # ALLOW | RESTRICT | BLOCK (guard decision)
    cells: tuple[Cell, ...]  # all cells before suppression
    revealed: tuple[Cell, ...]  # cells the user actually received
    measures: frozenset[Measure]
    dimensions: frozenset[str]  # filter + group columns
    known: frozenset[int]  # people the user may already see record by record

    @property
    def population(self) -> frozenset[int]:
        ids: set[int] = set()
        for cell in self.cells:
            ids |= cell.ids
        return frozenset(ids)


@dataclass(frozen=True, slots=True)
class Finding:
    attack: AttackClass
    score: float  # 0..1
    triggered: bool
    explanation: str  # internal (stored), never returned to the client
    evidence: dict[str, Any] = field(default_factory=dict)
    # Output cells whose removal would remove the risk (grouped queries only).
    implicated: frozenset[tuple[Any, ...]] = frozenset()
