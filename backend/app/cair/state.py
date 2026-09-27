"""The conversation security state: what a user already learned and was refused.

Loaded, for every question, from askq_system (query_history joined with the
cair_assessments CAIR itself wrote). Nothing is taken from the request or the
model, so risk scores, earlier decisions and "revealed facts" cannot be forged
by a client.

Window: the user's last `cair_window_queries` statistical questions within
`cair_window_hours`, across ALL their conversations (an attacker can switch
conversations); CONTEXT_CARRYOVER additionally looks at the current
conversation only. Populations are recomputed from the stored, validated probe
SQL, so the ledger never stores lists of people.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.cair.model import Cell, Measure, Observation
from app.cair.population import PopulationProbe, Probe
from app.db.repositories.cair import AssessedQuery, recent_statistical_assessments

_EXECUTED = ("EXECUTED", "RESTRICTED")


def _keys(raw) -> frozenset[tuple]:
    return frozenset(tuple(k) for k in raw or [])


def revealed_cells(cells: tuple[Cell, ...], min_size: int, excluded: frozenset) -> tuple[Cell, ...]:
    """Cells an executed statistical query returned: >= k people and not excluded by CAIR."""
    return tuple(c for c in cells if c.size >= min_size and c.key not in excluded)


def observation_from_assessment(
    record: AssessedQuery, probe: PopulationProbe, min_size: int
) -> Observation:
    """Rebuild one earlier question. Any failure propagates: CAIR fails closed rather
    than silently forgetting part of what the user already knows."""
    data = record.assessment
    cells = probe.cells([Probe.from_json(p) for p in data.get("probes", [])])
    known_probes = [Probe.from_json(p) for p in data.get("known_probes", [])]
    known = probe.ids(known_probes) if known_probes else frozenset()
    executed = record.final_status in _EXECUTED
    excluded = _keys(data.get("excluded"))
    return Observation(
        query_id=record.query_id,
        conversation_id=record.conversation_id,
        decision=record.cair_decision or "",
        cells=cells,
        revealed=revealed_cells(cells, min_size, excluded) if executed else (),
        measures=frozenset(Measure(*m.split(":", 1)) for m in data.get("measures", [])),
        dimensions=frozenset(data.get("dimensions", [])),
        known=known,
    )


@dataclass(frozen=True, slots=True)
class ConversationSecurityState:
    conversation_id: int | None
    history: tuple[Observation, ...]  # oldest first

    @property
    def executed(self) -> tuple[Observation, ...]:
        return tuple(o for o in self.history if o.revealed)

    @property
    def refused(self) -> tuple[Observation, ...]:
        return tuple(o for o in self.history if o.decision == "BLOCK")

    def in_conversation(self) -> tuple[Observation, ...]:
        if self.conversation_id is None:
            return ()
        return tuple(o for o in self.history if o.conversation_id == self.conversation_id)


def load_state(
    session: Session,
    probe: PopulationProbe,
    *,
    user_id: int,
    conversation_id: int | None,
    now: datetime,
    window_queries: int,
    window_hours: int,
    min_size: int,
) -> ConversationSecurityState:
    records = recent_statistical_assessments(
        session, user_id, now - timedelta(hours=window_hours), window_queries
    )
    history = tuple(observation_from_assessment(r, probe, min_size) for r in records)
    return ConversationSecurityState(conversation_id, history)
