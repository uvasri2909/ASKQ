"""From findings to a decision.

    risk = 1 - PRODUCT(1 - score_i)          over all six audits (0 = no risk)

Decision:
  * nothing triggered                                   -> ALLOW
  * NARROWING or REFUSAL_SIDE_CHANNEL triggered         -> BLOCK (no safe part)
  * otherwise, for a grouped statistic: withhold the implicated groups
    (plus complementary suppression for arithmetic recovery), re-run every
    audit on what would remain, repeat; if something safe remains -> RESTRICT
  * otherwise                                           -> BLOCK

Deterministic: same history, same question, same decision.
"""

from dataclasses import dataclass

from app.cair import detectors
from app.cair.model import AttackClass, Cell, Finding, Observation
from app.cair.state import ConversationSecurityState
from app.query.decision import Decision

_UNRESTRICTABLE = {AttackClass.NARROWING, AttackClass.REFUSAL_SIDE_CHANNEL}
_MAX_ROUNDS = 5


@dataclass(frozen=True, slots=True)
class Assessment:
    decision: Decision
    risk: float
    findings: tuple[Finding, ...]
    excluded: frozenset[tuple]  # group keys withheld (RESTRICT)
    revealed: tuple[Cell, ...]  # what the user will receive

    @property
    def attack_classes(self) -> list[str]:
        return sorted(f.attack.value for f in self.findings if f.triggered)


def risk_level(risk: float) -> str:
    return "HIGH" if risk >= 0.7 else "MEDIUM" if risk >= 0.3 else "LOW"


def run_audits(
    current: Observation,
    candidate: tuple[Cell, ...],
    state: ConversationSecurityState,
    *,
    k: int,
    refusal_limit: int,
    threshold: float,
) -> tuple[Finding, ...]:
    history = state.history
    raw = (
        detectors.differencing(current, candidate, state.executed, k),
        detectors.narrowing(current, candidate, state.executed, k),
        detectors.arithmetic_recovery(current, candidate, state.executed, k),
        detectors.cross_view_linking(current, candidate, history, k),
        detectors.refusal_side_channel(current, state.refused, refusal_limit, threshold),
        detectors.context_carryover(current, state.in_conversation(), k),
    )
    # A finding counts as triggered only at or above the configured threshold.
    return tuple(
        Finding(f.attack, f.score, f.triggered and f.score >= threshold, f.explanation,
                f.evidence, f.implicated)
        for f in raw
    )  # fmt: skip


def combined_risk(findings: tuple[Finding, ...]) -> float:
    remaining = 1.0
    for finding in findings:
        remaining *= 1.0 - max(0.0, min(1.0, finding.score))
    return round(1.0 - remaining, 4)


def assess(
    current: Observation,
    state: ConversationSecurityState,
    *,
    k: int,
    refusal_limit: int,
    threshold: float,
    grouped: bool,
) -> Assessment:
    candidate = tuple(c for c in current.cells if c.size >= k)
    findings = run_audits(
        current, candidate, state, k=k, refusal_limit=refusal_limit, threshold=threshold
    )
    risk = combined_risk(findings)
    triggered = [f for f in findings if f.triggered]
    if not triggered:
        return Assessment(Decision.ALLOW, risk, findings, frozenset(), candidate)
    if not grouped or any(f.attack in _UNRESTRICTABLE for f in triggered):
        return Assessment(Decision.BLOCK, risk, findings, frozenset(), ())

    excluded: set[tuple] = set()
    round_findings = findings
    for _ in range(_MAX_ROUNDS):
        round_triggered = [f for f in round_findings if f.triggered]
        if not round_triggered:
            remaining = tuple(c for c in candidate if c.key not in excluded)
            return Assessment(Decision.RESTRICT, risk, findings, frozenset(excluded), remaining)
        implicated = set().union(*(f.implicated for f in round_triggered))
        if (
            not implicated
            or implicated <= excluded
            or any(f.attack in _UNRESTRICTABLE for f in round_triggered)
        ):
            break
        excluded |= implicated
        remaining = tuple(c for c in candidate if c.key not in excluded)
        if not remaining:
            break
        round_findings = run_audits(
            current, remaining, state, k=k, refusal_limit=refusal_limit, threshold=threshold
        )
    return Assessment(Decision.BLOCK, risk, findings, frozenset(), ())
