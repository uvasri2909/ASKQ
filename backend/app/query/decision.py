"""The security decision model and the inference-guard hook that CAIR (Phase 5) implements.

Every question ends in exactly one server-controlled Decision:

  ALLOW     executed as authorized (possibly row-scoped and row-limited)
  RESTRICT  executed in a narrower form chosen by the guard
  BLOCK     guard refused it: not executed
  DENIED    authorization refused it (table, column or scope): not executed
  REJECTED  SQL safety validation refused it: not executed
  FAILED    a system error at some stage (generation, validation, ...)

These map one-to-one onto query_history.final_status (see FINAL_STATUS).

The guard runs after authorization and before execution. Phase 4 ships
PassThroughGuard (always ALLOW, risk 0, says so in its reasons). Phase 5
replaces it with CAIR: same interface, reading the per-user ledger. A guard
can only narrow: RESTRICT returns SQL derived from the authorized, scoped
query, and the pipeline re-validates AND re-authorizes it (role tables,
hidden columns, row scope, LIMIT) before running, so a faulty guard cannot
widen what the user may see.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from app.query.authorization import AuthorizedQuery
from app.query.sql_validator import ValidatedQuery
from app.rbac.scope import UserContext


class Decision(StrEnum):
    ALLOW = "ALLOW"
    RESTRICT = "RESTRICT"
    BLOCK = "BLOCK"
    DENIED = "DENIED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


FINAL_STATUS: dict[Decision, str] = {
    Decision.ALLOW: "EXECUTED",
    Decision.RESTRICT: "RESTRICTED",
    Decision.BLOCK: "BLOCKED",
    Decision.DENIED: "DENIED",
    Decision.REJECTED: "REJECTED",
    Decision.FAILED: "FAILED",
}

GUARD_DECISIONS = (Decision.ALLOW, Decision.RESTRICT, Decision.BLOCK)


@dataclass(frozen=True, slots=True)
class PriorTurn:
    """One earlier turn of the conversation, as recorded by the server."""

    question: str
    resolved_question: str | None
    generated_sql: str | None
    final_status: str | None


@dataclass(frozen=True, slots=True)
class GuardInput:
    user: UserContext  # from the server, never from the request or the model
    conversation_id: int | None
    question: str
    resolved_question: str
    validated: ValidatedQuery  # the model's query, as parsed
    authorized: AuthorizedQuery  # scoped + bounded: what would run
    history: tuple[PriorTurn, ...] = ()


@dataclass(frozen=True, slots=True)
class GuardResult:
    decision: Decision  # ALLOW | RESTRICT | BLOCK
    risk_score: float  # 0..1
    policy_version: str
    reasons: tuple[str, ...] = field(default_factory=tuple)
    restricted_sql: str | None = None  # required for RESTRICT

    def __post_init__(self) -> None:
        if self.decision not in GUARD_DECISIONS:
            raise ValueError(f"guard decision must be one of {GUARD_DECISIONS}")
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("risk_score must be within [0, 1]")
        if (self.decision is Decision.RESTRICT) != (self.restricted_sql is not None):
            raise ValueError("restricted_sql is required for RESTRICT and only for RESTRICT")


class InferenceGuard(Protocol):
    def assess(self, request: GuardInput) -> GuardResult: ...


class PassThroughGuard:
    """Phase 4 placeholder: records that no inference analysis ran."""

    policy_version = "phase4-passthrough"

    def assess(self, request: GuardInput) -> GuardResult:
        return GuardResult(
            decision=Decision.ALLOW,
            risk_score=0.0,
            policy_version=self.policy_version,
            reasons=("Inference-risk analysis (CAIR) is not enabled in this version.",),
        )
