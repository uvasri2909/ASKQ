"""CAIR persistence (askq_app): findings, the knowledge ledger, and the history window."""

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import CairAssessment, CairAuditFinding, CairLedgerEntry, QueryHistory


def add_findings(session: Session, assessment_id: int, findings) -> None:
    for finding in findings:
        session.add(
            CairAuditFinding(
                assessment_id=assessment_id,
                audit_type=finding.attack.value,
                score=Decimal(str(round(finding.score, 4))),
                triggered=finding.triggered,
                explanation=finding.explanation[:1000],
                evidence=finding.evidence or None,
            )
        )


def add_ledger_entry(
    session: Session,
    *,
    query_id: int,
    user_id: int,
    descriptor: dict[str, Any],
    fingerprint: str,
    result_cardinality: int | None,
) -> None:
    session.add(
        CairLedgerEntry(
            query_id=query_id,
            user_id=user_id,
            descriptor=descriptor,
            population_fingerprint=fingerprint,
            result_cardinality=result_cardinality,
        )
    )


@dataclass(frozen=True, slots=True)
class AssessedQuery:
    query_id: int
    conversation_id: int | None
    cair_decision: str | None
    final_status: str
    assessment: dict[str, Any]


def recent_statistical_assessments(
    session: Session, user_id: int, since: datetime, limit: int
) -> list[AssessedQuery]:
    """The user's most recent CAIR-assessed statistical queries, oldest first.

    Read from the server's own tables only: nothing here comes from the request.
    """
    rows = session.execute(
        select(QueryHistory, CairAssessment)
        .join(CairAssessment, CairAssessment.query_id == QueryHistory.query_id)
        .where(QueryHistory.user_id == user_id, QueryHistory.created_at >= since)
        .order_by(QueryHistory.query_id.desc())
        .limit(limit * 3)
    ).all()
    found: list[AssessedQuery] = []
    for history, assessment in rows:
        reasons = assessment.reasons
        if not isinstance(reasons, dict) or reasons.get("tier") != "STATISTICAL":
            continue
        found.append(
            AssessedQuery(
                query_id=history.query_id,
                conversation_id=history.conversation_id,
                cair_decision=history.cair_decision,
                final_status=history.final_status,
                assessment=reasons,
            )
        )
        if len(found) >= limit:
            break
    return list(reversed(found))
