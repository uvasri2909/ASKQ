import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.llm.sql_generator import ChartHint
from app.query.decision import Decision
from app.rbac.scope import ScopeKind

MAX_QUESTION_LENGTH = 1000


class QueryRequest(BaseModel):
    # Only the question and (optionally) which of the caller's conversations it
    # continues. Role, scope, SQL and decisions are never accepted from clients.
    model_config = ConfigDict(extra="forbid")

    question: str = Field(min_length=1, max_length=MAX_QUESTION_LENGTH)
    conversation_id: uuid.UUID | None = None

    @field_validator("question")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("question must not be blank")
        return value


class SecuritySummary(BaseModel):
    validation: str | None = Field(description="PASSED | REJECTED, or null if not reached")
    authorization: str | None = Field(description="ALLOWED | REWRITTEN | DENIED, or null")
    guard_decision: str | None = Field(description="ALLOW | RESTRICT | BLOCK, or null")
    risk_score: float | None
    guard_reasons: list[str]
    scope: ScopeKind
    notes: list[str]


class QueryResponse(BaseModel):
    query_id: int
    conversation_id: str
    decision: Decision
    message: str
    reason_code: str | None
    question: str
    resolved_question: str | None
    explanation: str | None
    sql: str | None = Field(description="The SQL that was executed (null if nothing ran)")
    columns: list[str]
    rows: list[list[Any]]
    row_count: int
    row_limit: int | None
    execution_ms: int | None
    chart: ChartHint | None
    security: SecuritySummary
