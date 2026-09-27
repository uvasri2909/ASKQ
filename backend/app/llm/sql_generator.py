"""The SQL-generation contract, independent of any model provider."""

from dataclasses import dataclass, field
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from app.query.decision import PriorTurn

ChartType = Literal["table", "bar", "line", "pie", "number"]


@dataclass(frozen=True, slots=True)
class GenerationRequest:
    question: str
    role: str
    scope_description: str
    schema_context: str
    history: tuple[PriorTurn, ...] = field(default_factory=tuple)


class ChartHint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: ChartType
    x: str = Field(default="", max_length=64)
    y: str = Field(default="", max_length=64)


class GeneratedSql(BaseModel):
    """The model's structured answer. Validated strictly; the SQL is still untrusted."""

    model_config = ConfigDict(extra="forbid")

    resolved_question: str = Field(min_length=1, max_length=2000)
    sql: str = Field(max_length=10_000)  # "" = cannot be answered from the schema
    explanation: str = Field(max_length=1000)
    chart: ChartHint
    # Which population the question is about: the user's own row scope, or
    # university-wide aggregate statistics. A request, not a permission: each
    # tier's rules are enforced by the server on the SQL.
    population: Literal["scope", "university"] = "scope"


# JSON schema sent to the API as output_config.format (mirrors GeneratedSql).
OUTPUT_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "resolved_question": {"type": "string"},
        "sql": {"type": "string"},
        "explanation": {"type": "string"},
        "chart": {
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["table", "bar", "line", "pie", "number"]},
                "x": {"type": "string"},
                "y": {"type": "string"},
            },
            "required": ["type", "x", "y"],
            "additionalProperties": False,
        },
        "population": {"type": "string", "enum": ["scope", "university"]},
    },
    "required": ["resolved_question", "sql", "explanation", "chart", "population"],
    "additionalProperties": False,
}


class GenerationCode:
    NOT_CONFIGURED = "LLM_NOT_CONFIGURED"
    TIMEOUT = "LLM_TIMEOUT"
    RATE_LIMITED = "LLM_RATE_LIMITED"
    UNAVAILABLE = "LLM_UNAVAILABLE"
    AUTH = "LLM_AUTH_ERROR"
    REQUEST_ERROR = "LLM_REQUEST_ERROR"
    ERROR = "LLM_ERROR"
    REFUSED = "LLM_REFUSED"
    TRUNCATED = "LLM_TRUNCATED"
    MALFORMED = "LLM_MALFORMED_OUTPUT"
    UNANSWERABLE = "UNANSWERABLE"


_MESSAGES = {
    GenerationCode.NOT_CONFIGURED: "Question answering is not configured on this server.",
    GenerationCode.TIMEOUT: "The language model took too long to respond. Please try again.",
    GenerationCode.RATE_LIMITED: "The language model is busy. Please try again shortly.",
    GenerationCode.UNAVAILABLE: "The language model is unavailable. Please try again later.",
    GenerationCode.AUTH: "Question answering is not configured correctly on this server.",
    GenerationCode.REQUEST_ERROR: "The question could not be processed.",
    GenerationCode.ERROR: "The language model returned an error. Please try again.",
    GenerationCode.REFUSED: "The language model declined to answer this question.",
    GenerationCode.TRUNCATED: "The language model's answer was incomplete. Please rephrase.",
    GenerationCode.MALFORMED: "The language model returned an invalid answer. Please try again.",
    GenerationCode.UNANSWERABLE: "This question cannot be answered from the available data.",
}


class SqlGenerationError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code
        self.message = _MESSAGES[code]


class SqlGenerator(Protocol):
    def generate(self, request: GenerationRequest) -> GeneratedSql: ...
