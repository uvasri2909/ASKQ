"""ClaudeSqlGenerator against a stub client: no network, no real API key."""

import json
import logging
import secrets
from types import SimpleNamespace

import anthropic
import httpx2
import pytest

from app.config import ConfigurationError
from app.llm.claude import ClaudeSqlGenerator
from app.llm.sql_generator import (
    OUTPUT_SCHEMA,
    GeneratedSql,
    GenerationCode,
    GenerationRequest,
    SqlGenerationError,
)
from app.query.decision import PriorTurn
from app.query.schema_context import schema_context
from app.rbac.roles import Role
from tests.conftest import make_settings

FAKE_KEY = "sk-ant-test-" + secrets.token_urlsafe(24)

GOOD = {
    "resolved_question": "How many students are there?",
    "sql": "SELECT COUNT(*) AS students FROM students",
    "explanation": "Counts students.",
    "chart": {"type": "number", "x": "", "y": "students"},
}


class StubMessages:
    def __init__(self, result):
        self.result = result
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def response(text=None, stop_reason="end_turn", blocks=None):
    content = blocks if blocks is not None else [SimpleNamespace(type="text", text=text)]
    return SimpleNamespace(content=content, stop_reason=stop_reason)


def generator_for(result):
    messages = StubMessages(result)
    client = SimpleNamespace(messages=messages)
    return ClaudeSqlGenerator(client, "claude-sonnet-5", 16000), messages


def request(role=Role.HOD, history=()):
    return GenerationRequest(
        question="How many students are there?",
        role=role.value,
        scope_description="your own department (department_id = 1)",
        schema_context=schema_context(role),
        history=history,
    )


_REQ = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


def _status(cls, code):
    return cls(
        f"error mentioning {FAKE_KEY}",
        response=httpx2.Response(code, request=_REQ),
        body={"error": {"message": FAKE_KEY}},
    )


# ---------- success ----------


def test_structured_generation_succeeds():
    generator, messages = generator_for(response(json.dumps(GOOD)))
    result = generator.generate(request())
    assert isinstance(result, GeneratedSql)
    assert result.sql == GOOD["sql"] and result.chart.type == "number"


def test_request_uses_structured_output_caching_and_role_schema():
    generator, messages = generator_for(response(json.dumps(GOOD)))
    generator.generate(request(Role.TEACHER))
    call = messages.calls[0]
    assert call["model"] == "claude-sonnet-5"
    assert call["output_config"] == {"format": {"type": "json_schema", "schema": OUTPUT_SCHEMA}}
    system = call["system"][0]
    assert system["cache_control"] == {"type": "ephemeral"}
    # The teacher's schema: no financial tables, no hidden columns, no auth/system tables.
    for absent in ("fees", "annual_salary", "gender", "users", "app_user_credentials"):
        assert absent not in system["text"].split("Schema:")[1]
    user = call["messages"][0]["content"]
    assert "<user_role>TEACHER</user_role>" in user
    assert "<question>How many students are there?</question>" in user


def test_history_is_passed_as_data():
    history = (PriorTurn("How many CSE students?", "Count CSE students", "SELECT 1", "EXECUTED"),)
    generator, messages = generator_for(response(json.dumps(GOOD)))
    generator.generate(request(history=history))
    user = messages.calls[0]["messages"][0]["content"]
    assert "<conversation>" in user and "<resolved>Count CSE students</resolved>" in user


def test_empty_sql_is_returned_for_the_pipeline_to_handle():
    generator, _ = generator_for(response(json.dumps({**GOOD, "sql": ""})))
    assert generator.generate(request()).sql == ""


# ---------- malformed output ----------


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "",
        json.dumps({**GOOD, "extra": "field"}),
        json.dumps({k: v for k, v in GOOD.items() if k != "chart"}),
        json.dumps({**GOOD, "chart": {"type": "radar", "x": "", "y": ""}}),
        json.dumps({**GOOD, "sql": 42}),
        json.dumps({**GOOD, "resolved_question": ""}),
        json.dumps({**GOOD, "sql": "SELECT " + "x" * 20_000}),
        json.dumps([GOOD]),
    ],
)
def test_malformed_output_rejected(text):
    generator, _ = generator_for(response(text))
    with pytest.raises(SqlGenerationError) as info:
        generator.generate(request())
    assert info.value.code == GenerationCode.MALFORMED


def test_no_text_block_rejected():
    generator, _ = generator_for(response(blocks=[SimpleNamespace(type="thinking", thinking="")]))
    with pytest.raises(SqlGenerationError) as info:
        generator.generate(request())
    assert info.value.code == GenerationCode.MALFORMED


@pytest.mark.parametrize(
    ("stop_reason", "code"),
    [("refusal", GenerationCode.REFUSED), ("max_tokens", GenerationCode.TRUNCATED)],
)
def test_stop_reasons_rejected(stop_reason, code):
    generator, _ = generator_for(response(json.dumps(GOOD), stop_reason=stop_reason))
    with pytest.raises(SqlGenerationError) as info:
        generator.generate(request())
    assert info.value.code == code


# ---------- API failures ----------


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (anthropic.APITimeoutError(request=_REQ), GenerationCode.TIMEOUT),
        (anthropic.APIConnectionError(request=_REQ), GenerationCode.UNAVAILABLE),
        (_status(anthropic.RateLimitError, 429), GenerationCode.RATE_LIMITED),
        (_status(anthropic.AuthenticationError, 401), GenerationCode.AUTH),
        (_status(anthropic.PermissionDeniedError, 403), GenerationCode.AUTH),
        (_status(anthropic.BadRequestError, 400), GenerationCode.REQUEST_ERROR),
        (_status(anthropic.InternalServerError, 500), GenerationCode.ERROR),
        (_status(anthropic.APIStatusError, 529), GenerationCode.ERROR),
    ],
)
def test_api_errors_map_to_safe_codes_without_leaking(error, code, caplog):
    caplog.set_level(logging.DEBUG)
    generator, _ = generator_for(error)
    with pytest.raises(SqlGenerationError) as info:
        generator.generate(request())
    assert info.value.code == code
    assert info.value.__cause__ is None and info.value.__suppress_context__
    assert FAKE_KEY not in str(info.value) + info.value.message + caplog.text


# ---------- configuration ----------


def test_from_settings_passes_key_timeout_and_retries_explicitly():
    settings = make_settings(
        anthropic_api_key=FAKE_KEY, anthropic_timeout_seconds=12.5, anthropic_max_retries=0
    )
    generator = ClaudeSqlGenerator.from_settings(settings)
    client = generator._client
    assert client.api_key == FAKE_KEY
    assert client.timeout == 12.5 and client.max_retries == 0
    assert FAKE_KEY not in repr(generator) + repr(client)


@pytest.mark.parametrize("key", [None, "", "your-anthropic-api-key-here"])
def test_no_api_key_means_not_configured(key):
    with pytest.raises(ConfigurationError, match="ANTHROPIC_API_KEY"):
        ClaudeSqlGenerator.from_settings(make_settings(anthropic_api_key=key))
