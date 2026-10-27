"""OllamaSqlGenerator against httpx.MockTransport: no network, no Ollama server."""

import json
import logging

import httpx
import pytest

from app.llm.ollama import CHAT_PATH, OllamaSqlGenerator
from app.llm.prompt import system_prompt, user_message
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

BASE_URL = "http://127.0.0.1:11434"
# A marker that must never reach the logs or the error shown to the caller.
LEAK = "ollama-internal-detail-must-not-leak"

GOOD = {
    "resolved_question": "How many students are there?",
    "sql": "SELECT COUNT(*) AS students FROM students",
    "explanation": "Counts students.",
    "chart": {"type": "number", "x": "", "y": "students"},
    "population": "scope",
}


def chat_response(content, done_reason="stop", status=200):
    return httpx.Response(
        status,
        json={
            "model": "qwen2.5-coder:7b",
            "message": {"role": "assistant", "content": content},
            "done": True,
            "done_reason": done_reason,
        },
    )


def generator_for(result):
    """result: an httpx.Response, an exception to raise, or a callable(request)."""
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        if isinstance(result, Exception):
            raise result
        if callable(result):
            return result(req)
        return result

    client = httpx.Client(base_url=BASE_URL, transport=httpx.MockTransport(handler))
    generator = OllamaSqlGenerator(
        client, "qwen2.5-coder:7b", num_ctx=8192, max_tokens=2048, temperature=0.0
    )
    return generator, calls


def request(role=Role.HOD, history=()):
    return GenerationRequest(
        question="How many students are there?",
        role=role.value,
        scope_description="your own department (department_id = 1)",
        schema_context=schema_context(role),
        history=history,
    )


def body_of(call: httpx.Request) -> dict:
    return json.loads(call.content)


# ---------- success ----------


def test_structured_generation_succeeds():
    generator, _ = generator_for(chat_response(json.dumps(GOOD)))
    result = generator.generate(request())
    assert isinstance(result, GeneratedSql)
    assert result.sql == GOOD["sql"] and result.chart.type == "number"


def test_request_uses_chat_endpoint_schema_and_options():
    generator, calls = generator_for(chat_response(json.dumps(GOOD)))
    generator.generate(request(Role.TEACHER))
    call = calls[0]
    assert call.method == "POST" and call.url == BASE_URL + CHAT_PATH
    assert "authorization" not in call.headers
    body = body_of(call)
    assert body["model"] == "qwen2.5-coder:7b"
    assert body["stream"] is False
    assert body["format"] == OUTPUT_SCHEMA
    assert body["options"] == {"temperature": 0.0, "num_ctx": 8192, "num_predict": 2048}


def test_prompt_is_the_shared_prompt_with_the_roles_schema():
    req = request(Role.TEACHER)
    generator, calls = generator_for(chat_response(json.dumps(GOOD)))
    generator.generate(req)
    system, user = body_of(calls[0])["messages"]
    assert system == {"role": "system", "content": system_prompt(req)}
    assert user == {"role": "user", "content": user_message(req)}
    # The teacher's schema: no financial tables, no hidden columns, no auth/system tables.
    for absent in ("fees", "annual_salary", "gender", "users", "app_user_credentials"):
        assert absent not in system["content"].split("Schema:")[1]
    assert "<user_role>TEACHER</user_role>" in user["content"]
    assert "<question>How many students are there?</question>" in user["content"]


def test_history_is_passed_as_data():
    history = (PriorTurn("How many CSE students?", "Count CSE students", "SELECT 1", "EXECUTED"),)
    generator, calls = generator_for(chat_response(json.dumps(GOOD)))
    generator.generate(request(history=history))
    user = body_of(calls[0])["messages"][1]["content"]
    assert "<conversation>" in user and "<resolved>Count CSE students</resolved>" in user


def test_empty_sql_is_returned_for_the_pipeline_to_handle():
    generator, _ = generator_for(chat_response(json.dumps({**GOOD, "sql": ""})))
    assert generator.generate(request()).sql == ""


def test_dangerous_sql_is_returned_untouched_for_the_pipeline_to_reject():
    # The generator does not judge SQL; validation is the pipeline's job.
    generator, _ = generator_for(chat_response(json.dumps({**GOOD, "sql": "DROP TABLE users"})))
    assert generator.generate(request()).sql == "DROP TABLE users"


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
        json.dumps({**GOOD, "population": "everyone"}),
        json.dumps({**GOOD, "sql": "SELECT " + "x" * 20_000}),
        json.dumps([GOOD]),
    ],
)
def test_malformed_output_rejected(text):
    generator, _ = generator_for(chat_response(text))
    with pytest.raises(SqlGenerationError) as info:
        generator.generate(request())
    assert info.value.code == GenerationCode.MALFORMED


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="not json"),
        httpx.Response(200, json=[1, 2]),
        httpx.Response(200, json={"done": True}),
        httpx.Response(200, json={"message": "text"}),
        httpx.Response(200, json={"message": {"role": "assistant", "content": None}}),
    ],
)
def test_malformed_envelope_rejected(response):
    generator, _ = generator_for(response)
    with pytest.raises(SqlGenerationError) as info:
        generator.generate(request())
    assert info.value.code == GenerationCode.MALFORMED


def test_truncated_output_rejected():
    generator, _ = generator_for(chat_response(json.dumps(GOOD), done_reason="length"))
    with pytest.raises(SqlGenerationError) as info:
        generator.generate(request())
    assert info.value.code == GenerationCode.TRUNCATED


# ---------- server failures ----------


def _error_response(status):
    return httpx.Response(status, json={"error": LEAK})


@pytest.mark.parametrize(
    ("result", "code"),
    [
        (httpx.ReadTimeout(LEAK), GenerationCode.TIMEOUT),
        (httpx.ConnectTimeout(LEAK), GenerationCode.TIMEOUT),
        (httpx.ConnectError(LEAK), GenerationCode.UNAVAILABLE),
        (httpx.RemoteProtocolError(LEAK), GenerationCode.UNAVAILABLE),
        (_error_response(404), GenerationCode.UNAVAILABLE),
        (_error_response(400), GenerationCode.REQUEST_ERROR),
        (_error_response(500), GenerationCode.ERROR),
        (_error_response(503), GenerationCode.ERROR),
        (
            httpx.Response(302, headers={"location": "http://elsewhere.example/"}),
            GenerationCode.ERROR,
        ),
    ],
)
def test_failures_map_to_safe_codes_without_leaking(result, code, caplog):
    caplog.set_level(logging.DEBUG)
    generator, calls = generator_for(result)
    with pytest.raises(SqlGenerationError) as info:
        generator.generate(request())
    assert info.value.code == code
    # No chained exception (which could carry the server's detail) reaches the caller.
    assert info.value.__cause__ is None
    assert info.value.__context__ is None or info.value.__suppress_context__
    assert LEAK not in str(info.value) + info.value.message + caplog.text
    assert len(calls) == 1  # no retries, no redirect followed


# ---------- configuration ----------


def test_from_settings_uses_configured_server_and_options():
    settings = make_settings(
        llm_provider="ollama",
        anthropic_api_key=None,
        ollama_base_url="http://127.0.0.1:11500",
        ollama_model="qwen2.5-coder:7b",
        ollama_timeout_seconds=90,
        ollama_num_ctx=16384,
        ollama_max_tokens=1024,
        ollama_temperature=0.0,
    )
    generator = OllamaSqlGenerator.from_settings(settings)
    client = generator._client
    assert str(client.base_url).rstrip("/") == "http://127.0.0.1:11500"
    assert client.timeout == httpx.Timeout(90)
    assert client.trust_env is False and client.follow_redirects is False
    assert generator._model == "qwen2.5-coder:7b"
    assert (generator._num_ctx, generator._max_tokens, generator._temperature) == (
        16384,
        1024,
        0.0,
    )


def test_defaults_match_the_demo_configuration():
    generator = OllamaSqlGenerator.from_settings(make_settings(llm_provider="ollama"))
    assert str(generator._client.base_url).rstrip("/") == "http://127.0.0.1:11434"
    assert generator._client.timeout == httpx.Timeout(120)
    assert generator._model == "qwen2.5-coder:7b"
    assert (generator._num_ctx, generator._temperature) == (8192, 0.0)
