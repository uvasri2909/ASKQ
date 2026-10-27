"""SqlGenerator backed by a local Ollama server (POST /api/chat).

* Same prompt as Claude (app/llm/prompt.py): the system message carries the
  instructions and this role's schema, the user message the per-user details.
* Output is constrained with Ollama structured outputs ("format": the JSON
  schema) and then validated again with the same strict Pydantic model:
  anything malformed is rejected, never "repaired".
* One non-streaming request, no retries, temperature from settings (0 by
  default) and an explicit context window, because Ollama silently truncates
  a prompt that does not fit.
* No API key. The client ignores proxy environment variables (trust_env=False)
  so the prompt goes only to OLLAMA_BASE_URL, and does not follow redirects.
* HTTP failures map to SqlGenerationError codes; only the exception class
  name or status code is logged, never a response body.
"""

import json
import logging

import httpx
from pydantic import ValidationError

from app.config import Settings
from app.llm.prompt import system_prompt, user_message
from app.llm.sql_generator import (
    OUTPUT_SCHEMA,
    GeneratedSql,
    GenerationCode,
    GenerationRequest,
    SqlGenerationError,
)

logger = logging.getLogger(__name__)

CHAT_PATH = "/api/chat"
# Keep the model loaded between questions so a demo does not reload it each time.
KEEP_ALIVE = "30m"


class OllamaSqlGenerator:
    def __init__(
        self,
        client: httpx.Client,
        model: str,
        *,
        num_ctx: int,
        max_tokens: int,
        temperature: float,
    ) -> None:
        self._client = client
        self._model = model
        self._num_ctx = num_ctx
        self._max_tokens = max_tokens
        self._temperature = temperature

    @classmethod
    def from_settings(cls, settings: Settings) -> "OllamaSqlGenerator":
        client = httpx.Client(
            base_url=settings.ollama_base_url,
            timeout=settings.ollama_timeout_seconds,
            trust_env=False,
            follow_redirects=False,
        )
        return cls(
            client,
            settings.ollama_model,
            num_ctx=settings.ollama_num_ctx,
            max_tokens=settings.ollama_max_tokens,
            temperature=settings.ollama_temperature,
        )

    def generate(self, request: GenerationRequest) -> GeneratedSql:
        body = {
            "model": self._model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system_prompt(request)},
                {"role": "user", "content": user_message(request)},
            ],
            "format": OUTPUT_SCHEMA,
            "options": {
                "temperature": self._temperature,
                "num_ctx": self._num_ctx,
                "num_predict": self._max_tokens,
            },
            "keep_alive": KEEP_ALIVE,
        }
        try:
            response = self._client.post(CHAT_PATH, json=body)
        except httpx.TimeoutException as exc:
            raise self._error(GenerationCode.TIMEOUT, type(exc).__name__) from None
        except httpx.TransportError as exc:
            raise self._error(GenerationCode.UNAVAILABLE, type(exc).__name__) from None
        except httpx.HTTPError as exc:
            raise self._error(GenerationCode.ERROR, type(exc).__name__) from None

        status = response.status_code
        if status == 404:
            # Ollama answers 404 when the model has not been pulled.
            raise self._error(GenerationCode.UNAVAILABLE, "HTTP 404 (model not available?)")
        if 400 <= status < 500:
            raise self._error(GenerationCode.REQUEST_ERROR, f"HTTP {status}")
        if status != 200:
            raise self._error(GenerationCode.ERROR, f"HTTP {status}")

        try:
            envelope = response.json()
        except ValueError:
            raise self._error(GenerationCode.MALFORMED, "invalid response envelope") from None
        if not isinstance(envelope, dict):
            raise self._error(GenerationCode.MALFORMED, "invalid response envelope")
        if envelope.get("done_reason") == "length":
            raise self._error(GenerationCode.TRUNCATED, "done_reason=length")
        message = envelope.get("message")
        text = message.get("content") if isinstance(message, dict) else None
        if not isinstance(text, str):
            raise self._error(GenerationCode.MALFORMED, "no message content")
        try:
            return GeneratedSql.model_validate(json.loads(text))
        except (json.JSONDecodeError, ValidationError, TypeError):
            raise self._error(GenerationCode.MALFORMED, "invalid JSON output") from None

    @staticmethod
    def _error(code: str, what: str) -> SqlGenerationError:
        logger.warning("SQL generation failed: %s (%s)", code, what)
        return SqlGenerationError(code)
