"""SqlGenerator backed by the Claude API (Anthropic Python SDK).

* The API key comes only from Settings (ANTHROPIC_API_KEY, a SecretStr) and
  is passed explicitly to the client; it is never logged or returned.
* Output is constrained with structured outputs (output_config.format, a JSON
  schema) and then validated again with a strict Pydantic model: anything
  malformed is rejected, never "repaired".
* SDK errors map to SqlGenerationError codes; only the exception class name
  is logged, because SDK error messages can echo request details.
* The system prompt (app/llm/prompt.py: instructions + this role's schema)
  is identical for all users of a role and is marked for prompt caching;
  per-user details (scope, history, question) follow in the user message.
"""

import json
import logging

import anthropic
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


class ClaudeSqlGenerator:
    def __init__(self, client: anthropic.Anthropic, model: str, max_tokens: int) -> None:
        self._client = client
        self._model = model
        self._max_tokens = max_tokens

    @classmethod
    def from_settings(cls, settings: Settings) -> "ClaudeSqlGenerator":
        """Raises ConfigurationError if ANTHROPIC_API_KEY is not configured."""
        client = anthropic.Anthropic(
            api_key=settings.secret("anthropic_api_key"),
            timeout=settings.anthropic_timeout_seconds,
            max_retries=settings.anthropic_max_retries,
        )
        return cls(client, settings.anthropic_model, settings.anthropic_max_tokens)

    def generate(self, request: GenerationRequest) -> GeneratedSql:
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=[
                    {
                        "type": "text",
                        "text": system_prompt(request),
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[{"role": "user", "content": user_message(request)}],
                output_config={"format": {"type": "json_schema", "schema": OUTPUT_SCHEMA}},
            )
        except anthropic.APITimeoutError:
            raise self._error(GenerationCode.TIMEOUT, "APITimeoutError") from None
        except anthropic.APIConnectionError:
            raise self._error(GenerationCode.UNAVAILABLE, "APIConnectionError") from None
        except anthropic.RateLimitError:
            raise self._error(GenerationCode.RATE_LIMITED, "RateLimitError") from None
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as exc:
            logger.error("Claude API rejected the credentials: %s", type(exc).__name__)
            raise SqlGenerationError(GenerationCode.AUTH) from None
        except anthropic.BadRequestError:
            raise self._error(GenerationCode.REQUEST_ERROR, "BadRequestError") from None
        except anthropic.APIStatusError as exc:
            raise self._error(GenerationCode.ERROR, f"APIStatusError {exc.status_code}") from None
        except anthropic.AnthropicError as exc:
            raise self._error(GenerationCode.ERROR, type(exc).__name__) from None

        if response.stop_reason == "refusal":
            raise self._error(GenerationCode.REFUSED, "stop_reason=refusal")
        if response.stop_reason == "max_tokens":
            raise self._error(GenerationCode.TRUNCATED, "stop_reason=max_tokens")
        text = next((b.text for b in response.content if b.type == "text"), None)
        if text is None:
            raise self._error(GenerationCode.MALFORMED, "no text block")
        try:
            return GeneratedSql.model_validate(json.loads(text))
        except (json.JSONDecodeError, ValidationError, TypeError):
            raise self._error(GenerationCode.MALFORMED, "invalid JSON output") from None

    @staticmethod
    def _error(code: str, what: str) -> SqlGenerationError:
        logger.warning("SQL generation failed: %s (%s)", code, what)
        return SqlGenerationError(code)
