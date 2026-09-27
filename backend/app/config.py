"""Application settings, loaded from environment variables / the root .env file.

Variable names are shared with database/setup_db.ps1 and
database/tools/verify_accounts.py (DB_*), so they must not be renamed.

Secrets are SecretStr (masked in repr, logs and validation errors), never
hard-coded, and have no fallback values. Outside production a missing or
placeholder secret is allowed: the feature that needs it answers HTTP 503
("not configured") instead of running with a weak default. APP_ENV=production
refuses to start unless every secret and CORS_ORIGINS are set explicitly.
"""

import re
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The single .env file lives at the project root (C:\ASKQ\.env), one level above backend/.
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Values copied unchanged from .env.example count as "not configured".
PLACEHOLDER_PREFIXES = ("change-me", "your-")
MIN_JWT_SECRET_LENGTH = 32
# HMAC only: the secret is shared by issuer and verifier, and "none" is never accepted.
ALLOWED_JWT_ALGORITHMS = ("HS256", "HS384", "HS512")
SECRET_FIELDS = ("db_reader_password", "db_app_password", "jwt_secret", "anthropic_api_key")

_IDENTIFIER = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_ORIGIN = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$")
_MODEL_ID = re.compile(r"^[A-Za-z0-9._:@/-]{1,100}$")


class ConfigurationError(RuntimeError):
    """A feature was used whose settings are missing. The message never contains a secret."""


def _is_placeholder(value: SecretStr | None) -> bool:
    return value is not None and value.get_secret_value().startswith(PLACEHOLDER_PREFIXES)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        # .env also holds settings for later phases; ignore ones not modelled yet.
        extra="ignore",
        # Never echo a rejected value (it may be a secret) in a validation error.
        hide_input_in_errors=True,
    )

    app_env: Literal["development", "test", "production"] = "development"
    # Comma-separated list of allowed browser origins for CORS (no "*").
    cors_origins: str = "http://localhost:5173"

    # ---- MySQL (names shared with database/setup_db.ps1) ----
    db_host: str = "127.0.0.1"
    db_port: int = Field(default=3306, ge=1, le=65535)
    db_university_name: str = "askq_university"
    db_system_name: str = "askq_system"
    db_reader_user: str = "askq_reader"
    db_reader_password: SecretStr | None = None
    db_app_user: str = "askq_app"
    db_app_password: SecretStr | None = None
    # Per engine. Each account is capped at MAX_USER_CONNECTIONS 20 in MySQL,
    # so pool_size + max_overflow must stay <= 20.
    db_pool_size: int = Field(default=5, ge=1, le=10)
    db_max_overflow: int = Field(default=5, ge=0, le=10)
    db_pool_recycle_seconds: int = Field(default=1800, ge=60, le=28800)
    db_connect_timeout_seconds: int = Field(default=5, ge=1, le=60)

    # ---- Authentication ----
    jwt_secret: SecretStr | None = None
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = Field(default=60, ge=1, le=1440)

    # ---- Claude (SQL generation) ----
    anthropic_api_key: SecretStr | None = None
    # Model id as named in the Claude API. The project default is kept in
    # .env.example; any current model id can be configured.
    anthropic_model: str = "claude-sonnet-5"
    anthropic_max_tokens: int = Field(default=16000, ge=1024, le=64000)
    anthropic_timeout_seconds: float = Field(default=60.0, ge=5.0, le=600.0)
    anthropic_max_retries: int = Field(default=1, ge=0, le=5)

    # ---- Query execution limits (askq_reader) ----
    # Every executed SELECT is bounded to this many rows (a larger LIMIT is capped).
    sql_max_rows: int = Field(default=500, ge=1, le=10000)
    # Server-side statement timeout for each executed SELECT (max_execution_time).
    sql_timeout_ms: int = Field(default=5000, ge=100, le=60000)
    # Recent conversation turns shown to the model to resolve follow-up questions.
    query_context_turns: int = Field(default=5, ge=0, le=20)

    # ---- CAIR (conversation-aware inference risk) ----
    # When false, the aggregate-only statistical tier is switched off entirely
    # (it is only safe behind CAIR); record-scope queries work as in Phase 4.
    cair_enabled: bool = True
    # Minimum number of people behind any statistic that is revealed.
    cair_min_group_size: int = Field(default=5, ge=2, le=100)
    # A detector finding with at least this score is "triggered".
    cair_trigger_threshold: float = Field(default=0.5, gt=0.0, le=1.0)
    # How much of a user's history CAIR re-examines for each question.
    cair_window_queries: int = Field(default=20, ge=1, le=200)
    cair_window_hours: int = Field(default=24, ge=1, le=24 * 30)
    # Refused statistical questions on the same attributes before further ones are refused.
    cair_refusal_probe_limit: int = Field(default=3, ge=1, le=20)
    # Largest population (distinct people) CAIR materialises per query.
    cair_population_cap: int = Field(default=20000, ge=100, le=200000)

    @field_validator(*SECRET_FIELDS, mode="before")
    @classmethod
    def _empty_secret_is_unset(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @model_validator(mode="after")
    def _validate(self) -> "Settings":
        # Secrets are checked here, not in field validators, so errors never carry the value.
        if self.jwt_algorithm not in ALLOWED_JWT_ALGORITHMS:
            raise ValueError(f"JWT_ALGORITHM must be one of {', '.join(ALLOWED_JWT_ALGORITHMS)}")
        jwt_secret = self.jwt_secret
        if (
            jwt_secret is not None
            and not _is_placeholder(jwt_secret)
            and len(jwt_secret.get_secret_value()) < MIN_JWT_SECRET_LENGTH
        ):
            raise ValueError(f"JWT_SECRET must be at least {MIN_JWT_SECRET_LENGTH} characters")

        for name in ("db_university_name", "db_system_name", "db_reader_user", "db_app_user"):
            if not _IDENTIFIER.match(getattr(self, name)):
                raise ValueError(f"{name.upper()} must match {_IDENTIFIER.pattern}")
        if self.db_university_name == self.db_system_name:
            raise ValueError("DB_UNIVERSITY_NAME and DB_SYSTEM_NAME must differ")
        # The reader (LLM-generated SQL) and the app account must never be merged.
        if self.db_reader_user == self.db_app_user:
            raise ValueError("DB_READER_USER and DB_APP_USER must be different accounts")
        reader_pw, app_pw = self.db_reader_password, self.db_app_password
        if reader_pw and app_pw and reader_pw.get_secret_value() == app_pw.get_secret_value():
            raise ValueError("DB_READER_PASSWORD and DB_APP_PASSWORD must differ")
        if self.db_pool_size + self.db_max_overflow > 20:
            raise ValueError("DB_POOL_SIZE + DB_MAX_OVERFLOW must not exceed 20")
        if not _MODEL_ID.match(self.anthropic_model):
            raise ValueError("ANTHROPIC_MODEL is not a valid model id")

        origins = self.cors_origin_list
        for origin in origins:
            if origin == "*":
                raise ValueError("CORS_ORIGINS must list explicit origins, not '*'")
            if not _ORIGIN.match(origin):
                raise ValueError(f"CORS_ORIGINS entry is not scheme://host[:port]: {origin}")

        if self.app_env == "production":
            missing = [
                name.upper()
                for name in SECRET_FIELDS
                if getattr(self, name) is None or _is_placeholder(getattr(self, name))
            ]
            if missing:
                raise ValueError(f"production requires real values for: {', '.join(missing)}")
            if "cors_origins" not in self.model_fields_set or not origins:
                raise ValueError("production requires CORS_ORIGINS to be set explicitly")
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    def secret(self, name: str) -> str:
        """Return a configured secret, or raise ConfigurationError (without the value)."""
        if name not in SECRET_FIELDS:
            raise KeyError(name)
        value: SecretStr | None = getattr(self, name)
        if value is None or _is_placeholder(value):
            raise ConfigurationError(f"{name.upper()} is not configured")
        return value.get_secret_value()

    def is_configured(self, name: str) -> bool:
        value: SecretStr | None = getattr(self, name)
        return value is not None and not _is_placeholder(value)


@lru_cache
def get_settings() -> Settings:
    return Settings()
