"""Application settings, loaded from environment variables / the root .env file.

Secrets (DB passwords, JWT secret, Anthropic API key) are never hard-coded.
Settings for later phases are added here as those phases are implemented.
"""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# The single .env file lives at the project root (C:\ASKQ\.env), one level above backend/.
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        # .env also holds settings for later phases; ignore ones not modelled yet.
        extra="ignore",
    )

    app_env: str = "development"
    # Comma-separated list of allowed browser origins for CORS.
    cors_origins: str = "http://localhost:5173"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
